'use strict';
const { GlobalState, verifyInclusionProof, verifyAbsenceProof } = require('./state');
const { sha3, domainHash } = require('./crypto');
const { DOMAINS, LIMITS } = require('./constants');
const { BinaryWriter } = require('./codec');
const { normalizeAct, TransferEvent } = require('./event');
const { ContractEvent } = require('./contractEvent');
const { canonicalBytes, compareUtf8 } = require('./causalGraph');
const { runtime, auth } = require('./koProgramRuntime');
const { PROFILE, PROFILE_HASH } = require('./koConsensusProfile');
const DOMAIN = Buffer.from('VLOCK7SIN/KO-STATE/v1\0', 'ascii');
const knownRecords = new WeakSet();
function fail(message) { const error = Error(message); error.code = 'KO_CONSENSUS_STATE'; throw error; }
function exact(value, fields) { if (!value || typeof value !== 'object' || Array.isArray(value)
  || Object.keys(value).sort().join(',') !== [...fields].sort().join(',')) fail('Unexpected state snapshot fields.'); }
function freeze(value) { if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); } return value; }
function baseOptions(state) { return { networkId: state.networkId, suite: state.suite, sequence: state.sequence,
  balances: state.entries().map(row => [row.address, row.balance]), nonces: state.entries().map(row => [row.address, row.nonce]),
  parametersRoot: state.parametersRoot, identitiesRoot: state.identitiesRoot, replayRoot: state.replayRoot }; }
function contractRecord(input, networkId) {
  if (knownRecords.has(input)) {
    if (input.state.networkId !== String(networkId)) fail('Contract belongs to another network or source profile.');
    return input;
  }
  exact(input, ['artifact', 'state']);
  const artifact = runtime.validateContract(input.artifact), state = runtime.validateContractState(artifact, input.state);
  if (state.networkId !== String(networkId) || Buffer.byteLength(artifact.source) > PROFILE.sourceBytes) fail('Contract belongs to another network or source profile.');
  const record = freeze({ artifact, state }); knownRecords.add(record); return record;
}
class KoGlobalState extends GlobalState {
  #contracts; #receipts; #executionCache = new WeakMap();
  constructor(options = {}) {
    super(options.baseState ? baseOptions(options.baseState) : options);
    const contracts = options.contracts ?? [];
    if (!Array.isArray(contracts) || contracts.length > PROFILE.contracts) fail('Contract count exceeds profile.');
    this.#contracts = new Map(); let previous = null;
    for (const input of contracts) {
      const record = contractRecord(input, this.networkId), id = record.state.contractId;
      if (previous !== null && previous >= id) fail('Contracts must be uniquely sorted.');
      previous = id; this.#contracts.set(id, record);
    }
    this.#receipts = freeze(JSON.parse(JSON.stringify(options.receipts ?? [])));
    if (!Array.isArray(this.#receipts) || this.#receipts.length > LIMITS.NEXUS_COUNT) fail('Invalid receipt collection.');
    if (canonicalBytes(this.contracts()).length + canonicalBytes(this.#receipts).length > PROFILE.stateBytes) fail('Contract state exceeds profile byte limit.');
  }
  get contractRuntimeHash() { return PROFILE_HASH; }
  contracts() { return Object.freeze([...this.#contracts.values()]); }
  contract(id) { return this.#contracts.get(id) ?? null; }
  receipts() { return this.#receipts; }
  contractsRoot() { return sha3(Buffer.concat([Buffer.from('VLOCK7SIN/KO-CONTRACTS/v1\0'), canonicalBytes(this.contracts().map(({ artifact, state }) =>
    ({ contractId: state.contractId, programSha256: artifact.programSha256, sourceSha256: artifact.sourceSha256, stateRoot: state.stateRoot })))])); }
  receiptsRoot() { return sha3(Buffer.concat([Buffer.from('VLOCK7SIN/KO-RECEIPTS/v1\0'), canonicalBytes(this.#receipts)])); }
  commitmentBytes() { return Buffer.concat([DOMAIN, sha3(super.commitmentBytes()), this.contractsRoot(), this.receiptsRoot()]); }
  canonicalBytes() { return canonicalBytes(this.snapshot()); }
  #accounts() { return new GlobalState(baseOptions(this)); }
  clone() { return new KoGlobalState({ baseState: this, contracts: this.contracts(), receipts: this.#receipts }); }
  createInclusionProof(address) { return this.#wrapProof(this.#accounts().createInclusionProof(address)); }
  createAbsenceProof(address) { return this.#wrapProof(this.#accounts().createAbsenceProof(address)); }
  #wrapProof(accountProof) { return freeze({ format: 'vlock7sin-ko-account-proof-v1', accountProof,
    contractsRoot: this.contractsRoot().toString('hex'), receiptsRoot: this.receiptsRoot().toString('hex'), stateRoot: this.root().toString('hex') }); }
  validateContractEvent(event) {
    if (!(event instanceof ContractEvent)) fail('Typed contract event required.');
    if (this.#executionCache.has(event)) return this.#executionCache.get(event);
    let receipt;
    if (event.kind === 'KONAET_KO_DEPLOY_V1') {
      if (this.#contracts.has(event.contractId) || this.#contracts.size >= PROFILE.contracts) fail('Contract already deployed or count limit reached.');
      receipt = auth.deploySignedContract(event.artifact, event.envelope);
    } else {
      const record = this.contract(event.contractId); if (!record) fail('Contract not deployed.');
      receipt = auth.callSignedContract(record.artifact, record.state, event.envelope);
      if (receipt.readOnly) fail('Views are queried without consensus transactions.');
    }
    this.#executionCache.set(event, receipt);
    return receipt;
  }
  applyConstellation(eventLikes) {
    if (!Array.isArray(eventLikes) || !eventLikes.length || eventLikes.length > PROFILE.actsPerClosure) fail('Invalid closure event count.');
    const events = eventLikes.map(normalizeAct).sort((a, b) => Buffer.compare(a.id(), b.id()));
    const resources = new Set(), ids = new Set(), receipts = [], contracts = new Map(this.#contracts), accounts = this.#accounts();
    let gas = 0;
    for (const event of events) {
      event.assertValid({ expectedNetworkId: this.networkId, expectedStateSuite: this.suite });
      if (!event.previousRoot.equals(this.root()) || event.sequence !== this.sequence + 1n || event.nonce !== this.getNonce(event.senderAddress) + 1n) fail('Event root, sequence or nonce mismatch.');
      const id = event.id().toString('hex'); if (ids.has(id)) fail('Duplicate event.'); ids.add(id);
      const locks = event instanceof ContractEvent ? event.locks.write
        : [`account:${event.senderAddress}`, `account:${event.receiverAddress}`, `nonce:${event.senderAddress}`];
      for (const resource of locks) { if (resources.has(resource)) fail('Conflicting event resources.'); resources.add(resource); }
      if (event instanceof ContractEvent) {
        // Reserve the signed maximum before running; block work is bounded even
        // when every call is valid but computationally expensive.
        gas += event.envelope.payload.gasLimit; if (gas > PROFILE.gasPerClosure) fail('Closure gas reservation exceeds profile.');
        const receipt = this.validateContractEvent(event), artifact = event.artifact ?? this.contract(event.contractId).artifact;
        contracts.set(event.contractId, contractRecord({ artifact, state: receipt.state }, this.networkId));
        receipts.push({ eventId: id, contractId: event.contractId, caller: event.senderAddress,
          method: receipt.method ?? '$deploy', result: receipt.result ?? null, gasUsed: receipt.gasUsed, events: receipt.events ?? [],
          contractStateRoot: receipt.state.stateRoot });
      } else {
        if (!(event instanceof TransferEvent)) fail('Unsupported transaction type.');
        accounts.debit(event.senderAddress, event.amountAtomic); accounts.credit(event.receiverAddress, event.amountAtomic);
      }
      accounts.setNonce(event.senderAddress, event.nonce);
    }
    const writer = new BinaryWriter(LIMITS.RECORD_BYTES); writer.write(this.replayRoot).u16(events.length);
    for (const event of events) writer.write(event.id()).write(event.transitionTrace());
    const nextBase = new GlobalState({ ...baseOptions(accounts), sequence: this.sequence + 1n, replayRoot: domainHash(DOMAINS.REPLAY, writer.finish()) });
    return new KoGlobalState({ baseState: nextBase, contracts: [...contracts.values()].sort((a, b) => compareUtf8(a.state.contractId, b.state.contractId)), receipts });
  }
  snapshot() { return freeze({ format: PROFILE.stateFormat, accountState: this.#accounts().snapshot(), contracts: this.contracts(), receipts: this.#receipts,
    contractsRoot: this.contractsRoot().toString('hex'), receiptsRoot: this.receiptsRoot().toString('hex'), root: this.root().toString('hex') }); }
  static fromSnapshot(snapshot) {
    exact(snapshot, ['format', 'accountState', 'contracts', 'receipts', 'contractsRoot', 'receiptsRoot', 'root']);
    if (snapshot.format !== PROFILE.stateFormat || snapshot.accountState?.format !== 'vlock7sin-state-js-v1') fail('Unsupported state snapshot.');
    const baseState = require('./ledger').stateFromSnapshot(snapshot.accountState); // eslint-disable-line global-require
    const state = new KoGlobalState({ baseState, contracts: snapshot.contracts, receipts: snapshot.receipts });
    if (!canonicalBytes(state.snapshot()).equals(canonicalBytes(snapshot))) fail('State snapshot roots or canonical data differ.');
    return state;
  }
}
function verifyKoAccountProof(proof, expectedRoot) {
  try {
    exact(proof, ['format', 'accountProof', 'contractsRoot', 'receiptsRoot', 'stateRoot']);
    if (proof.format !== 'vlock7sin-ko-account-proof-v1' || ![proof.contractsRoot, proof.receiptsRoot, proof.stateRoot, expectedRoot].every(value => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value))) return false;
    const valid = proof.accountProof.type === 'inclusion' ? verifyInclusionProof(proof.accountProof) : verifyAbsenceProof(proof.accountProof);
    const root = sha3(Buffer.concat([DOMAIN, Buffer.from(proof.accountProof.stateRoot, 'hex'), Buffer.from(proof.contractsRoot, 'hex'), Buffer.from(proof.receiptsRoot, 'hex')])).toString('hex');
    return valid && root === expectedRoot && root === proof.stateRoot;
  } catch { return false; }
}
module.exports = Object.freeze({ KoGlobalState, verifyKoAccountProof });
