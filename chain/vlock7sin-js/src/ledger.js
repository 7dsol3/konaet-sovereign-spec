'use strict';

const { createHash } = require('node:crypto');
const {
  CausalGraph,
  canonicalBytes,
  compareUtf8,
  normalizeId,
} = require('./causalGraph');
const { ConstellationSelector, computeConstellationId } = require('./constellation');
const eventCore = require('./event');
const stateCore = require('./state');
const pccCore = require('./pcc');
const { verifyHybridTransferAuthorization } = require('./hybridTransferAuthorization');
const { LIMITS, NETWORK_ID, VERSION_STRING } = require('./constants');
const { decodeRecord } = require('./persistence');
const { validateKoPolicy, executeKoPolicy } = require('./koPolicy');

const DOMAIN_PREPARATION = Buffer.from('VLOCK7SIN/LEDGER-PREPARATION/v1\0', 'ascii');

class LedgerError extends Error {
  constructor(code, message, details = undefined) {
    super(message);
    this.name = 'LedgerError';
    this.code = code;
    if (details !== undefined) this.details = details;
  }
}

function hashHex(domain, value) {
  return createHash('sha3-256').update(domain).update(canonicalBytes(value)).digest('hex');
}

function rootHex(state) { return stateCore.computeStateRoot(state).toString('hex'); }

function sequenceString(value) { return BigInt(value).toString(10); }

function eventBytes(event) {
  if (!event || typeof event.canonicalBytes !== 'function') {
    throw new LedgerError('UNSERIALIZABLE_ACT', 'ledger acts must expose canonicalBytes()');
  }
  return event.canonicalBytes();
}

function eventId(event) {
  if (!event || typeof event.id !== 'function') throw new LedgerError('INVALID_ACT', 'ledger act must expose id()');
  return normalizeId(event.id(), 'event id');
}

function assertExactKeys(value, expected, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new LedgerError('INVALID_SNAPSHOT', `${label} must be an object`);
  const actual = Object.keys(value).sort(compareUtf8);
  const wanted = [...expected].sort(compareUtf8);
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw new LedgerError('INVALID_SNAPSHOT', `${label} has missing or unexpected fields`);
  }
}

function canonicalDecimal(value, label) {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]*)$/.test(value)) {
    throw new LedgerError('INVALID_STATE_SNAPSHOT', `${label} must be canonical unsigned decimal`);
  }
  return BigInt(value);
}

function canonicalHash(value, label) {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) {
    throw new LedgerError('INVALID_STATE_SNAPSHOT', `${label} must be canonical 32-byte hex`);
  }
  return value;
}

function stateFromSnapshot(snapshot) {
  assertExactKeys(snapshot, [
    'format', 'networkId', 'suite', 'sequence', 'parametersRoot', 'identitiesRoot',
    'replayRoot', 'root', 'accounts',
  ], 'state snapshot');
  if (!snapshot || snapshot.format !== 'vlock7sin-state-js-v1' || !Array.isArray(snapshot.accounts)) {
    throw new LedgerError('INVALID_STATE_SNAPSHOT', 'unsupported state snapshot');
  }
  if (!Number.isSafeInteger(snapshot.networkId) || snapshot.networkId < 0
    || !Number.isSafeInteger(snapshot.suite) || snapshot.suite < 0) {
    throw new LedgerError('INVALID_STATE_SNAPSHOT', 'state network and suite must be canonical integers');
  }
  const sequence = canonicalDecimal(snapshot.sequence, 'state sequence');
  canonicalHash(snapshot.parametersRoot, 'parameters root');
  canonicalHash(snapshot.identitiesRoot, 'identities root');
  canonicalHash(snapshot.replayRoot, 'replay root');
  canonicalHash(snapshot.root, 'state root');
  const balances = new Map();
  const nonces = new Map();
  let previousAddress = null;
  for (const account of snapshot.accounts) {
    assertExactKeys(account, ['address', 'balance', 'nonce'], 'state account');
    if (!account || typeof account.address !== 'string') throw new LedgerError('INVALID_STATE_SNAPSHOT', 'invalid account entry');
    if (previousAddress !== null && compareUtf8(previousAddress, account.address) >= 0) {
      throw new LedgerError('INVALID_STATE_SNAPSHOT', 'state accounts are duplicated or not canonically ordered');
    }
    previousAddress = account.address;
    const balance = canonicalDecimal(account.balance, 'account balance');
    const nonce = canonicalDecimal(account.nonce, 'account nonce');
    if (balance === 0n && nonce === 0n) {
      throw new LedgerError('INVALID_STATE_SNAPSHOT', 'zero-only state accounts are not canonical');
    }
    if (balance !== 0n) balances.set(account.address, balance);
    if (nonce !== 0n) nonces.set(account.address, nonce);
  }
  const state = new stateCore.GlobalState({
    networkId: snapshot.networkId,
    suite: snapshot.suite,
    sequence,
    balances,
    nonces,
    parametersRoot: snapshot.parametersRoot,
    identitiesRoot: snapshot.identitiesRoot,
    replayRoot: snapshot.replayRoot,
  });
  if (rootHex(state) !== snapshot.root) throw new LedgerError('STATE_ROOT_MISMATCH', 'state snapshot root is invalid');
  return state;
}

class VlockLedger {
  #state;

  #graph;

  #selector;

  #quorum;

  #wal;

  #preparations;

  #hybridAuthorizations;

  #pendingNonces;

  #closures;

  #quarantined;

  #busy;

  #nativePolicy;

  constructor(options = {}) {
    this.#nativePolicy = options.nativePolicy == null ? null : validateKoPolicy(options.nativePolicy);
    this.#state = stateCore.cloneState(options.state);
    const networkId = options.networkId ?? this.#state.networkId ?? NETWORK_ID;
    if (Number(networkId) !== Number(this.#state.networkId)) {
      throw new LedgerError('WRONG_NETWORK', 'ledger network and state network differ');
    }
    const protocolVersion = String(options.protocolVersion ?? VERSION_STRING);
    if ((protocolVersion === '0.5.0-sovereign-ko.1') !== Boolean(this.#nativePolicy)) {
      throw new LedgerError('KO_POLICY_REQUIRED', 'This protocol requires its genesis-bound .ko policy.');
    }
    Object.defineProperties(this, {
      networkId: { value: networkId, enumerable: true },
      protocolVersion: { value: protocolVersion, enumerable: true },
      requireCertificate: { value: options.requireCertificate ?? Boolean(options.quorum), enumerable: true },
      requireWal: { value: options.requireWal === true, enumerable: true },
      requireHybridTransferAuthorization: { value: options.requireHybridTransferAuthorization === true, enumerable: true },
      nativePolicyHash: { value: this.#nativePolicy?.programSha256 ?? null, enumerable: true },
    });
    if (options.graph !== undefined
      && (!(options.graph instanceof CausalGraph) || Object.getPrototypeOf(options.graph) !== CausalGraph.prototype)) {
      throw new LedgerError('INVALID_GRAPH', 'ledger graph must be an exact CausalGraph instance');
    }
    this.#graph = options.graph
      ? CausalGraph.fromSnapshot(options.graph.snapshot())
      : new CausalGraph({ requireExplicitLocks: true });
    if (options.selector !== undefined
      && (!(options.selector instanceof ConstellationSelector)
        || Object.getPrototypeOf(options.selector) !== ConstellationSelector.prototype)) {
      throw new LedgerError('INVALID_SELECTOR', 'ledger selector must be an exact ConstellationSelector instance');
    }
    const selectorOptions = options.selector
      ? {
        networkId: options.selector.networkId ?? String(networkId),
        maxActs: options.selector.maxActs,
        maxBytes: options.selector.maxBytes,
        allowInternalDependencies: options.selector.allowInternalDependencies,
      }
      : {
        networkId: String(networkId),
        maxActs: options.maxActs,
        maxBytes: options.maxBytes,
        allowInternalDependencies: false,
      };
    if (String(selectorOptions.networkId) !== String(networkId)
      || selectorOptions.allowInternalDependencies === true) {
      throw new LedgerError('POLICY_MISMATCH', 'ledger selector must use this network and frontier-only dependencies');
    }
    this.#selector = new ConstellationSelector(selectorOptions);
    this.#quorum = options.quorum ?? null;
    if (this.#quorum && typeof this.#quorum.verifyCertificate !== 'function') {
      throw new LedgerError('INVALID_QUORUM', 'quorum service must expose verifyCertificate()');
    }
    if (this.requireCertificate && !this.#quorum) {
      throw new LedgerError('QUORUM_REQUIRED', 'requireCertificate needs a PermissionedQuorum verifier');
    }
    this.#wal = options.wal ?? null;
    if (this.#wal && typeof this.#wal.appendRecord !== 'function' && typeof this.#wal.append !== 'function') {
      throw new LedgerError('INVALID_WAL', 'WAL service must expose appendRecord() or append()');
    }
    if (this.requireWal && !this.#wal) throw new LedgerError('WAL_REQUIRED', 'requireWal is set but no WAL store was supplied');
    this.#preparations = new Map();
    this.#hybridAuthorizations = new Map();
    this.#pendingNonces = new Map();
    this.#closures = [];
    this.#quarantined = new Map();
    this.#busy = false;
  }

  get sequence() { return this.#state.sequence; }

  get root() { return rootHex(this.#state); }

  get closureCount() {
    return this.#state.sequence <= BigInt(Number.MAX_SAFE_INTEGER)
      ? Number(this.#state.sequence)
      : this.#state.sequence;
  }

  getState() { return this.#state.clone(); }

  getGraphSnapshot() { return this.#graph.snapshot(); }

  quarantinedActs() {
    return Object.freeze([...this.#quarantined.entries()]
      .sort(([left], [right]) => compareUtf8(left, right))
      .map(([id, metadata]) => Object.freeze({
        id,
        ...metadata,
        eventBytes: eventBytes(this.#graph.get(id)),
      })));
  }

  #eligibleIds() {
    return this.#graph.topologicalOrder()
      .filter((id) => !this.#graph.isClosed(id) && !this.#quarantined.has(id));
  }

  #assertNativeTransfer(act) {
    if (!this.#nativePolicy) return;
    executeKoPolicy(this.#nativePolicy, 'transfer', {
      'transfer.amountAtomic': act.amountAtomic.toString(), 'transfer.nonce': act.nonce.toString(),
      'transfer.networkId': String(act.networkId), 'transfer.previousRoot': act.previousRoot.toString('hex'),
      'state.senderBalance': this.#state.getBalance(act.senderAddress).toString(),
      'state.nextNonce': (this.#state.getNonce(act.senderAddress) + 1n).toString(),
      'state.networkId': String(this.#state.networkId), 'state.root': this.root,
    });
  }

  #assertNativeClosure(events) {
    if (!this.#nativePolicy) return;
    for (const act of events) this.#assertNativeTransfer(act);
    executeKoPolicy(this.#nativePolicy, 'closure', {
      'closure.actCount': String(events.length),
      'closure.byteLength': String(events.reduce((sum, act) => sum + eventBytes(act).length, 0)),
    });
  }

  #assertIndividuallyFeasible(act) {
    if (this.#state.getBalance(act.senderAddress) < act.amountAtomic) {
      throw new LedgerError('INSUFFICIENT_BALANCE', 'act sender cannot fund the transfer');
    }
    if (!this.#state.hasAccount(act.receiverAddress)
      && this.#state.accountCount >= LIMITS.STATE_ACCOUNTS) {
      throw new LedgerError('STATE_ACCOUNT_LIMIT', 'act would exceed the state account limit');
    }
  }

  #normalizeHybridAuthorization(act, evidence = undefined) {
    if (!this.requireHybridTransferAuthorization && evidence === undefined) return null;
    if (!evidence || evidence.authorization === undefined || evidence.publicIdentity === undefined) {
      throw new LedgerError('HYBRID_AUTHORIZATION_REQUIRED', 'hybrid transfer authorization and public identity are required');
    }
    let detached;
    try {
      const parsed = JSON.parse(JSON.stringify({
        authorization: evidence.authorization,
        publicIdentity: evidence.publicIdentity,
      }));
      detached = Object.freeze({
        authorization: Object.freeze(parsed.authorization),
        publicIdentity: Object.freeze(parsed.publicIdentity),
      });
    } catch (error) {
      throw new LedgerError('INVALID_HYBRID_AUTHORIZATION', 'hybrid authorization must be JSON-safe', { cause: error.message });
    }
    if (!verifyHybridTransferAuthorization(act, detached.authorization, detached.publicIdentity)) {
      throw new LedgerError('INVALID_HYBRID_AUTHORIZATION', 'hybrid authorization does not bind to this transfer');
    }
    return detached;
  }

  #setHybridAuthorization(id, evidence) {
    if (evidence) this.#hybridAuthorizations.set(id, evidence);
  }

  submitAct(actLike, evidence = undefined) {
    let act;
    try {
      act = eventCore.normalizeAct(actLike);
      act.assertValid({ expectedNetworkId: Number(this.networkId), expectedStateSuite: this.#state.suite });
    } catch (error) {
      throw new LedgerError('INVALID_ACT', 'act failed canonical/signature validation', { cause: error.message });
    }
    const id = eventId(act);
    const hybridEvidence = this.#normalizeHybridAuthorization(act, evidence);
    if (this.#graph.has(id)) throw new LedgerError('DUPLICATE_ACT', `act ${id} is already known`);
    if (!act.previousRoot.equals(this.#state.root())) {
      throw new LedgerError('STALE_ROOT', 'act does not commit to the current ledger root');
    }
    if (act.sequence !== this.#state.sequence + 1n) {
      throw new LedgerError('WRONG_SEQUENCE', 'act does not target the next constellation sequence');
    }
    if (act.nonce !== this.#state.getNonce(act.senderAddress) + 1n) {
      throw new LedgerError('NONCE_REPLAY', 'act nonce is not exactly the next sender nonce');
    }
    this.#assertIndividuallyFeasible(act);
    this.#assertNativeTransfer(act);
    const nonceKey = `${act.senderAddress}\u0000${act.nonce}`;
    const existing = this.#pendingNonces.get(nonceKey);
    if (existing) {
      throw new LedgerError('NONCE_CONFLICT', 'another pending act already uses this sender nonce', {
        existingActId: existing,
        rejectedActId: id,
      });
    }
    try { this.#graph.addAct(act); } catch (error) {
      throw new LedgerError(error.code ?? 'CAUSAL_GRAPH_REJECTED', error.message, error.details);
    }
    this.#pendingNonces.set(nonceKey, id);
    this.#setHybridAuthorization(id, hybridEvidence);
    return id;
  }

  submitActs(acts, options = {}) {
    if (!Array.isArray(acts) || !acts.length) throw new LedgerError('INVALID_BATCH', 'submitActs requires a non-empty array');
    const proofRows = options.hybridAuthorizations ?? [];
    if (!Array.isArray(proofRows)) throw new LedgerError('INVALID_HYBRID_AUTHORIZATION', 'hybridAuthorizations must be an array');
    const proofById = new Map();
    for (const row of proofRows) {
      if (!row || typeof row !== 'object' || Array.isArray(row)
        || Object.keys(row).sort().join(',') !== 'authorization,eventId,publicIdentity'
        || typeof row.eventId !== 'string' || !/^[0-9a-f]{64}$/.test(row.eventId)
        || proofById.has(row.eventId)) {
        throw new LedgerError('INVALID_HYBRID_AUTHORIZATION', 'hybrid authorization rows must have unique canonical event ids');
      }
      proofById.set(row.eventId, row);
    }
    // Validate all fields before graph insertion. Graph.addBatch itself is atomic.
    const normalized = acts.map((actLike) => {
      const act = eventCore.normalizeAct(actLike);
      act.assertValid({ expectedNetworkId: Number(this.networkId), expectedStateSuite: this.#state.suite });
      if (!act.previousRoot.equals(this.#state.root()) || act.sequence !== this.#state.sequence + 1n) {
        throw new LedgerError('STALE_ACT', 'every submitted act must target the current root and next closure sequence');
      }
      if (act.nonce !== this.#state.getNonce(act.senderAddress) + 1n) {
        throw new LedgerError('NONCE_REPLAY', 'act nonce is not exactly the next sender nonce');
      }
      this.#assertIndividuallyFeasible(act);
      this.#assertNativeTransfer(act);
      const id = eventId(act);
      const hybridEvidence = this.#normalizeHybridAuthorization(act, proofById.get(id));
      proofById.delete(id);
      return { act, id, hybridEvidence };
    });
    const nonceKeys = new Set();
    for (const { act } of normalized) {
      const key = `${act.senderAddress}\u0000${act.nonce}`;
      if (nonceKeys.has(key) || this.#pendingNonces.has(key)) throw new LedgerError('NONCE_CONFLICT', 'duplicate sender nonce in submitted batch');
      nonceKeys.add(key);
    }
    if (proofById.size) throw new LedgerError('INVALID_HYBRID_AUTHORIZATION', 'hybrid authorization references an event outside this batch');
    let ids;
    try { ids = this.#graph.addBatch(normalized.map(({ act }) => act)); } catch (error) {
      throw new LedgerError(error.code ?? 'CAUSAL_GRAPH_REJECTED', error.message, error.details);
    }
    normalized.forEach(({ act, hybridEvidence }, index) => {
      this.#pendingNonces.set(`${act.senderAddress}\u0000${act.nonce}`, ids[index]);
      this.#setHybridAuthorization(ids[index], hybridEvidence);
    });
    return ids;
  }

  proposeConstellation(options = {}) {
    if (options.eligibleIds !== undefined) {
      throw new LedgerError('NON_CANONICAL_SUBSET', 'ledger proposals always select from the complete eligible frontier');
    }
    if ((options.maxActs !== undefined && options.maxActs !== this.#selector.maxActs)
      || (options.maxBytes !== undefined && options.maxBytes !== this.#selector.maxBytes)
      || options.allowInternalDependencies === true) {
      throw new LedgerError('POLICY_MISMATCH', 'constellation limits/dependency policy are fixed by the ledger');
    }
    return this.#selector.select(this.#graph, {
      eligibleIds: this.#eligibleIds(),
      maxActs: this.#selector.maxActs,
      maxBytes: this.#selector.maxBytes,
      networkId: String(this.networkId),
      sequence: this.#state.sequence + 1n,
      previousRoot: this.#state.root(),
      allowInternalDependencies: false,
    });
  }

  prepareConstellation(candidate = undefined) {
    if (Array.isArray(candidate)) {
      throw new LedgerError('NON_CANONICAL_SUBSET', 'pass the exact proposal returned by proposeConstellation()');
    }
    const constellation = candidate == null
      ? this.proposeConstellation()
      : candidate;
    if (!constellation || !Array.isArray(constellation.actIds) || !constellation.actIds.length) {
      throw new LedgerError('EMPTY_CONSTELLATION', 'cannot prepare an empty constellation');
    }
    const actIds = constellation.actIds.map((id) => normalizeId(id));
    if (new Set(actIds).size !== actIds.length) throw new LedgerError('DUPLICATE_ACT', 'constellation contains duplicate act ids');
    const expectedSequence = this.#state.sequence + 1n;
    const expectedRoot = this.#state.root();
    const expectedId = computeConstellationId({
      networkId: String(this.networkId),
      sequence: expectedSequence,
      previousRoot: expectedRoot,
      actIds,
    });
    if (constellation.id !== expectedId) throw new LedgerError('CONSTELLATION_ID_MISMATCH', 'constellation id/context is invalid');
    if (String(constellation.sequence) !== expectedSequence.toString()
      || String(constellation.previousRoot) !== expectedRoot.toString('hex')) {
      throw new LedgerError('STALE_CONSTELLATION', 'constellation was selected for another ledger state');
    }
    if (constellation.policy?.maxActs !== this.#selector.maxActs
      || constellation.policy?.maxBytes !== this.#selector.maxBytes
      || constellation.policy?.allowInternalDependencies === true) {
      throw new LedgerError('POLICY_MISMATCH', 'constellation policy differs from the fixed ledger policy');
    }
    try {
      this.#selector.verify(this.#graph, constellation, { eligibleIds: this.#eligibleIds() });
    } catch (error) {
      throw new LedgerError('NON_CANONICAL_SELECTION', 'constellation is not the deterministic full-frontier selection', { cause: error.message });
    }
    for (const id of actIds) {
      const node = this.#graph.getNode(id);
      if (!node) throw new LedgerError('ACT_MISSING', `constellation act ${id} is missing`);
      if (this.#graph.isClosed(id)) throw new LedgerError('ALREADY_CLOSED', `act ${id} is already closed`);
      const unclosedParent = node.parents.find((parentId) => !this.#graph.isClosed(parentId));
      if (unclosedParent) throw new LedgerError('UNCLOSED_PARENT', `act ${id} has unclosed parent ${unclosedParent}`);
    }
    for (let left = 0; left < actIds.length; left += 1) {
      for (let right = left + 1; right < actIds.length; right += 1) {
        const conflicts = this.#graph.conflictDetails(actIds[left], actIds[right]);
        if (conflicts.length) throw new LedgerError('LOCK_CONFLICT', 'constellation contains conflicting acts', {
          left: actIds[left], right: actIds[right], conflicts,
        });
      }
    }
    const canonicalIds = [...actIds].sort(compareUtf8);
    if (canonicalIds.some((id, index) => id !== actIds[index])) {
      throw new LedgerError('NON_CANONICAL_ORDER', 'ready constellation acts must use lexicographic id order');
    }
    const events = actIds.map((id) => eventCore.normalizeAct(this.#graph.get(id)));
    this.#assertNativeClosure(events);
    const originalRoot = this.#state.root();
    let receipt;
    try {
      if (typeof this.#state.applyConstellationWithReceipt !== 'function') {
        throw new Error('core state lacks applyConstellationWithReceipt');
      }
      receipt = this.#state.applyConstellationWithReceipt(events);
    } catch (error) {
      throw new LedgerError('TRANSITION_REJECTED', 'constellation transition failed on cloned state', { cause: error.message });
    }
    if (!this.#state.root().equals(originalRoot)) {
      throw new LedgerError('CORE_MUTATED_SOURCE', 'state core mutated the source during staging');
    }
    if (receipt.state.sequence !== expectedSequence || receipt.eventIds.some((id, index) => id !== canonicalIds[index])) {
      throw new LedgerError('INVALID_CORE_RECEIPT', 'state core returned a non-canonical closure receipt');
    }
    const witness = pccCore.createPcc({
      networkId: Number(this.networkId),
      sequence: expectedSequence,
      previousRoot: receipt.previousRoot,
      nextRoot: receipt.nextRoot,
      transitionTrace: receipt.transitionTrace,
    });
    const pccProof = witness.proof();
    if (!pccCore.verifyPccTransition(witness, pccProof, {
      previousState: this.#state,
      transition: events,
      transitionTrace: receipt.transitionTrace,
    })) {
      throw new LedgerError('PCC_TRANSITION_INVALID', 'PCC failed full transition recomputation');
    }
    const proposalBase = {
      version: 1,
      networkId: String(this.networkId),
      protocolVersion: this.protocolVersion,
      sequence: sequenceString(expectedSequence),
      constellationId: constellation.id,
      actIds: canonicalIds,
      previousRoot: receipt.previousRoot.toString('hex'),
      nextRoot: receipt.nextRoot.toString('hex'),
      transitionTrace: receipt.transitionTrace.toString('hex'),
      pcc: pccProof.toString('hex'),
      pccWitness: witness.toJSON(),
      policy: constellation.policy,
      ...(actIds.some((id) => this.#hybridAuthorizations.has(id)) ? {
        hybridTransferAuthorizations: Object.freeze(actIds
          .filter((id) => this.#hybridAuthorizations.has(id))
          .map((id) => Object.freeze({
            eventId: id,
            authorization: this.#hybridAuthorizations.get(id).authorization,
            publicIdentity: this.#hybridAuthorizations.get(id).publicIdentity,
          }))),
      } : {}),
    };
    const preparationId = hashHex(DOMAIN_PREPARATION, proposalBase);
    const proposal = Object.freeze({ ...proposalBase, preparationId, actIds: Object.freeze(canonicalIds) });
    this.#preparations.set(preparationId, Object.freeze({ proposal, constellation, events: Object.freeze(events), witness }));
    return proposal;
  }

  commitPrepared(preparation, options = {}) {
    if (this.#busy) throw new LedgerError('LEDGER_BUSY', 'another closure commit is in progress');
    this.#busy = true;
    try {
      return this._commitPrepared(preparation, options, true);
    } finally {
      this.#busy = false;
    }
  }

  _commitPrepared(preparation, options, persist) {
    const id = typeof preparation === 'string' ? preparation : preparation?.preparationId;
    const staged = this.#preparations.get(String(id));
    if (!staged) throw new LedgerError('PREPARATION_MISSING', 'unknown or stale preparation id');
    const { proposal, events, witness } = staged;
    this.#assertNativeClosure(events);
    if (this.root !== proposal.previousRoot || this.#state.sequence + 1n !== BigInt(proposal.sequence)) {
      this.#preparations.delete(proposal.preparationId);
      throw new LedgerError('STALE_PREPARATION', 'ledger advanced after this constellation was prepared');
    }
    let recomputed;
    try { recomputed = this.#state.applyConstellationWithReceipt(events); } catch (error) {
      throw new LedgerError('TRANSITION_REJECTED', 'transition no longer applies', { cause: error.message });
    }
    if (recomputed.nextRoot.toString('hex') !== proposal.nextRoot
      || recomputed.transitionTrace.toString('hex') !== proposal.transitionTrace
      || !pccCore.verifyPccTransition(witness, Buffer.from(proposal.pcc, 'hex'), {
        previousState: this.#state,
        transition: events,
        transitionTrace: recomputed.transitionTrace,
      })) {
      throw new LedgerError('PREPARATION_TAMPERED', 'prepared closure failed deterministic recomputation');
    }
    const expectedHybridAuthorizations = proposal.actIds
      .filter((actId) => this.#hybridAuthorizations.has(actId))
      .map((actId) => Object.freeze({
        eventId: actId,
        authorization: this.#hybridAuthorizations.get(actId).authorization,
        publicIdentity: this.#hybridAuthorizations.get(actId).publicIdentity,
      }));
    if ((this.requireHybridTransferAuthorization && expectedHybridAuthorizations.length !== proposal.actIds.length)
      || !canonicalBytes(expectedHybridAuthorizations).equals(canonicalBytes(proposal.hybridTransferAuthorizations ?? []))) {
      throw new LedgerError('HYBRID_AUTHORIZATION_MISMATCH', 'prepared transfer authorization set changed or is incomplete');
    }
    const certificate = options.certificate ?? null;
    if (this.requireCertificate && !certificate) throw new LedgerError('CERTIFICATE_REQUIRED', 'permissioned k-of-n certificate is required');
    const round = options.round ?? 0;
    const roundChangeCertificate = options.roundChangeCertificate ?? null;
    if (!Number.isSafeInteger(round) || round < 0
      || (round === 0 && roundChangeCertificate !== null)
      || (round > 0 && !roundChangeCertificate)) {
      throw new LedgerError('INVALID_ROUND_METADATA', 'round metadata must include a valid round-change certificate when round is nonzero');
    }
    if (certificate) {
      if (!this.#quorum) throw new LedgerError('QUORUM_UNAVAILABLE', 'cannot verify supplied permissioned certificate');
      let certificateValid;
      try { certificateValid = this.#quorum.verifyCertificate(certificate, proposal); } catch (error) {
        throw new LedgerError('INVALID_CERTIFICATE', 'permissioned k-of-n certificate failed verification', { cause: error.message });
      }
      if (certificateValid !== true) {
        throw new LedgerError('INVALID_CERTIFICATE', 'permissioned k-of-n verifier did not positively accept certificate');
      }
    }
    const closingSet = new Set(proposal.actIds);
    const staleAfterClosure = this.#eligibleIds().filter((candidateId) => {
      if (closingSet.has(candidateId)) return false;
      const candidateAct = eventCore.normalizeAct(this.#graph.get(candidateId));
      return candidateAct.sequence === BigInt(proposal.sequence)
        && candidateAct.previousRoot.toString('hex') === proposal.previousRoot;
    }).sort(compareUtf8);
    const record = Object.freeze({
      kind: 'VLOCK7SIN_CLOSURE_COMMIT',
      version: 1,
      networkId: String(this.networkId),
      protocolVersion: this.protocolVersion,
      sequence: proposal.sequence,
      constellationId: proposal.constellationId,
      actIds: proposal.actIds,
      events: Object.freeze(events.map(eventBytes)),
      previousRoot: proposal.previousRoot,
      nextRoot: proposal.nextRoot,
      transitionTrace: proposal.transitionTrace,
      pcc: proposal.pcc,
      pccWitness: witness.encode(),
      policy: proposal.policy,
      certificate,
      round,
      roundChangeCertificate,
      ...(expectedHybridAuthorizations.length ? {
        hybridTransferAuthorizations: Object.freeze(expectedHybridAuthorizations),
      } : {}),
      closureScope: certificate?.scope === 'hybrid-permissioned-k-of-n'
        ? 'hybrid-permissioned-k-of-n'
        : (certificate ? 'permissioned-k-of-n' : 'local-only'),
      expiredActIds: Object.freeze(staleAfterClosure),
    });
    let walFrame = null;
    if (persist && this.#wal) {
      try {
        walFrame = typeof this.#wal.appendRecord === 'function'
          ? this.#wal.appendRecord(record)
          : this.#wal.append(record);
      } catch (error) {
        throw new LedgerError('WAL_APPEND_FAILED', 'durable WAL append failed; state was not committed', { cause: error.message });
      }
    } else if (persist && this.requireWal) {
      throw new LedgerError('WAL_REQUIRED', 'durable WAL is required before commit');
    }

    // All throwing checks, certificate verification and fsync happen before this
    // short in-memory commit section. A crash after WAL fsync is recovered by replay.
    try { this.#graph.markClosed(proposal.actIds); } catch (error) {
      throw new LedgerError('GRAPH_COMMIT_FAILED', 'WAL is durable but graph commit failed; restart and replay WAL', { cause: error.message });
    }
    this.#state = recomputed.state;
    for (const event of events) this.#pendingNonces.delete(`${event.senderAddress}\u0000${event.nonce}`);
    for (const staleId of staleAfterClosure) {
      const staleEvent = eventCore.normalizeAct(this.#graph.get(staleId));
      this.#pendingNonces.delete(`${staleEvent.senderAddress}\u0000${staleEvent.nonce}`);
      this.#quarantined.set(staleId, Object.freeze({
        reason: 'STALE_AFTER_CLOSURE',
        closedSequence: proposal.sequence,
        previousRoot: proposal.previousRoot,
      }));
    }
    const closure = Object.freeze({
      ...record,
      events: Object.freeze(record.events.map((bytes) => Buffer.from(bytes))),
      walFrame,
    });
    this.#closures.push(Object.freeze({
      sequence: proposal.sequence,
      constellationId: proposal.constellationId,
      nextRoot: proposal.nextRoot,
      closureScope: record.closureScope,
    }));
    this.#preparations.clear();
    return closure;
  }

  closeConstellation(candidate = undefined, options = {}) {
    const proposal = this.prepareConstellation(candidate);
    return this.commitPrepared(proposal, options);
  }

  recover(report, options = {}) {
    if (this.#closures.length || [...this.#graph.nodes.keys()].some((id) => !this.#graph.isClosed(id))) {
      throw new LedgerError('RECOVERY_REQUIRES_PRISTINE_LEDGER', 'recover requires initial state with no pending acts or closures');
    }
    if (!report || !Array.isArray(report.frames)) throw new LedgerError('INVALID_RECOVERY_REPORT', 'WAL recovery report is required');
    if (!report.clean && !(report.truncated && !report.corrupt && options.allowTruncatedTail === true)) {
      throw new LedgerError('UNCLEAN_WAL', 'WAL is corrupt or truncated; explicit truncated-tail acceptance is required');
    }
    for (const frame of report.frames) {
      const record = frame.record ?? decodeRecord(frame.payload);
      if (!record || record.kind !== 'VLOCK7SIN_CLOSURE_COMMIT' || record.version !== 1) {
        throw new LedgerError('INVALID_WAL_RECORD', `unsupported WAL record at frame ${frame.index}`);
      }
      if (record.networkId !== String(this.networkId) || record.protocolVersion !== this.protocolVersion) {
        throw new LedgerError('WRONG_NETWORK', `WAL frame ${frame.index} belongs to another network/version`);
      }
      const events = record.events.map((bytes) => eventCore.decodeEvent(bytes));
      const ids = this.submitActs(events, { hybridAuthorizations: record.hybridTransferAuthorizations ?? [] });
      if (ids.length !== record.actIds.length || ids.some((id, index) => id !== record.actIds[index])) {
        throw new LedgerError('WAL_ACT_MISMATCH', `WAL frame ${frame.index} act ids are invalid`);
      }
      const constellation = this.proposeConstellation();
      const proposal = this.prepareConstellation(constellation);
      for (const field of ['sequence', 'constellationId', 'previousRoot', 'nextRoot', 'transitionTrace', 'pcc']) {
        if (proposal[field] !== record[field]) throw new LedgerError('WAL_COMMITMENT_MISMATCH', `WAL frame ${frame.index} has invalid ${field}`);
      }
      if (!canonicalBytes(proposal.hybridTransferAuthorizations ?? [])
        .equals(canonicalBytes(record.hybridTransferAuthorizations ?? []))) {
        throw new LedgerError('WAL_COMMITMENT_MISMATCH', `WAL frame ${frame.index} has invalid hybrid transfer authorizations`);
      }
      this._commitPrepared(proposal, {
        certificate: record.certificate,
        round: record.round ?? 0,
        roundChangeCertificate: record.roundChangeCertificate ?? null,
      }, false);
    }
    return Object.freeze({ closures: this.closureCount, sequence: this.sequence, root: this.root, cleanWal: report.clean });
  }

  snapshot() {
    return Object.freeze({
      format: 'vlock7sin-ledger-js-v1',
      networkId: String(this.networkId),
      protocolVersion: this.protocolVersion,
      state: this.#state.snapshot(),
      ...(this.#nativePolicy ? { nativePolicyHash: this.nativePolicyHash } : {}),
      graph: Object.freeze({
        version: this.#hybridAuthorizations.size ? 2 : 1,
        closed: Object.freeze([...this.#graph.closed].sort(compareUtf8)),
        quarantined: Object.freeze(this.quarantinedActs().map(({ id, reason, closedSequence, previousRoot }) => Object.freeze({
          id,
          reason,
          closedSequence,
          previousRoot,
        }))),
        acts: Object.freeze(this.#graph.topologicalOrder().map((id) => eventBytes(this.#graph.get(id)))),
        ...(this.#hybridAuthorizations.size ? {
          hybridTransferAuthorizations: Object.freeze([...this.#hybridAuthorizations.entries()]
            .sort(([left], [right]) => compareUtf8(left, right))
            .map(([eventIdValue, evidence]) => Object.freeze({
              eventId: eventIdValue,
              authorization: evidence.authorization,
              publicIdentity: evidence.publicIdentity,
            }))),
        } : {}),
      }),
      root: this.root,
    });
  }

  static fromSnapshot(snapshot, options = {}) {
    assertExactKeys(snapshot, ['format', 'networkId', 'protocolVersion', 'state', 'graph', 'root',
      ...(snapshot?.protocolVersion === '0.5.0-sovereign-ko.1' ? ['nativePolicyHash'] : [])], 'ledger snapshot');
    if (snapshot.format !== 'vlock7sin-ledger-js-v1') throw new LedgerError('INVALID_LEDGER_SNAPSHOT', 'unsupported ledger snapshot');
    if (typeof snapshot.networkId !== 'string' || typeof snapshot.protocolVersion !== 'string'
      || !/^[0-9a-f]{64}$/.test(String(snapshot.root))) {
      throw new LedgerError('INVALID_LEDGER_SNAPSHOT', 'ledger snapshot identity/root fields are invalid');
    }
    const graphKeys = snapshot.graph?.version === 2
      ? ['version', 'closed', 'quarantined', 'acts', 'hybridTransferAuthorizations']
      : ['version', 'closed', 'quarantined', 'acts'];
    assertExactKeys(snapshot.graph, graphKeys, 'ledger graph snapshot');
    if (![1, 2].includes(snapshot.graph.version) || !Array.isArray(snapshot.graph.acts)
      || !Array.isArray(snapshot.graph.closed) || !Array.isArray(snapshot.graph.quarantined)) {
      throw new LedgerError('INVALID_LEDGER_SNAPSHOT', 'invalid graph snapshot collections');
    }
    if (snapshot.graph.version === 2 && !Array.isArray(snapshot.graph.hybridTransferAuthorizations)) {
      throw new LedgerError('INVALID_LEDGER_SNAPSHOT', 'invalid hybrid transfer authorization collection');
    }
    const state = stateFromSnapshot(snapshot.state);
    if (String(state.networkId) !== snapshot.networkId) throw new LedgerError('WRONG_NETWORK', 'snapshot state/ledger networks differ');
    const graph = new CausalGraph({ requireExplicitLocks: true });
    const acts = snapshot.graph.acts.map((bytes) => eventCore.decodeEvent(bytes));
    if (acts.length) graph.addBatch(acts);
    if (new Set(snapshot.graph.closed).size !== snapshot.graph.closed.length) throw new LedgerError('INVALID_LEDGER_SNAPSHOT', 'duplicate closed act id');
    const sortedClosed = [...snapshot.graph.closed].sort(compareUtf8);
    if (sortedClosed.some((id, index) => id !== snapshot.graph.closed[index])) throw new LedgerError('INVALID_LEDGER_SNAPSHOT', 'closed act ids are not canonical');
    const encodedOrder = acts.map(eventId);
    const canonicalOrder = graph.topologicalOrder();
    if (encodedOrder.some((id, index) => id !== canonicalOrder[index])) throw new LedgerError('INVALID_LEDGER_SNAPSHOT', 'graph acts are not in canonical topological order');
    if (snapshot.graph.closed.length) graph.markClosed(snapshot.graph.closed);
    const ledger = new VlockLedger({ ...options, state, graph, networkId: snapshot.networkId, protocolVersion: snapshot.protocolVersion });
    if (ledger.nativePolicyHash !== (snapshot.nativePolicyHash ?? null)) {
      throw new LedgerError('KO_POLICY_MISMATCH', 'Snapshot and runtime .ko policy commitments differ.');
    }
    const snapshotAuthorizations = snapshot.graph.hybridTransferAuthorizations ?? [];
    if (!Array.isArray(snapshotAuthorizations)) throw new LedgerError('INVALID_LEDGER_SNAPSHOT', 'hybrid authorizations must be an array');
    let previousAuthorizationId = null;
    for (const row of snapshotAuthorizations) {
      if (!row || typeof row !== 'object' || Array.isArray(row)
        || Object.keys(row).sort().join(',') !== 'authorization,eventId,publicIdentity'
        || typeof row.eventId !== 'string' || !/^[0-9a-f]{64}$/.test(row.eventId)
        || (previousAuthorizationId !== null && compareUtf8(previousAuthorizationId, row.eventId) >= 0)
        || !graph.has(row.eventId)) {
        throw new LedgerError('INVALID_LEDGER_SNAPSHOT', 'hybrid authorization rows must be canonical and reference known events');
      }
      previousAuthorizationId = row.eventId;
      const event = eventCore.normalizeAct(graph.get(row.eventId));
      const evidence = ledger.#normalizeHybridAuthorization(event, row);
      ledger.#setHybridAuthorization(row.eventId, evidence);
    }
    if (ledger.requireHybridTransferAuthorization && acts.length !== snapshotAuthorizations.length) {
      throw new LedgerError('HYBRID_AUTHORIZATION_REQUIRED', 'hybrid-required snapshot is missing transfer authorization evidence');
    }
    let previousQuarantined = null;
    for (const item of snapshot.graph.quarantined) {
      assertExactKeys(item, ['id', 'reason', 'closedSequence', 'previousRoot'], 'quarantined act');
      const id = normalizeId(item.id);
      if (previousQuarantined !== null && compareUtf8(previousQuarantined, id) >= 0) throw new LedgerError('INVALID_LEDGER_SNAPSHOT', 'quarantine entries are not canonical');
      previousQuarantined = id;
      if (!graph.has(id) || graph.isClosed(id) || ledger.#quarantined.has(id)
        || item.reason !== 'STALE_AFTER_CLOSURE'
        || !/^(0|[1-9][0-9]*)$/.test(String(item.closedSequence))
        || !/^[0-9a-f]{64}$/.test(String(item.previousRoot))) {
        throw new LedgerError('INVALID_LEDGER_SNAPSHOT', `invalid quarantine entry ${id}`);
      }
      ledger.#quarantined.set(id, Object.freeze({
        reason: item.reason,
        closedSequence: String(item.closedSequence),
        previousRoot: item.previousRoot,
      }));
    }
    for (const id of graph.topologicalOrder()) {
      if (graph.isClosed(id) || ledger.#quarantined.has(id)) continue;
      const act = eventCore.normalizeAct(graph.get(id));
      if (!act.previousRoot.equals(state.root()) || act.sequence !== state.sequence + 1n
        || act.nonce !== state.getNonce(act.senderAddress) + 1n) {
        throw new LedgerError('INVALID_LEDGER_SNAPSHOT', `pending act ${id} is stale or has invalid nonce`);
      }
      ledger.#assertNativeTransfer(act);
      const nonceKey = `${act.senderAddress}\u0000${act.nonce}`;
      if (ledger.#pendingNonces.has(nonceKey)) throw new LedgerError('INVALID_LEDGER_SNAPSHOT', 'pending acts reuse a sender nonce');
      ledger.#pendingNonces.set(nonceKey, id);
    }
    if (ledger.root !== snapshot.root) throw new LedgerError('LEDGER_ROOT_MISMATCH', 'ledger snapshot root is invalid');
    return ledger;
  }
}

module.exports = {
  LedgerError,
  VlockLedger,
  stateFromSnapshot,
};
