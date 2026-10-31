'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { crypto: vcrypto, UNIT, VlockLedger, createTransfer, recoverWal, WalStore, decodeEvent } = require('../chain/vlock7sin-js/src');
const { createGenesis, validateGenesis, stateFromGenesis, SovereignNode } = require('../chain/network/sovereign');
const { compileKoPolicy } = require('../chain/vlock7sin-js/src/koPolicy');
const { ContractEvent } = require('../chain/vlock7sin-js/src/contractEvent');
const { KoGlobalState, verifyKoAccountProof } = require('../chain/vlock7sin-js/src/koState');
const { PROFILE, FORMAT, PROTOCOL } = require('../chain/vlock7sin-js/src/koConsensusProfile');
const { runtime, auth } = require('../chain/vlock7sin-js/src/koProgramRuntime');
const { encodeRecord, decodeRecord } = require('../chain/vlock7sin-js/src/persistence');
const root = path.resolve(__dirname, '..');
const source = fs.readFileSync(path.join(root, 'chain/ko-program/examples/RegistryToken.ko'), 'utf8');
function fixture() {
  const keys = Array.from({ length: 4 }, () => vcrypto.IdentityKeypair.generate());
  const owner = vcrypto.IdentityKeypair.generate(), bob = vcrypto.IdentityKeypair.generate();
  const nativePolicy = compileKoPolicy(fs.readFileSync(path.join(root, 'chain/contracts-ko/SindraRuntime.ko'), 'utf8'));
  const options = { format: FORMAT, contractRuntime: PROFILE, networkId: 77110777, createdAt: '2026-10-30T00:00:00.000Z',
    validators: keys.map((key, i) => ({ id: `validator-${i}`, publicKey: key.publicBytes() })), threshold: 3,
    allocations: [{ address: owner.address(), amountAtomic: UNIT.initialSupplyAtomic }], nativePolicy,
    parameters: { maxActs: 64, maxBytes: 262144, stateSyncChunk: 4, messageRateLimit: 512 } };
  const genesis = createGenesis(options);
  const ledger = extra => new VlockLedger({ state: stateFromGenesis(genesis), protocolVersion: PROTOCOL, nativePolicy, ...extra });
  return { keys, owner, bob, options, genesis, nativePolicy, ledger };
}
function directory(t) { const base = fs.mkdtempSync(path.join(os.tmpdir(), 'konaet-ko-consensus-'));
  t.after(() => { const target = path.resolve(base); assert.ok(target.startsWith(path.resolve(os.tmpdir()) + path.sep));
    assert.match(path.basename(target), /^konaet-ko-consensus-/); fs.rmSync(target, { recursive: true, force: true }); }); return base; }
function deploy(f, state, signer = f.owner, salt = '0', gasLimit = 10000) {
  const artifact = runtime.compileContract(source), envelope = auth.signDeployment(artifact, { networkId: f.genesis.networkId, salt, gasLimit }, signer.privateKeyObject());
  return new ContractEvent({ source, envelope, previousRoot: state.root().toString('hex'), sequence: (state.sequence + 1n).toString(), nonce: (state.getNonce(signer.address()) + 1n).toString(), signature: '' }).sign(signer);
}
function call(f, state, contractId, method, args, signer = f.owner) {
  const record = state.contract(contractId), envelope = auth.signCall(record.artifact, record.state, { method, args, gasLimit: 10000 }, signer.privateKeyObject());
  return new ContractEvent({ source: null, envelope, previousRoot: state.root().toString('hex'), sequence: (state.sequence + 1n).toString(), nonce: (state.getNonce(signer.address()) + 1n).toString(), signature: '' }).sign(signer);
}
test('v7 genesis binds contract runtime, isolated state and protocol without changing v6', () => {
  const f = fixture(); assert.equal(f.genesis.protocolVersion, PROTOCOL); assert.deepEqual(validateGenesis(f.genesis), f.genesis);
  const old = { ...f.options }; delete old.contractRuntime; delete old.format; const v6 = createGenesis(old);
  assert.equal(v6.format, 'konaet-sovereign-genesis-v6-ko-policy'); assert.notEqual(v6.stateRoot, f.genesis.stateRoot);
  assert.throws(() => createGenesis({ ...f.options, contractRuntime: { ...PROFILE, gasPerClosure: 1 } }), { code: 'KO_PROGRAM_PROFILE_MISMATCH' });
  assert.throws(() => createGenesis({ ...f.options, protocolVersion: v6.protocolVersion }), { code: 'KO_PROTOCOL_MISMATCH' });
  assert.throws(() => new VlockLedger({ state: stateFromGenesis(v6), protocolVersion: PROTOCOL, nativePolicy: f.nativePolicy }), { code: 'KO_PROGRAM_PROFILE_REQUIRED' });
  const { build } = require('../chain/scripts/buildIndependentGenesis');
  const roster = { ...f.options, parameters: undefined, scope: 'private-testnet-no-value', validators: f.options.validators.map((row, i) =>
    ({ ...row, publicKey: row.publicKey.toString('hex'), administratorId: `operator-${i}` })) };
  const operated = build(roster); assert.equal(operated.protocolVersion, PROTOCOL); assert.equal(operated.parameters.maxActs, 64); assert.equal(operated.parameters.maxBytes, 262144);
  assert.throws(() => createGenesis({ ...f.options, parameters: { maxActs: 65 } }), { code: 'KO_PROGRAM_CLOSURE_LIMIT' });
});
test('typed wire events bind both signatures, root, nonce and source; canonical decode rejects edits', () => {
  const f = fixture(), event = deploy(f, stateFromGenesis(f.genesis));
  assert.ok(decodeEvent(event.canonicalBytes()) instanceof ContractEvent); assert.equal(decodeEvent(event.canonicalBytes()).id().toString('hex'), event.id().toString('hex'));
  const json = event.toJSON(); delete json.format; delete json.kind; delete json.id;
  json.previousRoot = 'f'.repeat(64); assert.equal(new ContractEvent(json).verify({ expectedNetworkId: Number(f.genesis.networkId) }), false);
  assert.throws(() => decodeEvent(Buffer.concat([event.canonicalBytes(), Buffer.from(' ')])));
  assert.throws(() => event.sign(f.bob));
});
test('deployment, issuance and transfer finalize into the ledger root; failed and repeated calls are atomic', () => {
  const f = fixture(), ledger = f.ledger(), event = deploy(f, ledger.getState());
  ledger.submitAct(event); ledger.closeConstellation();
  assert.equal(ledger.getState().contract(event.contractId).state.storage.supply, '0');
  const mint = call(f, ledger.getState(), event.contractId, 'mint', [f.owner.address(), '100']); ledger.submitAct(mint); ledger.closeConstellation();
  assert.equal(ledger.getState().contract(event.contractId).state.storage.supply, '100');
  const transfer = call(f, ledger.getState(), event.contractId, 'transfer', [f.bob.address(), '7']); ledger.submitAct(transfer); ledger.closeConstellation();
  const state = ledger.getState(), rootBefore = ledger.root;
  assert.deepEqual(state.contract(event.contractId).state.mappings.balances.find(row => row.key === f.bob.address()).value, '7');
  assert.equal(state.receipts()[0].events[0].name, 'Moved'); assert.equal(state.getBalance(f.owner.address()), UNIT.initialSupplyAtomic);
  assert.throws(() => ledger.submitAct(transfer));
  assert.throws(() => ledger.submitAct(call(f, state, event.contractId, 'mint', [f.bob.address(), '1'], f.bob)), { code: 'KO_REQUIRE_FAILED' });
  assert.equal(ledger.root, rootBefore);
  const proof = state.createInclusionProof(f.owner.address()); assert.equal(verifyKoAccountProof(proof, ledger.root), true);
  assert.equal(verifyKoAccountProof({ ...proof, contractsRoot: 'f'.repeat(64) }, ledger.root), false);
  assert.equal(verifyKoAccountProof(state.createAbsenceProof(f.bob.address()), ledger.root), true);
  const nativeTransfer = createTransfer({ networkId: state.networkId, sequence: state.sequence + 1n, nonce: state.getNonce(f.owner.address()) + 1n,
    previousRoot: state.root(), amountAtomic: 1n, senderPublicKey: f.owner.publicBytes(), receiverAddress: f.bob.address() }, f.owner);
  ledger.submitAct(nativeTransfer); ledger.closeConstellation();
  assert.equal(ledger.getState().getBalance(f.owner.address()) + ledger.getState().getBalance(f.bob.address()), UNIT.initialSupplyAtomic);
  assert.equal(ledger.getState().contract(event.contractId).state.storage.supply, '100');
});
test('journal and snapshots replay contract state, receipts and roots; legacy ledgers reject these events', t => {
  const f = fixture(), base = directory(t), file = path.join(base, 'ledger.wal'), wal = new WalStore(file);
  t.after(() => wal.close()); const ledger = f.ledger({ wal, requireWal: true });
  const event = deploy(f, ledger.getState()); ledger.submitAct(event); ledger.closeConstellation();
  ledger.submitAct(call(f, ledger.getState(), event.contractId, 'mint', [f.bob.address(), '10'])); ledger.closeConstellation();
  const restored = f.ledger(); restored.recover(recoverWal(file, { decodeRecords: true })); assert.equal(restored.root, ledger.root);
  const snapshot = decodeRecord(encodeRecord(ledger.snapshot()));
  const copy = VlockLedger.fromSnapshot(snapshot, { nativePolicy: f.nativePolicy }); assert.equal(copy.root, ledger.root);
  snapshot.state.contracts[0].state.storage.supply = '999'; assert.throws(() => VlockLedger.fromSnapshot(snapshot, { nativePolicy: f.nativePolicy }));
  const old = { ...f.options }; delete old.contractRuntime; delete old.format; const v6 = createGenesis(old);
  const legacy = new VlockLedger({ state: stateFromGenesis(v6), protocolVersion: v6.protocolVersion, nativePolicy: f.nativePolicy });
  assert.throws(() => legacy.submitAct(event));
});
test('gas-aware selection defers excess reservations and prevents a closure-budget stall', () => {
  const f = fixture(), ledger = f.ledger();
  for (let i = 0; i < 11; i++) ledger.submitAct(deploy(f, ledger.getState(), vcrypto.IdentityKeypair.generate(), String(i), 100000));
  const selection = ledger.proposeConstellation(); assert.equal(selection.actIds.length, 10); assert.equal(selection.totalGas, 1000000);
  assert.equal(selection.deferred[0].reason, 'MAX_GAS'); ledger.closeConstellation(selection);
  assert.equal(ledger.getState().contracts().length, 10); assert.equal(ledger.quarantinedActs().length, 1);
});
test('state capacity is checked during admission and aggregate selection instead of blocking all valid work', () => {
  const f = fixture(), initial = stateFromGenesis(f.genesis), contracts = [];
  const artifact = runtime.compileContract(source);
  for (let i = 0; i < PROFILE.contracts - 1; i++) contracts.push({ artifact,
    state: auth.deploySignedContract(artifact, auth.signDeployment(artifact, { networkId: f.genesis.networkId, salt: String(i + 100), gasLimit: 10000 }, f.owner.privateKeyObject())).state });
  contracts.sort((a, b) => a.state.contractId.localeCompare(b.state.contractId));
  const state = new KoGlobalState({ baseState: initial, contracts }), ledger = new VlockLedger({ state, protocolVersion: PROTOCOL, nativePolicy: f.nativePolicy });
  ledger.submitAct(deploy(f, state, f.owner)); ledger.submitAct(deploy(f, state, f.bob));
  const selection = ledger.proposeConstellation(); assert.equal(selection.actIds.length, 1); assert.equal(selection.deferred[0].reason, 'STATE_CAPACITY');
  ledger.closeConstellation(selection); assert.equal(ledger.getState().contracts().length, PROFILE.contracts);
  assert.throws(() => ledger.submitAct(deploy(f, ledger.getState(), vcrypto.IdentityKeypair.generate())), { code: 'KO_CONSENSUS_STATE' });
});
test('WAL failure never installs a contract or consumes its sender nonce', () => {
  const f = fixture(), ledger = f.ledger({ wal: { appendRecord() { throw Error('DISK_FULL'); } }, requireWal: true });
  const root = ledger.root, event = deploy(f, ledger.getState()); ledger.submitAct(event);
  assert.throws(() => ledger.closeConstellation(), { code: 'WAL_APPEND_FAILED' });
  assert.equal(ledger.root, root); assert.equal(ledger.getState().contracts().length, 0); assert.equal(ledger.getState().getNonce(f.owner.address()), 0n);
});
test('four validators enforce stateful contracts, sign finality, catch up an offline peer and recover after restart', async t => {
  const f = fixture(), base = directory(t), nodes = f.keys.map((identity, i) => new SovereignNode({ genesis: f.genesis, identity,
    validatorId: `validator-${i}`, dataDir: path.join(base, `node-${i}`), automaticConsensus: true, proposalDelayMs: 30, roundTimeoutMs: 180 }));
  let restarted; t.after(async () => { if (restarted) await restarted.close(); await Promise.all(nodes.map(node => node.close())); });
  const ports = []; for (let i = 0; i < 3; i++) ports[i] = (await nodes[i].start({ host: '127.0.0.1', port: 0 })).address.port;
  for (let i = 0; i < 3; i++) for (let j = i + 1; j < 3; j++) await nodes[i].connect(`ws://127.0.0.1:${ports[j]}`, `validator-${j}`);
  const deployment = nodes[0].createContractDeployment({ sender: f.owner, source }); nodes[0].submitContract(deployment);
  await Promise.all(nodes.slice(0, 3).map(node => node.waitForSequence(1n, 15000)));
  nodes[0].submitContract(nodes[0].createContractCall({ sender: f.owner, contractId: deployment.contractId, method: 'mint', args: [f.owner.address(), '100'] }));
  await Promise.all(nodes.slice(0, 3).map(node => node.waitForSequence(2n, 15000)));
  nodes[0].submitContract(nodes[0].createContractCall({ sender: f.owner, contractId: deployment.contractId, method: 'transfer', args: [f.bob.address(), '7'] }));
  await Promise.all(nodes.slice(0, 3).map(node => node.waitForSequence(3n, 15000)));
  const port = (await nodes[3].start({ host: '127.0.0.1', port: 0 })).address.port;
  await nodes[0].connect(`ws://127.0.0.1:${port}`, 'validator-3'); await nodes[3].waitForSequence(3n, 15000);
  assert.equal(new Set(nodes.map(node => node.ledger.root)).size, 1);
  assert.ok(nodes.every(node => node.status().contractRuntime.enforced));
  assert.equal(nodes[3].ledger.getState().contract(deployment.contractId).state.storage.supply, '100');
  assert.equal(nodes[3].ledger.getState().receipts()[0].events[0].name, 'Moved');
  const frames = recoverWal(nodes[3].ledgerPath, { decodeRecords: true }).frames;
  assert.equal(frames.length, 3); assert.ok(frames.every(frame => frame.record.certificate.signatures.length >= 3));
  assert.ok(frames.every(frame => frame.record.closureScope === 'permissioned-k-of-n'));
  await nodes[3].close(); restarted = new SovereignNode({ genesis: f.genesis, identity: f.keys[3], validatorId: 'validator-3', dataDir: path.join(base, 'node-3') });
  assert.equal(restarted.ledger.root, nodes[0].ledger.root);
});
