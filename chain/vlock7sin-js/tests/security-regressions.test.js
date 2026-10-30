'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createHash, sign: edSign } = require('node:crypto');
const test = require('node:test');

const core = require('../src');
const { CausalGraph, canonicalBytes, computeActId } = require('../src/causalGraph');
const { VlockLedger, stateFromSnapshot } = require('../src/ledger');
const {
  decodeRecord,
  encodeRecord,
  readSnapshot,
  recoverWal,
  SnapshotStore,
  truncateIncompleteWal,
  WalStore,
} = require('../src/persistence');
const { PermissionedQuorum } = require('../src/quorum');
const {
  createEnvelope,
  encodeEnvelope,
  EnvelopeVerifier,
  NonceReplayWindow,
  signingBytes,
} = require('../src/network');

function identity(label) {
  return core.crypto.IdentityKeypair.fromTestSeed(Buffer.from(label, 'utf8'));
}

function tempDirectory(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'vlock7sin-security-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

function signedTransfer({ state, sender, receiver, amount = 1n, sequence = state.sequence + 1n, nonce = state.getNonce(sender.address()) + 1n, nexuses = [] }) {
  return core.createTransfer({
    sequence,
    nonce,
    timestampMs: 1n,
    amountAtomic: amount,
    previousRoot: state.root(),
    senderPublicKey: sender.publicBytes(),
    receiverAddress: receiver.address(),
    nexuses,
    memo: 'security-regression',
  }, sender);
}

test('core records never expose mutable private bytes', () => {
  const sender = identity('immutability/sender');
  const receiver = identity('immutability/receiver');
  const state = new core.GlobalState({ balances: [[sender.address(), 5n]] });
  const event = signedTransfer({ state, sender, receiver });
  const beforeBytes = event.canonicalBytes();
  const beforeId = event.id();
  const exposed = event.toObject();
  exposed.previousRoot.fill(0xff);
  exposed.senderPublicKey.fill(0xff);
  exposed.signature.fill(0xff);
  exposed.nexuses.push(Buffer.alloc(32, 0xff));

  assert.deepEqual(event.canonicalBytes(), beforeBytes);
  assert.deepEqual(event.id(), beforeId);
  assert.equal(event.verify(), true);
});

test('state snapshots require one canonical decimal and account ordering', () => {
  const first = identity('snapshot/first').address();
  const second = identity('snapshot/second').address();
  const state = new core.GlobalState({ balances: [[first, 1n], [second, 2n]] });
  const snapshot = state.snapshot();
  const duplicate = {
    ...snapshot,
    accounts: [snapshot.accounts[0], { ...snapshot.accounts[0] }],
  };
  const leadingZero = {
    ...snapshot,
    accounts: snapshot.accounts.map((account, index) => (
      index === 0 ? { ...account, balance: `0${account.balance}` } : account
    )),
  };
  const reversed = { ...snapshot, accounts: [...snapshot.accounts].reverse() };

  assert.throws(() => stateFromSnapshot(duplicate), { code: 'INVALID_STATE_SNAPSHOT' });
  assert.throws(() => stateFromSnapshot(leadingZero), { code: 'INVALID_STATE_SNAPSHOT' });
  assert.throws(() => stateFromSnapshot(reversed), { code: 'INVALID_STATE_SNAPSHOT' });
  assert.equal(stateFromSnapshot(snapshot).root().toString('hex'), snapshot.root);
});

test('an insolvent signed act cannot poison the canonical ledger frontier', () => {
  const funded = identity('poison/funded');
  const empty = identity('poison/empty');
  const receiverA = identity('poison/receiver-a');
  const receiverB = identity('poison/receiver-b');
  const state = new core.GlobalState({ balances: [[funded.address(), 5n]] });
  const valid = signedTransfer({ state, sender: funded, receiver: receiverA, amount: 1n });
  const insolvent = signedTransfer({ state, sender: empty, receiver: receiverB, amount: 1n });
  const ledger = new VlockLedger({ state });

  assert.throws(() => ledger.submitActs([valid, insolvent]), { code: 'INSUFFICIENT_BALANCE' });
  assert.deepEqual(ledger.getGraphSnapshot().acts, []);
  ledger.submitAct(valid);
  ledger.closeConstellation();
  assert.equal(ledger.sequence, 1n);
});

test('causal graph owns immutable snapshots of generic acts', () => {
  const graph = new CausalGraph();
  const source = { kind: 'GENERIC', payload: { value: 1 }, writeSet: ['resource:a'] };
  const id = graph.addAct(source);
  source.payload.value = 9;
  source.writeSet[0] = 'resource:changed';

  const firstRead = graph.get(id);
  assert.equal(firstRead.payload.value, 1);
  assert.equal(computeActId(firstRead), id);
  firstRead.payload.value = 2;
  firstRead.writeSet[0] = 'resource:mutated-copy';

  const secondRead = graph.get(id);
  assert.equal(secondRead.payload.value, 1);
  assert.equal(secondRead.writeSet[0], 'resource:a');
  assert.equal(computeActId(secondRead), id);
  assert.equal(graph.assertValid(), true);
});

test('causal graph rejects mutable record impersonators, unsupported classes and string lock sets', () => {
  class MutablePretender {
    constructor() {
      this.value = 1;
      this.writeSet = ['resource:a'];
    }
    canonicalBytes() { return Buffer.from(String(this.value)); }
    id() { return Buffer.alloc(32, this.value); }
  }
  const graph = new CausalGraph();
  assert.throws(() => graph.addAct(new MutablePretender()), { code: 'INVALID_ACT' });
  assert.throws(() => computeActId(new MutablePretender()), { code: 'INVALID_ACT' });
  assert.throws(() => graph.addAct({ kind: 'DATE', payload: new Date(0), writeSet: ['resource:a'] }), { code: 'INVALID_ACT' });
  assert.throws(() => graph.addAct({ kind: 'LOCK', writeSet: 'resource:a' }), { code: 'INVALID_LOCK' });
});

test('ledger owns a snapshot of a caller-supplied graph', () => {
  const a = identity('graph-owner/a');
  const b = identity('graph-owner/b');
  const c = identity('graph-owner/c');
  const d = identity('graph-owner/d');
  const state = new core.GlobalState({ balances: [[a.address(), 5n], [c.address(), 5n]] });
  const first = signedTransfer({ state, sender: a, receiver: b });
  const second = signedTransfer({ state, sender: c, receiver: d });
  const external = new CausalGraph();
  external.addAct(first);
  const ledger = new VlockLedger({ state, graph: external });
  external.addAct(second);
  assert.deepEqual(ledger.proposeConstellation().actIds, [first.id().toString('hex')]);
});

test('ledger staging is private and commit installs only the recomputed state', () => {
  const sender = identity('ledger-private/sender');
  const receiver = identity('ledger-private/receiver');
  const state = new core.GlobalState({ balances: [[sender.address(), 10n]] });
  const ledger = new VlockLedger({ state });
  ledger.submitAct(signedTransfer({ state, sender, receiver, amount: 2n }));
  const proposal = ledger.prepareConstellation();

  assert.equal(ledger.state, undefined);
  assert.equal(ledger.preparations, undefined);
  assert.equal(Object.isFrozen(proposal), true);
  const closure = ledger.commitPrepared(proposal);
  assert.equal(ledger.root, closure.nextRoot);
  assert.equal(ledger.getState().getBalance(receiver.address()), 2n);

  const copy = ledger.getState();
  copy.credit(receiver.address(), 7n);
  assert.equal(ledger.getState().getBalance(receiver.address()), 2n);
});

test('acts deferred by a closure are quarantined, then may be re-signed for the new root', () => {
  const a = identity('quarantine/a');
  const b = identity('quarantine/b');
  const c = identity('quarantine/c');
  const d = identity('quarantine/d');
  const state = new core.GlobalState({ balances: [[a.address(), 10n], [c.address(), 10n]] });
  const eventA = signedTransfer({ state, sender: a, receiver: b });
  const eventC = signedTransfer({ state, sender: c, receiver: b });
  const byId = new Map([[eventA.id().toString('hex'), a], [eventC.id().toString('hex'), c]]);
  const ledger = new VlockLedger({ state });
  ledger.submitActs([eventA, eventC]);
  const closure = ledger.closeConstellation();

  assert.equal(closure.actIds.length, 1);
  assert.equal(closure.expiredActIds.length, 1);
  const quarantined = ledger.quarantinedActs();
  assert.equal(quarantined.length, 1);
  assert.equal(quarantined[0].reason, 'STALE_AFTER_CLOSURE');
  assert.equal(quarantined[0].id, closure.expiredActIds[0]);

  const staleSender = byId.get(quarantined[0].id);
  const current = ledger.getState();
  const replacement = signedTransfer({
    state: current,
    sender: staleSender,
    receiver: d,
    nexuses: [Buffer.from(closure.actIds[0], 'hex')],
  });
  ledger.submitAct(replacement);
  const next = ledger.closeConstellation();
  assert.equal(next.sequence, '2');
  assert.equal(ledger.sequence, 2n);
});

test('tagged decoder rejects type confusion, extra fields, invalid UTF-8 and non-canonical bytes', () => {
  const invalid = [
    Buffer.from('["string",5]'),
    Buffer.from('["boolean","true"]'),
    Buffer.from('["null","ignored"]'),
    Buffer.from('["undefined",0]'),
    Buffer.from('[ "string", "x" ]'),
    Buffer.from('["map",[[["string","b"],["number","1"]],[["string","a"],["number","2"]]]]'),
    Buffer.from('["set",[["string","b"],["string","a"]]]'),
    Buffer.from([0x5b, 0x22, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x22, 0x2c, 0x22, 0xff, 0x22, 0x5d]),
  ];
  for (const bytes of invalid) assert.throws(
    () => decodeRecord(bytes),
    (error) => ['INVALID_RECORD', 'NON_CANONICAL_RECORD'].includes(error?.code),
  );
  const canonical = encodeRecord({ answer: 42n });
  assert.deepEqual(encodeRecord(decodeRecord(canonical)), canonical);
});

test('WAL refuses append after an unverified tail and snapshot reads are size bounded', (t) => {
  const directory = tempDirectory(t);
  const walPath = path.join(directory, 'tail.wal');
  const wal = new WalStore(walPath, { maxFrameBytes: 1024 });
  wal.appendRecord({ sequence: 1n });
  wal.close();
  fs.appendFileSync(walPath, Buffer.from([0, 0, 0]));
  const before = fs.statSync(walPath).size;
  assert.throws(() => new WalStore(walPath, { maxFrameBytes: 1024 }), { code: 'UNCLEAN_WAL' });
  assert.equal(fs.statSync(walPath).size, before);
  const report = recoverWal(walPath, { maxFrameBytes: 1024 });
  truncateIncompleteWal(report);
  const reopened = new WalStore(walPath, { maxFrameBytes: 1024 });
  reopened.close();

  const snapshotPath = path.join(directory, 'state.v7snap');
  new SnapshotStore(snapshotPath).write({ payload: 'x'.repeat(128) });
  assert.throws(() => readSnapshot(snapshotPath, { maxSnapshotBytes: 16 }), { code: 'SNAPSHOT_TOO_LARGE' });
});

test('permissioned votes and certificates have one canonical representation', () => {
  const one = identity('quorum-canonical/one');
  const two = identity('quorum-canonical/two');
  const quorum = new PermissionedQuorum({
    validators: [
      { id: 'one', publicKey: one.publicKeyObject() },
      { id: 'two', publicKey: two.publicKeyObject() },
    ],
    threshold: 2,
    networkId: '28673',
    protocolVersion: '0.2.0',
  });
  const proposal = {
    networkId: '28673',
    protocolVersion: '0.2.0',
    sequence: 1n,
    constellationId: '01'.repeat(32),
    previousRoot: '02'.repeat(32),
    nextRoot: '03'.repeat(32),
    transitionTrace: '04'.repeat(32),
    pcc: '05'.repeat(32),
  };
  const voteOne = quorum.createVote(proposal, 'one', one.privateKeyObject());
  const voteTwo = quorum.createVote(proposal, 'two', two.privateKeyObject());
  assert.throws(
    () => quorum.verifyVote(proposal, { ...voteOne, signature: `${voteOne.signature}zz` }),
    { code: 'INVALID_FIELD' },
  );
  const certificate = quorum.assembleCertificate(proposal, [voteTwo, voteOne]);
  assert.equal(quorum.verifyCertificate(certificate, proposal), true);
  assert.throws(() => quorum.verifyCertificate({
    ...certificate,
    signatures: [...certificate.signatures].reverse(),
  }, proposal), { code: 'NON_CANONICAL_SIGNER_ORDER' });
});

test('a signed envelope with an invalid semantic payload does not consume replay state', () => {
  const sender = identity('network-atomic/sender');
  const valid = createEnvelope({
    networkId: '28673',
    protocolVersion: '0.2.0',
    type: 'ACT',
    senderId: 'sender',
    nonce: 1n,
    timestampMs: 1000,
    payload: Buffer.from('binary'),
    privateKey: sender.privateKeyObject(),
  });
  const payload = Buffer.from('["string",5]', 'utf8');
  const malformed = {
    ...valid,
    payload,
    payloadEncoding: 'V7_RECORD',
    payloadSize: payload.length,
    payloadHash: createHash('sha3-256')
      .update(Buffer.from('VLOCK7SIN/NET-PAYLOAD/v1\0', 'ascii'))
      .update(payload)
      .digest('hex'),
  };
  delete malformed.id;
  delete malformed.signature;
  malformed.signature = edSign(null, signingBytes(malformed), sender.privateKeyObject()).toString('hex');
  malformed.id = createHash('sha3-256')
    .update(Buffer.from('VLOCK7SIN/NET-ENVELOPE-ID/v1\0', 'ascii'))
    .update(canonicalBytes(malformed))
    .digest('hex');

  let persisted = 0;
  const replay = new NonceReplayWindow({ persist: () => { persisted += 1; } });
  const verifier = new EnvelopeVerifier({
    networkId: '28673',
    protocolVersion: '0.2.0',
    trustedKeys: { sender: sender.publicKeyObject() },
    replay,
  });
  assert.throws(() => verifier.verify(malformed, { now: 1000 }), { code: 'MALFORMED_PAYLOAD' });
  assert.deepEqual(replay.exportState(), Object.create(null));
  assert.equal(persisted, 0);
});

test('verified network results own immutable defensive payload snapshots', () => {
  const sender = identity('network-owner/sender');
  const envelope = createEnvelope({
    networkId: '28673',
    protocolVersion: '0.2.0',
    type: 'ACT',
    senderId: 'sender',
    nonce: 7n,
    timestampMs: 1000,
    payload: { amount: 7n, bytes: Buffer.from('aabb', 'hex') },
    privateKey: sender.privateKeyObject(),
  });
  const verifier = new EnvelopeVerifier({
    networkId: '28673',
    protocolVersion: '0.2.0',
    trustedKeys: { sender: sender.publicKeyObject() },
  });
  const result = verifier.verify(encodeEnvelope(envelope), { now: 1000 });
  const payloadCopy = result.payload;
  payloadCopy.amount = 99n;
  payloadCopy.bytes.fill(0xff);
  const rawCopy = result.envelope.payload;
  rawCopy.fill(0xff);
  assert.equal(result.payload.amount, 7n);
  assert.deepEqual(result.payload.bytes, Buffer.from('aabb', 'hex'));
  assert.notDeepEqual(result.envelope.payload, rawCopy);
});
