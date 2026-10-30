'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const core = require('../src');
const {
  decodeRecord,
  encodeRecord,
  readSnapshot,
  recoverWal,
  SnapshotStore,
  truncateIncompleteWal,
  WalStore,
} = require('../src/persistence');
const {
  createEnvelope,
  encodeEnvelope,
  EnvelopeVerifier,
  NetworkProtocolError,
  NonceCounter,
} = require('../src/network');
const { VlockLedger } = require('../src/ledger');

function identity(label) {
  return core.crypto.IdentityKeypair.fromTestSeed(Buffer.from(label, 'utf8'));
}

function temporaryDirectory(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'vlock7sin-js-test-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return directory;
}

function genesisAndEvents() {
  const alice = identity('runtime/alice');
  const bob = identity('runtime/bob');
  const carol = identity('runtime/carol');
  const dave = identity('runtime/dave');
  const state = new core.GlobalState({
    balances: [
      [alice.address(), 100n],
      [carol.address(), 80n],
    ],
  });
  const common = {
    sequence: 1n,
    nonce: 1n,
    timestampMs: 100n,
    previousRoot: state.root(),
  };
  const first = core.createTransfer({
    ...common,
    amountAtomic: 11n,
    senderPublicKey: alice.publicBytes(),
    receiverAddress: bob.address(),
    memo: 'alice para bob',
  }, alice);
  const second = core.createTransfer({
    ...common,
    amountAtomic: 13n,
    senderPublicKey: carol.publicBytes(),
    receiverAddress: dave.address(),
    memo: 'carol para dave',
  }, carol);
  return { state, first, second, alice, bob, carol, dave };
}

test('tagged persistence round-trips bytes, BigInt and supported containers', () => {
  const value = {
    amount: (1n << 127n) + 9n,
    bytes: Buffer.from('00ff10', 'hex'),
    list: [undefined, null, true, 12.5],
    map: new Map([['a', 1n], ['b', Buffer.from([2])]]),
    set: new Set(['x', 'y']),
    date: new Date('2026-04-05T00:26:40.000Z'),
  };
  const encoded = encodeRecord(value);
  const decoded = decodeRecord(encoded);
  assert.equal(decoded.amount, value.amount);
  assert.deepEqual(decoded.bytes, value.bytes);
  assert.deepEqual(decoded.list, value.list);
  assert.deepEqual([...decoded.map], [...value.map]);
  assert.deepEqual([...decoded.set], [...value.set]);
  assert.equal(decoded.date.toISOString(), value.date.toISOString());
  assert.deepEqual(encodeRecord(decoded), encoded);
});

test('WAL detects corruption and only truncates a positively identified partial tail', (t) => {
  const directory = temporaryDirectory(t);
  const cleanPath = path.join(directory, 'clean.wal');
  const wal = new WalStore(cleanPath, { maxFrameBytes: 4096 });
  wal.appendRecord({ sequence: 1n, payload: Buffer.from('one') });
  wal.appendRecord({ sequence: 2n, payload: Buffer.from('two') });
  wal.close();

  const clean = recoverWal(cleanPath, { maxFrameBytes: 4096, decodeRecords: true });
  assert.equal(clean.clean, true);
  assert.equal(clean.frames.length, 2);
  assert.equal(clean.frames[1].record.sequence, 2n);

  const corruptPath = path.join(directory, 'corrupt.wal');
  fs.copyFileSync(cleanPath, corruptPath);
  const corrupt = fs.readFileSync(corruptPath);
  corrupt[corrupt.length - 1] ^= 1;
  fs.writeFileSync(corruptPath, corrupt);
  const corruptReport = recoverWal(corruptPath, { maxFrameBytes: 4096 });
  assert.equal(corruptReport.corrupt, true);
  assert.throws(() => truncateIncompleteWal(corruptReport), { code: 'UNSAFE_TRUNCATION' });

  const truncatedPath = path.join(directory, 'truncated.wal');
  fs.copyFileSync(cleanPath, truncatedPath);
  const completeSize = fs.statSync(truncatedPath).size;
  fs.truncateSync(truncatedPath, completeSize - 3);
  const truncated = recoverWal(truncatedPath, { maxFrameBytes: 4096 });
  assert.equal(truncated.truncated, true);
  assert.equal(truncated.corrupt, false);
  assert.equal(truncateIncompleteWal(truncated), truncated.lastValidOffset);
  assert.equal(recoverWal(truncatedPath, { maxFrameBytes: 4096 }).clean, true);
});

test('snapshot writes are atomic, integrity checked and CAS guarded', (t) => {
  const directory = temporaryDirectory(t);
  const file = path.join(directory, 'state.v7snap');
  const store = new SnapshotStore(file);
  const first = store.write({ sequence: 1n, root: Buffer.alloc(32, 1) });
  const decoded = store.read();
  assert.equal(decoded.hash, first.hash);
  assert.equal(decoded.value.sequence, 1n);

  assert.throws(() => store.write({ sequence: 2n }, { expectedPreviousHash: '00'.repeat(32) }), {
    code: 'SNAPSHOT_CAS_MISMATCH',
  });
  const second = store.write({ sequence: 2n }, { expectedPreviousHash: first.hash });
  assert.notEqual(second.hash, first.hash);
  assert.equal(readSnapshot(file).value.sequence, 2n);

  const tampered = fs.readFileSync(file);
  tampered[tampered.length - 1] ^= 1;
  fs.writeFileSync(file, tampered);
  assert.throws(() => readSnapshot(file), { code: 'INVALID_SNAPSHOT' });
});

test('signed network envelopes bind sender, payload, network, time and replay nonce', () => {
  const sender = identity('runtime/network/sender');
  const envelope = createEnvelope({
    networkId: '28673',
    protocolVersion: '0.2.0',
    type: 'ACT',
    senderId: 'validator-a',
    nonce: 9n,
    timestampMs: 1_000_000,
    payload: { eventId: '11'.repeat(32), amount: 9n },
    privateKey: sender.privateKeyObject(),
  });
  const encoded = encodeEnvelope(envelope);
  const verifier = new EnvelopeVerifier({
    networkId: '28673',
    protocolVersion: '0.2.0',
    trustedKeys: { 'validator-a': sender.publicKeyObject() },
  });
  const result = verifier.verify(encoded, { now: 1_000_000 });
  assert.equal(result.type, 'ACT');
  assert.equal(result.payload.amount, 9n);
  assert.throws(() => verifier.verify(encoded, { now: 1_000_000 }), { code: 'REPLAY_DETECTED' });

  const otherNetwork = new EnvelopeVerifier({
    networkId: 'other',
    protocolVersion: '0.2.0',
    trustedKeys: { 'validator-a': sender.publicKeyObject() },
  });
  assert.throws(() => otherNetwork.verify(encoded, { now: 1_000_000 }), { code: 'WRONG_NETWORK' });

  const changed = Buffer.from(encoded);
  changed[changed.length - 2] ^= 1;
  assert.throws(() => verifier.verify(changed, { now: 1_000_000 }), NetworkProtocolError);

  const skewVerifier = new EnvelopeVerifier({
    networkId: '28673',
    protocolVersion: '0.2.0',
    trustedKeys: { 'validator-a': sender.publicKeyObject() },
    maxPastMs: 100,
    maxFutureMs: 100,
  });
  const stale = encodeEnvelope(createEnvelope({
    networkId: '28673',
    protocolVersion: '0.2.0',
    type: 'ACT',
    senderId: 'validator-a',
    nonce: 10n,
    timestampMs: 999_899,
    payload: { eventId: '22'.repeat(32) },
    privateKey: sender.privateKeyObject(),
  }));
  const future = encodeEnvelope(createEnvelope({
    networkId: '28673',
    protocolVersion: '0.2.0',
    type: 'ACT',
    senderId: 'validator-a',
    nonce: 11n,
    timestampMs: 1_000_101,
    payload: { eventId: '33'.repeat(32) },
    privateKey: sender.privateKeyObject(),
  }));
  assert.throws(() => skewVerifier.verify(stale, { now: 1_000_000 }), { code: 'STALE_TIMESTAMP' });
  assert.throws(() => skewVerifier.verify(future, { now: 1_000_000 }), { code: 'FUTURE_TIMESTAMP' });
  assert.equal(skewVerifier.verify(stale, { now: 999_899 }).nonce, '10');
  assert.equal(skewVerifier.verify(future, { now: 1_000_101 }).nonce, '11');

  const counter = new NonceCounter(0n);
  assert.equal(counter.next(), 1n);
  assert.equal(counter.next(), 2n);
});

test('disk-full WAL failure leaves the ledger root, sequence and balances unchanged', (t) => {
  const directory = temporaryDirectory(t);
  const walPath = path.join(directory, 'disk-full.wal');
  const { state, first, alice, bob } = genesisAndEvents();
  const wal = new WalStore(walPath);
  const ledger = new VlockLedger({ state, wal, requireWal: true });
  ledger.submitAct(first);

  const rootBefore = ledger.root;
  const sequenceBefore = ledger.sequence;
  const aliceBefore = ledger.getState().getBalance(alice.address());
  const bobBefore = ledger.getState().getBalance(bob.address());
  const originalWriteSync = fs.writeSync;
  fs.writeSync = function injectedDiskFull(fd, ...args) {
    if (fd === wal.fd) {
      const error = new Error('injected disk full');
      error.code = 'ENOSPC';
      throw error;
    }
    return originalWriteSync.call(fs, fd, ...args);
  };
  try {
    assert.throws(() => ledger.closeConstellation(), { code: 'WAL_APPEND_FAILED' });
  } finally {
    fs.writeSync = originalWriteSync;
  }

  assert.equal(ledger.root, rootBefore);
  assert.equal(ledger.sequence, sequenceBefore);
  assert.equal(ledger.getState().getBalance(alice.address()), aliceBefore);
  assert.equal(ledger.getState().getBalance(bob.address()), bobBefore);

  const closure = ledger.closeConstellation();
  assert.equal(closure.sequence, '1');
  assert.equal(ledger.getState().getBalance(bob.address()), bobBefore + 11n);
  wal.close();
});

test('ledger closes independent transfers once and recovers the exact root from WAL', (t) => {
  const directory = temporaryDirectory(t);
  const walPath = path.join(directory, 'ledger.wal');
  const { state, first, second, alice, bob, carol, dave } = genesisAndEvents();
  const initialSnapshot = state.snapshot();
  const wal = new WalStore(walPath);
  const ledger = new VlockLedger({ state, wal, requireWal: true });

  const ids = ledger.submitActs([second, first]);
  assert.equal(ids.length, 2);
  const selected = ledger.proposeConstellation();
  assert.deepEqual(selected.actIds, [...selected.actIds].sort());
  assert.equal(selected.actIds.length, 2);
  const closure = ledger.closeConstellation(selected);
  assert.equal(closure.closureScope, 'local-only');
  assert.equal(ledger.sequence, 1n);
  assert.equal(ledger.getState().getBalance(alice.address()), 89n);
  assert.equal(ledger.getState().getBalance(bob.address()), 11n);
  assert.equal(ledger.getState().getBalance(carol.address()), 67n);
  assert.equal(ledger.getState().getBalance(dave.address()), 13n);
  const committedRoot = ledger.root;
  wal.close();

  const report = recoverWal(walPath, { decodeRecords: true });
  assert.equal(report.clean, true);
  assert.equal(report.frames.length, 1);
  const recovered = new VlockLedger({ state: new core.GlobalState({
    networkId: initialSnapshot.networkId,
    suite: initialSnapshot.suite,
    sequence: initialSnapshot.sequence,
    balances: initialSnapshot.accounts.map((account) => [account.address, account.balance]),
    nonces: initialSnapshot.accounts.map((account) => [account.address, account.nonce]),
    parametersRoot: initialSnapshot.parametersRoot,
    identitiesRoot: initialSnapshot.identitiesRoot,
    replayRoot: initialSnapshot.replayRoot,
  }) });
  const recovery = recovered.recover(report);
  assert.equal(recovery.closures, 1);
  assert.equal(recovery.root, committedRoot);
  assert.equal(recovered.sequence, 1n);
});

test('failed ledger submission is atomic and does not advance state', () => {
  const { state, first, alice } = genesisAndEvents();
  const ledger = new VlockLedger({ state });
  const initialRoot = ledger.root;
  const impossible = core.createTransfer({
    ...first.toObject(),
    amountAtomic: 101n,
    signature: undefined,
  }, alice);
  assert.throws(() => ledger.submitAct(impossible), { code: 'INSUFFICIENT_BALANCE' });
  assert.deepEqual(ledger.getGraphSnapshot().acts, []);
  assert.equal(ledger.root, initialRoot);
  assert.equal(ledger.sequence, 0n);
});
