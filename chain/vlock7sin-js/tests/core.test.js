'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { MAX_U128, NETWORK_ID } = require('../src/constants');
const {
  BinaryReader,
  BinaryWriter,
  decodeUnsigned,
  encodeU128,
  encodeUtf8,
} = require('../src/codec');
const {
  IdentityKeypair,
  addressMatchesPublicKey,
  sha3,
} = require('../src/crypto');
const {
  TransferEvent,
  createTransfer,
  decodeEvent,
} = require('../src/event');
const {
  GlobalState,
  verifyAbsenceProof,
  verifyInclusionProof,
} = require('../src/state');

function testKey(label) {
  return IdentityKeypair.fromTestSeed(Buffer.from(`vlock7sin-js-test:${label}`, 'utf8'));
}

function signedTransfer(state, sender, receiver, overrides = {}) {
  return createTransfer({
    networkId: state.networkId,
    sequence: state.sequence + 1n,
    nonce: state.getNonce(sender.address()) + 1n,
    timestampMs: 1_775_348_800_000n,
    amountAtomic: 100n,
    previousRoot: state.root(),
    senderPublicKey: sender.publicBytes(),
    senderAddress: sender.address(),
    receiverAddress: receiver.address(),
    memo: 'canonical transfer',
    ...overrides,
  }, sender.privateKeyObject());
}

test('u128 and strict strings round-trip at their boundaries', () => {
  assert.equal(decodeUnsigned(encodeU128(0n)), 0n);
  assert.equal(decodeUnsigned(encodeU128(MAX_U128)), MAX_U128);
  assert.throws(() => encodeU128(-1n), /range/i);
  assert.throws(() => encodeU128(MAX_U128 + 1n), /range/i);
  assert.throws(() => encodeUtf8('a\u0000b'), /NUL/i);

  const bytes = new BinaryWriter().u16(7).u64(9n).finish();
  const reader = new BinaryReader(bytes);
  assert.equal(reader.u16(), 7);
  assert.equal(reader.u64(), 9n);
  assert.equal(reader.eof(), true);
});

test('deterministic Ed25519 identities sign without exposing raw secret bytes', () => {
  const first = testKey('alice');
  const second = testKey('alice');
  const message = Buffer.from('deterministic bytes');
  assert.deepEqual(first.publicBytes(), second.publicBytes());
  assert.equal(first.address(), second.address());
  assert.equal(addressMatchesPublicKey(first.address(), first.publicBytes()), true);
  assert.deepEqual(first.sign(message), second.sign(message));
  assert.equal(Object.prototype.hasOwnProperty.call(first, 'privateKey'), false);
});

test('signed transfer is canonical, strict and mutation-evident', () => {
  const alice = testKey('alice');
  const bob = testKey('bob');
  const state = new GlobalState();
  state.credit(alice.address(), 1_000n);
  const event = signedTransfer(state, alice, bob);
  const encoded = event.canonicalBytes();
  const decoded = decodeEvent(encoded);

  assert.equal(decoded instanceof TransferEvent, true);
  assert.equal(decoded.verify({ expectedNetworkId: NETWORK_ID }), true);
  assert.deepEqual(decoded.canonicalBytes(), encoded);
  assert.deepEqual(decoded.id(), event.id());

  for (let offset = 0; offset < encoded.length; offset += 1) {
    const mutated = Buffer.from(encoded);
    mutated[offset] ^= 1;
    assert.throws(() => decodeEvent(mutated), undefined, `offset ${offset}`);
  }
});

test('state root ignores insertion order and normalizes zero balances', () => {
  const alice = testKey('alice').address();
  const bob = testKey('bob').address();
  const first = new GlobalState({ balances: new Map([[alice, 7n], [bob, 9n]]) });
  const second = new GlobalState({ balances: new Map([[bob, 9n], [alice, 7n]]) });
  assert.deepEqual(first.root(), second.root());
  first.debit(alice, 7n);
  assert.equal(first.hasAccount(alice), false);
  assert.equal(first.entries().some((entry) => entry.balance === 0n && entry.nonce === 0n), false);
});

test('state account count stays exact across balance and nonce mutations', () => {
  const account = testKey('account-count').address();
  const state = new GlobalState();
  assert.equal(state.accountCount, 0);
  state.credit(account, 2n);
  assert.equal(state.accountCount, 1);
  state.setNonce(account, 1n);
  state.debit(account, 2n);
  assert.equal(state.accountCount, 1);
  state.setNonce(account, 0n);
  assert.equal(state.accountCount, 0);
});

test('every valid multi-record state remains explicitly serializable beyond 64 KiB', () => {
  const balances = Array.from({ length: 1_100 }, (_, index) => [
    testKey(`large-state-${index}`).address(),
    1n,
  ]);
  const state = new GlobalState({ balances });
  const bytes = state.canonicalBytes();
  assert.equal(state.accountCount, balances.length);
  assert.ok(bytes.length > 64 * 1024);
});

test('inclusion and absence proofs bind the complete state commitment', () => {
  const alice = testKey('alice').address();
  const bob = testKey('bob').address();
  const carol = testKey('carol').address();
  const state = new GlobalState({ balances: new Map([[alice, 7n], [bob, 9n]]) });
  const root = state.root();
  const inclusion = state.createInclusionProof(alice);
  const absence = state.createAbsenceProof(carol);
  assert.equal(verifyInclusionProof(inclusion, root), true);
  assert.equal(verifyAbsenceProof(absence, root), true);

  for (const field of ['accountRoot', 'parametersRoot', 'identitiesRoot', 'replayRoot']) {
    const changed = { ...absence, [field]: '11'.repeat(32) };
    assert.equal(verifyAbsenceProof(changed, root), false, `accepted changed ${field}`);
  }

  const tampered = {
    ...inclusion,
    leaf: { ...inclusion.leaf, balance: (BigInt(inclusion.leaf.balance) + 1n).toString() },
  };
  assert.equal(verifyInclusionProof(tampered, root), false);
});

test('failed transitions leave the original state byte-for-byte unchanged', () => {
  const alice = testKey('alice');
  const bob = testKey('bob');
  const state = new GlobalState();
  state.credit(alice.address(), 50n);
  const beforeBytes = state.canonicalBytes();
  const beforeRoot = state.root();
  const event = signedTransfer(state, alice, bob, { amountAtomic: 51n });

  assert.throws(() => state.applyTransfer(event), /insufficient balance/i);
  assert.deepEqual(state.canonicalBytes(), beforeBytes);
  assert.deepEqual(state.root(), beforeRoot);
  assert.equal(state.getBalance(alice.address()), 50n);
  assert.equal(state.getBalance(bob.address()), 0n);
});

test('valid transfer commits on a clone and advances replay protection', () => {
  const alice = testKey('alice');
  const bob = testKey('bob');
  const state = new GlobalState();
  state.credit(alice.address(), 1_000n);
  const event = signedTransfer(state, alice, bob);
  const next = state.applyTransfer(event);

  assert.equal(state.sequence, 0n);
  assert.equal(next.sequence, 1n);
  assert.equal(state.getBalance(alice.address()), 1_000n);
  assert.equal(next.getBalance(alice.address()), 900n);
  assert.equal(next.getBalance(bob.address()), 100n);
  assert.equal(next.getNonce(alice.address()), 1n);
  assert.notDeepEqual(next.replayRoot, state.replayRoot);
  assert.notDeepEqual(next.root(), state.root());
});

test('cross-network events and address/root substitutions fail closed', () => {
  const alice = testKey('alice');
  const bob = testKey('bob');
  const state = new GlobalState();
  state.credit(alice.address(), 1_000n);
  const wrongNetwork = signedTransfer(state, alice, bob, { networkId: NETWORK_ID + 1 });
  assert.equal(wrongNetwork.verify(), false);
  assert.throws(() => state.applyTransfer(wrongNetwork), /network mismatch/i);

  const wrongRoot = signedTransfer(state, alice, bob, { previousRoot: sha3(Buffer.from('wrong')) });
  assert.throws(() => state.applyTransfer(wrongRoot), /previous root mismatch/i);
});
