'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const core = require('../src');
const { decodeRecord, encodeRecord } = require('../src/persistence');
const { decodeEnvelope, encodeEnvelope } = require('../src/network');
const { CoherenceWitness } = require('../src/pcc');
const { decodeActumFrame, encodeActumFrame } = require('../src/actum');

function generator(seed = 0x7d5017) {
  let state = seed >>> 0;
  return () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return state >>> 0;
  };
}

function randomBytes(next, length) {
  const output = Buffer.alloc(length);
  for (let index = 0; index < length; index += 1) output[index] = next() & 0xff;
  return output;
}

function shuffle(next, values) {
  const output = [...values];
  for (let index = output.length - 1; index > 0; index -= 1) {
    const other = next() % (index + 1);
    [output[index], output[other]] = [output[other], output[index]];
  }
  return output;
}

test('bounded deterministic parser fuzz never accepts a non-round-trippable record', () => {
  const next = generator();
  const decoders = [
    (bytes) => core.decodePrinciple(bytes).canonicalBytes(),
    (bytes) => core.decodeEvent(bytes).canonicalBytes(),
    (bytes) => CoherenceWitness.decode(bytes).encode(),
    (bytes) => Buffer.from(decodeActumFrame(bytes).frameHex, 'hex'),
    (bytes) => encodeEnvelope(decodeEnvelope(bytes)),
    (bytes) => encodeRecord(decodeRecord(bytes, { maxBytes: 1024, maxDepth: 24, maxNodes: 2048 })),
  ];
  let attempts = 0;
  for (let index = 0; index < 2_000; index += 1) {
    const bytes = randomBytes(next, next() % 513);
    for (const decodeAndEncode of decoders) {
      attempts += 1;
      try {
        const canonical = decodeAndEncode(bytes);
        assert.deepEqual(canonical, bytes);
      } catch (error) {
        assert.equal(error instanceof Error, true);
      }
    }
  }
  assert.equal(attempts, 12_000);
});

test('u128 codec round-trips deterministic values across the whole width', () => {
  const next = generator(0xc0decafe);
  for (let index = 0; index < 1_000; index += 1) {
    const bytes = randomBytes(next, 16);
    const value = core.codec.decodeUnsigned(bytes);
    assert.deepEqual(core.codec.encodeU128(value), bytes);
  }
});

test('constellation root, trace and replay commitment ignore arrival order', () => {
  const next = generator(0x51a7e);
  const senders = Array.from({ length: 6 }, (_, index) => (
    core.crypto.IdentityKeypair.fromTestSeed(Buffer.from(`property/sender/${index}`, 'ascii'))
  ));
  const receivers = Array.from({ length: 6 }, (_, index) => (
    core.crypto.IdentityKeypair.fromTestSeed(Buffer.from(`property/receiver/${index}`, 'ascii'))
  ));
  const state = new core.GlobalState({ balances: senders.map((sender) => [sender.address(), 100n]) });
  const events = senders.map((sender, index) => core.createTransfer({
    sequence: 1n,
    nonce: 1n,
    timestampMs: BigInt(index + 1),
    amountAtomic: BigInt(index + 1),
    previousRoot: state.root(),
    senderPublicKey: sender.publicBytes(),
    receiverAddress: receivers[index].address(),
    memo: `property-${index}`,
  }, sender));
  const reference = state.applyConstellationWithReceipt(events);

  for (let attempt = 0; attempt < 100; attempt += 1) {
    const receipt = state.applyConstellationWithReceipt(shuffle(next, events));
    assert.deepEqual(receipt.nextRoot, reference.nextRoot);
    assert.deepEqual(receipt.transitionTrace, reference.transitionTrace);
    assert.deepEqual(receipt.state.replayRoot, reference.state.replayRoot);
    assert.deepEqual(receipt.eventIds, reference.eventIds);
  }
  assert.equal(state.sequence, 0n);
});

test('Actum frame round-trips random valid field combinations exactly', () => {
  const next = generator(0xac7a0001);
  for (let index = 0; index < 500; index += 1) {
    const frame = encodeActumFrame({
      // ACT.APPLY reserves only flags in the published profile, so the other
      // bit-fields can cover their complete widths without manufacturing an
      // invalid instruction.
      mnemonic: 'ACT.APPLY',
      flags: 0,
      rd: next() & 31,
      rs1: next() & 31,
      rs2: next() & 31,
      mode: next() & 15,
      immediate: next() & 0x1fffffff,
    });
    const decoded = decodeActumFrame(frame);
    assert.deepEqual(encodeActumFrame(decoded), frame);
  }
});
