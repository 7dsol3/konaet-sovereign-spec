'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {
  ACTUM_FRAME_BYTES,
  ACTUM_NAMESPACE,
  OPCODES,
  ActumError,
  ActumMachine,
  decodeActum,
  decodeActumFrame,
  encodeActum,
  encodeActumFrame,
} = require('../src/actum');

test('catalog contains the 22 Phase-0 opcodes without duplicates', () => {
  assert.equal(OPCODES.length, 22);
  assert.equal(new Set(OPCODES.map((entry) => entry.code)).size, 22);
  assert.equal(new Set(OPCODES.map((entry) => entry.mnemonic)).size, 22);
});

test('64-bit Actum encoding round-trips every field exactly', () => {
  const word = encodeActum({
    mnemonic: 'ACT.APPLY',
    flags: 0,
    rd: 31,
    rs1: 30,
    rs2: 29,
    mode: 15,
    immediateSigned: -1,
  });
  const decoded = decodeActum(word);
  assert.equal(typeof word, 'bigint');
  assert.equal(decoded.word, word);
  assert.equal(decoded.opcode, 0x20);
  assert.equal(decoded.rd, 31);
  assert.equal(decoded.rs1, 30);
  assert.equal(decoded.rs2, 29);
  assert.equal(decoded.mode, 15);
  assert.equal(decoded.immediateSigned, -1);
});

test('V7ACTUM frame prevents collision with bare Q4 command words', () => {
  const machine = new ActumMachine();
  assert.throws(() => machine.execute(0x01n), (error) => (
    error instanceof ActumError && error.code === 'INVALID_NAMESPACE'
  ));

  const frame = encodeActumFrame({ mnemonic: 'ACT.NOP' });
  assert.equal(frame.length, ACTUM_FRAME_BYTES);
  assert.equal(decodeActumFrame(frame).namespace, ACTUM_NAMESPACE);
  assert.equal(machine.execute(frame).ok, true);
});

test('safe machine moves only into general anchors and maintains AZ0', () => {
  const machine = new ActumMachine({ initialAnchors: { OR1: 42n } });
  const move = encodeActumFrame({ mnemonic: 'VEY.MOV', rd: 16, rs1: 1 });
  machine.execute(move);
  assert.equal(machine.readAnchor('AN16'), 42n);
  assert.equal(machine.readAnchor('AZ0'), 0n);

  const unsafeMove = encodeActumFrame({ mnemonic: 'VEY.MOV', rd: 3, rs1: 1 });
  assert.throws(() => machine.execute(unsafeMove), (error) => (
    error instanceof ActumError && error.code === 'UNSAFE_OPERAND'
  ));
  assert.equal(machine.readAnchor('SR3'), 0n);
});

test('specified but absent hardware operations fail explicitly', () => {
  const machine = new ActumMachine();
  const frame = encodeActumFrame({ mnemonic: 'SEL.VERIFY', rd: 16, rs1: 1, rs2: 2 });
  assert.throws(() => machine.execute(frame), (error) => (
    error instanceof ActumError && error.code === 'UNIMPLEMENTED_OPCODE'
  ));
});

test('reserved fields and malformed frames are rejected deterministically', () => {
  assert.throws(
    () => encodeActum({ mnemonic: 'ACT.NOP', immediate: 1 }),
    (error) => error instanceof ActumError && error.code === 'RESERVED_FIELD',
  );
  assert.throws(
    () => decodeActumFrame(Buffer.alloc(ACTUM_FRAME_BYTES)),
    (error) => error instanceof ActumError && error.code === 'INVALID_MAGIC',
  );
});
