import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import { verifyEvent, verifyTransferVector, trace } from '../lib/event.mjs';

const vector = JSON.parse(fs.readFileSync(new URL('../examples/signed-transfer.json', import.meta.url), 'utf8'));
const wire = () => Buffer.from(vector.wireHex, 'hex');
const header = Buffer.byteLength('VLOCK7SIN/EVENT/js-v1') + 4;

test('independently verifies the VLOCK-generated event and exact integer amount', () => {
  const result = verifyTransferVector(vector);
  assert.equal(result.amountAtomic, '123456789012345678');
  assert.equal(result.cryptographicallyValid, true);
  assert.equal(result.ledgerFinalityProven, false);
  assert.equal(result.eventIdHex, vector.eventIdHex);
});

test('wrong network is rejected even though the original signature is valid', () => {
  assert.throws(() => verifyEvent(wire(), { expectedNetworkId: 0x7002 }), /NETWORK_MISMATCH/);
});

test('signature verification rejects tampering after an attacker repairs the checksum', () => {
  const changed = wire();
  changed[changed.length - 17] ^= 1;
  trace(changed.subarray(0, -16)).copy(changed, changed.length - 16, 0, 16);
  assert.throws(() => verifyEvent(changed), /SIGNATURE_INVALID/);
});

test('truncation, trailing bytes and oversized records are rejected', () => {
  for (const input of [wire().subarray(0, -1), Buffer.concat([wire(), Buffer.from([0])]), Buffer.alloc(65537)]) {
    assert.throws(() => verifyEvent(input));
  }
});

test('unknown record type, versions, suites and flags are rejected', () => {
  for (const offset of [header, header + 1, header + 4, header + 7, header + 13, header + 15]) {
    const changed = wire();
    changed[offset] ^= 0x40;
    assert.throws(() => verifyEvent(changed));
  }
});

test('every prefix truncation is rejected without state or filesystem operations', () => {
  const bytes = wire();
  for (let size = 0; size < bytes.length; size++) assert.throws(() => verifyEvent(bytes.subarray(0, size)));
});

test('zero counters and zero amount are rejected before execution', () => {
  const sequenceOffset = header + 17;
  for (const [offset, size] of [[sequenceOffset, 8], [sequenceOffset + 8, 8], [sequenceOffset + 24, 16]]) {
    const changed = wire(); changed.fill(0, offset, offset + size);
    assert.throws(() => verifyEvent(changed), /POSITIVE_/);
  }
});

test('a vector wrapper cannot relabel asset, amount, finality or signature', () => {
  for (const patch of [{ asset: 'NAET' }, { amountAtomic: '1' }, { ledgerFinalityProven: true },
    { signatureHex: '0'.repeat(128) }, { productionKeysUsed: true }, { networkId: 0x7002 }]) {
    assert.throws(() => verifyTransferVector({ ...vector, ...patch }));
  }
});

test('canonical hex refuses odd length, uppercase, nonhex and accidental Number coercion', () => {
  for (const invalid of [vector.wireHex.slice(1), vector.wireHex.toUpperCase(), 'zz', 123]) {
    assert.throws(() => verifyTransferVector({ ...vector, wireHex: invalid }));
  }
});

test('bounded memo and nexus counts reject inflated lengths', () => {
  // The published vector has two canonical 34-byte addresses and zero nexuses.
  const addressOffset = header + 17 + 24 + 16 + 32 + 32;
  const nexusOffset = addressOffset + 2 + 34 + 2 + 34;
  const nexus = wire(); nexus.writeUInt16BE(257, nexusOffset);
  assert.throws(() => verifyEvent(nexus), /NEXUS_LIMIT_EXCEEDED/);
  const memo = wire(); memo.writeUInt16BE(257, nexusOffset + 2);
  assert.throws(() => verifyEvent(memo), /FIELD_TOO_LARGE/);
});
