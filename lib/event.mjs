import assert from 'node:assert/strict';
import { createHash, createPublicKey, verify } from 'node:crypto';
import { TextDecoder } from 'node:util';

const DOMAIN = Buffer.from('VLOCK7SIN/EVENT/js-v1', 'ascii');
const TRACE = Buffer.from('VLOCK7SIN/TRACE/js-v1', 'ascii');
const ADDRESS_DOMAIN = Buffer.from('VLOCK7SIN/IDENTITY/v0.1', 'ascii');
const PUBLIC_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const UTF8 = new TextDecoder('utf-8', { fatal: true });
const MAX_BYTES = 65536;

export function trace(bytes) {
  assert.ok(Buffer.isBuffer(bytes) && bytes.length <= MAX_BYTES, 'TRACE_BYTES_INVALID');
  const length = Buffer.alloc(8);
  length.writeBigUInt64BE(BigInt(bytes.length));
  return createHash('sha3-256').update(TRACE).update(length).update(bytes).digest();
}

export function addressForKey(publicBytes) {
  assert.ok(Buffer.isBuffer(publicBytes) && publicBytes.length === 32, 'PUBLIC_KEY_INVALID');
  const bytes = createHash('sha3-256').update(ADDRESS_DOMAIN).update(publicBytes).digest().subarray(0, 20);
  const alphabet = 'abcdefghijklmnopqrstuvwxyz234567';
  let bits = 0, accumulator = 0, output = '';
  for (const octet of bytes) {
    accumulator = (accumulator << 8) | octet;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      output += alphabet[(accumulator >>> bits) & 31];
      accumulator &= (1 << bits) - 1;
    }
  }
  if (bits) output += alphabet[(accumulator << (5 - bits)) & 31];
  return `v7${output}`;
}

// A narrow independent verifier of the published EVENT/js-v1 profile.
// It has no state, network, ledger, signing API or finalization authority.
export function verifyEvent(bytes, { expectedNetworkId = 0x7001 } = {}) {
  assert.ok(Buffer.isBuffer(bytes) && bytes.length > 0 && bytes.length <= MAX_BYTES, 'RECORD_SIZE_INVALID');
  assert.ok(Number.isSafeInteger(expectedNetworkId) && expectedNetworkId >= 0
    && expectedNetworkId <= 0xffffffff, 'EXPECTED_NETWORK_INVALID');
  let offset = 0;
  function read(size) {
    assert.ok(Number.isSafeInteger(size) && size >= 0 && offset + size <= bytes.length, 'TRUNCATED_RECORD');
    const value = bytes.subarray(offset, offset + size);
    offset += size;
    return value;
  }
  function integer(size) {
    let value = 0n;
    for (const octet of read(size)) value = (value << 8n) | BigInt(octet);
    return value;
  }
  function expect(value, name) { assert.ok(read(value.length).equals(value), name); }
  function sized(maximum) {
    const size = Number(integer(2));
    assert.ok(size <= maximum, 'FIELD_TOO_LARGE');
    return read(size);
  }
  function address() {
    const raw = sized(128);
    assert.ok(raw.every(octet => octet < 128), 'ADDRESS_ASCII_REQUIRED');
    const text = raw.toString('ascii');
    assert.match(text, /^v7[a-z2-7]{32}$/, 'ADDRESS_INVALID');
    return text;
  }
  expect(DOMAIN, 'EVENT_DOMAIN_MISMATCH');
  expect(Buffer.from('V7SN'), 'MAGIC_MISMATCH');
  assert.equal(integer(1), 2n, 'EVENT_KIND_MISMATCH');
  expect(Buffer.from([1, 0, 0]), 'FORMAT_VERSION_MISMATCH');
  expect(Buffer.from([0, 2, 0]), 'PROTOCOL_VERSION_MISMATCH');
  assert.equal(integer(2), 0n, 'UNKNOWN_FLAGS');
  const networkId = Number(integer(4));
  assert.equal(networkId, expectedNetworkId, 'NETWORK_MISMATCH');
  assert.equal(integer(2), 1n, 'CRYPTO_SUITE_MISMATCH');
  assert.equal(integer(2), 1n, 'STATE_SUITE_MISMATCH');
  const sequence = integer(8), nonce = integer(8), timestampMs = integer(8), amountAtomic = integer(16);
  assert.ok(sequence > 0n && nonce > 0n, 'POSITIVE_COUNTERS_REQUIRED');
  assert.ok(amountAtomic > 0n, 'POSITIVE_AMOUNT_REQUIRED');
  const previousRoot = read(32).toString('hex');
  const senderPublicKey = read(32);
  const senderAddress = address(), receiverAddress = address();
  assert.equal(senderAddress, addressForKey(senderPublicKey), 'SENDER_KEY_MISMATCH');
  const count = Number(integer(2));
  assert.ok(count <= 256, 'NEXUS_LIMIT_EXCEEDED');
  const nexuses = [];
  for (let index = 0; index < count; index++) {
    const nexus = read(32);
    if (index) assert.ok(Buffer.compare(nexuses[index - 1], nexus) < 0, 'NEXUS_ORDER_INVALID');
    nexuses.push(nexus);
  }
  const memoBytes = sized(256);
  const memo = UTF8.decode(memoBytes);
  assert.equal(memo, memo.normalize('NFC'), 'MEMO_NFC_REQUIRED');
  assert.ok(!/[\p{Cc}\p{Cf}\uD800-\uDFFF]/u.test(memo), 'MEMO_CONTROLS_FORBIDDEN');
  assert.ok(Buffer.from(memo, 'utf8').equals(memoBytes), 'MEMO_ENCODING_INVALID');
  const unsignedEnd = offset;
  const signature = read(64);
  const checksum = read(16);
  assert.equal(offset, bytes.length, 'TRAILING_BYTES');
  const unsignedBytes = bytes.subarray(0, unsignedEnd);
  assert.ok(checksum.equals(trace(bytes.subarray(0, unsignedEnd + 64)).subarray(0, 16)), 'CHECKSUM_INVALID');
  const key = createPublicKey({ key: Buffer.concat([PUBLIC_PREFIX, senderPublicKey]), format: 'der', type: 'spki' });
  assert.equal(verify(null, unsignedBytes, key, signature), true, 'SIGNATURE_INVALID');
  return { networkId, sequence: sequence.toString(), nonce: nonce.toString(), timestampMs: timestampMs.toString(),
    amountAtomic: amountAtomic.toString(), previousRoot, senderPublicKey: senderPublicKey.toString('hex'),
    senderAddress, receiverAddress, nexuses: nexuses.map(nexus => nexus.toString('hex')), memo,
    unsignedHex: unsignedBytes.toString('hex'), signatureHex: signature.toString('hex'),
    eventIdHex: trace(bytes).toString('hex'), cryptographicallyValid: true, ledgerFinalityProven: false };
}

export function verifyTransferVector(vector) {
  assert.equal(vector?.schema, 'konaet.spec.transfer-vector.v1', 'VECTOR_SCHEMA_INVALID');
  assert.equal(vector.scope, 'synthetic-documentation-vector');
  assert.equal(vector.asset, 'SND');
  assert.equal(vector.decimals, 9);
  assert.equal(vector.networkId, 0x7001, 'VECTOR_NETWORK_INVALID');
  for (const field of ['ledgerFinalityProven', 'productionKeysUsed', 'privateKeysIncluded']) assert.equal(vector[field], false);
  assert.ok(typeof vector.wireHex === 'string' && vector.wireHex.length <= MAX_BYTES * 2
    && /^(?:[0-9a-f]{2})+$/.test(vector.wireHex), 'WIRE_HEX_INVALID');
  const result = verifyEvent(Buffer.from(vector.wireHex, 'hex'), { expectedNetworkId: vector.networkId });
  for (const field of ['amountAtomic', 'senderAddress', 'receiverAddress', 'unsignedHex', 'signatureHex', 'eventIdHex']) {
    assert.equal(vector[field], result[field], `VECTOR_FIELD_MISMATCH: ${field}`);
  }
  return result;
}
