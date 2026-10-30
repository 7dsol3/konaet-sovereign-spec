'use strict';

const assert = require('node:assert/strict');
const { createHash, generateKeyPairSync } = require('node:crypto');
const test = require('node:test');
const {
  HybridIdentity,
  nativeHybridSelfTest,
  verifyHybridSignature,
  verifyHybridBoundSignature,
} = require('../src/hybridCrypto');

function mutateBase64(value) {
  const bytes = Buffer.from(value, 'base64');
  bytes[0] ^= 1;
  return bytes.toString('base64');
}

test('hybrid identity requires valid Ed25519 and ML-DSA-65 over the same bytes', () => {
  const identity = HybridIdentity.generate();
  const message = Buffer.from('checkpoint bytes are immutable', 'utf8');
  const signature = identity.sign(message);

  assert.equal(identity.verify(message, signature), true);
  assert.equal(verifyHybridSignature(identity.publicIdentity(), message, signature), true);
  assert.equal(identity.verify(Buffer.from('checkpoint bytes changed', 'utf8'), signature), false);
  assert.equal(identity.verify(message, { ...signature, ed25519Signature: mutateBase64(signature.ed25519Signature) }), false);
  assert.equal(identity.verify(message, { ...signature, mlDsa65Signature: mutateBase64(signature.mlDsa65Signature) }), false);
  assert.equal(Object.prototype.hasOwnProperty.call(identity, 'privateKey'), false);
});

test('identity-bound v2 rejects KEM substitution and legacy downgrade', () => {
  const ed = generateKeyPairSync('ed25519').privateKey;
  const ml = generateKeyPairSync('ml-dsa-65').privateKey;
  const make = () => new HybridIdentity({ ed25519PrivateKey: ed, mlDsa65PrivateKey: ml,
    mlKem768PrivateKey: generateKeyPairSync('ml-kem-768').privateKey });
  const first = make();
  const replacement = make();
  const message = Buffer.from('identity is part of the signed message');
  const signature = first.signBound(message);
  assert.equal(signature.version, 2);
  assert.equal(first.verifyBound(message, signature), true);
  assert.equal(verifyHybridBoundSignature(first.publicIdentity(), message, signature), true);
  assert.equal(verifyHybridSignature(first.publicIdentity(), message, signature), false);
  assert.equal(verifyHybridBoundSignature(first.publicIdentity(), message, first.sign(message)), false);

  const replacementFingerprint = replacement.publicIdentity().fingerprint;
  const length = Buffer.alloc(8);
  length.writeBigUInt64BE(BigInt(message.length));
  const reboundMessage = Buffer.concat([Buffer.from('VLOCK7SIN/HYBRID-SIGNATURE/v2\0', 'ascii'),
    Buffer.from(replacementFingerprint, 'hex'), length, message]);
  const changed = { ...signature, signerFingerprint: replacementFingerprint,
    messageSha3_512: createHash('sha3-512').update(reboundMessage).digest('hex') };
  assert.equal(verifyHybridBoundSignature(replacement.publicIdentity(), message, changed), false);
  assert.equal(first.verifyBound(message, { ...signature, ed25519Signature: mutateBase64(signature.ed25519Signature) }), false);
  assert.equal(first.verifyBound(message, { ...signature, mlDsa65Signature: mutateBase64(signature.mlDsa65Signature) }), false);
  assert.equal(first.verifyBound(Buffer.from('changed'), signature), false);
});

test('ML-KEM-768 seals payloads to one hybrid recipient and binds context', () => {
  const recipient = HybridIdentity.generate();
  const other = HybridIdentity.generate();
  const payload = Buffer.from('vault://private/evidence/7', 'utf8');
  const sealed = recipient.seal(payload, { context: { purpose: 'reference', commitment: 'ab'.repeat(64) } });

  assert.deepEqual(
    recipient.open(sealed, { context: { purpose: 'reference', commitment: 'ab'.repeat(64) } }),
    payload,
  );
  assert.throws(
    () => recipient.open(sealed, { context: { purpose: 'other', commitment: 'ab'.repeat(64) } }),
    { code: 'CONTEXT_MISMATCH' },
  );
  assert.throws(
    () => other.open(sealed, { context: { purpose: 'reference', commitment: 'ab'.repeat(64) } }),
    { code: 'WRONG_RECIPIENT' },
  );
});

test('native hybrid self-test proves all three algorithms and rejects tampering', () => {
  const result = nativeHybridSelfTest();
  assert.equal(result.ed25519, true);
  assert.equal(result.mlDsa65, true);
  assert.equal(result.hybridSignature, true);
  assert.equal(result.mlKem768, true);
  assert.equal(result.tamperRejected, true);
  assert.equal(result.implementation, 'node-native-openssl-provider');
});
