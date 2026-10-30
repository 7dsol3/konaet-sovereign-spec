'use strict';

const { createPublicKey } = require('node:crypto');
const { normalizeAct } = require('./event');
const { rawPublicKey } = require('./crypto');
const {
  HYBRID_BOUND_POLICY,
  normalizePublicIdentity,
  verifyHybridBoundSignature,
} = require('./hybridCrypto');

const AUTHORIZATION_SCHEMA = 'vlock7sin-hybrid-transfer-authorization-v1';

function signerRawEd25519(publicIdentity) {
  const normalized = normalizePublicIdentity(publicIdentity);
  const der = Buffer.from(normalized.identity.ed25519PublicKeyDer, 'base64');
  const key = createPublicKey({ key: der, format: 'der', type: 'spki' });
  return { fingerprint: normalized.fingerprint, rawKey: rawPublicKey(key) };
}

function createHybridTransferAuthorization(eventLike, hybridIdentity) {
  const event = normalizeAct(eventLike);
  event.assertValid();
  if (!hybridIdentity || typeof hybridIdentity.publicIdentity !== 'function'
    || typeof hybridIdentity.signBound !== 'function') {
    throw new TypeError('a HybridIdentity with a private signing key is required');
  }
  const signer = signerRawEd25519(hybridIdentity.publicIdentity());
  if (!signer.rawKey.equals(event.senderPublicKey)) {
    throw new TypeError('hybrid identity Ed25519 key does not match the transfer sender');
  }
  const eventBytes = event.canonicalBytes();
  const authorization = Object.freeze({
    schema: AUTHORIZATION_SCHEMA,
    version: 1,
    signaturePolicy: HYBRID_BOUND_POLICY,
    eventId: event.id().toString('hex'),
    signerFingerprint: signer.fingerprint,
    signature: hybridIdentity.signBound(eventBytes),
  });
  if (!verifyHybridTransferAuthorization(event, authorization, hybridIdentity.publicIdentity())) {
    throw new TypeError('new hybrid transfer authorization failed self-verification');
  }
  return authorization;
}

function verifyHybridTransferAuthorization(eventLike, authorization, publicIdentity) {
  try {
    const event = normalizeAct(eventLike);
    event.assertValid();
    if (!authorization || typeof authorization !== 'object' || Array.isArray(authorization)) return false;
    const keys = Object.keys(authorization).sort();
    if (keys.join(',') !== 'eventId,schema,signature,signaturePolicy,signerFingerprint,version'
      || authorization.schema !== AUTHORIZATION_SCHEMA || authorization.version !== 1
      || authorization.signaturePolicy !== HYBRID_BOUND_POLICY
      || authorization.eventId !== event.id().toString('hex')) return false;
    const signer = signerRawEd25519(publicIdentity);
    if (authorization.signerFingerprint !== signer.fingerprint
      || !signer.rawKey.equals(event.senderPublicKey)) return false;
    return verifyHybridBoundSignature(publicIdentity, event.canonicalBytes(), authorization.signature);
  } catch {
    return false;
  }
}

module.exports = Object.freeze({
  AUTHORIZATION_SCHEMA,
  createHybridTransferAuthorization,
  verifyHybridTransferAuthorization,
});
