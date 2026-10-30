'use strict';

const nodeCrypto = require('node:crypto');
const {
  DOMAINS,
  LEGACY_DOMAINS,
  LENGTHS,
  LIMITS,
} = require('./constants');
const { asBuffer, encodeU64 } = require('./codec');
const { CryptoError, ValidationError } = require('./errors');

const ED25519_PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');
const ADDRESS_RE = /^v7[a-z2-7]{32}$/;

function sha3(value) {
  const data = asBuffer(value, 'hash input', { maxLength: Number.MAX_SAFE_INTEGER });
  return nodeCrypto.createHash('sha3-256').update(data).digest();
}

const sha3_256 = sha3;

function domainBytes(domain) {
  if (typeof domain !== 'string' || !/^[\x21-\x7e]+$/.test(domain)) {
    throw new CryptoError('domain must be a non-empty printable ASCII string');
  }
  return Buffer.from(domain, 'ascii');
}

function domainHash(domain, ...parts) {
  const hash = nodeCrypto.createHash('sha3-256').update(domainBytes(domain));
  for (const [index, part] of parts.entries()) {
    hash.update(asBuffer(part, `hash part ${index}`, { maxLength: Number.MAX_SAFE_INTEGER }));
  }
  return hash.digest();
}

function traceIrreversible(value, { legacy = false } = {}) {
  const data = asBuffer(value, 'trace input', { maxLength: LIMITS.RECORD_BYTES });
  const domain = legacy ? LEGACY_DOMAINS.TRACE : DOMAINS.TRACE;
  return domainHash(domain, encodeU64(data.length), data);
}

const trace_irreversivel = traceIrreversible;

function privateKeyFromSeed(seed) {
  const raw = asBuffer(seed, 'Ed25519 seed', { exactLength: LENGTHS.PRIVATE_SEED });
  try {
    return nodeCrypto.createPrivateKey({
      key: Buffer.concat([ED25519_PKCS8_PREFIX, raw]),
      format: 'der',
      type: 'pkcs8',
    });
  } catch (cause) {
    throw new CryptoError('could not construct Ed25519 private key from seed', { cause });
  } finally {
    raw.fill(0);
  }
}

function publicKeyFromRaw(publicKey) {
  const raw = asBuffer(publicKey, 'Ed25519 public key', { exactLength: LENGTHS.PUBLIC_KEY });
  try {
    return nodeCrypto.createPublicKey({
      key: Buffer.concat([ED25519_SPKI_PREFIX, raw]),
      format: 'der',
      type: 'spki',
    });
  } catch (cause) {
    throw new CryptoError('could not construct Ed25519 public key', { cause });
  }
}

function rawPublicKey(key) {
  let keyObject;
  try {
    keyObject = key instanceof nodeCrypto.KeyObject
      ? (key.type === 'private' ? nodeCrypto.createPublicKey(key) : key)
      : publicKeyFromRaw(key);
    if (keyObject.asymmetricKeyType !== 'ed25519' || keyObject.type !== 'public') {
      throw new TypeError('not an Ed25519 public key');
    }
    const der = keyObject.export({ format: 'der', type: 'spki' });
    if (der.length !== ED25519_SPKI_PREFIX.length + LENGTHS.PUBLIC_KEY
      || !der.subarray(0, ED25519_SPKI_PREFIX.length).equals(ED25519_SPKI_PREFIX)) {
      throw new TypeError('unexpected Ed25519 SPKI representation');
    }
    return Buffer.from(der.subarray(-LENGTHS.PUBLIC_KEY));
  } catch (cause) {
    if (cause instanceof CryptoError) throw cause;
    throw new CryptoError('invalid Ed25519 key', { cause });
  }
}

function normalizePrivateKey(value) {
  if (value instanceof IdentityKeypair) return value.privateKeyObject();
  if (value instanceof nodeCrypto.KeyObject) {
    if (value.type !== 'private' || value.asymmetricKeyType !== 'ed25519') {
      throw new CryptoError('private key must be an Ed25519 private KeyObject');
    }
    return value;
  }
  return privateKeyFromSeed(value);
}

function normalizePublicKey(value) {
  if (value instanceof IdentityKeypair) return value.publicKeyObject();
  if (value instanceof nodeCrypto.KeyObject) {
    const result = value.type === 'private' ? nodeCrypto.createPublicKey(value) : value;
    if (result.type !== 'public' || result.asymmetricKeyType !== 'ed25519') {
      throw new CryptoError('public key must be Ed25519');
    }
    return result;
  }
  return publicKeyFromRaw(value);
}

function sign(privateKey, message) {
  const data = asBuffer(message, 'message', { maxLength: LIMITS.RECORD_BYTES });
  try {
    const signature = nodeCrypto.sign(null, data, normalizePrivateKey(privateKey));
    if (signature.length !== LENGTHS.SIGNATURE) {
      throw new Error('unexpected signature length');
    }
    return Buffer.from(signature);
  } catch (cause) {
    if (cause instanceof CryptoError) throw cause;
    throw new CryptoError('Ed25519 signing failed', { cause });
  }
}

function verify(publicKey, message, signature) {
  try {
    const data = asBuffer(message, 'message', { maxLength: LIMITS.RECORD_BYTES });
    const sig = asBuffer(signature, 'signature', { exactLength: LENGTHS.SIGNATURE });
    return nodeCrypto.verify(null, data, normalizePublicKey(publicKey), sig);
  } catch {
    return false;
  }
}

const verifySignature = verify;

const BASE32_ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567';

function base32NoPadding(value) {
  const bytes = asBuffer(value, 'base32 input');
  let bits = 0;
  let accumulator = 0;
  let output = '';
  for (const octet of bytes) {
    accumulator = (accumulator << 8) | octet;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      output += BASE32_ALPHABET[(accumulator >>> bits) & 31];
      accumulator &= (1 << bits) - 1;
    }
  }
  if (bits > 0) output += BASE32_ALPHABET[(accumulator << (5 - bits)) & 31];
  return output;
}

function encodeAddress(publicKey) {
  const raw = rawPublicKey(publicKey);
  const digest = domainHash(DOMAINS.ADDRESS, raw).subarray(0, LENGTHS.ADDRESS_HASH);
  return `v7${base32NoPadding(digest)}`;
}

function validateAddress(address) {
  if (typeof address !== 'string' || !ADDRESS_RE.test(address)) {
    throw new ValidationError('address must be canonical v7 Base32 (34 characters)');
  }
  return address;
}

function addressMatchesPublicKey(address, publicKey) {
  try {
    return validateAddress(address) === encodeAddress(publicKey);
  } catch {
    return false;
  }
}

function deriveTestSeed(seed) {
  const input = asBuffer(seed, 'test seed', { maxLength: 1024 });
  return domainHash(DOMAINS.TEST_SEED, input);
}

class IdentityKeypair {
  #privateKey;

  #publicKey;

  constructor(privateKey) {
    this.#privateKey = normalizePrivateKey(privateKey);
    this.#publicKey = nodeCrypto.createPublicKey(this.#privateKey);
  }

  static fromSeed(seed) {
    return new IdentityKeypair(privateKeyFromSeed(seed));
  }

  static fromTestSeed(seed) {
    const derived = deriveTestSeed(seed);
    try {
      return IdentityKeypair.fromSeed(derived);
    } finally {
      derived.fill(0);
    }
  }

  static generate() {
    const { privateKey } = nodeCrypto.generateKeyPairSync('ed25519');
    return new IdentityKeypair(privateKey);
  }

  privateKeyObject() { return this.#privateKey; }

  publicKeyObject() { return this.#publicKey; }

  publicBytes() { return rawPublicKey(this.#publicKey); }

  address() { return encodeAddress(this.publicBytes()); }

  sign(message) { return sign(this.#privateKey, message); }
}

function keypairFromSeed(seed) {
  return IdentityKeypair.fromSeed(seed);
}

function keypairFromTestSeed(seed) {
  return IdentityKeypair.fromTestSeed(seed);
}

module.exports = Object.freeze({
  sha3,
  sha3_256,
  domainHash,
  traceIrreversible,
  trace_irreversivel,
  privateKeyFromSeed,
  publicKeyFromRaw,
  rawPublicKey,
  sign,
  verify,
  verifySignature,
  base32NoPadding,
  encodeAddress,
  validateAddress,
  addressMatchesPublicKey,
  deriveTestSeed,
  IdentityKeypair,
  keypairFromSeed,
  keypairFromTestSeed,
});
