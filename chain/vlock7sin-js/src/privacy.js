'use strict';

const { createHash, randomBytes, timingSafeEqual } = require('node:crypto');
const { BinaryWriter } = require('./codec');
const { canonicalBytes, compareUtf8 } = require('./causalGraph');
const { sealForHybridRecipient } = require('./hybridCrypto');

const PRIVACY_SCHEMA = 'vlock7sin-private-payload-commitment-v1';
const PRIVACY_POLICY = 'BLINDED_SHA3_512_OFF_LEDGER_V1';
const DOMAIN_COMMITMENT = Buffer.from('VLOCK7SIN/PRIVATE-COMMITMENT/v1\0', 'ascii');
const DOMAIN_PRIVACY_LEAF = Buffer.from('VLOCK7SIN/PRIVACY-LEAF/v1\0', 'ascii');
const DOMAIN_PRIVACY_NODE = Buffer.from('VLOCK7SIN/PRIVACY-NODE/v1\0', 'ascii');
const DOMAIN_PRIVACY_EMPTY = Buffer.from('VLOCK7SIN/PRIVACY-EMPTY/v1\0', 'ascii');
const MAX_PRIVATE_PAYLOAD_BYTES = 1024 * 1024;
const MAX_PUBLIC_RECORD_BYTES = 128 * 1024;
const MAX_PUBLIC_DEPTH = 16;
const MAX_PUBLIC_NODES = 4096;

const FORBIDDEN_KEY = /^(?:e-?mail|phone|telephone|mobile|cpf|cnpj|rg|passport|document(?:id)?|full(?:_|-)?name|legal(?:_|-)?name|first(?:_|-)?name|last(?:_|-)?name|password|passphrase|secret|private(?:_|-)?key|seed|mnemonic|token|session(?:_|-)?id|cookie|authorization|bearer|ip(?:_|-)?address|user(?:_|-)?agent|birth(?:_|-)?date|address(?:_|-)?line|postal(?:_|-)?code|zip(?:_|-)?code|latitude|longitude|geolocation|biometric|faceprint)$/i;
const EMAIL_VALUE = /(^|[^A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,63}($|[^A-Za-z0-9.-])/;
const CPF_VALUE = /(?:^|\D)\d{3}\.\d{3}\.\d{3}-\d{2}(?:\D|$)/;
const PHONE_VALUE = /(?:^|\s)(?:\+\d{1,3}[ .-]?)?(?:\(\d{2,3}\)[ .-]?)\d{4,5}[ .-]\d{4}(?:\s|$)/;
const IPV4_VALUE = /(?:^|[^0-9])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?:[^0-9]|$)/;
const JWT_VALUE = /(?:^|\s)eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}(?:\s|$)/;
const PRIVATE_KEY_VALUE = /-----BEGIN (?:ENCRYPTED )?PRIVATE KEY-----/;
const RAW_REFERENCE_VALUE = /(?:^|\s)(?:https?|wss?|s3|ipfs|vault):\/\//i;

class PrivacyBoundaryError extends Error {
  constructor(code, message, details = undefined) {
    super(message);
    this.name = 'PrivacyBoundaryError';
    this.code = code;
    if (details !== undefined) this.details = details;
  }
}

function publicStringSafe(value, path) {
  if (value.length > 8192) {
    throw new PrivacyBoundaryError('PUBLIC_VALUE_TOO_LARGE', `public string at ${path} exceeds 8192 characters`);
  }
  const detectors = [
    ['EMAIL_DETECTED', EMAIL_VALUE],
    ['CPF_DETECTED', CPF_VALUE],
    ['PHONE_DETECTED', PHONE_VALUE],
    ['IP_ADDRESS_DETECTED', IPV4_VALUE],
    ['JWT_DETECTED', JWT_VALUE],
    ['PRIVATE_KEY_DETECTED', PRIVATE_KEY_VALUE],
    ['RAW_REFERENCE_DETECTED', RAW_REFERENCE_VALUE],
  ];
  for (const [code, pattern] of detectors) {
    if (pattern.test(value)) {
      throw new PrivacyBoundaryError(code, `public ledger value at ${path} contains forbidden sensitive data`);
    }
  }
}

function assertPublicLedgerSafe(value, options = {}) {
  const maximumBytes = options.maximumBytes ?? MAX_PUBLIC_RECORD_BYTES;
  const seen = new Set();
  let nodes = 0;
  function visit(current, path, depth) {
    nodes += 1;
    if (nodes > MAX_PUBLIC_NODES) throw new PrivacyBoundaryError('PUBLIC_RECORD_TOO_COMPLEX', 'public ledger record has too many nodes');
    if (depth > MAX_PUBLIC_DEPTH) throw new PrivacyBoundaryError('PUBLIC_RECORD_TOO_DEEP', 'public ledger record is too deeply nested');
    if (typeof current === 'string') {
      publicStringSafe(current, path);
      return;
    }
    if (current === null || typeof current === 'boolean') return;
    if (typeof current === 'number') {
      if (!Number.isFinite(current) || Object.is(current, -0)) {
        throw new PrivacyBoundaryError('NON_CANONICAL_PUBLIC_NUMBER', `public number at ${path} is not canonical`);
      }
      return;
    }
    if (typeof current !== 'object') {
      throw new PrivacyBoundaryError('NON_JSON_PUBLIC_VALUE', `public value at ${path} is not JSON interoperable`);
    }
    if (Buffer.isBuffer(current) || current instanceof Uint8Array) {
      throw new PrivacyBoundaryError('PUBLIC_BINARY_FORBIDDEN', `public binary value at ${path} must be encoded explicitly`);
    }
    if (current instanceof Map || current instanceof Set) {
      throw new PrivacyBoundaryError('NON_JSON_PUBLIC_CONTAINER', `public container at ${path} is not JSON interoperable`);
    }
    if (seen.has(current)) throw new PrivacyBoundaryError('CYCLIC_PUBLIC_RECORD', 'public ledger record is cyclic');
    seen.add(current);
    try {
      if (Array.isArray(current)) {
        const descriptors = Object.getOwnPropertyDescriptors(current);
        const allowed = new Set(['length', ...Array.from({ length: current.length }, (_, index) => String(index))]);
        if (Reflect.ownKeys(descriptors).some((key) => typeof key !== 'string' || !allowed.has(key))) {
          throw new PrivacyBoundaryError('AMBIGUOUS_PUBLIC_ARRAY', `public array at ${path} has holes, symbols or custom fields`);
        }
        for (let index = 0; index < current.length; index += 1) {
          const descriptor = descriptors[String(index)];
          if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, 'value')) {
            throw new PrivacyBoundaryError('AMBIGUOUS_PUBLIC_ARRAY', `public array at ${path} has a hole or accessor`);
          }
          visit(descriptor.value, `${path}[${index}]`, depth + 1);
        }
        return;
      }
      const prototype = Object.getPrototypeOf(current);
      if (prototype !== Object.prototype && prototype !== null) {
        throw new PrivacyBoundaryError('NON_JSON_PUBLIC_OBJECT', `public object at ${path} must be a plain object`);
      }
      const descriptors = Object.getOwnPropertyDescriptors(current);
      if (Reflect.ownKeys(descriptors).some((key) => typeof key !== 'string')) {
        throw new PrivacyBoundaryError('PUBLIC_SYMBOL_FORBIDDEN', `public object at ${path} contains a symbol field`);
      }
      for (const key of Object.keys(descriptors)) {
        const descriptor = descriptors[key];
        if (!descriptor.enumerable || !Object.prototype.hasOwnProperty.call(descriptor, 'value')) {
          throw new PrivacyBoundaryError('AMBIGUOUS_PUBLIC_FIELD', `public ledger field ${path}.${key} must be enumerable data`);
        }
        if (FORBIDDEN_KEY.test(key.replace(/[\s.]/g, ''))) {
          throw new PrivacyBoundaryError('FORBIDDEN_PUBLIC_FIELD', `public ledger field ${path}.${key} is sensitive`);
        }
        visit(descriptor.value, `${path}.${key}`, depth + 1);
      }
    } finally {
      seen.delete(current);
    }
  }
  visit(value, '$', 0);

  let encoded;
  try { encoded = canonicalBytes(value); } catch (cause) {
    throw new PrivacyBoundaryError('NON_CANONICAL_PUBLIC_RECORD', 'public ledger record is not canonically encodable', {
      cause: cause.message,
    });
  }
  if (encoded.length > maximumBytes) {
    throw new PrivacyBoundaryError('PUBLIC_RECORD_TOO_LARGE', `public ledger record exceeds ${maximumBytes} bytes`);
  }
  return true;
}

function privatePayloadBytes(value) {
  let bytes;
  try { bytes = canonicalBytes(value); } catch (cause) {
    throw new PrivacyBoundaryError('INVALID_PRIVATE_PAYLOAD', 'private payload is not canonically encodable', {
      cause: cause.message,
    });
  }
  if (bytes.length > MAX_PRIVATE_PAYLOAD_BYTES) {
    throw new PrivacyBoundaryError('PRIVATE_PAYLOAD_TOO_LARGE', `private payload exceeds ${MAX_PRIVATE_PAYLOAD_BYTES} bytes`);
  }
  return bytes;
}

function saltBytes(value = undefined) {
  const salt = value === undefined ? randomBytes(32) : Buffer.from(value);
  if (salt.length !== 32) throw new PrivacyBoundaryError('INVALID_SALT', 'privacy opening salt must contain 32 bytes');
  return salt;
}

function commitmentDigest(payload, salt) {
  const input = new BinaryWriter(MAX_PRIVATE_PAYLOAD_BYTES + 128)
    .write(DOMAIN_COMMITMENT)
    .u64(payload.length)
    .write(salt)
    .write(payload)
    .finish();
  return createHash('sha3-512').update(input).digest();
}

function createPrivatePayloadCommitment(payload, options = {}) {
  const bytes = privatePayloadBytes(payload);
  const salt = saltBytes(options.salt);
  const commitment = commitmentDigest(bytes, salt).toString('hex');
  let encryptedReference = null;
  if (options.reference !== undefined) {
    if (!options.recipient) {
      throw new PrivacyBoundaryError('RECIPIENT_REQUIRED', 'encrypted off-ledger reference requires a hybrid recipient');
    }
    const reference = Buffer.from(String(options.reference), 'utf8');
    if (reference.length < 1 || reference.length > 4096) {
      throw new PrivacyBoundaryError('INVALID_REFERENCE', 'off-ledger reference must contain 1..4096 UTF-8 bytes');
    }
    encryptedReference = sealForHybridRecipient(options.recipient, reference, {
      context: Object.freeze({ commitment, purpose: 'private-off-ledger-reference' }),
    });
  }
  const publicRecord = Object.freeze({
    schema: PRIVACY_SCHEMA,
    version: 1,
    policy: PRIVACY_POLICY,
    commitmentAlgorithm: 'sha3-512-domain-separated-salted',
    commitment,
    encryptedReference,
  });
  assertPublicLedgerSafe(publicRecord);
  const opening = Object.freeze({
    schema: 'vlock7sin-private-payload-opening-v1',
    salt: salt.toString('base64'),
  });
  salt.fill(0);
  return Object.freeze({ publicRecord, opening });
}

function validatePublicCommitment(record) {
  if (!record || typeof record !== 'object' || Array.isArray(record)) return false;
  const expected = [
    'schema', 'version', 'policy', 'commitmentAlgorithm', 'commitment', 'encryptedReference',
  ].sort(compareUtf8);
  const actual = Object.keys(record).sort(compareUtf8);
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) return false;
  if (record.schema !== PRIVACY_SCHEMA || record.version !== 1 || record.policy !== PRIVACY_POLICY
    || record.commitmentAlgorithm !== 'sha3-512-domain-separated-salted'
    || !/^[0-9a-f]{128}$/.test(String(record.commitment))) return false;
  try { return assertPublicLedgerSafe(record); } catch { return false; }
}

function verifyPrivatePayloadCommitment(payload, opening, publicRecord) {
  if (!validatePublicCommitment(publicRecord) || !opening || opening.schema !== 'vlock7sin-private-payload-opening-v1'
    || typeof opening.salt !== 'string') return false;
  let salt;
  try {
    salt = Buffer.from(opening.salt, 'base64');
    if (salt.length !== 32 || salt.toString('base64') !== opening.salt) return false;
    const actual = commitmentDigest(privatePayloadBytes(payload), salt);
    const expected = Buffer.from(publicRecord.commitment, 'hex');
    return timingSafeEqual(actual, expected);
  } catch {
    return false;
  } finally {
    salt?.fill(0);
  }
}

function privacyLeaf(record) {
  if (!validatePublicCommitment(record)) throw new PrivacyBoundaryError('INVALID_COMMITMENT', 'privacy record is invalid');
  return createHash('sha3-256').update(DOMAIN_PRIVACY_LEAF).update(canonicalBytes(record)).digest();
}

function computePrivacyRoot(records) {
  if (!Array.isArray(records)) throw new PrivacyBoundaryError('INVALID_COMMITMENTS', 'privacy records must be an array');
  let level = records.map(privacyLeaf).sort(Buffer.compare);
  if (level.length === 0) return createHash('sha3-256').update(DOMAIN_PRIVACY_EMPTY).digest('hex');
  for (let index = 1; index < level.length; index += 1) {
    if (level[index - 1].equals(level[index])) {
      throw new PrivacyBoundaryError('DUPLICATE_COMMITMENT', 'privacy commitments must be unique');
    }
  }
  while (level.length > 1) {
    const next = [];
    for (let index = 0; index < level.length; index += 2) {
      if (index + 1 >= level.length) next.push(level[index]);
      else next.push(createHash('sha3-256').update(DOMAIN_PRIVACY_NODE).update(level[index]).update(level[index + 1]).digest());
    }
    level = next;
  }
  return level[0].toString('hex');
}

module.exports = Object.freeze({
  PRIVACY_SCHEMA,
  PRIVACY_POLICY,
  PrivacyBoundaryError,
  assertPublicLedgerSafe,
  createPrivatePayloadCommitment,
  validatePublicCommitment,
  verifyPrivatePayloadCommitment,
  computePrivacyRoot,
});
