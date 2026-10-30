'use strict';

const {
  createCipheriv,
  createDecipheriv,
  createHash,
  createPrivateKey,
  createPublicKey,
  decapsulate,
  encapsulate,
  generateKeyPairSync,
  hkdfSync,
  KeyObject,
  randomBytes,
  sign,
  timingSafeEqual,
  verify,
} = require('node:crypto');
const { BinaryWriter, asBuffer } = require('./codec');
const { canonicalBytes, compareUtf8 } = require('./causalGraph');

const HYBRID_POLICY = 'ED25519_AND_ML_DSA_65_V1';
const SIGNATURE_SCHEMA = 'vlock7sin-hybrid-signature-v1';
const HYBRID_BOUND_POLICY = 'ED25519_AND_ML_DSA_65_IDENTITY_BOUND_V2';
const BOUND_SIGNATURE_SCHEMA = 'vlock7sin-hybrid-signature-v2';
const IDENTITY_SCHEMA = 'vlock7sin-hybrid-public-identity-v1';
const SEALED_SCHEMA = 'vlock7sin-ml-kem-sealed-payload-v1';
const DOMAIN_IDENTITY = Buffer.from('VLOCK7SIN/HYBRID-IDENTITY/v1\0', 'ascii');
const DOMAIN_SIGNATURE = Buffer.from('VLOCK7SIN/HYBRID-SIGNATURE/v1\0', 'ascii');
const DOMAIN_BOUND_SIGNATURE = Buffer.from('VLOCK7SIN/HYBRID-SIGNATURE/v2\0', 'ascii');
const DOMAIN_SEAL = Buffer.from('VLOCK7SIN/ML-KEM-SEAL/v1\0', 'ascii');
const MAX_MESSAGE_BYTES = 1024 * 1024;
const MAX_SEALED_BYTES = 64 * 1024;

class HybridCryptoError extends Error {
  constructor(code, message, details = undefined) {
    super(message);
    this.name = 'HybridCryptoError';
    this.code = code;
    if (details !== undefined) this.details = details;
  }
}

function exactFields(value, expected, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new HybridCryptoError('INVALID_RECORD', `${label} must be an object`);
  }
  const actual = Object.keys(value).sort(compareUtf8);
  const wanted = [...expected].sort(compareUtf8);
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw new HybridCryptoError('INVALID_RECORD', `${label} has missing or unexpected fields`);
  }
}

function boundedBytes(value, label, maximum = MAX_MESSAGE_BYTES) {
  try {
    return asBuffer(value, label, { maxLength: maximum });
  } catch (cause) {
    throw new HybridCryptoError('INVALID_BYTES', `${label} must be bounded bytes`, { cause: cause.message });
  }
}

function canonicalBase64(value, label, maximum = MAX_SEALED_BYTES) {
  if (typeof value !== 'string' || value.length === 0 || value.length > Math.ceil(maximum * 4 / 3) + 4
    || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new HybridCryptoError('INVALID_BASE64', `${label} must be canonical base64`);
  }
  const bytes = Buffer.from(value, 'base64');
  if (bytes.length > maximum || bytes.toString('base64') !== value) {
    throw new HybridCryptoError('INVALID_BASE64', `${label} must be canonical base64`);
  }
  return bytes;
}

function canonicalHex(value, bytes, label) {
  const text = String(value ?? '');
  if (!new RegExp(`^[0-9a-f]{${bytes * 2}}$`).test(text)) {
    throw new HybridCryptoError('INVALID_HEX', `${label} must be ${bytes}-byte canonical lowercase hex`);
  }
  return text;
}

function publicDer(key) {
  const object = key instanceof KeyObject
    ? (key.type === 'public' ? key : createPublicKey(key))
    : createPublicKey(key);
  return Buffer.from(object.export({ format: 'der', type: 'spki' }));
}

function privateObject(value, algorithm, label) {
  let object;
  try {
    object = value instanceof KeyObject ? value : createPrivateKey(value);
  } catch (cause) {
    throw new HybridCryptoError('INVALID_PRIVATE_KEY', `${label} private key is invalid`, { cause: cause.message });
  }
  if (object.type !== 'private' || object.asymmetricKeyType !== algorithm) {
    throw new HybridCryptoError('WRONG_KEY_TYPE', `${label} private key must be ${algorithm}`);
  }
  return object;
}

function publicObjectFromBase64(value, algorithm, label) {
  let object;
  try {
    object = createPublicKey({
      key: canonicalBase64(value, `${label} public key`, MAX_SEALED_BYTES),
      format: 'der',
      type: 'spki',
    });
  } catch (cause) {
    if (cause instanceof HybridCryptoError) throw cause;
    throw new HybridCryptoError('INVALID_PUBLIC_KEY', `${label} public key is invalid`, { cause: cause.message });
  }
  if (object.type !== 'public' || object.asymmetricKeyType !== algorithm) {
    throw new HybridCryptoError('WRONG_KEY_TYPE', `${label} public key must be ${algorithm}`);
  }
  return object;
}

function digest(algorithm, domain, value) {
  return createHash(algorithm).update(domain).update(value).digest();
}

function identityStatement({ ed25519PublicKeyDer, mlDsa65PublicKeyDer, mlKem768PublicKeyDer }) {
  return Object.freeze({
    schema: IDENTITY_SCHEMA,
    version: 1,
    policy: HYBRID_POLICY,
    ed25519: 'ed25519',
    mlDsa: 'ml-dsa-65',
    mlKem: 'ml-kem-768',
    ed25519PublicKeyDer,
    mlDsa65PublicKeyDer,
    mlKem768PublicKeyDer,
  });
}

function identityFingerprint(statement) {
  return digest('sha3-256', DOMAIN_IDENTITY, canonicalBytes(statement)).toString('hex');
}

function normalizePublicIdentity(identity) {
  exactFields(identity, [
    'schema', 'version', 'policy', 'ed25519', 'mlDsa', 'mlKem',
    'ed25519PublicKeyDer', 'mlDsa65PublicKeyDer', 'mlKem768PublicKeyDer', 'fingerprint',
  ], 'hybrid public identity');
  if (identity.schema !== IDENTITY_SCHEMA || identity.version !== 1 || identity.policy !== HYBRID_POLICY
    || identity.ed25519 !== 'ed25519' || identity.mlDsa !== 'ml-dsa-65' || identity.mlKem !== 'ml-kem-768') {
    throw new HybridCryptoError('UNSUPPORTED_IDENTITY', 'hybrid public identity profile is unsupported');
  }
  const statement = identityStatement(identity);
  const fingerprint = identityFingerprint(statement);
  if (canonicalHex(identity.fingerprint, 32, 'identity fingerprint') !== fingerprint) {
    throw new HybridCryptoError('IDENTITY_FINGERPRINT_MISMATCH', 'hybrid public identity fingerprint is invalid');
  }
  const keys = Object.freeze({
    ed25519: publicObjectFromBase64(identity.ed25519PublicKeyDer, 'ed25519', 'Ed25519'),
    mlDsa: publicObjectFromBase64(identity.mlDsa65PublicKeyDer, 'ml-dsa-65', 'ML-DSA-65'),
    mlKem: publicObjectFromBase64(identity.mlKem768PublicKeyDer, 'ml-kem-768', 'ML-KEM-768'),
  });
  return Object.freeze({ identity: Object.freeze({ ...identity }), statement, fingerprint, keys });
}

function signingMessage(message) {
  const data = boundedBytes(message, 'hybrid message');
  return new BinaryWriter(MAX_MESSAGE_BYTES + 128)
    .write(DOMAIN_SIGNATURE)
    .u64(data.length)
    .write(data)
    .finish();
}

function messageDigest(message) {
  return createHash('sha3-512').update(signingMessage(message)).digest('hex');
}

function boundSigningMessage(fingerprint, message) {
  const data = boundedBytes(message, 'hybrid message');
  const identity = Buffer.from(canonicalHex(fingerprint, 32, 'signer fingerprint'), 'hex');
  return new BinaryWriter(MAX_MESSAGE_BYTES + 128)
    .write(DOMAIN_BOUND_SIGNATURE)
    .write(identity)
    .u64(data.length)
    .write(data)
    .finish();
}

// V2 is an explicitly selected profile. V1 remains readable through
// verifyHybridSignature and is never accepted as an identity-bound signature.
function verifyHybridBoundSignature(publicIdentity, message, envelope) {
  try {
    const normalized = normalizePublicIdentity(publicIdentity);
    exactFields(envelope, [
      'schema', 'version', 'policy', 'signerFingerprint', 'messageSha3_512',
      'ed25519Signature', 'mlDsa65Signature',
    ], 'identity-bound hybrid signature');
    if (envelope.schema !== BOUND_SIGNATURE_SCHEMA || envelope.version !== 2
      || envelope.policy !== HYBRID_BOUND_POLICY
      || canonicalHex(envelope.signerFingerprint, 32, 'signer fingerprint') !== normalized.fingerprint) {
      return false;
    }
    const data = boundSigningMessage(normalized.fingerprint, message);
    if (canonicalHex(envelope.messageSha3_512, 64, 'message digest')
      !== createHash('sha3-512').update(data).digest('hex')) return false;
    const edSignature = canonicalBase64(envelope.ed25519Signature, 'Ed25519 signature', 128);
    const mlSignature = canonicalBase64(envelope.mlDsa65Signature, 'ML-DSA-65 signature', 8192);
    return verify(null, data, normalized.keys.ed25519, edSignature)
      && verify(null, data, normalized.keys.mlDsa, mlSignature);
  } catch {
    return false;
  }
}

function verifyHybridSignature(publicIdentity, message, envelope) {
  try {
    const normalized = normalizePublicIdentity(publicIdentity);
    exactFields(envelope, [
      'schema', 'version', 'policy', 'signerFingerprint', 'messageSha3_512',
      'ed25519Signature', 'mlDsa65Signature',
    ], 'hybrid signature');
    if (envelope.schema !== SIGNATURE_SCHEMA || envelope.version !== 1 || envelope.policy !== HYBRID_POLICY) {
      return false;
    }
    if (canonicalHex(envelope.signerFingerprint, 32, 'signer fingerprint') !== normalized.fingerprint
      || canonicalHex(envelope.messageSha3_512, 64, 'message digest') !== messageDigest(message)) {
      return false;
    }
    const data = signingMessage(message);
    const edSignature = canonicalBase64(envelope.ed25519Signature, 'Ed25519 signature', 128);
    const mlSignature = canonicalBase64(envelope.mlDsa65Signature, 'ML-DSA-65 signature', 8192);
    return verify(null, data, normalized.keys.ed25519, edSignature)
      && verify(null, data, normalized.keys.mlDsa, mlSignature);
  } catch {
    return false;
  }
}

function sealHeader(recipientFingerprint, contextSha3_256) {
  return Object.freeze({
    schema: SEALED_SCHEMA,
    version: 1,
    kem: 'ml-kem-768',
    kdf: 'hkdf-sha3-256',
    cipher: 'aes-256-gcm',
    recipientFingerprint,
    contextSha3_256,
  });
}

function sealingContext(value) {
  if (value == null) return Buffer.alloc(0);
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) return boundedBytes(value, 'seal context', 4096);
  if (typeof value === 'string') return boundedBytes(Buffer.from(value, 'utf8'), 'seal context', 4096);
  return boundedBytes(canonicalBytes(value), 'seal context', 4096);
}

function deriveSealingKey(sharedKey, kemCiphertext, header, context) {
  const salt = digest('sha3-256', DOMAIN_SEAL, kemCiphertext);
  const info = Buffer.concat([canonicalBytes(header), context]);
  return Buffer.from(hkdfSync('sha3-256', sharedKey, salt, info, 32));
}

function sealForHybridRecipient(publicIdentity, plaintext, options = {}) {
  const normalized = normalizePublicIdentity(publicIdentity);
  const data = boundedBytes(plaintext, 'sealed plaintext', MAX_SEALED_BYTES);
  const context = sealingContext(options.context);
  const contextHash = digest('sha3-256', DOMAIN_SEAL, context).toString('hex');
  const header = sealHeader(normalized.fingerprint, contextHash);
  let sharedKey;
  let encryptionKey;
  try {
    const exchange = encapsulate(normalized.keys.mlKem);
    sharedKey = Buffer.from(exchange.sharedKey);
    const kemCiphertext = Buffer.from(exchange.ciphertext);
    encryptionKey = deriveSealingKey(sharedKey, kemCiphertext, header, context);
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', encryptionKey, iv, { authTagLength: 16 });
    cipher.setAAD(canonicalBytes(header));
    const ciphertext = Buffer.concat([cipher.update(data), cipher.final()]);
    const envelope = Object.freeze({
      ...header,
      kemCiphertext: kemCiphertext.toString('base64'),
      iv: iv.toString('base64'),
      ciphertext: ciphertext.toString('base64'),
      authenticationTag: cipher.getAuthTag().toString('base64'),
    });
    return envelope;
  } catch (cause) {
    if (cause instanceof HybridCryptoError) throw cause;
    throw new HybridCryptoError('SEAL_FAILED', 'ML-KEM hybrid sealing failed', { cause: cause.message });
  } finally {
    sharedKey?.fill(0);
    encryptionKey?.fill(0);
  }
}

function openHybridSealed(privateKemKey, publicIdentity, envelope, options = {}) {
  const normalized = normalizePublicIdentity(publicIdentity);
  exactFields(envelope, [
    'schema', 'version', 'kem', 'kdf', 'cipher', 'recipientFingerprint', 'contextSha3_256',
    'kemCiphertext', 'iv', 'ciphertext', 'authenticationTag',
  ], 'sealed envelope');
  if (envelope.schema !== SEALED_SCHEMA || envelope.version !== 1 || envelope.kem !== 'ml-kem-768'
    || envelope.kdf !== 'hkdf-sha3-256' || envelope.cipher !== 'aes-256-gcm') {
    throw new HybridCryptoError('UNSUPPORTED_SEAL', 'sealed envelope profile is unsupported');
  }
  if (canonicalHex(envelope.recipientFingerprint, 32, 'recipient fingerprint') !== normalized.fingerprint) {
    throw new HybridCryptoError('WRONG_RECIPIENT', 'sealed envelope belongs to another hybrid identity');
  }
  const context = sealingContext(options.context);
  const expectedContext = digest('sha3-256', DOMAIN_SEAL, context).toString('hex');
  if (canonicalHex(envelope.contextSha3_256, 32, 'context digest') !== expectedContext) {
    throw new HybridCryptoError('CONTEXT_MISMATCH', 'sealed envelope context is invalid');
  }
  const privateKey = privateObject(privateKemKey, 'ml-kem-768', 'ML-KEM-768');
  const derivedPublic = publicDer(privateKey);
  if (!timingSafeEqual(derivedPublic, publicDer(normalized.keys.mlKem))) {
    throw new HybridCryptoError('KEY_MISMATCH', 'ML-KEM private key does not match recipient identity');
  }
  const kemCiphertext = canonicalBase64(envelope.kemCiphertext, 'KEM ciphertext', MAX_SEALED_BYTES);
  const iv = canonicalBase64(envelope.iv, 'seal IV', 32);
  const ciphertext = canonicalBase64(envelope.ciphertext, 'sealed ciphertext', MAX_SEALED_BYTES + 16);
  const tag = canonicalBase64(envelope.authenticationTag, 'authentication tag', 32);
  if (iv.length !== 12 || tag.length !== 16) throw new HybridCryptoError('INVALID_SEAL', 'invalid AES-GCM IV or tag');
  const header = sealHeader(normalized.fingerprint, expectedContext);
  let sharedKey;
  let encryptionKey;
  try {
    sharedKey = Buffer.from(decapsulate(privateKey, kemCiphertext));
    encryptionKey = deriveSealingKey(sharedKey, kemCiphertext, header, context);
    const decipher = createDecipheriv('aes-256-gcm', encryptionKey, iv, { authTagLength: 16 });
    decipher.setAAD(canonicalBytes(header));
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch (cause) {
    throw new HybridCryptoError('OPEN_FAILED', 'sealed payload authentication failed', { cause: cause.message });
  } finally {
    sharedKey?.fill(0);
    encryptionKey?.fill(0);
  }
}

class HybridIdentity {
  #ed25519PrivateKey;

  #mlDsa65PrivateKey;

  #mlKem768PrivateKey;

  #publicIdentity;

  constructor({ ed25519PrivateKey, mlDsa65PrivateKey, mlKem768PrivateKey }) {
    this.#ed25519PrivateKey = privateObject(ed25519PrivateKey, 'ed25519', 'Ed25519');
    this.#mlDsa65PrivateKey = privateObject(mlDsa65PrivateKey, 'ml-dsa-65', 'ML-DSA-65');
    this.#mlKem768PrivateKey = privateObject(mlKem768PrivateKey, 'ml-kem-768', 'ML-KEM-768');
    const statement = identityStatement({
      ed25519PublicKeyDer: publicDer(this.#ed25519PrivateKey).toString('base64'),
      mlDsa65PublicKeyDer: publicDer(this.#mlDsa65PrivateKey).toString('base64'),
      mlKem768PublicKeyDer: publicDer(this.#mlKem768PrivateKey).toString('base64'),
    });
    this.#publicIdentity = Object.freeze({ ...statement, fingerprint: identityFingerprint(statement) });
  }

  static generate() {
    const ed25519 = generateKeyPairSync('ed25519');
    const mlDsa65 = generateKeyPairSync('ml-dsa-65');
    const mlKem768 = generateKeyPairSync('ml-kem-768');
    return new HybridIdentity({
      ed25519PrivateKey: ed25519.privateKey,
      mlDsa65PrivateKey: mlDsa65.privateKey,
      mlKem768PrivateKey: mlKem768.privateKey,
    });
  }

  publicIdentity() { return this.#publicIdentity; }

  sign(message) {
    const data = signingMessage(message);
    return Object.freeze({
      schema: SIGNATURE_SCHEMA,
      version: 1,
      policy: HYBRID_POLICY,
      signerFingerprint: this.#publicIdentity.fingerprint,
      messageSha3_512: createHash('sha3-512').update(data).digest('hex'),
      ed25519Signature: sign(null, data, this.#ed25519PrivateKey).toString('base64'),
      mlDsa65Signature: sign(null, data, this.#mlDsa65PrivateKey).toString('base64'),
    });
  }

  verify(message, envelope) {
    return verifyHybridSignature(this.#publicIdentity, message, envelope);
  }

  signBound(message) {
    const data = boundSigningMessage(this.#publicIdentity.fingerprint, message);
    return Object.freeze({
      schema: BOUND_SIGNATURE_SCHEMA,
      version: 2,
      policy: HYBRID_BOUND_POLICY,
      signerFingerprint: this.#publicIdentity.fingerprint,
      messageSha3_512: createHash('sha3-512').update(data).digest('hex'),
      ed25519Signature: sign(null, data, this.#ed25519PrivateKey).toString('base64'),
      mlDsa65Signature: sign(null, data, this.#mlDsa65PrivateKey).toString('base64'),
    });
  }

  verifyBound(message, envelope) {
    return verifyHybridBoundSignature(this.#publicIdentity, message, envelope);
  }

  seal(plaintext, options = {}) {
    return sealForHybridRecipient(this.#publicIdentity, plaintext, options);
  }

  open(envelope, options = {}) {
    return openHybridSealed(this.#mlKem768PrivateKey, this.#publicIdentity, envelope, options);
  }
}

function nativeHybridSelfTest() {
  const identity = HybridIdentity.generate();
  const message = Buffer.from('VLOCK7SIN/HYBRID-SELF-TEST/v1', 'ascii');
  const signature = identity.sign(message);
  const sealed = identity.seal(message, { context: 'self-test' });
  const opened = identity.open(sealed, { context: 'self-test' });
  const data = signingMessage(message);
  const keys = normalizePublicIdentity(identity.publicIdentity()).keys;
  const ed25519Valid = verify(null, data, keys.ed25519, Buffer.from(signature.ed25519Signature, 'base64'));
  const mlDsa65Valid = verify(null, data, keys.mlDsa, Buffer.from(signature.mlDsa65Signature, 'base64'));
  return Object.freeze({
    policy: HYBRID_POLICY,
    ed25519: ed25519Valid,
    mlDsa65: mlDsa65Valid,
    hybridSignature: identity.verify(message, signature),
    mlKem768: opened.equals(message),
    tamperRejected: !identity.verify(Buffer.from('tampered'), signature),
    implementation: 'node-native-openssl-provider',
  });
}

module.exports = Object.freeze({
  HYBRID_POLICY,
  HYBRID_BOUND_POLICY,
  IDENTITY_SCHEMA,
  SIGNATURE_SCHEMA,
  BOUND_SIGNATURE_SCHEMA,
  SEALED_SCHEMA,
  HybridCryptoError,
  HybridIdentity,
  normalizePublicIdentity,
  verifyHybridSignature,
  verifyHybridBoundSignature,
  sealForHybridRecipient,
  openHybridSealed,
  nativeHybridSelfTest,
});
