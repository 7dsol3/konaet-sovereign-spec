'use strict';

const { createHash, sign: edSign, verify: edVerify } = require('node:crypto');
const { canonicalBytes, compareUtf8 } = require('./causalGraph');
const { encodeRecord, decodeRecord } = require('./persistence');
const { publicKeyObject, privateKeyObject } = require('./quorum');

const MESSAGE_TYPES = Object.freeze([
  'HELLO',
  'PRINCIPLE',
  'ACT',
  'ROOT',
  'GET_STATE',
  'STATE_CHUNK',
  'FAULT',
]);
const MESSAGE_TYPE_SET = new Set(MESSAGE_TYPES);
const ENVELOPE_MAGIC = 'VLOCK7SIN_NET';
const ENVELOPE_VERSION = 1;
const DOMAIN_PAYLOAD = Buffer.from('VLOCK7SIN/NET-PAYLOAD/v1\0', 'ascii');
const DOMAIN_ENVELOPE = Buffer.from('VLOCK7SIN/NET-ENVELOPE/v1\0', 'ascii');
const DOMAIN_ENVELOPE_ID = Buffer.from('VLOCK7SIN/NET-ENVELOPE-ID/v1\0', 'ascii');
const U64_MAX = 0xffffffffffffffffn;

class NetworkProtocolError extends Error {
  constructor(code, message, details = undefined) {
    super(message);
    this.name = 'NetworkProtocolError';
    this.code = code;
    if (details !== undefined) this.details = details;
  }
}

function safeIdentifier(value, label, max = 128) {
  const text = String(value ?? '').normalize('NFC');
  const hasControl = [...text].some((character) => {
    const codePoint = character.codePointAt(0);
    return codePoint <= 0x1f || codePoint === 0x7f;
  });
  if (!text || Buffer.byteLength(text, 'utf8') > max || hasControl) {
    throw new NetworkProtocolError('INVALID_IDENTIFIER', `${label} must be 1..${max} UTF-8 bytes without controls`);
  }
  return text;
}

function nonceString(value) {
  let nonce;
  try { nonce = BigInt(value); } catch {
    throw new NetworkProtocolError('INVALID_NONCE', 'envelope nonce must be an unsigned integer');
  }
  if (nonce < 0n || nonce > U64_MAX) throw new NetworkProtocolError('INVALID_NONCE', 'envelope nonce must fit u64');
  return nonce.toString(10);
}

function timestampNumber(value) {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new NetworkProtocolError('INVALID_TIMESTAMP', 'envelope timestampMs must be a non-negative safe integer');
  }
  return value;
}

function messageType(value) {
  const type = String(value ?? '').toUpperCase();
  if (!MESSAGE_TYPE_SET.has(type)) throw new NetworkProtocolError('UNKNOWN_MESSAGE_TYPE', `unsupported message type: ${type}`);
  return type;
}

function hashPayload(payload) {
  return createHash('sha3-256').update(DOMAIN_PAYLOAD).update(payload).digest('hex');
}

function signedBody(envelope) {
  return Object.freeze({
    magic: envelope.magic,
    envelopeVersion: envelope.envelopeVersion,
    networkId: envelope.networkId,
    protocolVersion: envelope.protocolVersion,
    type: envelope.type,
    senderId: envelope.senderId,
    nonce: envelope.nonce,
    timestampMs: envelope.timestampMs,
    payloadEncoding: envelope.payloadEncoding,
    payloadSize: envelope.payloadSize,
    payloadHash: envelope.payloadHash,
    payload: envelope.payload,
  });
}

function signingBytes(envelope) {
  return Buffer.concat([DOMAIN_ENVELOPE, canonicalBytes(signedBody(envelope))]);
}

function createEnvelope(options) {
  if (!options || typeof options !== 'object') throw new NetworkProtocolError('INVALID_ENVELOPE', 'envelope options are required');
  const payloadIsBytes = Buffer.isBuffer(options.payload) || options.payload instanceof Uint8Array;
  const payload = payloadIsBytes ? Buffer.from(options.payload) : encodeRecord(options.payload);
  const maxPayloadBytes = options.maxPayloadBytes ?? 8 * 1024 * 1024;
  if (!Number.isSafeInteger(maxPayloadBytes) || maxPayloadBytes < 1 || maxPayloadBytes > 0xffffffff || payload.length > maxPayloadBytes) {
    throw new NetworkProtocolError('PAYLOAD_TOO_LARGE', `payload exceeds ${maxPayloadBytes} bytes`);
  }
  const envelope = {
    magic: ENVELOPE_MAGIC,
    envelopeVersion: ENVELOPE_VERSION,
    networkId: safeIdentifier(options.networkId, 'networkId'),
    protocolVersion: safeIdentifier(options.protocolVersion ?? '1', 'protocolVersion', 32),
    type: messageType(options.type),
    senderId: safeIdentifier(options.senderId, 'senderId'),
    nonce: nonceString(options.nonce),
    timestampMs: timestampNumber(options.timestampMs ?? Date.now()),
    payloadEncoding: payloadIsBytes ? 'BINARY' : 'V7_RECORD',
    payloadSize: payload.length,
    payloadHash: hashPayload(payload),
    payload,
  };
  const privateKey = privateKeyObject(options.privateKey);
  if (privateKey.asymmetricKeyType !== 'ed25519') throw new NetworkProtocolError('WRONG_KEY_TYPE', 'network envelopes require Ed25519');
  envelope.signature = edSign(null, signingBytes(envelope), privateKey).toString('hex');
  envelope.id = createHash('sha3-256').update(DOMAIN_ENVELOPE_ID).update(canonicalBytes(envelope)).digest('hex');
  return Object.freeze(envelope);
}

function encodeEnvelope(envelope, options = {}) {
  const bytes = encodeRecord(envelope);
  const maxEnvelopeBytes = options.maxEnvelopeBytes ?? 12 * 1024 * 1024;
  if (!Number.isSafeInteger(maxEnvelopeBytes) || maxEnvelopeBytes < 1 || maxEnvelopeBytes > 0xffffffff || bytes.length > maxEnvelopeBytes) {
    throw new NetworkProtocolError('ENVELOPE_TOO_LARGE', `encoded envelope exceeds ${maxEnvelopeBytes} bytes`);
  }
  return bytes;
}

function decodeEnvelope(bytes, options = {}) {
  const maxEnvelopeBytes = options.maxEnvelopeBytes ?? 12 * 1024 * 1024;
  if (!Number.isSafeInteger(maxEnvelopeBytes) || maxEnvelopeBytes < 1 || maxEnvelopeBytes > 0xffffffff) {
    throw new NetworkProtocolError('INVALID_LIMIT', 'maxEnvelopeBytes is invalid');
  }
  const input = Buffer.from(bytes);
  if (input.length > maxEnvelopeBytes) throw new NetworkProtocolError('ENVELOPE_TOO_LARGE', `encoded envelope exceeds ${maxEnvelopeBytes} bytes`);
  let envelope;
  try { envelope = decodeRecord(input); } catch (error) {
    throw new NetworkProtocolError('MALFORMED_ENVELOPE', 'cannot decode network envelope', { cause: error.message });
  }
  return envelope;
}

function normalizeTrustedKeys(input) {
  const map = new Map();
  if (input == null) return map;
  const entries = input instanceof Map ? [...input] : Array.isArray(input)
    ? input.map((item) => [item.id, item.publicKey])
    : Object.entries(input);
  for (const [rawId, key] of entries) {
    const id = safeIdentifier(rawId, 'trusted sender id');
    if (map.has(id)) throw new NetworkProtocolError('DUPLICATE_TRUST_ENTRY', `duplicate trusted sender ${id}`);
    const object = publicKeyObject(key);
    if (object.asymmetricKeyType !== 'ed25519') throw new NetworkProtocolError('WRONG_KEY_TYPE', `trusted key for ${id} is not Ed25519`);
    map.set(id, object);
  }
  return map;
}

class NonceReplayWindow {
  #windowSize;

  #scopes;

  #persist;

  constructor(options = {}) {
    this.#windowSize = options.windowSize ?? 128;
    if (!Number.isSafeInteger(this.#windowSize) || this.#windowSize < 1 || this.#windowSize > 65536) {
      throw new NetworkProtocolError('INVALID_REPLAY_WINDOW', 'replay window must be 1..65536');
    }
    this.#scopes = new Map();
    this.#persist = typeof options.persist === 'function' ? options.persist : null;
    if (options.state) this.importState(options.state);
  }

  get windowSize() { return this.#windowSize; }

  _scope(networkId, protocolVersion, senderId) {
    return `${safeIdentifier(networkId, 'networkId')}\u0000${safeIdentifier(protocolVersion, 'protocolVersion', 32)}\u0000${safeIdentifier(senderId, 'senderId')}`;
  }

  _nextState(current, nonce) {
    if (!current) return { highest: nonce, seen: new Set([nonce.toString(10)]) };
    const lowest = current.highest - BigInt(this.#windowSize) + 1n;
    if (nonce < lowest) throw new NetworkProtocolError('STALE_NONCE', 'nonce is older than the accepted replay window');
    const key = nonce.toString(10);
    if (current.seen.has(key)) throw new NetworkProtocolError('REPLAY_DETECTED', 'nonce was already accepted');
    const highest = nonce > current.highest ? nonce : current.highest;
    const newLowest = highest - BigInt(this.#windowSize) + 1n;
    const seen = new Set([...current.seen].filter((item) => BigInt(item) >= newLowest));
    seen.add(key);
    return { highest, seen };
  }

  check({ networkId, protocolVersion, senderId, nonce }) {
    const scope = this._scope(networkId, protocolVersion, senderId);
    const value = BigInt(nonceString(nonce));
    this._nextState(this.#scopes.get(scope), value);
    return true;
  }

  accept({ networkId, protocolVersion, senderId, nonce }) {
    const scope = this._scope(networkId, protocolVersion, senderId);
    const value = BigInt(nonceString(nonce));
    const next = this._nextState(this.#scopes.get(scope), value);
    const persisted = Object.freeze({ highest: next.highest.toString(10), seen: Object.freeze([...next.seen].sort((a, b) => (BigInt(a) < BigInt(b) ? -1 : 1))) });
    if (this.#persist) this.#persist(scope, persisted);
    this.#scopes.set(scope, next);
    return true;
  }

  exportState() {
    const output = Object.create(null);
    for (const [scope, state] of [...this.#scopes].sort(([a], [b]) => compareUtf8(a, b))) {
      output[scope] = {
        highest: state.highest.toString(10),
        seen: [...state.seen].sort((a, b) => (BigInt(a) < BigInt(b) ? -1 : 1)),
      };
    }
    return output;
  }

  importState(input) {
    if (!input || typeof input !== 'object') throw new NetworkProtocolError('INVALID_REPLAY_STATE', 'replay state must be an object');
    const rebuilt = new Map();
    for (const [scope, value] of Object.entries(input)) {
      if (!value || !Array.isArray(value.seen)) throw new NetworkProtocolError('INVALID_REPLAY_STATE', `invalid replay state for ${scope}`);
      const highest = BigInt(nonceString(value.highest));
      const seen = new Set(value.seen.map(nonceString));
      if (seen.size !== value.seen.length || !seen.has(highest.toString(10)) || seen.size > this.#windowSize) {
        throw new NetworkProtocolError('INVALID_REPLAY_STATE', `inconsistent replay window for ${scope}`);
      }
      const lowest = highest - BigInt(this.#windowSize) + 1n;
      if ([...seen].some((item) => BigInt(item) < lowest || BigInt(item) > highest)) {
        throw new NetworkProtocolError('INVALID_REPLAY_STATE', `nonce outside replay window for ${scope}`);
      }
      rebuilt.set(scope, { highest, seen });
    }
    this.#scopes = rebuilt;
  }
}

class NonceCounter {
  #current;

  #persist;

  constructor(initial = -1n, persist = undefined) {
    this.#current = BigInt(initial);
    if (this.#current < -1n || this.#current >= U64_MAX) throw new NetworkProtocolError('INVALID_NONCE', 'initial counter is outside supported range');
    this.#persist = typeof persist === 'function' ? persist : null;
  }
  get current() { return this.#current; }
  next() {
    const value = this.#current + 1n;
    if (value > U64_MAX) throw new NetworkProtocolError('NONCE_EXHAUSTED', 'u64 network nonce exhausted');
    if (this.#persist) this.#persist(value.toString(10));
    this.#current = value;
    return value;
  }
}

class EnvelopeVerifier {
  #networkId;

  #protocolVersions;

  #trustedKeys;

  #keyResolver;

  #replay;

  #maxPayloadBytes;

  #maxEnvelopeBytes;

  #maxPastMs;

  #maxFutureMs;

  constructor(options = {}) {
    this.#networkId = safeIdentifier(options.networkId, 'networkId');
    this.#protocolVersions = new Set((options.protocolVersions ?? [options.protocolVersion ?? '1']).map((item) => safeIdentifier(item, 'protocolVersion', 32)));
    if (this.#protocolVersions.size < 1 || this.#protocolVersions.size > 16) {
      throw new NetworkProtocolError('INVALID_VERSION_POLICY', '1..16 accepted protocol versions are required');
    }
    this.#trustedKeys = normalizeTrustedKeys(options.trustedKeys);
    this.#keyResolver = typeof options.keyResolver === 'function' ? options.keyResolver : null;
    this.#replay = options.replay ?? new NonceReplayWindow();
    this.#maxPayloadBytes = options.maxPayloadBytes ?? 8 * 1024 * 1024;
    this.#maxEnvelopeBytes = options.maxEnvelopeBytes ?? 12 * 1024 * 1024;
    this.#maxPastMs = options.maxPastMs ?? 5 * 60 * 1000;
    this.#maxFutureMs = options.maxFutureMs ?? 30 * 1000;
    for (const [label, value, minimum, maximum] of [
      ['maxPayloadBytes', this.#maxPayloadBytes, 1, 0xffffffff],
      ['maxEnvelopeBytes', this.#maxEnvelopeBytes, 1, 0xffffffff],
      ['maxPastMs', this.#maxPastMs, 0, 7 * 24 * 60 * 60 * 1000],
      ['maxFutureMs', this.#maxFutureMs, 0, 7 * 24 * 60 * 60 * 1000],
    ]) {
      if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
        throw new NetworkProtocolError('INVALID_LIMIT', `${label} must be an integer in ${minimum}..${maximum}`);
      }
    }
    if (this.#maxEnvelopeBytes <= this.#maxPayloadBytes) {
      throw new NetworkProtocolError('INVALID_LIMIT', 'maxEnvelopeBytes must exceed maxPayloadBytes for framing/signature overhead');
    }
    if (!this.#replay || typeof this.#replay.check !== 'function' || typeof this.#replay.accept !== 'function') {
      throw new NetworkProtocolError('INVALID_REPLAY_GUARD', 'replay guard must expose check() and accept()');
    }
  }

  _key(senderId) {
    let key = this.#trustedKeys.get(senderId);
    if (!key && this.#keyResolver) key = this.#keyResolver(senderId);
    if (!key) throw new NetworkProtocolError('UNTRUSTED_SENDER', `no trusted key for sender ${senderId}`);
    const object = publicKeyObject(key);
    if (object.asymmetricKeyType !== 'ed25519') throw new NetworkProtocolError('WRONG_KEY_TYPE', 'sender key is not Ed25519');
    return object;
  }

  verify(input, options = {}) {
    let encoded;
    try {
      encoded = Buffer.isBuffer(input) || input instanceof Uint8Array
        ? Buffer.from(input)
        : encodeEnvelope(input, { maxEnvelopeBytes: this.#maxEnvelopeBytes });
    } catch (error) {
      if (error instanceof NetworkProtocolError) throw error;
      throw new NetworkProtocolError('MALFORMED_ENVELOPE', 'envelope cannot be snapshotted canonically', { cause: error.message });
    }
    if (encoded.length > this.#maxEnvelopeBytes) throw new NetworkProtocolError('ENVELOPE_TOO_LARGE', 'envelope exceeds configured maximum');
    const envelope = decodeEnvelope(encoded, { maxEnvelopeBytes: this.#maxEnvelopeBytes });
    if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope)) throw new NetworkProtocolError('MALFORMED_ENVELOPE', 'envelope must be an object');
    const exactFields = ['envelopeVersion', 'id', 'magic', 'networkId', 'nonce', 'payload', 'payloadEncoding', 'payloadHash', 'payloadSize', 'protocolVersion', 'senderId', 'signature', 'timestampMs', 'type'];
    const actualFields = Object.keys(envelope).sort(compareUtf8);
    if (actualFields.length !== exactFields.length || actualFields.some((field, index) => field !== exactFields[index])) {
      throw new NetworkProtocolError('MALFORMED_ENVELOPE', 'envelope has missing or unsigned extra fields');
    }
    if (envelope.magic !== ENVELOPE_MAGIC || envelope.envelopeVersion !== ENVELOPE_VERSION) throw new NetworkProtocolError('UNSUPPORTED_ENVELOPE', 'unsupported envelope format');
    if (safeIdentifier(envelope.networkId, 'networkId') !== this.#networkId) throw new NetworkProtocolError('WRONG_NETWORK', 'envelope belongs to another network');
    const version = safeIdentifier(envelope.protocolVersion, 'protocolVersion', 32);
    if (!this.#protocolVersions.has(version)) throw new NetworkProtocolError('UNSUPPORTED_VERSION', `protocol version ${version} is not accepted`);
    const type = messageType(envelope.type);
    const senderId = safeIdentifier(envelope.senderId, 'senderId');
    const nonce = nonceString(envelope.nonce);
    const timestampMs = timestampNumber(envelope.timestampMs);
    const now = timestampNumber(options.now ?? Date.now());
    if (timestampMs < now - this.#maxPastMs) throw new NetworkProtocolError('STALE_TIMESTAMP', 'envelope timestamp is too old');
    if (timestampMs > now + this.#maxFutureMs) throw new NetworkProtocolError('FUTURE_TIMESTAMP', 'envelope timestamp is too far in the future');
    if (!Buffer.isBuffer(envelope.payload)) throw new NetworkProtocolError('MALFORMED_PAYLOAD', 'envelope payload must decode as bytes');
    if (!Number.isSafeInteger(envelope.payloadSize) || envelope.payloadSize !== envelope.payload.length) throw new NetworkProtocolError('SIZE_MISMATCH', 'declared payload size is invalid');
    if (envelope.payload.length > this.#maxPayloadBytes) throw new NetworkProtocolError('PAYLOAD_TOO_LARGE', 'payload exceeds configured maximum');
    if (envelope.payloadEncoding !== 'BINARY' && envelope.payloadEncoding !== 'V7_RECORD') throw new NetworkProtocolError('UNKNOWN_PAYLOAD_ENCODING', 'unsupported payload encoding');
    if (envelope.payloadHash !== hashPayload(envelope.payload)) throw new NetworkProtocolError('PAYLOAD_HASH_MISMATCH', 'payload SHA3 does not match');
    if (!/^[0-9a-f]{128}$/.test(String(envelope.signature))) throw new NetworkProtocolError('INVALID_SIGNATURE', 'Ed25519 signature must be 64 bytes');
    if (!edVerify(null, signingBytes(envelope), this._key(senderId), Buffer.from(envelope.signature, 'hex'))) {
      throw new NetworkProtocolError('INVALID_SIGNATURE', 'network envelope signature is invalid');
    }
    const unsigned = { ...envelope };
    delete unsigned.id;
    const expectedId = createHash('sha3-256').update(DOMAIN_ENVELOPE_ID).update(canonicalBytes(unsigned)).digest('hex');
    if (envelope.id !== expectedId) throw new NetworkProtocolError('ENVELOPE_ID_MISMATCH', 'envelope id is invalid');
    if (envelope.payloadEncoding === 'V7_RECORD') {
      try { decodeRecord(envelope.payload); } catch (error) {
        throw new NetworkProtocolError('MALFORMED_PAYLOAD', 'record payload cannot be decoded', { cause: error.message });
      }
    }
    // Replay state is consumed only after every structural, cryptographic and
    // semantic payload check succeeds.
    const replayInput = { networkId: this.#networkId, protocolVersion: version, senderId, nonce };
    if (options.consumeReplay === false) this.#replay.check(replayInput);
    else this.#replay.accept(replayInput);
    const rawPayload = Buffer.from(envelope.payload);
    const safeEnvelope = { ...envelope };
    delete safeEnvelope.payload;
    Object.defineProperty(safeEnvelope, 'payload', {
      enumerable: true,
      get: () => Buffer.from(rawPayload),
    });
    Object.freeze(safeEnvelope);
    const result = { envelope: safeEnvelope, type, senderId, nonce };
    Object.defineProperty(result, 'payload', {
      enumerable: true,
      get: envelope.payloadEncoding === 'V7_RECORD'
        ? () => decodeRecord(rawPayload)
        : () => Buffer.from(rawPayload),
    });
    return Object.freeze(result);
  }
}

module.exports = {
  MESSAGE_TYPES,
  ENVELOPE_MAGIC,
  ENVELOPE_VERSION,
  NetworkProtocolError,
  NonceReplayWindow,
  NonceCounter,
  EnvelopeVerifier,
  createEnvelope,
  encodeEnvelope,
  decodeEnvelope,
  signingBytes,
};
