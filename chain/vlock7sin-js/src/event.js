'use strict';

const {
  DOMAINS,
  MAGIC,
  NETWORK_ID,
  PROTOCOL_VERSION,
  FORMAT_VERSION,
  RECORD_KIND,
  CRYPTO_SUITE,
  STATE_SUITE,
  EVENT_FLAGS_MASK,
  LENGTHS,
  LIMITS,
  MAX_U16,
  MAX_U32,
  MAX_U64,
  MAX_U128,
} = require('./constants');
const {
  asBigInt,
  asBuffer,
  asNumber,
  BinaryReader,
  BinaryWriter,
} = require('./codec');
const {
  encodeAddress,
  validateAddress,
  addressMatchesPublicKey,
  rawPublicKey,
  sign,
  verify,
  traceIrreversible,
} = require('./crypto');
const { CodecError, ValidationError } = require('./errors');

const EVENT_FORMAT = 'vlock7sin-event-js-v1';

function checkedHash(value, label) {
  return asBuffer(value, label, { exactLength: LENGTHS.HASH });
}

function validateFlags(value) {
  const flags = asNumber(value, 'event flags', Number(MAX_U16));
  if ((flags & ~EVENT_FLAGS_MASK) !== 0) {
    throw new ValidationError(`unknown event flag bits 0x${(flags & ~EVENT_FLAGS_MASK).toString(16)}`);
  }
  return flags;
}

function normalizeNexuses(values = [], { requireSorted = false } = {}) {
  if (!Array.isArray(values) || values.length > LIMITS.NEXUS_COUNT) {
    throw new ValidationError(`nexuses must be an array with at most ${LIMITS.NEXUS_COUNT} items`);
  }
  const normalized = values.map((value, index) => checkedHash(value, `nexus ${index}`));
  const sorted = [...normalized].sort(Buffer.compare);
  for (let index = 1; index < sorted.length; index += 1) {
    if (sorted[index - 1].equals(sorted[index])) throw new ValidationError('duplicate nexus hash');
  }
  if (requireSorted && normalized.some((value, index) => !value.equals(sorted[index]))) {
    throw new CodecError('nexus hashes are not in canonical byte order');
  }
  return sorted;
}

function readVersion(reader, expected, label) {
  const actual = {
    major: reader.u8(`${label} major`),
    minor: reader.u8(`${label} minor`),
    patch: reader.u8(`${label} patch`),
  };
  if (actual.major !== expected.major || actual.minor !== expected.minor || actual.patch !== expected.patch) {
    throw new CodecError(`unsupported ${label} ${actual.major}.${actual.minor}.${actual.patch}`);
  }
}

class TransferEvent {
  #flags;

  #networkId;

  #cryptoSuite;

  #stateSuite;

  #sequence;

  #nonce;

  #timestampMs;

  #amountAtomic;

  #previousRoot;

  #senderPublicKey;

  #senderAddress;

  #receiverAddress;

  #nexuses;

  #memo;

  #signature;

  constructor({
    flags = 0,
    networkId = NETWORK_ID,
    cryptoSuite = CRYPTO_SUITE.SHA3_256_ED25519,
    stateSuite = STATE_SUITE.SORTED_MERKLE_V1,
    sequence,
    nonce,
    timestampMs = 0n,
    amountAtomic,
    previousRoot,
    senderPublicKey,
    senderAddress,
    receiverAddress,
    nexuses = [],
    memo = '',
    signature,
  }) {
    this.#flags = validateFlags(flags);
    this.#networkId = asNumber(networkId, 'networkId', Number(MAX_U32));
    this.#cryptoSuite = asNumber(cryptoSuite, 'crypto suite', Number(MAX_U16));
    this.#stateSuite = asNumber(stateSuite, 'state suite', Number(MAX_U16));
    if (this.#cryptoSuite !== CRYPTO_SUITE.SHA3_256_ED25519) {
      throw new ValidationError(`unsupported crypto suite ${this.#cryptoSuite}`);
    }
    if (this.#stateSuite !== STATE_SUITE.SORTED_MERKLE_V1) {
      throw new ValidationError(`unsupported state suite ${this.#stateSuite}`);
    }
    this.#sequence = asBigInt(sequence, 'event sequence', MAX_U64);
    this.#nonce = asBigInt(nonce, 'sender nonce', MAX_U64);
    if (this.#sequence === 0n || this.#nonce === 0n) {
      throw new ValidationError('event sequence and nonce must be positive');
    }
    this.#timestampMs = asBigInt(timestampMs, 'timestampMs', MAX_U64);
    this.#amountAtomic = asBigInt(amountAtomic, 'amountAtomic', MAX_U128);
    if (this.#amountAtomic === 0n) throw new ValidationError('transfer amount must be positive');
    this.#previousRoot = checkedHash(previousRoot, 'previous root');
    this.#senderPublicKey = rawPublicKey(senderPublicKey);
    this.#senderAddress = validateAddress(senderAddress || encodeAddress(this.#senderPublicKey));
    this.#receiverAddress = validateAddress(receiverAddress);
    if (this.#senderAddress === this.#receiverAddress) {
      throw new ValidationError('sender and receiver addresses must differ');
    }
    this.#nexuses = normalizeNexuses(nexuses);
    if (typeof memo !== 'string') throw new ValidationError('memo must be a string');
    // BinaryWriter performs the full UTF-8/NUL/byte-limit check immediately.
    new BinaryWriter(LIMITS.MEMO_BYTES + 2).utf8(memo, {
      maxLength: LIMITS.MEMO_BYTES,
      label: 'memo',
    });
    this.#memo = memo;
    this.#signature = signature === undefined || signature === null
      ? Buffer.alloc(0)
      : asBuffer(signature, 'event signature', { exactLength: LENGTHS.SIGNATURE });
  }

  get format() { return EVENT_FORMAT; }

  get flags() { return this.#flags; }

  get networkId() { return this.#networkId; }

  get cryptoSuite() { return this.#cryptoSuite; }

  get stateSuite() { return this.#stateSuite; }

  get sequence() { return this.#sequence; }

  get nonce() { return this.#nonce; }

  get timestampMs() { return this.#timestampMs; }

  get amountAtomic() { return this.#amountAtomic; }

  get previousRoot() { return Buffer.from(this.#previousRoot); }

  get senderPublicKey() { return Buffer.from(this.#senderPublicKey); }

  get senderAddress() { return this.#senderAddress; }

  get receiverAddress() { return this.#receiverAddress; }

  get nexuses() { return this.#nexuses.map((item) => Buffer.from(item)); }

  get memo() { return this.#memo; }

  get signature() { return Buffer.from(this.#signature); }

  get signed() { return this.#signature.length === LENGTHS.SIGNATURE; }

  unsignedBytes() {
    const writer = new BinaryWriter(LIMITS.RECORD_BYTES);
    writer.write(Buffer.from(DOMAINS.EVENT, 'ascii'), 'event domain');
    writer.write(Buffer.from(MAGIC, 'ascii'), 'magic');
    writer.u8(RECORD_KIND.EVENT);
    writer.u8(FORMAT_VERSION.major).u8(FORMAT_VERSION.minor).u8(FORMAT_VERSION.patch);
    writer.u8(PROTOCOL_VERSION.major).u8(PROTOCOL_VERSION.minor).u8(PROTOCOL_VERSION.patch);
    writer.u16(this.#flags);
    writer.u32(this.#networkId);
    writer.u16(this.#cryptoSuite).u16(this.#stateSuite);
    writer.u64(this.#sequence).u64(this.#nonce).u64(this.#timestampMs);
    writer.u128(this.#amountAtomic);
    writer.write(this.#previousRoot, 'previous root');
    writer.write(this.#senderPublicKey, 'sender public key');
    writer.ascii(this.#senderAddress, {
      maxLength: LIMITS.ADDRESS_BYTES,
      label: 'sender address',
      allowEmpty: false,
    });
    writer.ascii(this.#receiverAddress, {
      maxLength: LIMITS.ADDRESS_BYTES,
      label: 'receiver address',
      allowEmpty: false,
    });
    writer.u16(this.#nexuses.length);
    for (const nexus of this.#nexuses) writer.write(nexus, 'nexus');
    writer.utf8(this.#memo, { maxLength: LIMITS.MEMO_BYTES, label: 'memo' });
    return writer.finish();
  }

  canonicalBytes() {
    if (!this.signed) throw new CodecError('event must have a 64-byte signature');
    const body = Buffer.concat([this.unsignedBytes(), this.#signature]);
    return Buffer.concat([
      body,
      traceIrreversible(body).subarray(0, LENGTHS.CHECKSUM),
    ]);
  }

  transitionTrace() { return traceIrreversible(this.unsignedBytes()); }

  id() { return traceIrreversible(this.canonicalBytes()); }

  sign(privateKey) {
    const signed = new TransferEvent({ ...this.toObject(), signature: sign(privateKey, this.unsignedBytes()) });
    if (!signed.verify({
      expectedNetworkId: signed.networkId,
      expectedCryptoSuite: signed.cryptoSuite,
      expectedStateSuite: signed.stateSuite,
    })) {
      throw new ValidationError('signing key does not match sender public key/address');
    }
    return signed;
  }

  assertValid({
    expectedNetworkId = NETWORK_ID,
    expectedCryptoSuite = CRYPTO_SUITE.SHA3_256_ED25519,
    expectedStateSuite = STATE_SUITE.SORTED_MERKLE_V1,
  } = {}) {
    validateFlags(this.#flags);
    if (this.#networkId !== expectedNetworkId) throw new ValidationError('event network mismatch');
    if (this.#cryptoSuite !== expectedCryptoSuite) throw new ValidationError('event crypto suite mismatch');
    if (this.#stateSuite !== expectedStateSuite) throw new ValidationError('event state suite mismatch');
    if (!addressMatchesPublicKey(this.#senderAddress, this.#senderPublicKey)) {
      throw new ValidationError('sender address does not match sender public key');
    }
    if (!this.signed || !verify(this.#senderPublicKey, this.unsignedBytes(), this.#signature)) {
      throw new ValidationError('invalid event signature');
    }
    return this;
  }

  verify(options) {
    try {
      this.assertValid(options);
      return true;
    } catch {
      return false;
    }
  }

  toObject() {
    return {
      flags: this.#flags,
      networkId: this.#networkId,
      cryptoSuite: this.#cryptoSuite,
      stateSuite: this.#stateSuite,
      sequence: this.#sequence,
      nonce: this.#nonce,
      timestampMs: this.#timestampMs,
      amountAtomic: this.#amountAtomic,
      previousRoot: Buffer.from(this.#previousRoot),
      senderPublicKey: Buffer.from(this.#senderPublicKey),
      senderAddress: this.#senderAddress,
      receiverAddress: this.#receiverAddress,
      nexuses: this.#nexuses.map((item) => Buffer.from(item)),
      memo: this.#memo,
      signature: this.#signature.length ? Buffer.from(this.#signature) : undefined,
    };
  }

  toJSON() {
    return Object.freeze({
      format: EVENT_FORMAT,
      flags: this.#flags,
      networkId: this.#networkId,
      cryptoSuite: this.#cryptoSuite,
      stateSuite: this.#stateSuite,
      sequence: this.#sequence.toString(),
      nonce: this.#nonce.toString(),
      timestampMs: this.#timestampMs.toString(),
      amountAtomic: this.#amountAtomic.toString(),
      previousRoot: this.#previousRoot.toString('hex'),
      senderPublicKey: this.#senderPublicKey.toString('hex'),
      senderAddress: this.#senderAddress,
      receiverAddress: this.#receiverAddress,
      nexuses: Object.freeze(this.#nexuses.map((item) => item.toString('hex'))),
      memo: this.#memo,
      signature: this.#signature.toString('hex'),
      transitionTrace: this.transitionTrace().toString('hex'),
      id: this.signed ? this.id().toString('hex') : null,
    });
  }

  static decode(value) {
    const data = asBuffer(value, 'event record', { maxLength: LIMITS.RECORD_BYTES });
    const reader = new BinaryReader(data);
    reader.expect(DOMAINS.EVENT, 'event domain');
    reader.expect(MAGIC, 'magic');
    if (reader.u8('record kind') !== RECORD_KIND.EVENT) throw new CodecError('invalid event record kind');
    readVersion(reader, FORMAT_VERSION, 'event format version');
    readVersion(reader, PROTOCOL_VERSION, 'protocol version');
    const flags = reader.u16('event flags');
    const networkId = reader.u32('networkId');
    const cryptoSuite = reader.u16('crypto suite');
    const stateSuite = reader.u16('state suite');
    const sequence = reader.u64('event sequence');
    const nonce = reader.u64('sender nonce');
    const timestampMs = reader.u64('timestampMs');
    const amountAtomic = reader.u128('amountAtomic');
    const previousRoot = reader.read(LENGTHS.HASH, 'previous root');
    const senderPublicKey = reader.read(LENGTHS.PUBLIC_KEY, 'sender public key');
    const senderAddress = reader.ascii({
      maxLength: LIMITS.ADDRESS_BYTES,
      label: 'sender address',
      allowEmpty: false,
    });
    const receiverAddress = reader.ascii({
      maxLength: LIMITS.ADDRESS_BYTES,
      label: 'receiver address',
      allowEmpty: false,
    });
    const nexusCount = reader.u16('nexus count');
    if (nexusCount > LIMITS.NEXUS_COUNT) throw new CodecError('nexus count exceeds limit');
    const nexusesInWireOrder = [];
    for (let index = 0; index < nexusCount; index += 1) {
      nexusesInWireOrder.push(reader.read(LENGTHS.HASH, `nexus ${index}`));
    }
    normalizeNexuses(nexusesInWireOrder, { requireSorted: true });
    const memo = reader.utf8({ maxLength: LIMITS.MEMO_BYTES, label: 'memo' });
    const signatureOffset = reader.offset;
    const signature = reader.read(LENGTHS.SIGNATURE, 'event signature');
    const checksum = reader.read(LENGTHS.CHECKSUM, 'event checksum');
    reader.eof();
    const expectedChecksum = traceIrreversible(data.subarray(0, signatureOffset + LENGTHS.SIGNATURE))
      .subarray(0, LENGTHS.CHECKSUM);
    if (!checksum.equals(expectedChecksum)) throw new CodecError('event checksum mismatch');
    const event = new TransferEvent({
      flags,
      networkId,
      cryptoSuite,
      stateSuite,
      sequence,
      nonce,
      timestampMs,
      amountAtomic,
      previousRoot,
      senderPublicKey,
      senderAddress,
      receiverAddress,
      nexuses: nexusesInWireOrder,
      memo,
      signature,
    });
    if (!event.canonicalBytes().equals(data)) throw new CodecError('non-canonical event encoding');
    return event;
  }
}

function createTransfer(fields, privateKey) {
  const event = new TransferEvent(fields);
  return privateKey === undefined ? event : event.sign(privateKey);
}

function decodeEvent(bytes) { return TransferEvent.decode(bytes); }

function normalizeAct(value) {
  if (value instanceof TransferEvent) return value;
  if (Buffer.isBuffer(value) || value instanceof Uint8Array || value instanceof ArrayBuffer) {
    return TransferEvent.decode(value);
  }
  if (value && typeof value === 'object') return new TransferEvent(value);
  throw new ValidationError('act must be a TransferEvent, encoded bytes, or event object');
}

function verifyAct(value, options) {
  try {
    return normalizeAct(value).verify(options);
  } catch {
    return false;
  }
}

const verifyEvent = verifyAct;
const createEvent = createTransfer;

module.exports = Object.freeze({
  EVENT_FORMAT,
  TransferEvent,
  createTransfer,
  createEvent,
  decodeEvent,
  normalizeAct,
  verifyAct,
  verifyEvent,
});
