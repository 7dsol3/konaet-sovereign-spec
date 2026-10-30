'use strict';

const {
  DOMAINS,
  LEGACY_DOMAINS,
  NETWORK_ID,
  PROTOCOL_VERSION,
  FORMAT_VERSION,
  CRYPTO_SUITE,
  STATE_SUITE,
  LENGTHS,
  MAX_U16,
  MAX_U32,
  MAX_U64,
} = require('./constants');
const {
  asBigInt,
  asBuffer,
  asNumber,
  BinaryReader,
  BinaryWriter,
} = require('./codec');
const { sha3 } = require('./crypto');
const { PccError } = require('./errors');

const PCC_FORMAT = 'vlock7sin-pcc-js-v1';

function checkedHash(value, label) {
  return asBuffer(value, label, { exactLength: LENGTHS.HASH });
}

function readExactVersion(reader, expected, label) {
  const actual = [reader.u8(), reader.u8(), reader.u8()];
  if (actual[0] !== expected.major || actual[1] !== expected.minor || actual[2] !== expected.patch) {
    throw new PccError(`unsupported ${label} ${actual.join('.')}`);
  }
}

class CoherenceWitness {
  #networkId;

  #protocolVersion;

  #cryptoSuite;

  #stateSuite;

  #sequence;

  #previousRoot;

  #nextRoot;

  #transitionTrace;

  constructor({
    networkId = NETWORK_ID,
    protocolVersion = PROTOCOL_VERSION,
    cryptoSuite = CRYPTO_SUITE.SHA3_256_ED25519,
    stateSuite = STATE_SUITE.SORTED_MERKLE_V1,
    sequence,
    previousRoot,
    nextRoot,
    transitionTrace,
  }) {
    this.#networkId = asNumber(networkId, 'PCC networkId', Number(MAX_U32));
    if (!protocolVersion || typeof protocolVersion !== 'object') {
      throw new PccError('PCC protocol version is required');
    }
    this.#protocolVersion = Object.freeze({
      major: asNumber(protocolVersion.major, 'protocol major', 255),
      minor: asNumber(protocolVersion.minor, 'protocol minor', 255),
      patch: asNumber(protocolVersion.patch, 'protocol patch', 255),
    });
    if (this.#protocolVersion.major !== PROTOCOL_VERSION.major
      || this.#protocolVersion.minor !== PROTOCOL_VERSION.minor
      || this.#protocolVersion.patch !== PROTOCOL_VERSION.patch) {
      throw new PccError('unsupported PCC protocol version');
    }
    this.#cryptoSuite = asNumber(cryptoSuite, 'PCC crypto suite', Number(MAX_U16));
    this.#stateSuite = asNumber(stateSuite, 'PCC state suite', Number(MAX_U16));
    if (this.#cryptoSuite !== CRYPTO_SUITE.SHA3_256_ED25519) {
      throw new PccError(`unsupported PCC crypto suite ${this.#cryptoSuite}`);
    }
    if (this.#stateSuite !== STATE_SUITE.SORTED_MERKLE_V1) {
      throw new PccError(`unsupported PCC state suite ${this.#stateSuite}`);
    }
    this.#sequence = asBigInt(sequence, 'PCC sequence', MAX_U64);
    this.#previousRoot = checkedHash(previousRoot, 'PCC previous root');
    this.#nextRoot = checkedHash(nextRoot, 'PCC next root');
    this.#transitionTrace = checkedHash(transitionTrace, 'PCC transition trace');
  }

  get format() { return PCC_FORMAT; }

  get networkId() { return this.#networkId; }

  get protocolVersion() { return this.#protocolVersion; }

  get cryptoSuite() { return this.#cryptoSuite; }

  get stateSuite() { return this.#stateSuite; }

  get sequence() { return this.#sequence; }

  get previousRoot() { return Buffer.from(this.#previousRoot); }

  get nextRoot() { return Buffer.from(this.#nextRoot); }

  get transitionTrace() { return Buffer.from(this.#transitionTrace); }

  encode() {
    const writer = new BinaryWriter(256);
    writer.write(Buffer.from(DOMAINS.PCC, 'ascii'), 'PCC domain');
    writer.write(Buffer.from('V7PC', 'ascii'), 'PCC magic');
    writer.u8(FORMAT_VERSION.major).u8(FORMAT_VERSION.minor).u8(FORMAT_VERSION.patch);
    writer.u8(this.#protocolVersion.major).u8(this.#protocolVersion.minor).u8(this.#protocolVersion.patch);
    writer.u32(this.#networkId);
    writer.u16(this.#cryptoSuite).u16(this.#stateSuite);
    writer.u64(this.#sequence);
    writer.write(this.#previousRoot).write(this.#nextRoot).write(this.#transitionTrace);
    return writer.finish();
  }

  proof() { return sha3(this.encode()); }

  links({
    sequence,
    previousRoot,
    nextRoot,
    transitionTrace,
    networkId = this.#networkId,
    cryptoSuite = this.#cryptoSuite,
    stateSuite = this.#stateSuite,
  } = {}) {
    try {
      return this.#networkId === networkId
        && this.#cryptoSuite === cryptoSuite
        && this.#stateSuite === stateSuite
        && this.#sequence === asBigInt(sequence, 'linked sequence', MAX_U64)
        && this.#previousRoot.equals(checkedHash(previousRoot, 'linked previous root'))
        && this.#nextRoot.equals(checkedHash(nextRoot, 'linked next root'))
        && this.#transitionTrace.equals(checkedHash(transitionTrace, 'linked transition trace'));
    } catch {
      return false;
    }
  }

  toJSON() {
    return Object.freeze({
      format: PCC_FORMAT,
      networkId: this.#networkId,
      protocolVersion: `${this.#protocolVersion.major}.${this.#protocolVersion.minor}.${this.#protocolVersion.patch}`,
      cryptoSuite: this.#cryptoSuite,
      stateSuite: this.#stateSuite,
      sequence: this.#sequence.toString(),
      previousRoot: this.#previousRoot.toString('hex'),
      nextRoot: this.#nextRoot.toString('hex'),
      transitionTrace: this.#transitionTrace.toString('hex'),
      proof: this.proof().toString('hex'),
    });
  }

  static decode(value) {
    const reader = new BinaryReader(value, { maxLength: 256 });
    reader.expect(DOMAINS.PCC, 'PCC domain');
    reader.expect('V7PC', 'PCC magic');
    readExactVersion(reader, FORMAT_VERSION, 'PCC format version');
    readExactVersion(reader, PROTOCOL_VERSION, 'PCC protocol version');
    const witness = new CoherenceWitness({
      networkId: reader.u32('PCC networkId'),
      cryptoSuite: reader.u16('PCC crypto suite'),
      stateSuite: reader.u16('PCC state suite'),
      sequence: reader.u64('PCC sequence'),
      previousRoot: reader.read(LENGTHS.HASH, 'PCC previous root'),
      nextRoot: reader.read(LENGTHS.HASH, 'PCC next root'),
      transitionTrace: reader.read(LENGTHS.HASH, 'PCC transition trace'),
    });
    reader.eof();
    return witness;
  }
}

class LegacyCoherenceWitness {
  #previousRoot;

  #nextRoot;

  #transitionTrace;

  #sequence;

  constructor({ previousRoot, nextRoot, transitionTrace, sequence }) {
    this.#previousRoot = checkedHash(previousRoot, 'legacy PCC previous root');
    this.#nextRoot = checkedHash(nextRoot, 'legacy PCC next root');
    this.#transitionTrace = checkedHash(transitionTrace, 'legacy PCC transition trace');
    this.#sequence = asBigInt(sequence, 'legacy PCC sequence', MAX_U64);
  }

  get previousRoot() { return Buffer.from(this.#previousRoot); }

  get nextRoot() { return Buffer.from(this.#nextRoot); }

  get transitionTrace() { return Buffer.from(this.#transitionTrace); }

  get sequence() { return this.#sequence; }

  encode() {
    const writer = new BinaryWriter(160);
    writer.write(Buffer.from(LEGACY_DOMAINS.PCC, 'ascii'));
    writer.u64(this.#sequence);
    writer.write(this.#previousRoot).write(this.#nextRoot).write(this.#transitionTrace);
    return writer.finish();
  }

  proof() { return sha3(this.encode()); }
}

function normalizeWitness(value) {
  if (value instanceof CoherenceWitness) return value;
  if (Buffer.isBuffer(value) || value instanceof Uint8Array || value instanceof ArrayBuffer) {
    return CoherenceWitness.decode(value);
  }
  if (value && typeof value === 'object') return new CoherenceWitness(value);
  throw new PccError('PCC witness must be fields, encoded bytes, or CoherenceWitness');
}

function createPcc(fields) { return new CoherenceWitness(fields); }

function verifyPcc(witnessLike, proof) {
  try {
    const witness = normalizeWitness(witnessLike);
    const claimed = proof === undefined && witnessLike && typeof witnessLike === 'object'
      ? witnessLike.pccProof || witnessLike.proofBytes
      : proof;
    return witness.proof().equals(checkedHash(claimed, 'PCC proof'));
  } catch {
    return false;
  }
}

function verifyLegacyPcc(witnessLike, proof) {
  try {
    const witness = witnessLike instanceof LegacyCoherenceWitness
      ? witnessLike
      : new LegacyCoherenceWitness(witnessLike);
    return witness.proof().equals(checkedHash(proof, 'legacy PCC proof'));
  } catch {
    return false;
  }
}

/**
 * Verifies that a PCC is more than a self-consistent hash: it checks the base
 * state, transition trace and recomputed next state. `applyTransition` may be
 * supplied for another independent state implementation. It must return a
 * state with `root()` (or a 32-byte root directly).
 */
function assertPccTransition(witnessLike, proof, {
  previousState,
  transition,
  transitionTrace,
  applyTransition,
} = {}) {
  const witness = normalizeWitness(witnessLike);
  if (!verifyPcc(witness, proof)) throw new PccError('PCC proof mismatch');
  if (!previousState || typeof previousState.root !== 'function') {
    throw new PccError('previousState with root() is required');
  }
  const actualPreviousRoot = checkedHash(previousState.root(), 'actual previous root');
  if (!actualPreviousRoot.equals(witness.previousRoot)) throw new PccError('PCC previous root mismatch');
  if (witness.sequence !== previousState.sequence + 1n) throw new PccError('PCC sequence mismatch');
  let actualTrace = transitionTrace;
  if (actualTrace === undefined && Array.isArray(transition)) {
    actualTrace = require('./state').constellationTransitionTrace(transition); // eslint-disable-line global-require
  }
  if (actualTrace === undefined && transition && typeof transition.transitionTrace === 'function') {
    actualTrace = transition.transitionTrace();
  }
  if (actualTrace === undefined) throw new PccError('transition trace or trace-producing transition is required');
  if (!checkedHash(actualTrace, 'actual transition trace').equals(witness.transitionTrace)) {
    throw new PccError('PCC transition trace mismatch');
  }
  let nextState;
  if (typeof applyTransition === 'function') {
    nextState = applyTransition(previousState, transition);
  } else if (Array.isArray(transition) && typeof previousState.applyConstellation === 'function') {
    nextState = previousState.applyConstellation(transition);
  } else if (typeof previousState.applyTransfer === 'function') {
    nextState = previousState.applyTransfer(transition);
  } else {
    throw new PccError('no transition recomputation function is available');
  }
  const actualNextRoot = Buffer.isBuffer(nextState) || nextState instanceof Uint8Array
    ? checkedHash(nextState, 'actual next root')
    : checkedHash(nextState?.root?.(), 'actual next root');
  if (!actualNextRoot.equals(witness.nextRoot)) throw new PccError('PCC next root mismatch');
  return true;
}

function verifyPccTransition(...args) {
  try {
    return assertPccTransition(...args);
  } catch {
    return false;
  }
}

module.exports = Object.freeze({
  PCC_FORMAT,
  CoherenceWitness,
  LegacyCoherenceWitness,
  normalizeWitness,
  createPcc,
  verifyPcc,
  verifyLegacyPcc,
  assertPccTransition,
  verifyPccTransition,
});
