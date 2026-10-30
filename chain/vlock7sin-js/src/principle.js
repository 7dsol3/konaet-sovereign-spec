'use strict';

const {
  DOMAINS,
  LEGACY_DOMAINS,
  MAGIC,
  NETWORK_ID,
  LEGACY_PROTOCOL_VERSION,
  PROTOCOL_VERSION,
  FORMAT_VERSION,
  RECORD_KIND,
  CRYPTO_SUITE,
  STATE_SUITE,
  PRINCIPLE_FLAGS,
  PRINCIPLE_FLAGS_MASK,
  PRINCIPLE_REQUIRED_FLAGS,
  UNIT,
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
  addressMatchesPublicKey,
  rawPublicKey,
  sign: cryptoSign,
  verify: cryptoVerify,
  traceIrreversible,
  privateKeyFromSeed,
} = require('./crypto');
const {
  GlobalState,
  computeLegacyStateRoot,
  emptyComponentRoot,
} = require('./state');
const {
  CoherenceWitness,
  LegacyCoherenceWitness,
} = require('./pcc');
const { CodecError, ValidationError } = require('./errors');

const PRINCIPLE_FORMAT = 'vlock7sin-principle-js-v1';
const LEGACY_PRINCIPLE_FORMAT = 'vlock7sin-principle-phase0-v0.1';
const ZERO_ROOT = Buffer.alloc(LENGTHS.HASH);

function checkedHash(value, label) {
  return asBuffer(value, label, { exactLength: LENGTHS.HASH });
}

function checkFlags(value, { requireFinal = true } = {}) {
  const flags = asNumber(value, 'principle flags', Number(MAX_U16));
  if ((flags & ~PRINCIPLE_FLAGS_MASK) !== 0) {
    throw new ValidationError(`unknown principle flag bits 0x${(flags & ~PRINCIPLE_FLAGS_MASK).toString(16)}`);
  }
  if (requireFinal && (flags & PRINCIPLE_REQUIRED_FLAGS) !== PRINCIPLE_REQUIRED_FLAGS) {
    throw new ValidationError('principle requires SUPPLY_FIXED and CLOSED flags');
  }
  return flags;
}

function checkEconomicFields({ unitSymbol, decimals, initialSupplyAtomic }, {
  expectedUnitSymbol = UNIT.symbol,
  expectedDecimals = UNIT.decimals,
  expectedInitialSupplyAtomic = UNIT.initialSupplyAtomic,
} = {}) {
  if (typeof unitSymbol !== 'string' || !/^[A-Z][A-Z0-9]{0,15}$/.test(unitSymbol)) {
    throw new ValidationError('unit symbol must be 1..16 uppercase ASCII alphanumerics');
  }
  const precision = asNumber(decimals, 'decimals', 38);
  const supply = asBigInt(initialSupplyAtomic, 'initial supply', MAX_U128);
  if (supply === 0n) throw new ValidationError('initial supply must be positive');
  if (expectedUnitSymbol !== undefined && unitSymbol !== expectedUnitSymbol) {
    throw new ValidationError(`unexpected unit symbol ${unitSymbol}`);
  }
  if (expectedDecimals !== undefined && precision !== expectedDecimals) {
    throw new ValidationError(`unexpected decimal precision ${precision}`);
  }
  if (expectedInitialSupplyAtomic !== undefined
    && supply !== asBigInt(expectedInitialSupplyAtomic, 'expected initial supply', MAX_U128)) {
    throw new ValidationError('initial supply does not match the fixed network supply');
  }
  return { precision, supply };
}

function readVersion(reader, expected, label) {
  const actual = [reader.u8(), reader.u8(), reader.u8()];
  if (actual[0] !== expected.major || actual[1] !== expected.minor || actual[2] !== expected.patch) {
    throw new CodecError(`unsupported ${label} ${actual.join('.')}`);
  }
}

function encodePrincipleTransition(fields) {
  const writer = new BinaryWriter(1024);
  writer.write(Buffer.from(DOMAINS.PRINCIPLE_TRANSITION, 'ascii'));
  writer.write(Buffer.from('V7PT', 'ascii'));
  writer.u8(FORMAT_VERSION.major).u8(FORMAT_VERSION.minor).u8(FORMAT_VERSION.patch);
  writer.u8(PROTOCOL_VERSION.major).u8(PROTOCOL_VERSION.minor).u8(PROTOCOL_VERSION.patch);
  writer.u32(asNumber(fields.networkId, 'networkId', Number(MAX_U32)));
  writer.u16(asNumber(fields.cryptoSuite, 'crypto suite', Number(MAX_U16)));
  writer.u16(asNumber(fields.stateSuite, 'state suite', Number(MAX_U16)));
  writer.u64(0n);
  writer.u16(checkFlags(fields.flags));
  writer.ascii(fields.unitSymbol, {
    maxLength: LIMITS.UNIT_SYMBOL_BYTES,
    label: 'unit symbol',
    allowEmpty: false,
  });
  writer.u8(asNumber(fields.decimals, 'decimals', 38));
  writer.u128(asBigInt(fields.initialSupplyAtomic, 'initial supply', MAX_U128));
  writer.write(rawPublicKey(fields.founderPublicKey));
  writer.ascii(fields.founderAddress, {
    maxLength: LIMITS.ADDRESS_BYTES,
    label: 'founder address',
    allowEmpty: false,
  });
  writer.write(checkedHash(fields.parametersRoot, 'parameters root'));
  writer.write(checkedHash(fields.identitiesRoot, 'identities root'));
  writer.write(checkedHash(fields.replayRoot, 'replay root'));
  return writer.finish();
}

function computePrincipleTransitionTrace(fields) {
  return traceIrreversible(encodePrincipleTransition(fields));
}

class PrincipleRecord {
  #values;

  constructor(fields) {
    if (!fields || typeof fields !== 'object') throw new ValidationError('principle fields are required');
    const flags = checkFlags(fields.flags ?? PRINCIPLE_REQUIRED_FLAGS);
    const networkId = asNumber(fields.networkId ?? NETWORK_ID, 'networkId', Number(MAX_U32));
    const cryptoSuite = asNumber(
      fields.cryptoSuite ?? CRYPTO_SUITE.SHA3_256_ED25519,
      'crypto suite',
      Number(MAX_U16),
    );
    const stateSuite = asNumber(
      fields.stateSuite ?? STATE_SUITE.SORTED_MERKLE_V1,
      'state suite',
      Number(MAX_U16),
    );
    if (cryptoSuite !== CRYPTO_SUITE.SHA3_256_ED25519) throw new ValidationError('unsupported crypto suite');
    if (stateSuite !== STATE_SUITE.SORTED_MERKLE_V1) throw new ValidationError('unsupported state suite');
    const timestampMs = asBigInt(fields.timestampMs ?? 0n, 'timestampMs', MAX_U64);
    const alias = fields.alias ?? '7dsolv';
    const legalName = fields.legalName ?? 'Adilson Oliveira';
    const message = fields.message ?? 'O estado verificavel nasce no Principio.';
    const unitSymbol = fields.unitSymbol ?? UNIT.symbol;
    const decimals = fields.decimals ?? UNIT.decimals;
    const initialSupplyAtomic = fields.initialSupplyAtomic ?? UNIT.initialSupplyAtomic;
    checkEconomicFields({ unitSymbol, decimals, initialSupplyAtomic });
    const founderPublicKey = rawPublicKey(fields.founderPublicKey);
    const founderAddress = fields.founderAddress || encodeAddress(founderPublicKey);
    if (!addressMatchesPublicKey(founderAddress, founderPublicKey)) {
      throw new ValidationError('founder address does not match founder public key');
    }
    // Writers validate text canonically now, before any signature can be made.
    new BinaryWriter(1024)
      .utf8(alias, { maxLength: LIMITS.ALIAS_BYTES, label: 'alias', allowEmpty: false })
      .utf8(legalName, { maxLength: LIMITS.LEGAL_NAME_BYTES, label: 'legal name', allowEmpty: false })
      .utf8(message, { maxLength: LIMITS.MESSAGE_BYTES, label: 'message', allowEmpty: false });
    const parametersRoot = checkedHash(
      fields.parametersRoot ?? emptyComponentRoot(DOMAINS.PARAMETERS_EMPTY),
      'parameters root',
    );
    const identitiesRoot = checkedHash(
      fields.identitiesRoot ?? emptyComponentRoot(DOMAINS.IDENTITIES_EMPTY),
      'identities root',
    );
    const replayRoot = checkedHash(
      fields.replayRoot ?? emptyComponentRoot(DOMAINS.REPLAY_EMPTY),
      'replay root',
    );
    const previousRoot = checkedHash(fields.previousRoot ?? ZERO_ROOT, 'previous root');
    if (!previousRoot.equals(ZERO_ROOT)) throw new ValidationError('Principle previous root must be zero');
    this.#values = {
      flags,
      networkId,
      cryptoSuite,
      stateSuite,
      timestampMs,
      alias,
      legalName,
      message,
      unitSymbol,
      decimals: asNumber(decimals, 'decimals', 38),
      initialSupplyAtomic: asBigInt(initialSupplyAtomic, 'initial supply', MAX_U128),
      founderPublicKey,
      founderAddress,
      previousRoot,
      parametersRoot,
      identitiesRoot,
      replayRoot,
      globalStateRoot: checkedHash(fields.globalStateRoot, 'global state root'),
      transitionTrace: checkedHash(fields.transitionTrace, 'principle transition trace'),
      pccProof: checkedHash(fields.pccProof, 'principle PCC proof'),
      signature: fields.signature === undefined || fields.signature === null
        ? Buffer.alloc(0)
        : asBuffer(fields.signature, 'principle signature', { exactLength: LENGTHS.SIGNATURE }),
    };
  }

  get format() { return PRINCIPLE_FORMAT; }

  get flags() { return this.#values.flags; }

  get networkId() { return this.#values.networkId; }

  get cryptoSuite() { return this.#values.cryptoSuite; }

  get stateSuite() { return this.#values.stateSuite; }

  get timestampMs() { return this.#values.timestampMs; }

  get alias() { return this.#values.alias; }

  get legalName() { return this.#values.legalName; }

  get message() { return this.#values.message; }

  get unitSymbol() { return this.#values.unitSymbol; }

  get decimals() { return this.#values.decimals; }

  get initialSupplyAtomic() { return this.#values.initialSupplyAtomic; }

  get founderPublicKey() { return Buffer.from(this.#values.founderPublicKey); }

  get founderAddress() { return this.#values.founderAddress; }

  get previousRoot() { return Buffer.from(this.#values.previousRoot); }

  get parametersRoot() { return Buffer.from(this.#values.parametersRoot); }

  get identitiesRoot() { return Buffer.from(this.#values.identitiesRoot); }

  get replayRoot() { return Buffer.from(this.#values.replayRoot); }

  get globalStateRoot() { return Buffer.from(this.#values.globalStateRoot); }

  get transitionTrace() { return Buffer.from(this.#values.transitionTrace); }

  get pccProof() { return Buffer.from(this.#values.pccProof); }

  get signature() { return Buffer.from(this.#values.signature); }

  get signed() { return this.#values.signature.length === LENGTHS.SIGNATURE; }

  toObject() {
    return {
      ...this.#values,
      founderPublicKey: Buffer.from(this.#values.founderPublicKey),
      previousRoot: Buffer.from(this.#values.previousRoot),
      parametersRoot: Buffer.from(this.#values.parametersRoot),
      identitiesRoot: Buffer.from(this.#values.identitiesRoot),
      replayRoot: Buffer.from(this.#values.replayRoot),
      globalStateRoot: Buffer.from(this.#values.globalStateRoot),
      transitionTrace: Buffer.from(this.#values.transitionTrace),
      pccProof: Buffer.from(this.#values.pccProof),
      signature: this.signed ? Buffer.from(this.#values.signature) : undefined,
    };
  }

  unsignedBytes() {
    const writer = new BinaryWriter(LIMITS.RECORD_BYTES);
    writer.write(Buffer.from(DOMAINS.PRINCIPLE, 'ascii'));
    writer.write(Buffer.from(MAGIC, 'ascii'));
    writer.u8(RECORD_KIND.PRINCIPLE);
    writer.u8(FORMAT_VERSION.major).u8(FORMAT_VERSION.minor).u8(FORMAT_VERSION.patch);
    writer.u8(PROTOCOL_VERSION.major).u8(PROTOCOL_VERSION.minor).u8(PROTOCOL_VERSION.patch);
    writer.u16(this.#values.flags).u32(this.#values.networkId);
    writer.u16(this.#values.cryptoSuite).u16(this.#values.stateSuite);
    writer.u64(this.#values.timestampMs);
    writer.u8(this.#values.decimals).u8(0); // reserved byte, required to be zero
    writer.u128(this.#values.initialSupplyAtomic);
    writer.utf8(this.#values.alias, { maxLength: LIMITS.ALIAS_BYTES, label: 'alias', allowEmpty: false });
    writer.utf8(this.#values.legalName, {
      maxLength: LIMITS.LEGAL_NAME_BYTES,
      label: 'legal name',
      allowEmpty: false,
    });
    writer.utf8(this.#values.message, {
      maxLength: LIMITS.MESSAGE_BYTES,
      label: 'message',
      allowEmpty: false,
    });
    writer.ascii(this.#values.unitSymbol, {
      maxLength: LIMITS.UNIT_SYMBOL_BYTES,
      label: 'unit symbol',
      allowEmpty: false,
    });
    writer.write(this.#values.founderPublicKey);
    writer.ascii(this.#values.founderAddress, {
      maxLength: LIMITS.ADDRESS_BYTES,
      label: 'founder address',
      allowEmpty: false,
    });
    writer.write(this.#values.previousRoot);
    writer.write(this.#values.parametersRoot).write(this.#values.identitiesRoot).write(this.#values.replayRoot);
    writer.write(this.#values.globalStateRoot).write(this.#values.transitionTrace).write(this.#values.pccProof);
    return writer.finish();
  }

  canonicalBytes() {
    if (!this.signed) throw new CodecError('principle must have a 64-byte signature');
    const body = Buffer.concat([this.unsignedBytes(), this.#values.signature]);
    return Buffer.concat([body, traceIrreversible(body).subarray(0, LENGTHS.CHECKSUM)]);
  }

  recordTrace() { return traceIrreversible(this.canonicalBytes()); }

  sign(privateKey) {
    const record = new PrincipleRecord({
      ...this.toObject(),
      signature: cryptoSign(privateKey, this.unsignedBytes()),
    });
    if (!cryptoVerify(record.founderPublicKey, record.unsignedBytes(), record.signature)) {
      throw new ValidationError('signing key does not match founder public key');
    }
    return record;
  }

  initialState() {
    return new GlobalState({
      sequence: 0n,
      balances: [[this.#values.founderAddress, this.#values.initialSupplyAtomic]],
      parametersRoot: this.#values.parametersRoot,
      identitiesRoot: this.#values.identitiesRoot,
      replayRoot: this.#values.replayRoot,
      networkId: this.#values.networkId,
      suite: this.#values.stateSuite,
    });
  }

  assertValid({
    expectedNetworkId = NETWORK_ID,
    expectedUnitSymbol = UNIT.symbol,
    expectedDecimals = UNIT.decimals,
    expectedInitialSupplyAtomic = UNIT.initialSupplyAtomic,
    allowTestVector = true,
  } = {}) {
    checkFlags(this.#values.flags);
    if (this.#values.networkId !== expectedNetworkId) throw new ValidationError('principle network mismatch');
    if (!allowTestVector && (this.#values.flags & PRINCIPLE_FLAGS.TEST_VECTOR) !== 0) {
      throw new ValidationError('test-vector Principle is not accepted in this context');
    }
    checkEconomicFields(this.#values, {
      expectedUnitSymbol,
      expectedDecimals,
      expectedInitialSupplyAtomic,
    });
    if (!addressMatchesPublicKey(this.#values.founderAddress, this.#values.founderPublicKey)) {
      throw new ValidationError('founder address mismatch');
    }
    const expectedTrace = computePrincipleTransitionTrace(this.#values);
    if (!expectedTrace.equals(this.#values.transitionTrace)) {
      throw new ValidationError('principle transition trace mismatch');
    }
    const state = this.initialState();
    if (!state.root().equals(this.#values.globalStateRoot)) {
      throw new ValidationError('principle global state root mismatch');
    }
    const witness = new CoherenceWitness({
      networkId: this.#values.networkId,
      cryptoSuite: this.#values.cryptoSuite,
      stateSuite: this.#values.stateSuite,
      sequence: 0n,
      previousRoot: ZERO_ROOT,
      nextRoot: this.#values.globalStateRoot,
      transitionTrace: this.#values.transitionTrace,
    });
    if (!witness.proof().equals(this.#values.pccProof)) throw new ValidationError('principle PCC mismatch');
    if (!this.signed || !cryptoVerify(
      this.#values.founderPublicKey,
      this.unsignedBytes(),
      this.#values.signature,
    )) throw new ValidationError('invalid principle signature');
    return this;
  }

  verify(options) {
    try { this.assertValid(options); return true; } catch { return false; }
  }

  toJSON() {
    return Object.freeze({
      format: PRINCIPLE_FORMAT,
      flags: this.#values.flags,
      networkId: this.#values.networkId,
      cryptoSuite: this.#values.cryptoSuite,
      stateSuite: this.#values.stateSuite,
      timestampMs: this.#values.timestampMs.toString(),
      alias: this.#values.alias,
      legalName: this.#values.legalName,
      message: this.#values.message,
      unitSymbol: this.#values.unitSymbol,
      decimals: this.#values.decimals,
      initialSupplyAtomic: this.#values.initialSupplyAtomic.toString(),
      founderPublicKey: this.#values.founderPublicKey.toString('hex'),
      founderAddress: this.#values.founderAddress,
      previousRoot: this.#values.previousRoot.toString('hex'),
      parametersRoot: this.#values.parametersRoot.toString('hex'),
      identitiesRoot: this.#values.identitiesRoot.toString('hex'),
      replayRoot: this.#values.replayRoot.toString('hex'),
      globalStateRoot: this.#values.globalStateRoot.toString('hex'),
      transitionTrace: this.#values.transitionTrace.toString('hex'),
      pccProof: this.#values.pccProof.toString('hex'),
      signature: this.#values.signature.toString('hex'),
      recordTrace: this.signed ? this.recordTrace().toString('hex') : null,
    });
  }

  static decode(value) {
    const data = asBuffer(value, 'principle record', { maxLength: LIMITS.RECORD_BYTES });
    const reader = new BinaryReader(data);
    reader.expect(DOMAINS.PRINCIPLE, 'principle domain');
    reader.expect(MAGIC, 'magic');
    if (reader.u8('record kind') !== RECORD_KIND.PRINCIPLE) throw new CodecError('invalid record kind');
    readVersion(reader, FORMAT_VERSION, 'principle format version');
    readVersion(reader, PROTOCOL_VERSION, 'protocol version');
    const fields = {
      flags: reader.u16('principle flags'),
      networkId: reader.u32('networkId'),
      cryptoSuite: reader.u16('crypto suite'),
      stateSuite: reader.u16('state suite'),
      timestampMs: reader.u64('timestampMs'),
      decimals: reader.u8('decimals'),
    };
    if (reader.u8('reserved') !== 0) throw new CodecError('reserved principle byte must be zero');
    fields.initialSupplyAtomic = reader.u128('initial supply');
    fields.alias = reader.utf8({ maxLength: LIMITS.ALIAS_BYTES, label: 'alias', allowEmpty: false });
    fields.legalName = reader.utf8({
      maxLength: LIMITS.LEGAL_NAME_BYTES,
      label: 'legal name',
      allowEmpty: false,
    });
    fields.message = reader.utf8({
      maxLength: LIMITS.MESSAGE_BYTES,
      label: 'message',
      allowEmpty: false,
    });
    fields.unitSymbol = reader.ascii({
      maxLength: LIMITS.UNIT_SYMBOL_BYTES,
      label: 'unit symbol',
      allowEmpty: false,
    });
    fields.founderPublicKey = reader.read(LENGTHS.PUBLIC_KEY, 'founder public key');
    fields.founderAddress = reader.ascii({
      maxLength: LIMITS.ADDRESS_BYTES,
      label: 'founder address',
      allowEmpty: false,
    });
    fields.previousRoot = reader.read(LENGTHS.HASH, 'previous root');
    fields.parametersRoot = reader.read(LENGTHS.HASH, 'parameters root');
    fields.identitiesRoot = reader.read(LENGTHS.HASH, 'identities root');
    fields.replayRoot = reader.read(LENGTHS.HASH, 'replay root');
    fields.globalStateRoot = reader.read(LENGTHS.HASH, 'global state root');
    fields.transitionTrace = reader.read(LENGTHS.HASH, 'transition trace');
    fields.pccProof = reader.read(LENGTHS.HASH, 'PCC proof');
    const signatureEnd = reader.offset + LENGTHS.SIGNATURE;
    fields.signature = reader.read(LENGTHS.SIGNATURE, 'principle signature');
    const checksum = reader.read(LENGTHS.CHECKSUM, 'principle checksum');
    reader.eof();
    if (!checksum.equals(traceIrreversible(data.subarray(0, signatureEnd)).subarray(0, LENGTHS.CHECKSUM))) {
      throw new CodecError('principle checksum mismatch');
    }
    const record = new PrincipleRecord(fields);
    if (!record.canonicalBytes().equals(data)) throw new CodecError('non-canonical principle encoding');
    return record;
  }
}

class LegacyPrincipleRecord {
  #values;

  constructor(fields) {
    this.#values = {
      flags: checkFlags(fields.flags, { requireFinal: false }),
      networkId: asNumber(fields.networkId, 'legacy networkId', Number(MAX_U32)),
      timestampMs: asBigInt(fields.timestampMs, 'legacy timestampMs', MAX_U64),
      alias: fields.alias,
      legalName: fields.legalName,
      message: fields.message,
      unitSymbol: fields.unitSymbol,
      decimals: asNumber(fields.decimals, 'legacy decimals', 255),
      initialSupplyAtomic: asBigInt(fields.initialSupplyAtomic, 'legacy initial supply', MAX_U128),
      founderPublicKey: rawPublicKey(fields.founderPublicKey),
      founderAddress: fields.founderAddress,
      globalStateRoot: checkedHash(fields.globalStateRoot, 'legacy global state root'),
      transitionTrace: checkedHash(fields.transitionTrace, 'legacy transition trace'),
      pccProof: checkedHash(fields.pccProof, 'legacy PCC proof'),
      signature: fields.signature === undefined || fields.signature === null
        ? Buffer.alloc(0)
        : asBuffer(fields.signature, 'legacy signature', { exactLength: LENGTHS.SIGNATURE }),
    };
  }

  get format() { return LEGACY_PRINCIPLE_FORMAT; }

  get flags() { return this.#values.flags; }

  get networkId() { return this.#values.networkId; }

  get timestampMs() { return this.#values.timestampMs; }

  get alias() { return this.#values.alias; }

  get legalName() { return this.#values.legalName; }

  get message() { return this.#values.message; }

  get unitSymbol() { return this.#values.unitSymbol; }

  get decimals() { return this.#values.decimals; }

  get initialSupplyAtomic() { return this.#values.initialSupplyAtomic; }

  get founderPublicKey() { return Buffer.from(this.#values.founderPublicKey); }

  get founderAddress() { return this.#values.founderAddress; }

  get globalStateRoot() { return Buffer.from(this.#values.globalStateRoot); }

  get transitionTrace() { return Buffer.from(this.#values.transitionTrace); }

  get pccProof() { return Buffer.from(this.#values.pccProof); }

  get signature() { return Buffer.from(this.#values.signature); }

  get signed() { return this.#values.signature.length === LENGTHS.SIGNATURE; }

  unsignedBytes() {
    const writer = new BinaryWriter(LIMITS.RECORD_BYTES);
    writer.write(Buffer.from(LEGACY_DOMAINS.PRINCIPLE, 'ascii'));
    writer.write(Buffer.from(MAGIC, 'ascii'));
    writer.u8(RECORD_KIND.PRINCIPLE);
    writer.u8(LEGACY_PROTOCOL_VERSION.major)
      .u8(LEGACY_PROTOCOL_VERSION.minor)
      .u8(LEGACY_PROTOCOL_VERSION.patch);
    writer.u16(this.#values.flags).u32(this.#values.networkId).u64(this.#values.timestampMs);
    writer.utf8(this.#values.alias, { maxLength: LIMITS.ALIAS_BYTES, label: 'legacy alias' });
    writer.utf8(this.#values.legalName, { maxLength: LIMITS.LEGAL_NAME_BYTES, label: 'legacy legal name' });
    writer.utf8(this.#values.message, { maxLength: LIMITS.MESSAGE_BYTES, label: 'legacy message' });
    writer.ascii(this.#values.unitSymbol, { maxLength: LIMITS.UNIT_SYMBOL_BYTES, label: 'legacy unit' });
    writer.u8(this.#values.decimals).u128(this.#values.initialSupplyAtomic);
    writer.write(this.#values.founderPublicKey);
    writer.ascii(this.#values.founderAddress, {
      maxLength: LIMITS.ADDRESS_BYTES,
      label: 'legacy founder address',
    });
    writer.write(this.#values.globalStateRoot)
      .write(this.#values.transitionTrace)
      .write(this.#values.pccProof);
    return writer.finish();
  }

  canonicalBytes() {
    if (!this.signed) throw new CodecError('legacy Principle must have a 64-byte signature');
    const body = Buffer.concat([this.unsignedBytes(), this.#values.signature]);
    return Buffer.concat([
      body,
      traceIrreversible(body, { legacy: true }).subarray(0, LENGTHS.LEGACY_CHECKSUM),
    ]);
  }

  recordTrace() { return traceIrreversible(this.canonicalBytes(), { legacy: true }); }

  sign(privateKey) {
    return new LegacyPrincipleRecord({
      ...this.#values,
      signature: cryptoSign(privateKey, this.unsignedBytes()),
    });
  }

  warnings() {
    const warnings = [];
    if ((this.#values.flags & PRINCIPLE_FLAGS.TEST_VECTOR) === 0) warnings.push('FLAG_TEST_VECTOR is not set');
    if ((this.#values.flags & PRINCIPLE_FLAGS.SUPPLY_FIXED) === 0) warnings.push('FLAG_SUPPLY_FIXED is not set');
    return Object.freeze(warnings);
  }

  assertValid({
    expectedNetworkId = NETWORK_ID,
    expectedUnitSymbol = UNIT.symbol,
    expectedDecimals = UNIT.decimals,
    expectedInitialSupplyAtomic = UNIT.initialSupplyAtomic,
    expectedTransitionTrace,
    requireFinalFlags = false,
  } = {}) {
    checkFlags(this.#values.flags, { requireFinal: requireFinalFlags });
    if (this.#values.networkId !== expectedNetworkId) throw new ValidationError('legacy network mismatch');
    checkEconomicFields(this.#values, {
      expectedUnitSymbol,
      expectedDecimals,
      expectedInitialSupplyAtomic,
    });
    if (!addressMatchesPublicKey(this.#values.founderAddress, this.#values.founderPublicKey)) {
      throw new ValidationError('legacy founder address mismatch');
    }
    const stateRoot = computeLegacyStateRoot({
      sequence: 0n,
      balances: [[this.#values.founderAddress, this.#values.initialSupplyAtomic]],
    });
    if (!stateRoot.equals(this.#values.globalStateRoot)) throw new ValidationError('legacy state root mismatch');
    if (expectedTransitionTrace !== undefined
      && !checkedHash(expectedTransitionTrace, 'expected transition trace').equals(this.#values.transitionTrace)) {
      throw new ValidationError('legacy transition trace mismatch');
    }
    const witness = new LegacyCoherenceWitness({
      previousRoot: ZERO_ROOT,
      nextRoot: this.#values.globalStateRoot,
      transitionTrace: this.#values.transitionTrace,
      sequence: 0n,
    });
    if (!witness.proof().equals(this.#values.pccProof)) throw new ValidationError('legacy PCC mismatch');
    if (!this.signed || !cryptoVerify(
      this.#values.founderPublicKey,
      this.unsignedBytes(),
      this.#values.signature,
    )) throw new ValidationError('invalid legacy Principle signature');
    return this;
  }

  verify(options) { try { this.assertValid(options); return true; } catch { return false; } }

  static decode(value) {
    const data = asBuffer(value, 'legacy Principle', { maxLength: LIMITS.RECORD_BYTES });
    const reader = new BinaryReader(data);
    reader.expect(LEGACY_DOMAINS.PRINCIPLE, 'legacy Principle domain');
    reader.expect(MAGIC, 'legacy magic');
    if (reader.u8('legacy kind') !== RECORD_KIND.PRINCIPLE) throw new CodecError('invalid legacy kind');
    readVersion(reader, LEGACY_PROTOCOL_VERSION, 'legacy protocol version');
    const fields = {
      flags: reader.u16('legacy flags'),
      networkId: reader.u32('legacy networkId'),
      timestampMs: reader.u64('legacy timestampMs'),
      alias: reader.utf8({ maxLength: LIMITS.ALIAS_BYTES, label: 'legacy alias' }),
      legalName: reader.utf8({ maxLength: LIMITS.LEGAL_NAME_BYTES, label: 'legacy legal name' }),
      message: reader.utf8({ maxLength: LIMITS.MESSAGE_BYTES, label: 'legacy message' }),
      unitSymbol: reader.ascii({ maxLength: LIMITS.UNIT_SYMBOL_BYTES, label: 'legacy unit' }),
      decimals: reader.u8('legacy decimals'),
      initialSupplyAtomic: reader.u128('legacy supply'),
      founderPublicKey: reader.read(LENGTHS.PUBLIC_KEY, 'legacy public key'),
      founderAddress: reader.ascii({ maxLength: LIMITS.ADDRESS_BYTES, label: 'legacy address' }),
      globalStateRoot: reader.read(LENGTHS.HASH, 'legacy state root'),
      transitionTrace: reader.read(LENGTHS.HASH, 'legacy transition trace'),
      pccProof: reader.read(LENGTHS.HASH, 'legacy PCC'),
    };
    const signatureEnd = reader.offset + LENGTHS.SIGNATURE;
    fields.signature = reader.read(LENGTHS.SIGNATURE, 'legacy signature');
    const checksum = reader.read(LENGTHS.LEGACY_CHECKSUM, 'legacy checksum');
    reader.eof();
    if (!checksum.equals(
      traceIrreversible(data.subarray(0, signatureEnd), { legacy: true })
        .subarray(0, LENGTHS.LEGACY_CHECKSUM),
    )) throw new CodecError('legacy Principle checksum mismatch');
    const record = new LegacyPrincipleRecord(fields);
    if (!record.canonicalBytes().equals(data)) throw new CodecError('non-canonical legacy encoding');
    return record;
  }
}

function createPrinciple({ keypair, privateKey, ...fields }) {
  const signingKey = privateKey || keypair;
  if (!signingKey) throw new ValidationError('keypair or privateKey is required');
  const founderPublicKey = fields.founderPublicKey
    || keypair?.publicBytes?.()
    || rawPublicKey(
      Buffer.isBuffer(signingKey) || signingKey instanceof Uint8Array
        ? privateKeyFromSeed(signingKey)
        : signingKey,
    );
  const base = {
    ...fields,
    founderPublicKey,
    founderAddress: fields.founderAddress || encodeAddress(founderPublicKey),
    flags: fields.flags ?? PRINCIPLE_REQUIRED_FLAGS,
    networkId: fields.networkId ?? NETWORK_ID,
    cryptoSuite: fields.cryptoSuite ?? CRYPTO_SUITE.SHA3_256_ED25519,
    stateSuite: fields.stateSuite ?? STATE_SUITE.SORTED_MERKLE_V1,
    unitSymbol: fields.unitSymbol ?? UNIT.symbol,
    decimals: fields.decimals ?? UNIT.decimals,
    initialSupplyAtomic: fields.initialSupplyAtomic ?? UNIT.initialSupplyAtomic,
    parametersRoot: fields.parametersRoot ?? emptyComponentRoot(DOMAINS.PARAMETERS_EMPTY),
    identitiesRoot: fields.identitiesRoot ?? emptyComponentRoot(DOMAINS.IDENTITIES_EMPTY),
    replayRoot: fields.replayRoot ?? emptyComponentRoot(DOMAINS.REPLAY_EMPTY),
    previousRoot: ZERO_ROOT,
  };
  const initialState = new GlobalState({
    balances: [[base.founderAddress, base.initialSupplyAtomic]],
    parametersRoot: base.parametersRoot,
    identitiesRoot: base.identitiesRoot,
    replayRoot: base.replayRoot,
    networkId: base.networkId,
    suite: base.stateSuite,
  });
  base.globalStateRoot = initialState.root();
  base.transitionTrace = computePrincipleTransitionTrace(base);
  base.pccProof = new CoherenceWitness({
    networkId: base.networkId,
    cryptoSuite: base.cryptoSuite,
    stateSuite: base.stateSuite,
    sequence: 0n,
    previousRoot: ZERO_ROOT,
    nextRoot: base.globalStateRoot,
    transitionTrace: base.transitionTrace,
  }).proof();
  return new PrincipleRecord(base).sign(signingKey);
}

function decodePrinciple(value, { legacy = false } = {}) {
  return legacy ? LegacyPrincipleRecord.decode(value) : PrincipleRecord.decode(value);
}

function normalizePrinciple(value, { legacy = false } = {}) {
  if (legacy && value instanceof PrincipleRecord) {
    throw new ValidationError('JS-v1 Principle cannot be verified as a legacy Principle');
  }
  if (!legacy && value instanceof LegacyPrincipleRecord) {
    throw new ValidationError('legacy Principle cannot be verified as a JS-v1 Principle');
  }
  if (value instanceof PrincipleRecord || value instanceof LegacyPrincipleRecord) return value;
  if (Buffer.isBuffer(value) || value instanceof Uint8Array || value instanceof ArrayBuffer) {
    return decodePrinciple(value, { legacy });
  }
  return legacy ? new LegacyPrincipleRecord(value) : new PrincipleRecord(value);
}

function verifyPrinciple(value, options) {
  try { return normalizePrinciple(value, { legacy: false }).verify(options); } catch { return false; }
}

function decodeLegacyPrinciple(value) { return LegacyPrincipleRecord.decode(value); }

function verifyLegacyPrinciple(value, options) {
  try { return normalizePrinciple(value, { legacy: true }).verify(options); } catch { return false; }
}

module.exports = Object.freeze({
  PRINCIPLE_FORMAT,
  LEGACY_PRINCIPLE_FORMAT,
  PrincipleRecord,
  LegacyPrincipleRecord,
  encodePrincipleTransition,
  computePrincipleTransitionTrace,
  createPrinciple,
  decodePrinciple,
  decodeLegacyPrinciple,
  normalizePrinciple,
  verifyPrinciple,
  verifyLegacyPrinciple,
});
