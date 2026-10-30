'use strict';

/**
 * VLOCK7SIN Actum Phase-0 JavaScript profile.
 *
 * The 64-bit word follows the layout published in Livro Zero.  A word by
 * itself is deliberately not considered a wire message: V7ACTUM frames add
 * an unambiguous magic/version header so neural-tile/NPU command words cannot
 * accidentally be executed as Actum instructions.
 */

const ACTUM_MAGIC_TEXT = 'V7ACTUM';
const ACTUM_MAGIC_BYTES = Buffer.from(ACTUM_MAGIC_TEXT, 'ascii');
const ACTUM_FRAME_VERSION = 1;
const ACTUM_FRAME_BYTES = 16;
const ACTUM_NAMESPACE = 'VLOCK7SIN/V7ACTUM/v0.1';
const ACTUM_WORD_BITS = 64;
const ACTUM_WORD_BYTES = 8;
const UINT64_MAX = (1n << 64n) - 1n;
const IMMEDIATE_BITS = 29;
const IMMEDIATE_MAX = (1 << IMMEDIATE_BITS) - 1;
const IMMEDIATE_SIGNED_MIN = -(1 << (IMMEDIATE_BITS - 1));
const IMMEDIATE_SIGNED_MAX = (1 << (IMMEDIATE_BITS - 1)) - 1;

const FIELD_LAYOUT = Object.freeze({
  opcode: Object.freeze({ bits: 8, shift: 56n, max: 0xff }),
  flags: Object.freeze({ bits: 8, shift: 48n, max: 0xff }),
  rd: Object.freeze({ bits: 5, shift: 43n, max: 0x1f }),
  rs1: Object.freeze({ bits: 5, shift: 38n, max: 0x1f }),
  rs2: Object.freeze({ bits: 5, shift: 33n, max: 0x1f }),
  mode: Object.freeze({ bits: 4, shift: 29n, max: 0x0f }),
  immediate: Object.freeze({ bits: IMMEDIATE_BITS, shift: 0n, max: IMMEDIATE_MAX }),
});

const OPCODE_ROWS = [
  [0x00, 'ACT.NOP', 'control', 'advance one pulse without state mutation', true,
    ['flags', 'rd', 'rs1', 'rs2', 'mode', 'immediate']],
  [0x01, 'VEY.MOV', 'data', 'copy anchor rs1 to rd', true,
    ['flags', 'rs2', 'mode', 'immediate']],
  [0x02, 'VEY.LOAD', 'memory', 'load a 64-bit Sintra from state memory', false,
    ['flags', 'rs2', 'mode']],
  [0x03, 'VEY.STORE', 'memory', 'store a 64-bit Sintra into state memory', false,
    ['flags', 'rd', 'mode']],
  [0x10, 'NEX.LINK', 'causal', 'attach dependency rs2 to event rs1 and return nexus handle', false,
    ['flags', 'mode', 'immediate']],
  [0x11, 'NEX.CHECK', 'causal', 'validate dependency closure for nexus handle', false,
    ['flags', 'rs2', 'mode', 'immediate']],
  [0x20, 'ACT.APPLY', 'state', 'apply deterministic state transition selected by mode', false,
    ['flags']],
  [0x21, 'ACT.REJECT', 'state', 'reject transition and record reason code', false,
    ['flags', 'rd', 'rs1', 'rs2', 'mode']],
  [0x30, 'TRC.INIT', 'causalography', 'initialize trace context with domain identifier', false,
    ['flags', 'rs1', 'rs2', 'mode']],
  [0x31, 'TRC.FOLD', 'causalography', 'absorb a Sintra into the active trace context', false,
    ['flags', 'rs2', 'mode', 'immediate']],
  [0x32, 'TRC.CLOSE', 'causalography', 'finalize a 256-bit irreversible trace', false,
    ['flags', 'rs1', 'rs2', 'mode', 'immediate']],
  [0x33, 'SEL.VERIFY', 'causalography', 'verify authorship seal over the active trace', false,
    ['flags', 'mode', 'immediate']],
  [0x40, 'ROOT.FOLD', 'state', 'fold a leaf or subtree into the Global State Root accumulator', false,
    ['flags', 'mode', 'immediate']],
  [0x41, 'ROOT.CLOSE', 'state', 'commit final state root and set the coherence flag', false,
    ['flags', 'rs1', 'rs2', 'mode', 'immediate']],
  [0x50, 'PCC.BEGIN', 'coherence', 'open Proof of Causal Coherence context', false,
    ['flags', 'rs1', 'rs2', 'mode', 'immediate']],
  [0x51, 'PCC.CHECK', 'coherence', 'validate roots, trace and sequence witness', false,
    ['flags', 'mode', 'immediate']],
  [0x52, 'PCC.CLOSE', 'coherence', 'close coherence proof and set the coherence flag', false,
    ['flags', 'rs1', 'rs2', 'mode', 'immediate']],
  [0x60, 'MEM.SEAL', 'memory', 'mark a state region immutable for the active sequence', false,
    ['flags', 'rd', 'mode']],
  [0x61, 'MEM.PROVE', 'memory', 'produce an inclusion or absence witness', false,
    ['flags', 'mode']],
  [0x70, 'PULSE.NEXT', 'control', 'increment pulse and sequence observables', true,
    ['flags', 'rd', 'rs1', 'rs2', 'mode', 'immediate']],
  [0x71, 'PRINC.CLOSE', 'control', 'close the Principle after every invariant passes', false,
    ['flags', 'rd', 'rs1', 'rs2', 'mode', 'immediate']],
  [0x7f, 'SYS.TRAP', 'control', 'raise a deterministic exception', true,
    ['flags', 'rd', 'rs1', 'rs2', 'mode']],
];

const OPCODES = Object.freeze(OPCODE_ROWS.map((row) => Object.freeze({
  code: row[0],
  hex: `0x${row[0].toString(16).padStart(2, '0')}`,
  mnemonic: row[1],
  class: row[2],
  semantics: row[3],
  implemented: row[4],
  reservedZero: Object.freeze(row[5].slice()),
})));

const OPCODE_BY_CODE = new Map(OPCODES.map((item) => [item.code, item]));
const OPCODE_BY_MNEMONIC = new Map(OPCODES.map((item) => [item.mnemonic, item]));

const ANCHOR_ROWS = [
  [0, 'AZ0', 'anchor', 'R', 0n, 'hard-wired zero anchor'],
  [1, 'OR1', 'origin', 'RW', 0n, 'origin/identity pointer'],
  [2, 'PX2', 'pulse', 'RW', 0n, 'pulse sequence index'],
  [3, 'SR3', 'state', 'RW', 0n, 'state-root window selector'],
  [4, 'CR4', 'coherence', 'RW', 0n, 'coherence-root window selector'],
  [5, 'TR5', 'trace', 'RW', 0n, 'trace-engine operand/result'],
  [6, 'NX6', 'nexus', 'RW', 0n, 'causal dependency handle'],
  [7, 'FL7', 'flux', 'RW', 0n, 'data-flow descriptor'],
  [8, 'EP8', 'energy', 'RW', 0n, 'operational energy estimate accumulator'],
  [9, 'EN9', 'entropy', 'RW', 0n, 'informational entropy estimate'],
  [10, 'PC10', 'control', 'RW', 0n, 'Actum program counter'],
  [11, 'SP11', 'control', 'RW', 0n, 'state stack pointer'],
  [12, 'BP12', 'control', 'RW', 0n, 'state base pointer'],
  [13, 'FG13', 'flags', 'RW', 1n, 'condition and protection flags'],
  [14, 'EX14', 'exception', 'RW', 0n, 'exception cause and vector'],
  [15, 'TM15', 'time', 'R', 0n, 'deterministic monotonic pulse time in this profile'],
  ...Array.from({ length: 16 }, (_, index) => {
    const id = index + 16;
    return [id, `AN${id}`, 'general', 'RW', 0n, `general anchor ${index}`];
  }),
];

const ANCHORS = Object.freeze(ANCHOR_ROWS.map((row) => Object.freeze({
  id: row[0],
  name: row[1],
  class: row[2],
  access: row[3],
  reset: row[4],
  purpose: row[5],
})));
const ANCHOR_BY_NAME = new Map(ANCHORS.map((anchor) => [anchor.name, anchor]));

const EXCEPTION_CODES = Object.freeze({
  INVALID_WORD: 0x01,
  INVALID_FIELD: 0x02,
  UNKNOWN_OPCODE: 0x03,
  RESERVED_FIELD: 0x04,
  INVALID_REGISTER: 0x05,
  READ_ONLY_ANCHOR: 0x06,
  UNIMPLEMENTED_OPCODE: 0x07,
  INVALID_NAMESPACE: 0x08,
  INVALID_MAGIC: 0x09,
  UNSUPPORTED_VERSION: 0x0a,
  UNSAFE_OPERAND: 0x0b,
  STEP_LIMIT: 0x0c,
  TRAP: 0x7f,
});

const FLAG_BASELINE = 1n;
const FLAG_EXCEPTION = 1n << 63n;

function canonicalDetails(value) {
  if (typeof value === 'bigint') return value.toString(10);
  if (Array.isArray(value)) return value.map(canonicalDetails);
  if (value && typeof value === 'object') {
    const out = {};
    for (const key of Object.keys(value).sort()) out[key] = canonicalDetails(value[key]);
    return out;
  }
  return value;
}

function deepFreeze(value, seen = new Set()) {
  if (!value || typeof value !== 'object' || seen.has(value)) return value;
  seen.add(value);
  for (const child of Object.values(value)) deepFreeze(child, seen);
  return Object.freeze(value);
}

class ActumError extends Error {
  constructor(code, message, details = {}) {
    super(message);
    this.name = 'ActumError';
    this.code = code;
    this.exceptionCode = EXCEPTION_CODES[code] || EXCEPTION_CODES.INVALID_FIELD;
    this.deterministic = true;
    const normalizedDetails = canonicalDetails(details === undefined ? {} : details);
    this.details = deepFreeze(
      normalizedDetails && typeof normalizedDetails === 'object'
        ? normalizedDetails
        : { value: normalizedDetails },
    );
  }

  toJSON() {
    return {
      name: this.name,
      code: this.code,
      exceptionCode: this.exceptionCode,
      message: this.message,
      deterministic: true,
      details: this.details,
    };
  }
}

function fail(code, message, details) {
  throw new ActumError(code, message, details);
}

function toUnsignedInteger(value, field, max) {
  let parsed = value;
  if (typeof parsed === 'bigint') {
    if (parsed < 0n || parsed > BigInt(max)) {
      fail('INVALID_FIELD', `${field} is outside its unsigned range`, { field, max, value: parsed });
    }
    return Number(parsed);
  }
  if (typeof parsed !== 'number' || !Number.isSafeInteger(parsed) || parsed < 0 || parsed > max) {
    fail('INVALID_FIELD', `${field} is outside its unsigned range`, { field, max, value: parsed });
  }
  return parsed;
}

function resolveOpcode(value) {
  if (typeof value === 'string') {
    const byName = OPCODE_BY_MNEMONIC.get(value.toUpperCase());
    if (byName) return byName.code;
    if (/^0x[0-9a-f]{1,2}$/i.test(value)) return Number.parseInt(value.slice(2), 16);
    fail('UNKNOWN_OPCODE', 'unknown Actum mnemonic', { opcode: value });
  }
  return toUnsignedInteger(value, 'opcode', 0xff);
}

function normalizeFields(fields) {
  if (!fields || typeof fields !== 'object' || Buffer.isBuffer(fields)) {
    fail('INVALID_FIELD', 'Actum fields must be an object', { type: typeof fields });
  }
  const opcode = resolveOpcode(fields.opcode ?? fields.mnemonic);
  const normalized = {
    opcode,
    flags: toUnsignedInteger(fields.flags ?? 0, 'flags', FIELD_LAYOUT.flags.max),
    rd: toUnsignedInteger(fields.rd ?? 0, 'rd', FIELD_LAYOUT.rd.max),
    rs1: toUnsignedInteger(fields.rs1 ?? 0, 'rs1', FIELD_LAYOUT.rs1.max),
    rs2: toUnsignedInteger(fields.rs2 ?? 0, 'rs2', FIELD_LAYOUT.rs2.max),
    mode: toUnsignedInteger(fields.mode ?? 0, 'mode', FIELD_LAYOUT.mode.max),
    immediate: 0,
  };

  if (fields.immediate !== undefined && fields.immediateSigned !== undefined) {
    fail('INVALID_FIELD', 'provide immediate or immediateSigned, not both', {});
  }
  if (fields.immediateSigned !== undefined) {
    const signed = fields.immediateSigned;
    if (typeof signed !== 'number' || !Number.isSafeInteger(signed)
      || signed < IMMEDIATE_SIGNED_MIN || signed > IMMEDIATE_SIGNED_MAX) {
      fail('INVALID_FIELD', 'immediateSigned is outside the signed 29-bit range', {
        min: IMMEDIATE_SIGNED_MIN,
        max: IMMEDIATE_SIGNED_MAX,
        value: signed,
      });
    }
    normalized.immediate = signed < 0 ? (1 << IMMEDIATE_BITS) + signed : signed;
  } else {
    normalized.immediate = toUnsignedInteger(
      fields.immediate ?? 0,
      'immediate',
      FIELD_LAYOUT.immediate.max,
    );
  }
  return normalized;
}

function packFields(fields) {
  const normalized = normalizeFields(fields);
  let word = 0n;
  for (const [field, layout] of Object.entries(FIELD_LAYOUT)) {
    word |= BigInt(normalized[field]) << layout.shift;
  }
  return { word, fields: normalized };
}

function normalizeWord(input) {
  if (typeof input === 'bigint') {
    if (input < 0n || input > UINT64_MAX) {
      fail('INVALID_WORD', 'Actum word must be an unsigned 64-bit integer', { value: input });
    }
    return input;
  }
  if (typeof input === 'number') {
    if (!Number.isSafeInteger(input) || input < 0) {
      fail('INVALID_WORD', 'numeric Actum words must be non-negative safe integers; use BigInt for full width', {
        value: input,
      });
    }
    return BigInt(input);
  }
  if (typeof input === 'string' && (/^0x[0-9a-f]{1,16}$/i.test(input) || /^\d{1,20}$/.test(input))) {
    return normalizeWord(BigInt(input));
  }
  if (Buffer.isBuffer(input) || input instanceof Uint8Array) {
    const bytes = Buffer.from(input);
    if (bytes.length !== ACTUM_WORD_BYTES) {
      fail('INVALID_WORD', 'binary Actum word must contain exactly 8 bytes', { length: bytes.length });
    }
    return bytes.readBigUInt64BE(0);
  }
  if (input && typeof input === 'object' && input.word !== undefined) {
    return normalizeWord(input.word);
  }
  fail('INVALID_WORD', 'unsupported Actum word representation', { type: typeof input });
}

function unpackWord(word) {
  const normalizedWord = normalizeWord(word);
  const fields = {};
  for (const [field, layout] of Object.entries(FIELD_LAYOUT)) {
    fields[field] = Number((normalizedWord >> layout.shift) & BigInt(layout.max));
  }
  return { word: normalizedWord, fields };
}

function signedImmediate(raw) {
  return raw >= (1 << (IMMEDIATE_BITS - 1)) ? raw - (1 << IMMEDIATE_BITS) : raw;
}

function validateDecoded(decoded, options = {}) {
  const opcode = OPCODE_BY_CODE.get(decoded.opcode);
  if (!opcode) {
    if (options.allowUnknown === true) return decoded;
    fail('UNKNOWN_OPCODE', 'unknown Actum opcode', {
      opcode: `0x${decoded.opcode.toString(16).padStart(2, '0')}`,
    });
  }

  for (const field of opcode.reservedZero) {
    if (decoded[field] !== 0) {
      fail('RESERVED_FIELD', `${field} must be zero for ${opcode.mnemonic} in profile v0.1`, {
        field,
        mnemonic: opcode.mnemonic,
        value: decoded[field],
      });
    }
  }

  // Instructions that produce rd may never target a read-only anchor.
  const writesRd = new Set([
    0x01, 0x02, 0x10, 0x11, 0x30, 0x32, 0x40, 0x41, 0x50, 0x51, 0x52, 0x61,
  ]);
  if (writesRd.has(decoded.opcode) && ANCHORS[decoded.rd].access === 'R') {
    fail('READ_ONLY_ANCHOR', `${opcode.mnemonic} cannot write read-only anchor ${ANCHORS[decoded.rd].name}`, {
      anchor: decoded.rd,
      mnemonic: opcode.mnemonic,
    });
  }

  if (options.requireImplemented === true && !opcode.implemented) {
    fail('UNIMPLEMENTED_OPCODE', `${opcode.mnemonic} is specified but not implemented by the safe JS machine`, {
      mnemonic: opcode.mnemonic,
      opcode: opcode.hex,
    });
  }
  return decoded;
}

function decodeActum(input, options = {}) {
  const unpacked = unpackWord(input);
  const opcode = OPCODE_BY_CODE.get(unpacked.fields.opcode);
  const decoded = Object.freeze({
    namespace: options.namespace || null,
    framed: options.framed === true,
    word: unpacked.word,
    wordHex: `0x${unpacked.word.toString(16).padStart(16, '0')}`,
    ...unpacked.fields,
    immediateSigned: signedImmediate(unpacked.fields.immediate),
    opcodeHex: `0x${unpacked.fields.opcode.toString(16).padStart(2, '0')}`,
    mnemonic: opcode ? opcode.mnemonic : null,
    class: opcode ? opcode.class : null,
    implemented: opcode ? opcode.implemented : false,
  });
  if (options.validate !== false) validateDecoded(decoded, options);
  return decoded;
}

function validateActum(input, options = {}) {
  if (input && typeof input === 'object' && !Buffer.isBuffer(input)
    && !(input instanceof Uint8Array) && input.word === undefined) {
    const packed = packFields(input);
    return decodeActum(packed.word, options);
  }
  return decodeActum(input, options);
}

function tryValidateActum(input, options = {}) {
  try {
    return Object.freeze({ valid: true, instruction: validateActum(input, options), error: null });
  } catch (error) {
    if (!(error instanceof ActumError)) throw error;
    return Object.freeze({ valid: false, instruction: null, error: error.toJSON() });
  }
}

function encodeActum(fields, options = {}) {
  const packed = packFields(fields);
  if (options.validate !== false) decodeActum(packed.word, options);
  return packed.word;
}

function actumWordToBuffer(input) {
  const word = normalizeWord(input);
  const out = Buffer.alloc(ACTUM_WORD_BYTES);
  out.writeBigUInt64BE(word, 0);
  return out;
}

function encodeActumFrame(input, options = {}) {
  const word = input && typeof input === 'object' && input.word !== undefined
    ? normalizeWord(input.word)
    : (typeof input === 'bigint' || typeof input === 'number' || typeof input === 'string'
      || Buffer.isBuffer(input) || input instanceof Uint8Array)
      ? normalizeWord(input)
      : encodeActum(input, options);
  if (options.validate !== false) decodeActum(word, options);

  const frame = Buffer.alloc(ACTUM_FRAME_BYTES);
  ACTUM_MAGIC_BYTES.copy(frame, 0);
  frame[ACTUM_MAGIC_BYTES.length] = ACTUM_FRAME_VERSION;
  frame.writeBigUInt64BE(word, 8);
  return frame;
}

function decodeActumFrame(input, options = {}) {
  if (!Buffer.isBuffer(input) && !(input instanceof Uint8Array)) {
    fail('INVALID_MAGIC', 'Actum frame must be binary', { type: typeof input });
  }
  const frame = Buffer.from(input);
  if (frame.length !== ACTUM_FRAME_BYTES) {
    fail('INVALID_MAGIC', 'Actum frame must contain exactly 16 bytes', { length: frame.length });
  }
  if (!frame.subarray(0, ACTUM_MAGIC_BYTES.length).equals(ACTUM_MAGIC_BYTES)) {
    fail('INVALID_MAGIC', 'Actum frame magic mismatch', {
      expected: ACTUM_MAGIC_TEXT,
      actualHex: frame.subarray(0, ACTUM_MAGIC_BYTES.length).toString('hex'),
    });
  }
  const version = frame[ACTUM_MAGIC_BYTES.length];
  if (version !== ACTUM_FRAME_VERSION) {
    fail('UNSUPPORTED_VERSION', 'unsupported V7ACTUM frame version', {
      expected: ACTUM_FRAME_VERSION,
      actual: version,
    });
  }
  const word = frame.readBigUInt64BE(8);
  const decoded = decodeActum(word, {
    ...options,
    namespace: ACTUM_NAMESPACE,
    framed: true,
  });
  return Object.freeze({
    ...decoded,
    frameVersion: version,
    frameHex: frame.toString('hex'),
  });
}

function resolveAnchor(value) {
  if (typeof value === 'string') {
    const anchor = ANCHOR_BY_NAME.get(value.toUpperCase());
    if (!anchor) fail('INVALID_REGISTER', 'unknown anchor name', { anchor: value });
    return anchor.id;
  }
  return toUnsignedInteger(value, 'anchor', 31);
}

function toUint64(value, label = 'value') {
  let parsed = value;
  if (typeof parsed === 'number' && Number.isSafeInteger(parsed)) parsed = BigInt(parsed);
  if (typeof parsed === 'string' && (/^0x[0-9a-f]{1,16}$/i.test(parsed) || /^\d{1,20}$/.test(parsed))) {
    parsed = BigInt(parsed);
  }
  if (typeof parsed !== 'bigint' || parsed < 0n || parsed > UINT64_MAX) {
    fail('INVALID_FIELD', `${label} must be an unsigned 64-bit integer`, { value: parsed });
  }
  return parsed;
}

function increment64(value, label) {
  if (value === UINT64_MAX) fail('INVALID_FIELD', `${label} overflow`, { value });
  return value + 1n;
}

function normalizeInitialAnchors(initialAnchors) {
  if (initialAnchors === undefined || initialAnchors === null) return Object.freeze([]);
  if (!(initialAnchors instanceof Map)
    && (typeof initialAnchors !== 'object' || Array.isArray(initialAnchors))) {
    fail('INVALID_FIELD', 'initialAnchors must be an object or Map', {});
  }
  const sourceEntries = initialAnchors instanceof Map
    ? [...initialAnchors.entries()]
    : Object.entries(initialAnchors);
  const values = new Map();
  for (const [anchor, value] of sourceEntries) {
    const id = resolveAnchor(anchor);
    if (values.has(id)) {
      fail('INVALID_REGISTER', 'initialAnchors contains the same anchor more than once', {
        anchor: id,
        name: ANCHORS[id].name,
      });
    }
    if (ANCHORS[id].access === 'R') {
      fail('READ_ONLY_ANCHOR', `anchor ${ANCHORS[id].name} is read-only`, { anchor: id });
    }
    values.set(id, toUint64(value, ANCHORS[id].name));
  }
  return Object.freeze([...values.entries()]
    .sort((left, right) => left[0] - right[0])
    .map((entry) => Object.freeze(entry.slice())));
}

class ActumMachine {
  #anchors;

  #steps;

  #attempts;

  #lastException;

  #requireFrame;

  #maxSteps;

  #initialAnchors;

  constructor(options = {}) {
    this.#requireFrame = options.requireFrame !== false;
    this.#maxSteps = options.maxSteps === undefined
      ? 1_000_000
      : toUnsignedInteger(options.maxSteps, 'maxSteps', Number.MAX_SAFE_INTEGER);
    if (this.#maxSteps === 0) fail('INVALID_FIELD', 'maxSteps must be greater than zero', {});
    this.#initialAnchors = normalizeInitialAnchors(options.initialAnchors);
    this.#resetState();
    // Prevent shadowing read-only accessors or replacing methods on one
    // instance. Architectural state itself lives exclusively in private slots.
    Object.seal(this);
  }

  get requireFrame() {
    return this.#requireFrame;
  }

  get maxSteps() {
    return this.#maxSteps;
  }

  get steps() {
    return this.#steps;
  }

  get attempts() {
    return this.#attempts;
  }

  get anchors() {
    return Object.freeze(this.#anchors.slice());
  }

  get lastException() {
    if (this.#lastException === null) return null;
    return deepFreeze(canonicalDetails(this.#lastException));
  }

  #resetState() {
    this.#anchors = ANCHORS.map((anchor) => anchor.reset);
    this.#steps = 0;
    this.#attempts = 0;
    this.#lastException = null;
    for (const [id, value] of this.#initialAnchors) this.#anchors[id] = value;
    this.#anchors[0] = 0n;
    // Phase-0 JS chooses a deterministic TM15: accepted pulse index.
    this.#anchors[15] = this.#anchors[2];
  }

  reset() {
    if (this.#attempts !== 0 || this.#steps !== 0) {
      fail('UNSAFE_OPERAND', 'an ActumMachine cannot be reset after execution has started; create a new machine', {
        attempts: this.#attempts,
        steps: this.#steps,
      });
    }
    this.#resetState();
    return this;
  }

  readAnchor(anchor) {
    return this.#anchors[resolveAnchor(anchor)];
  }

  setAnchor(anchor, value) {
    const id = resolveAnchor(anchor);
    if (ANCHORS[id].access === 'R') {
      fail('READ_ONLY_ANCHOR', `anchor ${ANCHORS[id].name} is read-only`, { anchor: id });
    }
    if (this.#attempts !== 0 || this.#steps !== 0) {
      fail('UNSAFE_OPERAND', 'anchors cannot be changed externally after execution has started', {
        anchor: id,
        attempts: this.#attempts,
        steps: this.#steps,
      });
    }
    if (id < 16) {
      fail('UNSAFE_OPERAND', 'setAnchor only initializes general anchors AN16..AN31', {
        anchor: id,
        name: ANCHORS[id].name,
      });
    }
    this.#anchors[id] = toUint64(value, ANCHORS[id].name);
    return this;
  }

  #decodeInput(input) {
    if ((Buffer.isBuffer(input) || input instanceof Uint8Array)
      && Buffer.from(input).length === ACTUM_FRAME_BYTES) {
      return decodeActumFrame(input);
    }
    if (input && typeof input === 'object' && input.namespace === ACTUM_NAMESPACE) {
      if (input.word !== undefined) {
        return decodeActum(input.word, { namespace: ACTUM_NAMESPACE, framed: input.framed === true });
      }
      return decodeActum(encodeActum(input), { namespace: ACTUM_NAMESPACE });
    }
    if (this.#requireFrame) {
      fail('INVALID_NAMESPACE', 'bare command rejected; provide a V7ACTUM frame or namespaced instruction', {
        expectedNamespace: ACTUM_NAMESPACE,
        expectedMagic: ACTUM_MAGIC_TEXT,
      });
    }
    return decodeActum(input);
  }

  #recordException(error) {
    const exceptionCode = BigInt(error.exceptionCode || EXCEPTION_CODES.INVALID_FIELD);
    this.#anchors[14] = exceptionCode;
    this.#anchors[13] |= FLAG_EXCEPTION;
    this.#lastException = deepFreeze(canonicalDetails(error.toJSON ? error.toJSON() : {
      name: 'ActumError',
      code: 'INVALID_FIELD',
      exceptionCode: Number(exceptionCode),
      message: 'deterministic Actum failure',
      deterministic: true,
      details: {},
    }));
  }

  #clearException(next) {
    next[14] = 0n;
    next[13] &= ~FLAG_EXCEPTION;
    next[13] |= FLAG_BASELINE;
  }

  execute(input) {
    this.#attempts += 1;
    try {
      if (this.#steps >= this.#maxSteps) {
        fail('STEP_LIMIT', 'Actum machine step limit reached', { maxSteps: this.#maxSteps });
      }
      const instruction = this.#decodeInput(input);
      const descriptor = OPCODE_BY_CODE.get(instruction.opcode);
      if (!descriptor.implemented) {
        fail('UNIMPLEMENTED_OPCODE', `${descriptor.mnemonic} is specified but intentionally not implemented`, {
          mnemonic: descriptor.mnemonic,
          opcode: descriptor.hex,
          maturity: 'M1/M2-safe-subset',
        });
      }

      const next = this.#anchors.slice();
      switch (instruction.opcode) {
      case 0x00: // ACT.NOP
        next[2] = increment64(next[2], 'PX2');
        next[15] = next[2];
        break;
      case 0x01: // VEY.MOV
        // The generic ISA describes rd as writable.  The safe profile only
        // exposes AN16..AN31 so MOV cannot rewrite identity, roots or control.
        if (instruction.rd < 16) {
          fail('UNSAFE_OPERAND', 'safe VEY.MOV may only target general anchors AN16..AN31', {
            rd: instruction.rd,
            anchor: ANCHORS[instruction.rd].name,
          });
        }
        next[instruction.rd] = next[instruction.rs1];
        break;
      case 0x70: // PULSE.NEXT
        next[2] = increment64(next[2], 'PX2');
        next[15] = next[2];
        break;
      case 0x7f: // SYS.TRAP
        throw new ActumError('TRAP', 'SYS.TRAP requested a deterministic exception', {
          reason: instruction.immediate,
        });
      default:
        fail('UNIMPLEMENTED_OPCODE', 'opcode has no safe execution handler', {
          opcode: instruction.opcodeHex,
        });
      }

      next[10] = increment64(next[10], 'PC10');
      next[0] = 0n;
      this.#clearException(next);
      this.#anchors = next;
      this.#steps += 1;
      this.#lastException = null;

      return Object.freeze({
        ok: true,
        namespace: ACTUM_NAMESPACE,
        step: this.#steps,
        instruction,
        pc: this.#anchors[10],
        pulse: this.#anchors[2],
      });
    } catch (error) {
      const deterministic = error instanceof ActumError
        ? error
        : new ActumError('INVALID_FIELD', 'unexpected Actum execution failure', {
          errorName: error && error.name ? error.name : typeof error,
        });
      this.#recordException(deterministic);
      throw deterministic;
    }
  }

  executeProgram(program) {
    if (!Array.isArray(program)) fail('INVALID_FIELD', 'program must be an array', {});
    return Object.freeze(program.map((instruction) => this.execute(instruction)));
  }

  snapshot() {
    return Object.freeze({
      namespace: ACTUM_NAMESPACE,
      frameMagic: ACTUM_MAGIC_TEXT,
      frameVersion: ACTUM_FRAME_VERSION,
      steps: this.#steps,
      attempts: this.#attempts,
      anchors: Object.freeze(this.#anchors.map((value) => `0x${value.toString(16).padStart(16, '0')}`)),
      lastException: this.lastException,
    });
  }
}

module.exports = Object.freeze({
  // Export a copy so a consumer cannot mutate the bytes used internally for
  // frame validation.
  ACTUM_MAGIC: Buffer.from(ACTUM_MAGIC_BYTES),
  ACTUM_MAGIC_TEXT,
  ACTUM_FRAME_VERSION,
  ACTUM_FRAME_BYTES,
  ACTUM_NAMESPACE,
  ACTUM_WORD_BITS,
  ACTUM_WORD_BYTES,
  UINT64_MAX,
  IMMEDIATE_BITS,
  IMMEDIATE_MAX,
  IMMEDIATE_SIGNED_MIN,
  IMMEDIATE_SIGNED_MAX,
  FIELD_LAYOUT,
  OPCODES,
  OPCODE_CATALOG: OPCODES,
  ANCHORS,
  ANCHOR_CATALOG: ANCHORS,
  EXCEPTION_CODES,
  ActumError,
  ActumMachine,
  encodeActum,
  encodeInstruction: encodeActum,
  decodeActum,
  decodeInstruction: decodeActum,
  validateActum,
  tryValidateActum,
  actumWordToBuffer,
  encodeActumFrame,
  decodeActumFrame,
});
