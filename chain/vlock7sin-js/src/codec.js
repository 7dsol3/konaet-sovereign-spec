'use strict';

const { TextDecoder } = require('node:util');
const {
  LIMITS,
  MAX_U16,
  MAX_U128,
} = require('./constants');
const { CodecError } = require('./errors');

const FATAL_UTF8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

function asBuffer(value, label = 'value', { exactLength, maxLength = LIMITS.RECORD_BYTES } = {}) {
  let result;
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    result = Buffer.from(value);
  } else if (value instanceof ArrayBuffer) {
    result = Buffer.from(new Uint8Array(value));
  } else {
    throw new CodecError(`${label} must be bytes`);
  }
  if (exactLength !== undefined && result.length !== exactLength) {
    throw new CodecError(`${label} must be exactly ${exactLength} bytes`);
  }
  if (!Number.isSafeInteger(maxLength) || maxLength < 0 || result.length > maxLength) {
    throw new CodecError(`${label} exceeds the ${maxLength}-byte limit`);
  }
  return result;
}

function asBigInt(value, label = 'value', max = MAX_U128) {
  let parsed;
  if (typeof value === 'bigint') {
    parsed = value;
  } else if (typeof value === 'number' && Number.isSafeInteger(value)) {
    parsed = BigInt(value);
  } else if (typeof value === 'string' && /^(0|[1-9][0-9]*)$/.test(value)) {
    parsed = BigInt(value);
  } else {
    throw new CodecError(`${label} must be a BigInt, safe integer, or canonical unsigned decimal string`);
  }
  if (parsed < 0n || parsed > max) {
    throw new CodecError(`${label} is outside its unsigned integer range`);
  }
  return parsed;
}

function asNumber(value, label, max = Number.MAX_SAFE_INTEGER) {
  const parsed = asBigInt(value, label, BigInt(max));
  return Number(parsed);
}

function encodeUnsigned(value, bytes, label) {
  const maximum = (1n << BigInt(bytes * 8)) - 1n;
  let current = asBigInt(value, label, maximum);
  const out = Buffer.alloc(bytes);
  for (let index = bytes - 1; index >= 0; index -= 1) {
    out[index] = Number(current & 0xffn);
    current >>= 8n;
  }
  return out;
}

const encodeU8 = (value) => encodeUnsigned(value, 1, 'u8');
const encodeU16 = (value) => encodeUnsigned(value, 2, 'u16');
const encodeU32 = (value) => encodeUnsigned(value, 4, 'u32');
const encodeU64 = (value) => encodeUnsigned(value, 8, 'u64');
const encodeU128 = (value) => encodeUnsigned(value, 16, 'u128');

function decodeUnsigned(bytes, label = 'unsigned integer') {
  const data = asBuffer(bytes, label, { maxLength: 16 });
  if (data.length === 0) throw new CodecError(`${label} cannot be empty`);
  let result = 0n;
  for (const octet of data) {
    result = (result << 8n) | BigInt(octet);
  }
  return result;
}

function encodeVarBytes(value, { maxLength = MAX_U16, label = 'field' } = {}) {
  const data = asBuffer(value, label, { maxLength: Number(maxLength) });
  if (data.length > Number(MAX_U16)) {
    throw new CodecError(`${label} is too large for a u16 length prefix`);
  }
  return Buffer.concat([encodeU16(data.length), data]);
}

function encodeUtf8(value, { maxLength = MAX_U16, label = 'field', allowEmpty = true } = {}) {
  if (typeof value !== 'string') {
    throw new CodecError(`${label} must be a string`);
  }
  if (!allowEmpty && value.length === 0) {
    throw new CodecError(`${label} cannot be empty`);
  }
  if (value !== value.normalize('NFC')) {
    throw new CodecError(`${label} must use Unicode NFC normalization`);
  }
  if (/[\p{Cc}\p{Cf}\uD800-\uDFFF]/u.test(value)) {
    throw new CodecError(`${label} contains NUL/control, formatting code point, or unpaired surrogate`);
  }
  return encodeVarBytes(Buffer.from(value, 'utf8'), { maxLength, label });
}

function encodeAscii(value, { maxLength = MAX_U16, label = 'field', allowEmpty = true } = {}) {
  if (typeof value !== 'string' || (!allowEmpty && value.length === 0)) {
    throw new CodecError(`${label} must be ${allowEmpty ? 'an ASCII string' : 'a non-empty ASCII string'}`);
  }
  if (!/^[\x20-\x7e]*$/.test(value)) {
    throw new CodecError(`${label} must contain printable ASCII only`);
  }
  return encodeVarBytes(Buffer.from(value, 'ascii'), { maxLength, label });
}

function decodeUtf8Strict(bytes, label = 'field') {
  const data = asBuffer(bytes, label);
  let decoded;
  try {
    decoded = FATAL_UTF8.decode(data);
  } catch (cause) {
    throw new CodecError(`${label} is not valid UTF-8`, { cause });
  }
  if (decoded !== decoded.normalize('NFC')) {
    throw new CodecError(`${label} is not Unicode NFC normalized`);
  }
  if (/[\p{Cc}\p{Cf}\uD800-\uDFFF]/u.test(decoded)) {
    throw new CodecError(`${label} contains NUL/control, formatting code point, or unpaired surrogate`);
  }
  if (!Buffer.from(decoded, 'utf8').equals(data)) {
    throw new CodecError(`${label} is not canonically encoded UTF-8`);
  }
  return decoded;
}

function decodeAsciiStrict(bytes, label = 'field', { allowEmpty = true } = {}) {
  const data = asBuffer(bytes, label);
  if ((!allowEmpty && data.length === 0) || !data.every((value) => value >= 0x20 && value <= 0x7e)) {
    throw new CodecError(`${label} must contain printable ASCII only`);
  }
  return data.toString('ascii');
}

function compareBytes(left, right) {
  return Buffer.compare(asBuffer(left, 'left'), asBuffer(right, 'right'));
}

function bytesEqual(left, right) {
  const first = asBuffer(left, 'left');
  const second = asBuffer(right, 'right');
  return first.length === second.length && first.equals(second);
}

function parseHex(value, { length, label = 'hex' } = {}) {
  if (typeof value !== 'string' || value.length % 2 !== 0 || !/^[0-9a-f]*$/.test(value)) {
    throw new CodecError(`${label} must be canonical lowercase hexadecimal`);
  }
  const out = Buffer.from(value, 'hex');
  if (length !== undefined && out.length !== length) {
    throw new CodecError(`${label} must encode exactly ${length} bytes`);
  }
  return out;
}

class BinaryWriter {
  #chunks = [];

  #length = 0;

  #maximum;

  constructor(maximum = LIMITS.RECORD_BYTES) {
    if (!Number.isSafeInteger(maximum) || maximum <= 0) {
      throw new CodecError('writer maximum must be a positive safe integer');
    }
    this.#maximum = maximum;
  }

  get length() {
    return this.#length;
  }

  write(value, label = 'bytes') {
    const chunk = asBuffer(value, label, { maxLength: this.#maximum });
    if (this.#length + chunk.length > this.#maximum) {
      throw new CodecError(`encoded record exceeds ${this.#maximum} bytes`);
    }
    this.#chunks.push(chunk);
    this.#length += chunk.length;
    return this;
  }

  u8(value) { return this.write(encodeU8(value), 'u8'); }

  u16(value) { return this.write(encodeU16(value), 'u16'); }

  u32(value) { return this.write(encodeU32(value), 'u32'); }

  u64(value) { return this.write(encodeU64(value), 'u64'); }

  u128(value) { return this.write(encodeU128(value), 'u128'); }

  varBytes(value, options) { return this.write(encodeVarBytes(value, options), options?.label); }

  utf8(value, options) { return this.write(encodeUtf8(value, options), options?.label); }

  ascii(value, options) { return this.write(encodeAscii(value, options), options?.label); }

  finish() {
    return Buffer.concat(this.#chunks, this.#length);
  }
}

class BinaryReader {
  #data;

  #offset = 0;

  constructor(value, { maxLength = LIMITS.RECORD_BYTES } = {}) {
    this.#data = asBuffer(value, 'record', { maxLength });
  }

  get offset() { return this.#offset; }

  get length() { return this.#data.length; }

  get remaining() { return this.#data.length - this.#offset; }

  read(length, label = 'field') {
    if (!Number.isSafeInteger(length) || length < 0 || this.#offset + length > this.#data.length) {
      throw new CodecError(`truncated ${label}`, {
        details: { offset: this.#offset, requested: length, remaining: this.remaining },
      });
    }
    const out = Buffer.from(this.#data.subarray(this.#offset, this.#offset + length));
    this.#offset += length;
    return out;
  }

  peek(length, label = 'field') {
    if (!Number.isSafeInteger(length) || length < 0 || this.#offset + length > this.#data.length) {
      throw new CodecError(`truncated ${label}`);
    }
    return Buffer.from(this.#data.subarray(this.#offset, this.#offset + length));
  }

  unsigned(bytes, label) { return decodeUnsigned(this.read(bytes, label), label); }

  u8(label = 'u8') { return Number(this.unsigned(1, label)); }

  u16(label = 'u16') { return Number(this.unsigned(2, label)); }

  u32(label = 'u32') { return Number(this.unsigned(4, label)); }

  u64(label = 'u64') { return this.unsigned(8, label); }

  u128(label = 'u128') { return this.unsigned(16, label); }

  varBytes({ maxLength = Number(MAX_U16), label = 'field' } = {}) {
    const length = this.u16(`${label} length`);
    if (length > maxLength) {
      throw new CodecError(`${label} exceeds its ${maxLength}-byte limit`);
    }
    return this.read(length, label);
  }

  utf8(options = {}) {
    const label = options.label || 'field';
    const out = decodeUtf8Strict(this.varBytes(options), label);
    if (options.allowEmpty === false && out.length === 0) {
      throw new CodecError(`${label} cannot be empty`);
    }
    return out;
  }

  ascii(options = {}) {
    const label = options.label || 'field';
    return decodeAsciiStrict(this.varBytes(options), label, options);
  }

  expect(value, label = 'constant') {
    const expected = Buffer.isBuffer(value) || value instanceof Uint8Array
      ? asBuffer(value, label)
      : Buffer.from(String(value), 'ascii');
    if (!this.read(expected.length, label).equals(expected)) {
      throw new CodecError(`invalid ${label}`);
    }
    return this;
  }

  eof() {
    if (this.remaining !== 0) {
      throw new CodecError(`unexpected ${this.remaining} trailing byte(s)`);
    }
    return true;
  }
}

module.exports = Object.freeze({
  asBuffer,
  asBigInt,
  asNumber,
  encodeUnsigned,
  encodeU8,
  encodeU16,
  encodeU32,
  encodeU64,
  encodeU128,
  decodeUnsigned,
  encodeVarBytes,
  encodeUtf8,
  encodeAscii,
  decodeUtf8Strict,
  decodeAsciiStrict,
  compareBytes,
  bytesEqual,
  parseHex,
  BinaryWriter,
  BinaryReader,
});
