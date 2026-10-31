'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { createHash, randomBytes } = require('node:crypto');

const WAL_MAGIC = Buffer.from('V7WAL1\r\n', 'ascii');
const SNAPSHOT_MAGIC = Buffer.from('V7SNAP1\n', 'ascii');
const DOMAIN_WAL_FRAME = Buffer.from('VLOCK7SIN/WAL-FRAME/v1\0', 'ascii');
const DOMAIN_SNAPSHOT = Buffer.from('VLOCK7SIN/SNAPSHOT/v1\0', 'ascii');
const FRAME_HEADER_BYTES = 4 + 32;
const DEFAULT_MAX_FRAME_BYTES = 64 * 1024 * 1024;
const DEFAULT_MAX_SNAPSHOT_BYTES = 256 * 1024 * 1024;

class PersistenceError extends Error {
  constructor(code, message, details = undefined) {
    super(message);
    this.name = 'PersistenceError';
    this.code = code;
    if (details !== undefined) this.details = details;
  }
}

function digestFrame(domain, lengthBytes, payload) {
  return createHash('sha3-256').update(domain).update(lengthBytes).update(payload).digest();
}

function compareUtf8(left, right) {
  return Buffer.compare(Buffer.from(String(left), 'utf8'), Buffer.from(String(right), 'utf8'));
}

function encodeTagged(value, seen = new Set()) {
  if (value === null) return ['null'];
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) return ['bytes', Buffer.from(value).toString('hex')];
  switch (typeof value) {
  case 'string': return ['string', value];
  case 'boolean': return ['boolean', value];
  case 'bigint': return ['bigint', value.toString(10)];
  case 'number':
    if (!Number.isFinite(value) || Object.is(value, -0)) throw new PersistenceError('UNENCODABLE_RECORD', 'record numbers must be finite and cannot be -0');
    return ['number', value.toString(10)];
  case 'undefined': return ['undefined'];
  case 'object': break;
  default: throw new PersistenceError('UNENCODABLE_RECORD', `unsupported record value: ${typeof value}`);
  }
  if (seen.has(value)) throw new PersistenceError('UNENCODABLE_RECORD', 'record contains a cycle');
  seen.add(value);
  try {
    if (Array.isArray(value)) return ['array', value.map((item) => encodeTagged(item, seen))];
    if (value instanceof Date) return ['date', value.toISOString()];
    if (value instanceof Map) {
      const entries = [...value].map(([key, item]) => [encodeTagged(key, seen), encodeTagged(item, seen)]);
      entries.sort((a, b) => compareUtf8(JSON.stringify(a[0]), JSON.stringify(b[0])));
      for (let index = 1; index < entries.length; index += 1) {
        if (compareUtf8(JSON.stringify(entries[index - 1][0]), JSON.stringify(entries[index][0])) === 0) {
          throw new PersistenceError('UNENCODABLE_RECORD', 'map contains canonically duplicate keys');
        }
      }
      return ['map', entries];
    }
    if (value instanceof Set) {
      const entries = [...value].map((item) => encodeTagged(item, seen));
      entries.sort((a, b) => compareUtf8(JSON.stringify(a), JSON.stringify(b)));
      for (let index = 1; index < entries.length; index += 1) {
        if (compareUtf8(JSON.stringify(entries[index - 1]), JSON.stringify(entries[index])) === 0) {
          throw new PersistenceError('UNENCODABLE_RECORD', 'set contains canonically duplicate values');
        }
      }
      return ['set', entries];
    }
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new PersistenceError('UNENCODABLE_RECORD', 'records accept only plain objects and supported built-ins');
    }
    return ['object', Object.keys(value).sort(compareUtf8).map((key) => [key, encodeTagged(value[key], seen)])];
  } finally {
    seen.delete(value);
  }
}

function decodeTagged(node, context, depth = 0) {
  if (depth > context.maxDepth) throw new PersistenceError('RECORD_LIMIT_EXCEEDED', 'record nesting exceeds configured maximum');
  context.nodes += 1;
  if (context.nodes > context.maxNodes) throw new PersistenceError('RECORD_LIMIT_EXCEEDED', 'record node count exceeds configured maximum');
  if (!Array.isArray(node) || typeof node[0] !== 'string') throw new PersistenceError('INVALID_RECORD', 'invalid tagged record node');
  const [tag, body] = node;
  const expectedLength = tag === 'null' || tag === 'undefined' ? 1 : 2;
  if (node.length !== expectedLength) throw new PersistenceError('INVALID_RECORD', `invalid ${tag} node length`);
  switch (tag) {
  case 'null': return null;
  case 'undefined': return undefined;
  case 'string':
    if (typeof body !== 'string') throw new PersistenceError('INVALID_RECORD', 'invalid string encoding');
    return body;
  case 'boolean':
    if (typeof body !== 'boolean') throw new PersistenceError('INVALID_RECORD', 'invalid boolean encoding');
    return body;
  case 'bigint':
    if (!/^(0|-?[1-9][0-9]*)$/.test(body)) throw new PersistenceError('INVALID_RECORD', 'invalid BigInt encoding');
    return BigInt(body);
  case 'number': {
    const value = Number(body);
    if (!Number.isFinite(value) || Object.is(value, -0) || value.toString(10) !== body) {
      throw new PersistenceError('INVALID_RECORD', 'non-canonical number encoding');
    }
    return value;
  }
  case 'bytes':
    if (typeof body !== 'string' || body.length % 2 || !/^[0-9a-f]*$/.test(body)) throw new PersistenceError('INVALID_RECORD', 'invalid byte encoding');
    return Buffer.from(body, 'hex');
  case 'date': {
    const value = new Date(body);
    if (Number.isNaN(value.getTime()) || value.toISOString() !== body) throw new PersistenceError('INVALID_RECORD', 'invalid date encoding');
    return value;
  }
  case 'array':
    if (!Array.isArray(body)) throw new PersistenceError('INVALID_RECORD', 'invalid array encoding');
    return body.map((item) => decodeTagged(item, context, depth + 1));
  case 'set': {
    if (!Array.isArray(body)) throw new PersistenceError('INVALID_RECORD', 'invalid set encoding');
    for (let index = 1; index < body.length; index += 1) {
      if (compareUtf8(JSON.stringify(body[index - 1]), JSON.stringify(body[index])) >= 0) {
        throw new PersistenceError('INVALID_RECORD', 'set entries are duplicated or not bytewise sorted');
      }
    }
    return new Set(body.map((item) => decodeTagged(item, context, depth + 1)));
  }
  case 'map': {
    if (!Array.isArray(body)) throw new PersistenceError('INVALID_RECORD', 'invalid map encoding');
    for (let index = 1; index < body.length; index += 1) {
      if (!Array.isArray(body[index - 1]) || !Array.isArray(body[index])
          || compareUtf8(JSON.stringify(body[index - 1][0]), JSON.stringify(body[index][0])) >= 0) {
        throw new PersistenceError('INVALID_RECORD', 'map keys are duplicated or not bytewise sorted');
      }
    }
    return new Map(body.map((entry) => {
      if (!Array.isArray(entry) || entry.length !== 2) throw new PersistenceError('INVALID_RECORD', 'invalid map entry');
      return [decodeTagged(entry[0], context, depth + 1), decodeTagged(entry[1], context, depth + 1)];
    }));
  }
  case 'object': {
    if (!Array.isArray(body)) throw new PersistenceError('INVALID_RECORD', 'invalid object encoding');
    const output = Object.create(null);
    let previous = null;
    for (const entry of body) {
      if (!Array.isArray(entry) || entry.length !== 2 || typeof entry[0] !== 'string') throw new PersistenceError('INVALID_RECORD', 'invalid object entry');
      const key = entry[0];
      if (previous !== null && compareUtf8(key, previous) <= 0) throw new PersistenceError('INVALID_RECORD', 'object keys are duplicated or not bytewise sorted');
      previous = key;
      output[key] = decodeTagged(entry[1], context, depth + 1);
    }
    return output;
  }
  default: throw new PersistenceError('INVALID_RECORD', `unknown record tag: ${tag}`);
  }
}

function encodeRecord(value) {
  return Buffer.from(JSON.stringify(encodeTagged(value)), 'utf8');
}

function validateDecodeLimit(value, fallback, minimum, maximum, label) {
  const selected = value ?? fallback;
  if (!Number.isSafeInteger(selected) || selected < minimum || selected > maximum) {
    throw new PersistenceError('INVALID_LIMIT', `${label} must be in ${minimum}..${maximum}`);
  }
  return selected;
}

function assertJsonDepth(input, maxDepth) {
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (const byte of input) {
    if (inString) {
      if (escaped) escaped = false;
      else if (byte === 0x5c) escaped = true;
      else if (byte === 0x22) inString = false;
      continue;
    }
    if (byte === 0x22) inString = true;
    else if (byte === 0x5b || byte === 0x7b) {
      depth += 1;
      if (depth > maxDepth * 4 + 8) throw new PersistenceError('RECORD_LIMIT_EXCEEDED', 'JSON nesting exceeds configured maximum');
    } else if (byte === 0x5d || byte === 0x7d) {
      depth -= 1;
      if (depth < 0) throw new PersistenceError('INVALID_RECORD', 'unbalanced JSON structure');
    }
  }
  if (inString || depth !== 0) throw new PersistenceError('INVALID_RECORD', 'unterminated JSON structure');
}

function decodeRecord(bytes, options = {}) {
  const input = Buffer.from(bytes);
  const maxBytes = validateDecodeLimit(options.maxBytes, DEFAULT_MAX_FRAME_BYTES, 1, 0xffffffff, 'maxBytes');
  const maxDepth = validateDecodeLimit(options.maxDepth, 128, 1, 1024, 'maxDepth');
  const maxNodes = validateDecodeLimit(options.maxNodes, 1_000_000, 1, 10_000_000, 'maxNodes');
  if (input.length < 1 || input.length > maxBytes) throw new PersistenceError('RECORD_LIMIT_EXCEEDED', `record exceeds ${maxBytes} bytes`);
  assertJsonDepth(input, maxDepth);
  let parsed;
  try { parsed = JSON.parse(input.toString('utf8')); } catch (error) {
    throw new PersistenceError('INVALID_RECORD', 'record is not valid UTF-8 JSON', { cause: error.message });
  }
  const decoded = decodeTagged(parsed, { maxDepth, maxNodes, nodes: 0 });
  const canonical = encodeRecord(decoded);
  if (!canonical.equals(input)) throw new PersistenceError('INVALID_RECORD', 'record bytes are not in canonical tagged form');
  return decoded;
}

function validateMaxBytes(value) {
  if (!Number.isSafeInteger(value) || value < 1 || value > 0xffffffff) {
    throw new PersistenceError('INVALID_LIMIT', 'maxFrameBytes must be between 1 and 2^32-1');
  }
  return value;
}

function validateSnapshotMaxBytes(value) {
  if (!Number.isSafeInteger(value) || value < 1 || value > 0xffffffff) {
    throw new PersistenceError('INVALID_LIMIT', 'maxSnapshotBytes must be between 1 and 2^32-1');
  }
  return value;
}

function ensureParent(filePath) {
  fs.mkdirSync(path.dirname(path.resolve(filePath)), { recursive: true });
}

function writeAll(fd, buffer) {
  let offset = 0;
  while (offset < buffer.length) {
    const written = fs.writeSync(fd, buffer, offset, buffer.length - offset);
    if (written < 1) throw new PersistenceError('PARTIAL_WRITE', 'filesystem made no progress while writing');
    offset += written;
  }
}

function readAtMost(fd, buffer, position) {
  let offset = 0;
  while (offset < buffer.length) {
    const count = fs.readSync(fd, buffer, offset, buffer.length - offset, position + offset);
    if (count === 0) break;
    offset += count;
  }
  return offset;
}

function fingerprintFromStat(stat) {
  return `${stat.dev}:${stat.ino}:${stat.size}:${stat.mtimeNs}`;
}

function sourceFingerprint(filePath) {
  return fingerprintFromStat(fs.statSync(filePath, { bigint: true }));
}

// Node has no portable flock API. Cooperative writers therefore use an
// exclusive sidecar lock. A crash leaves the lock in place deliberately: an
// operator must verify the WAL/snapshot and remove the stale lock explicitly.
function acquireWriterLock(targetPath) {
  const lockPath = `${targetPath}.lock`;
  // Bind the cooperative lock to both the PID and this process incarnation.
  // Operating systems reuse PIDs, so a PID alone cannot prove that a surviving
  // process is the writer that originally created a stale sidecar.
  const processStartedAtMs = Math.max(0, Math.floor(Date.now() - (process.uptime() * 1000)));
  const token = Buffer.from(
    `v2:${process.pid}:${processStartedAtMs}:${randomBytes(24).toString('hex')}\n`,
    'ascii'
  );
  let fd;
  try { fd = fs.openSync(lockPath, 'wx', 0o600); } catch (error) {
    if (error.code === 'EEXIST') {
      throw new PersistenceError('WRITER_LOCKED', `another writer or stale lock owns ${lockPath}`);
    }
    throw error;
  }
  try {
    writeAll(fd, token);
    fs.fsyncSync(fd);
    return { path: lockPath, fd, token };
  } catch (error) {
    try { fs.closeSync(fd); } catch { /* best-effort cleanup */ }
    try { fs.unlinkSync(lockPath); } catch { /* best-effort cleanup */ }
    throw error;
  }
}

function releaseWriterLock(lock) {
  if (!lock) return;
  try { fs.closeSync(lock.fd); } catch { /* best-effort cleanup */ }
  try {
    const current = fs.readFileSync(lock.path);
    if (current.equals(lock.token)) fs.unlinkSync(lock.path);
  } catch {
    // Never remove a lock whose ownership cannot be proven.
  }
}

function recoverAbandonedWriterLock(targetPath) {
  const resolved = path.resolve(targetPath), lockPath = `${resolved}.lock`;
  if (!fs.existsSync(lockPath)) return null;
  // Serialize recovery attempts. Never reclaim an unknown/live owner, and never
  // delete the lock: preserve the exact abandoned token alongside the WAL.
  const recoveryPath = `${lockPath}.recovery`;
  let recoveryFd;
  try { recoveryFd = fs.openSync(recoveryPath, 'wx', 0o600); }
  catch (error) {
    if (error.code === 'EEXIST') throw new PersistenceError('LOCK_RECOVERY_BUSY', 'Another recovery or abandoned recovery marker requires inspection.');
    throw error;
  }
  try {
    if (!fs.existsSync(lockPath)) return null;
    const stat = fs.lstatSync(lockPath, { bigint: true });
    if (stat.isSymbolicLink() || !stat.isFile() || stat.size > 256n) throw new PersistenceError('LOCK_RECOVERY_REFUSED', 'Writer lock is not a bounded regular token.');
    const token = fs.readFileSync(lockPath);
    if (!Buffer.from(token.toString('ascii'), 'ascii').equals(token)) throw new PersistenceError('LOCK_RECOVERY_REFUSED', 'Writer token must be canonical ASCII.');
    const match = /^v2:([1-9][0-9]{0,9}):([0-9]{1,16}):([0-9a-f]{48})\n$/.exec(token.toString('ascii'));
    if (!match || !Number.isSafeInteger(Number(match[1]))) throw new PersistenceError('LOCK_RECOVERY_REFUSED', 'Unknown writer token; automatic recovery is forbidden.');
    try { process.kill(Number(match[1]), 0); throw new PersistenceError('WRITER_LOCKED', 'Writer PID is alive; its lock was preserved.'); }
    catch (error) { if (error.code !== 'ESRCH') throw error; }
    const walStat = fs.lstatSync(resolved);
    if (walStat.isSymbolicLink() || !walStat.isFile()) throw new PersistenceError('LOCK_RECOVERY_REFUSED', 'Recovery requires a regular WAL.');
    const report = recoverWal(resolved, { decodeRecords: true });
    if (!report.clean) throw new PersistenceError('LOCK_RECOVERY_REFUSED', 'WAL is incomplete or corrupt; preserve it for explicit recovery.');
    if (sourceFingerprint(resolved) !== report.scannedFingerprint
      || fingerprintFromStat(fs.lstatSync(lockPath, { bigint: true })) !== fingerprintFromStat(stat)
      || !fs.readFileSync(lockPath).equals(token)) throw new PersistenceError('LOCK_RECOVERY_REFUSED', 'WAL or lock changed during recovery.');
    const archive = `${lockPath}.abandoned-${randomBytes(16).toString('hex')}`;
    fs.renameSync(lockPath, archive);
    return Object.freeze({ recovered: true, archive: path.basename(archive), walBytes: report.scannedSize });
  } finally {
    fs.closeSync(recoveryFd);
    fs.unlinkSync(recoveryPath);
  }
}

class WalStore {
  constructor(filePath, options = {}) {
    if (!filePath) throw new PersistenceError('INVALID_PATH', 'WAL path is required');
    this.path = path.resolve(filePath);
    this.maxFrameBytes = validateMaxBytes(options.maxFrameBytes ?? DEFAULT_MAX_FRAME_BYTES);
    ensureParent(this.path);
    this.fd = null;
    this.lock = acquireWriterLock(this.path);
    try {
      let validatedFingerprint = null;
      let validatedSize = 0;
      if (fs.existsSync(this.path)) {
        const recovery = recoverWal(this.path, { maxFrameBytes: this.maxFrameBytes });
        if (!recovery.clean) {
          throw new PersistenceError('UNCLEAN_WAL', 'existing WAL is truncated or corrupt; append was refused', {
            truncated: recovery.truncated,
            corrupt: recovery.corrupt,
            issueOffset: recovery.issueOffset,
          });
        }
        validatedFingerprint = recovery.scannedFingerprint;
        validatedSize = recovery.lastValidOffset;
      }
      this.fd = fs.openSync(this.path, fs.existsSync(this.path) ? 'a+' : 'ax+', 0o600);
      if (validatedFingerprint !== null) {
        if (fingerprintFromStat(fs.fstatSync(this.fd, { bigint: true })) !== validatedFingerprint) {
          throw new PersistenceError('WAL_CHANGED', 'WAL changed after validation; append was refused');
        }
        this.endOffset = validatedSize;
      } else {
        writeAll(this.fd, WAL_MAGIC);
        fs.fsyncSync(this.fd);
        this.endOffset = WAL_MAGIC.length;
      }
    } catch (error) {
      if (this.fd != null) {
        try { fs.closeSync(this.fd); } catch { /* best-effort cleanup */ }
        this.fd = null;
      }
      releaseWriterLock(this.lock);
      this.lock = null;
      throw error;
    }
  }

  append(payload, options = {}) {
    if (this.fd == null) throw new PersistenceError('WAL_CLOSED', 'WAL is closed');
    const bytes = Buffer.isBuffer(payload) || payload instanceof Uint8Array
      ? Buffer.from(payload)
      : encodeRecord(payload);
    if (bytes.length > this.maxFrameBytes) throw new PersistenceError('FRAME_TOO_LARGE', `WAL frame exceeds ${this.maxFrameBytes} bytes`);
    const length = Buffer.alloc(4);
    length.writeUInt32BE(bytes.length);
    const hash = digestFrame(DOMAIN_WAL_FRAME, length, bytes);
    const frame = Buffer.concat([length, hash, bytes]);
    const before = fs.fstatSync(this.fd).size;
    if (before !== this.endOffset) {
      throw new PersistenceError('WAL_CHANGED', 'WAL size changed outside this single writer; append was refused');
    }
    const written = fs.writeSync(this.fd, frame, 0, frame.length, null);
    if (written !== frame.length) {
      fs.fsyncSync(this.fd);
      throw new PersistenceError('PARTIAL_WRITE', 'WAL append was incomplete; recovery will report a truncated tail', {
        expected: frame.length,
        written,
        offset: before,
      });
    }
    if (options.fsync !== false) fs.fsyncSync(this.fd);
    this.endOffset = before + frame.length;
    return Object.freeze({ offset: before, endOffset: before + frame.length, length: bytes.length, hash: hash.toString('hex') });
  }

  appendRecord(record, options = {}) { return this.append(encodeRecord(record), options); }

  readFrames(indexes, options = {}) {
    if (this.fd == null) throw new PersistenceError('WAL_CLOSED', 'WAL is closed');
    const maxBytes = validateDecodeLimit(options.maxBytes, 4 * 1024 * 1024, 1, DEFAULT_MAX_FRAME_BYTES, 'maxBytes');
    if (!Array.isArray(indexes) || indexes.length > 256) throw new PersistenceError('RECORD_LIMIT_EXCEEDED', 'Bounded WAL frame index required');
    let budget = 0;
    for (const frame of indexes) {
      if (!frame || !Number.isSafeInteger(frame.offset) || frame.offset < WAL_MAGIC.length
        || !Number.isSafeInteger(frame.length) || frame.length < 1
        || frame.endOffset !== frame.offset + FRAME_HEADER_BYTES + frame.length
        || frame.endOffset > this.endOffset || !/^[0-9a-f]{64}$/.test(frame.hash)) throw new PersistenceError('INVALID_FRAME_INDEX', 'Invalid WAL index entry');
      budget += FRAME_HEADER_BYTES + frame.length;
      if (budget > maxBytes) throw new PersistenceError('RECORD_LIMIT_EXCEEDED', 'Indexed WAL read exceeds byte budget');
    }
    if (fs.fstatSync(this.fd).size !== this.endOffset) throw new PersistenceError('WAL_CHANGED', 'WAL size changed outside its writer');
    const magic = Buffer.alloc(WAL_MAGIC.length);
    if (readAtMost(this.fd, magic, 0) !== magic.length || !magic.equals(WAL_MAGIC)) throw new PersistenceError('INVALID_WAL_MAGIC', 'Invalid WAL header');
    return indexes.map(frame => {
      const bytes = Buffer.alloc(FRAME_HEADER_BYTES + frame.length);
      if (readAtMost(this.fd, bytes, frame.offset) !== bytes.length || bytes.readUInt32BE(0) !== frame.length) throw new PersistenceError('WAL_CHANGED', 'Indexed WAL frame changed');
      const payload = bytes.subarray(FRAME_HEADER_BYTES), hash = digestFrame(DOMAIN_WAL_FRAME, bytes.subarray(0, 4), payload);
      if (!hash.equals(bytes.subarray(4, FRAME_HEADER_BYTES)) || hash.toString('hex') !== frame.hash) throw new PersistenceError('INVALID_RECORD', 'Indexed WAL checksum mismatch');
      return decodeRecord(payload, { maxBytes });
    });
  }

  recover(options = {}) { return recoverWal(this.path, { maxFrameBytes: this.maxFrameBytes, ...options }); }

  close() {
    if (this.fd != null) {
      fs.closeSync(this.fd);
      this.fd = null;
      releaseWriterLock(this.lock);
      this.lock = null;
    }
  }
}

function recoverWal(filePath, options = {}) {
  const resolved = path.resolve(filePath);
  const maxFrameBytes = validateMaxBytes(options.maxFrameBytes ?? DEFAULT_MAX_FRAME_BYTES);
  const decodeRecords = options.decodeRecords === true;
  const fd = fs.openSync(resolved, 'r');
  try {
    const stat = fs.fstatSync(fd);
    const size = stat.size;
    const reportBase = {
      path: resolved,
      scannedSize: size,
      scannedFingerprint: fingerprintFromStat(fs.fstatSync(fd, { bigint: true })),
    };
    const frames = [];
    const magic = Buffer.alloc(WAL_MAGIC.length);
    const magicRead = readAtMost(fd, magic, 0);
    if (magicRead < WAL_MAGIC.length) {
      return Object.freeze({ ...reportBase, clean: false, truncated: true, corrupt: false, issueOffset: 0, lastValidOffset: 0, frames: Object.freeze([]) });
    }
    if (!magic.equals(WAL_MAGIC)) throw new PersistenceError('INVALID_WAL_MAGIC', 'file is not a VLOCK7SIN WAL');

    let position = WAL_MAGIC.length;
    let index = 0;
    while (position < size) {
      if (size - position < FRAME_HEADER_BYTES) {
        return Object.freeze({ ...reportBase, clean: false, truncated: true, corrupt: false, issueOffset: position, lastValidOffset: position, frames: Object.freeze(frames) });
      }
      const header = Buffer.alloc(FRAME_HEADER_BYTES);
      if (readAtMost(fd, header, position) !== header.length) {
        return Object.freeze({ ...reportBase, clean: false, truncated: true, corrupt: false, issueOffset: position, lastValidOffset: position, frames: Object.freeze(frames) });
      }
      const length = header.readUInt32BE(0);
      if (length > maxFrameBytes) {
        return Object.freeze({ ...reportBase, clean: false, truncated: false, corrupt: true, issueOffset: position, lastValidOffset: position, reason: 'FRAME_TOO_LARGE', frames: Object.freeze(frames) });
      }
      const endOffset = position + FRAME_HEADER_BYTES + length;
      if (endOffset > size) {
        return Object.freeze({ ...reportBase, clean: false, truncated: true, corrupt: false, issueOffset: position, lastValidOffset: position, frames: Object.freeze(frames) });
      }
      const payload = Buffer.alloc(length);
      if (length && readAtMost(fd, payload, position + FRAME_HEADER_BYTES) !== length) {
        return Object.freeze({ ...reportBase, clean: false, truncated: true, corrupt: false, issueOffset: position, lastValidOffset: position, frames: Object.freeze(frames) });
      }
      const lengthBytes = header.subarray(0, 4);
      const storedHash = header.subarray(4);
      const actualHash = digestFrame(DOMAIN_WAL_FRAME, lengthBytes, payload);
      if (!actualHash.equals(storedHash)) {
        return Object.freeze({ ...reportBase, clean: false, truncated: false, corrupt: true, issueOffset: position, lastValidOffset: position, reason: 'HASH_MISMATCH', frames: Object.freeze(frames) });
      }
      const frame = { index, offset: position, endOffset, length, hash: actualHash.toString('hex'), payload };
      if (decodeRecords) {
        try { frame.record = decodeRecord(payload); } catch (error) {
          return Object.freeze({ ...reportBase, clean: false, truncated: false, corrupt: true, issueOffset: position, lastValidOffset: position, reason: 'INVALID_RECORD', error, frames: Object.freeze(frames) });
        }
      }
      frames.push(Object.freeze(frame));
      position = endOffset;
      index += 1;
    }
    return Object.freeze({ ...reportBase, clean: true, truncated: false, corrupt: false, issueOffset: null, lastValidOffset: position, frames: Object.freeze(frames) });
  } finally {
    fs.closeSync(fd);
  }
}

function truncateIncompleteWal(report) {
  if (!report || report.corrupt || !report.truncated) {
    throw new PersistenceError('UNSAFE_TRUNCATION', 'only a positively identified incomplete WAL tail may be truncated');
  }
  const resolved = path.resolve(report.path);
  const writerLock = acquireWriterLock(resolved);
  try {
    const stat = fs.statSync(resolved, { bigint: true });
    if (Number(stat.size) !== report.scannedSize
      || !report.scannedFingerprint
      || fingerprintFromStat(stat) !== report.scannedFingerprint) {
      throw new PersistenceError('WAL_CHANGED', 'WAL changed after recovery scan; refusing truncation');
    }
    if (!Number.isSafeInteger(report.lastValidOffset) || report.lastValidOffset < WAL_MAGIC.length) {
      throw new PersistenceError('UNSAFE_TRUNCATION', 'WAL has no validated header to preserve');
    }
    const fd = fs.openSync(resolved, 'r+');
    try {
      fs.ftruncateSync(fd, report.lastValidOffset);
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    return report.lastValidOffset;
  } finally {
    releaseWriterLock(writerLock);
  }
}

function snapshotFrame(payload) {
  if (payload.length > 0xffffffff) throw new PersistenceError('SNAPSHOT_TOO_LARGE', 'snapshot payload exceeds u32 length');
  const length = Buffer.alloc(4);
  length.writeUInt32BE(payload.length);
  const hash = digestFrame(DOMAIN_SNAPSHOT, length, payload);
  return { frame: Buffer.concat([SNAPSHOT_MAGIC, length, hash, payload]), hash };
}

function readSnapshot(filePath, options = {}) {
  const resolved = path.resolve(filePath);
  const maxSnapshotBytes = validateSnapshotMaxBytes(options.maxSnapshotBytes ?? DEFAULT_MAX_SNAPSHOT_BYTES);
  const stat = fs.statSync(resolved);
  const maximumFileBytes = SNAPSHOT_MAGIC.length + FRAME_HEADER_BYTES + maxSnapshotBytes;
  if (!Number.isSafeInteger(stat.size) || stat.size > maximumFileBytes) {
    throw new PersistenceError('SNAPSHOT_TOO_LARGE', `snapshot exceeds ${maxSnapshotBytes} payload bytes`);
  }
  const bytes = fs.readFileSync(resolved);
  if (bytes.length !== stat.size) throw new PersistenceError('SNAPSHOT_CHANGED', 'snapshot changed while it was being read');
  if (bytes.length < SNAPSHOT_MAGIC.length + FRAME_HEADER_BYTES || !bytes.subarray(0, SNAPSHOT_MAGIC.length).equals(SNAPSHOT_MAGIC)) {
    throw new PersistenceError('INVALID_SNAPSHOT', 'snapshot header is missing or invalid');
  }
  const headerOffset = SNAPSHOT_MAGIC.length;
  const length = bytes.readUInt32BE(headerOffset);
  if (length > maxSnapshotBytes) throw new PersistenceError('SNAPSHOT_TOO_LARGE', `snapshot exceeds ${maxSnapshotBytes} payload bytes`);
  const expectedSize = SNAPSHOT_MAGIC.length + FRAME_HEADER_BYTES + length;
  if (bytes.length !== expectedSize) throw new PersistenceError('INVALID_SNAPSHOT', 'snapshot length does not match file size');
  const lengthBytes = bytes.subarray(headerOffset, headerOffset + 4);
  const storedHash = bytes.subarray(headerOffset + 4, headerOffset + FRAME_HEADER_BYTES);
  const payload = bytes.subarray(headerOffset + FRAME_HEADER_BYTES);
  const actualHash = digestFrame(DOMAIN_SNAPSHOT, lengthBytes, payload);
  if (!actualHash.equals(storedHash)) throw new PersistenceError('INVALID_SNAPSHOT', 'snapshot SHA3 integrity check failed');
  return Object.freeze({
    path: resolved,
    hash: actualHash.toString('hex'),
    payload: Buffer.from(payload),
    value: options.decodeRecord === false ? undefined : decodeRecord(payload),
  });
}

function writeSnapshotAtomic(filePath, value, options = {}) {
  const resolved = path.resolve(filePath);
  ensureParent(resolved);
  const maxSnapshotBytes = validateSnapshotMaxBytes(options.maxSnapshotBytes ?? DEFAULT_MAX_SNAPSHOT_BYTES);
  const writerLock = acquireWriterLock(resolved);
  let priorFingerprint = null;
  let previous = null;
  let payload = null;
  let frame = null;
  let hash = null;
  let temporary = null;
  let fd = null;
  try {
    if (fs.existsSync(resolved)) {
      priorFingerprint = sourceFingerprint(resolved);
      try { previous = readSnapshot(resolved, { decodeRecord: false, maxSnapshotBytes }); } catch (error) {
        throw new PersistenceError('SOURCE_SNAPSHOT_INVALID', 'existing snapshot is invalid and was not overwritten', { cause: error.message });
      }
      if (options.expectedPreviousHash && previous.hash !== String(options.expectedPreviousHash).toLowerCase()) {
        throw new PersistenceError('SNAPSHOT_CAS_MISMATCH', 'existing snapshot hash differs from expectedPreviousHash');
      }
    } else if (options.expectedPreviousHash) {
      throw new PersistenceError('SNAPSHOT_CAS_MISMATCH', 'expected a previous snapshot but none exists');
    }

    payload = Buffer.isBuffer(value) || value instanceof Uint8Array ? Buffer.from(value) : encodeRecord(value);
    if (payload.length > maxSnapshotBytes) throw new PersistenceError('SNAPSHOT_TOO_LARGE', `snapshot exceeds ${maxSnapshotBytes} payload bytes`);
    ({ frame, hash } = snapshotFrame(payload));
    temporary = `${resolved}.${process.pid}.${randomBytes(8).toString('hex')}.tmp`;
    fd = fs.openSync(temporary, 'wx', 0o600);
    writeAll(fd, frame);
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = null;
    const verified = readSnapshot(temporary, { decodeRecord: false, maxSnapshotBytes });
    if (verified.hash !== hash.toString('hex')) throw new PersistenceError('TEMP_SNAPSHOT_INVALID', 'temporary snapshot failed verification');

    if (priorFingerprint !== null) {
      if (!fs.existsSync(resolved) || sourceFingerprint(resolved) !== priorFingerprint) {
        throw new PersistenceError('SNAPSHOT_CHANGED', 'source snapshot changed during write; refusing replacement');
      }
    } else if (fs.existsSync(resolved)) {
      throw new PersistenceError('SNAPSHOT_CHANGED', 'snapshot appeared during write; refusing replacement');
    }
    fs.renameSync(temporary, resolved);
    try {
      const directoryFd = fs.openSync(path.dirname(resolved), 'r');
      try { fs.fsyncSync(directoryFd); } finally { fs.closeSync(directoryFd); }
    } catch {
      // Directory fsync is unavailable on some Windows/filesystem combinations.
    }
    return Object.freeze({ path: resolved, hash: hash.toString('hex'), previousHash: previous?.hash ?? null, bytes: payload.length });
  } catch (error) {
    if (fd != null) fs.closeSync(fd);
    if (temporary && fs.existsSync(temporary)) fs.unlinkSync(temporary);
    if (error instanceof PersistenceError) throw error;
    throw new PersistenceError('SNAPSHOT_WRITE_FAILED', 'atomic snapshot write failed; original was preserved', { cause: error.message });
  } finally {
    releaseWriterLock(writerLock);
  }
}

class SnapshotStore {
  constructor(filePath) { this.path = path.resolve(filePath); }
  read(options = {}) { return readSnapshot(this.path, options); }
  write(value, options = {}) { return writeSnapshotAtomic(this.path, value, options); }
}

module.exports = {
  WAL_MAGIC,
  SNAPSHOT_MAGIC,
  DEFAULT_MAX_SNAPSHOT_BYTES,
  PersistenceError,
  WalStore,
  SnapshotStore,
  encodeRecord,
  decodeRecord,
  recoverWal,
  recoverAbandonedWriterLock,
  truncateIncompleteWal,
  readSnapshot,
  writeSnapshotAtomic,
};
