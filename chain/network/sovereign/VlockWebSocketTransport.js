'use strict';

const EventEmitter = require('node:events');
const fs = require('node:fs');
const https = require('node:https');
const path = require('node:path');
const tls = require('node:tls');
const { createHash, randomBytes } = require('node:crypto');
const WebSocket = require('ws');
const {
  EnvelopeVerifier,
  NonceCounter,
  NonceReplayWindow,
  createEnvelope,
  encodeEnvelope,
} = require('../../vlock7sin-js/src/network');
const { canonicalBytes } = require('../../vlock7sin-js/src/causalGraph');
const { normalizePublicIdentity, verifyHybridSignature, HYBRID_POLICY, SIGNATURE_SCHEMA } = require('../../vlock7sin-js/src/hybridCrypto');

const REPLAY_SCHEMA = 'konaet-sovereign-replay-v1';
const NONCE_SCHEMA = 'konaet-sovereign-outbound-nonce-v1';
const HYBRID_TRANSPORT_SCHEMA = 'KONAET_HYBRID_TRANSPORT_FRAME_V1';
const HYBRID_TRANSPORT_PROFILE = 'ED25519_AND_ML_DSA_65_TRANSPORT_V1';
const HYBRID_BINARY_TRANSPORT_SCHEMA = 'KONAET_HYBRID_TRANSPORT_BINARY_FRAME_V2';
const HYBRID_BINARY_TRANSPORT_PROFILE = 'ED25519_AND_ML_DSA_65_TRANSPORT_BINARY_V2';
const HYBRID_BINARY_MAGIC = Buffer.from('KHTF', 'ascii');

class VlockTransportError extends Error {
  constructor(code, message, details = undefined) {
    super(message);
    this.name = 'VlockTransportError';
    this.code = code;
    if (details !== undefined) this.details = details;
  }
}

function safeReadJson(filePath, fallback, maximumBytes = 4 * 1024 * 1024) {
  if (!fs.existsSync(filePath)) return fallback;
  const stat = fs.statSync(filePath);
  if (!stat.isFile() || stat.size < 2 || stat.size > maximumBytes) {
    throw new VlockTransportError('INVALID_STATE_FILE', `Invalid transport state file: ${path.basename(filePath)}.`);
  }
  try { return JSON.parse(fs.readFileSync(filePath, 'utf8')); } catch (error) {
    throw new VlockTransportError('INVALID_STATE_FILE', `Cannot parse ${path.basename(filePath)}.`, { cause: error.message });
  }
}

function writeAll(fd, bytes) {
  let offset = 0;
  while (offset < bytes.length) {
    const count = fs.writeSync(fd, bytes, offset, bytes.length - offset);
    if (count < 1) throw new VlockTransportError('STATE_WRITE_FAILED', 'Filesystem made no write progress.');
    offset += count;
  }
}

function renameWithRetry(temporary, destination, dependencies = {}) {
  const rename = dependencies.rename || fs.renameSync;
  const wait = dependencies.wait || (milliseconds => Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, milliseconds));
  const delays = [5, 10, 20, 40, 80];
  for (let attempt = 0; ; attempt += 1) {
    try { rename(temporary, destination); return; } catch (error) {
      if (!['EPERM', 'EACCES', 'EBUSY'].includes(error.code) || attempt >= delays.length) throw error;
      wait(delays[attempt]);
    }
  }
}

function atomicJson(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
  const temporary = `${filePath}.${process.pid}.${randomBytes(8).toString('hex')}.tmp`;
  const bytes = Buffer.from(`${JSON.stringify(value)}\n`, 'utf8');
  let fd;
  try {
    fd = fs.openSync(temporary, 'wx', 0o600);
    writeAll(fd, bytes);
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    renameWithRetry(temporary, filePath);
    try {
      const directory = fs.openSync(path.dirname(filePath), 'r');
      try { fs.fsyncSync(directory); } finally { fs.closeSync(directory); }
    } catch { /* Directory fsync is not portable on Windows. */ }
  } catch (error) {
    if (fd !== undefined) try { fs.closeSync(fd); } catch { /* best effort */ }
    if (fs.existsSync(temporary)) try { fs.unlinkSync(temporary); } catch { /* best effort */ }
    if (error instanceof VlockTransportError) throw error;
    throw new VlockTransportError('STATE_WRITE_FAILED', `Cannot persist ${path.basename(filePath)}.`, { cause: error.message });
  }
}

function validatePath(filePath, dataDir, label) {
  const root = path.resolve(dataDir);
  const resolved = path.resolve(filePath);
  if (resolved !== root && !resolved.startsWith(`${root}${path.sep}`)) {
    throw new VlockTransportError('INVALID_PATH', `${label} must remain inside the node data directory.`);
  }
  return resolved;
}

function waitForOpen(socket, timeoutMs) {
  if (socket.readyState === WebSocket.OPEN) return Promise.resolve();
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      cleanup();
      reject(new VlockTransportError('CONNECT_TIMEOUT', 'WebSocket connection timed out.'));
    }, timeoutMs);
    const cleanup = () => {
      clearTimeout(timer);
      socket.off('open', onOpen);
      socket.off('error', onError);
    };
    const onOpen = () => { cleanup(); resolve(); };
    const onError = (error) => { cleanup(); reject(error); };
    socket.once('open', onOpen);
    socket.once('error', onError);
  });
}

function requiredTlsMaterial(value, label) {
  if ((!Buffer.isBuffer(value) && typeof value !== 'string') || value.length === 0) {
    throw new VlockTransportError('INVALID_TLS_CONFIG', `${label} is required for mutual TLS.`);
  }
  return value;
}

function certificateValidatorId(socket) {
  if (!socket || socket.authorized !== true || typeof socket.getPeerCertificate !== 'function') return null;
  const certificate = socket.getPeerCertificate();
  const commonName = String(certificate?.subject?.CN || '');
  return /^validator-[0-9]+$/.test(commonName) ? commonName : null;
}

class VlockWebSocketTransport extends EventEmitter {
  constructor(options = {}) {
    super();
    if (!options.identity || typeof options.identity.privateKeyObject !== 'function') {
      throw new VlockTransportError('INVALID_IDENTITY', 'VLOCK Ed25519 identity is required.');
    }
    this.identity = options.identity;
    this.validatorId = String(options.validatorId || '');
    this.networkId = String(options.networkId || '');
    this.protocolVersion = String(options.protocolVersion || '');
    this.genesisId = String(options.genesisId || '');
    this.transportSignatureProfile = options.transportSignatureProfile || null;
    if (this.transportSignatureProfile !== null
      && ![HYBRID_TRANSPORT_PROFILE, HYBRID_BINARY_TRANSPORT_PROFILE].includes(this.transportSignatureProfile)) {
      throw new VlockTransportError('INVALID_TRANSPORT_PROFILE', 'Transport signature profile is unsupported.');
    }
    this.hybridTransportRequired = this.transportSignatureProfile !== null;
    this.hybridTransportBinary = this.transportSignatureProfile === HYBRID_BINARY_TRANSPORT_PROFILE;
    this.hybridIdentity = options.hybridIdentity || null;
    this.dataDir = path.resolve(options.dataDir || '');
    if (!this.validatorId || !this.networkId || !this.protocolVersion || !/^[0-9a-f]{64}$/.test(this.genesisId)) {
      throw new VlockTransportError('INVALID_CONFIG', 'Transport identity, network, version and genesis are required.');
    }
    fs.mkdirSync(this.dataDir, { recursive: true, mode: 0o700 });
    this.replayPath = validatePath(options.replayPath || path.join(this.dataDir, 'network-replay.json'), this.dataDir, 'replayPath');
    this.noncePath = validatePath(options.noncePath || path.join(this.dataDir, 'network-nonce.json'), this.dataDir, 'noncePath');
    this.helloProvider = typeof options.helloProvider === 'function' ? options.helloProvider : () => ({});
    this.maxConnections = options.maxConnections ?? 128;
    this.maxBufferedBytes = options.maxBufferedBytes ?? 2 * 1024 * 1024;
    this.handshakeTimeoutMs = options.handshakeTimeoutMs ?? 5000;
    this.rateWindowMs = options.rateWindowMs ?? 10000;
    this.rateLimit = options.rateLimit ?? 256;
    this.tls = options.tls ? Object.freeze({
      ca: requiredTlsMaterial(options.tls.ca, 'TLS CA'),
      cert: requiredTlsMaterial(options.tls.cert, 'TLS certificate'),
      key: requiredTlsMaterial(options.tls.key, 'TLS private key'),
      minVersion: 'TLSv1.3',
    }) : null;
    for (const [label, value, minimum, maximum] of [
      ['maxConnections', this.maxConnections, 1, 1000],
      ['maxBufferedBytes', this.maxBufferedBytes, 1024, 64 * 1024 * 1024],
      ['handshakeTimeoutMs', this.handshakeTimeoutMs, 1000, 60000],
      ['rateWindowMs', this.rateWindowMs, 1000, 60000],
      ['rateLimit', this.rateLimit, 16, 4096],
    ]) {
      if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
        throw new VlockTransportError('INVALID_CONFIG', `${label} is outside its safe range.`);
      }
    }

    const replayFile = safeReadJson(this.replayPath, { schema: REPLAY_SCHEMA, scopes: {} });
    if (replayFile.schema !== REPLAY_SCHEMA || !replayFile.scopes || typeof replayFile.scopes !== 'object') {
      throw new VlockTransportError('INVALID_STATE_FILE', 'Replay state schema is invalid.');
    }
    this.replayState = replayFile.scopes;
    this.replay = new NonceReplayWindow({
      state: this.replayState,
      persist: (scope, state) => {
        this.replayState[scope] = state;
        atomicJson(this.replayPath, { schema: REPLAY_SCHEMA, scopes: this.replayState });
      },
    });
    const nonceFile = safeReadJson(this.noncePath, { schema: NONCE_SCHEMA, current: '-1' }, 4096);
    if (nonceFile.schema !== NONCE_SCHEMA || !/^-1$|^(?:0|[1-9][0-9]*)$/.test(String(nonceFile.current))) {
      throw new VlockTransportError('INVALID_STATE_FILE', 'Outbound nonce state is invalid.');
    }
    this.nonce = new NonceCounter(BigInt(nonceFile.current), (current) => {
      atomicJson(this.noncePath, { schema: NONCE_SCHEMA, current });
    });
    this.verifier = new EnvelopeVerifier({
      networkId: this.networkId,
      protocolVersion: this.protocolVersion,
      trustedKeys: options.trustedKeys,
      replay: this.replay,
      maxPayloadBytes: options.maxPayloadBytes ?? 8 * 1024 * 1024,
      maxEnvelopeBytes: options.maxEnvelopeBytes ?? 12 * 1024 * 1024,
      maxPastMs: options.maxPastMs ?? 5 * 60 * 1000,
      maxFutureMs: options.maxFutureMs ?? 30 * 1000,
    });
    this.maxEnvelopeBytes = options.maxEnvelopeBytes ?? 12 * 1024 * 1024;
    this.maxWireBytes = this.maxEnvelopeBytes + (this.hybridTransportRequired
      ? Math.ceil(this.maxEnvelopeBytes / 3) + 16 * 1024 : 0);
    this.trustedHybridIdentities = new Map();
    if (this.hybridTransportRequired) {
      if (!this.hybridIdentity || typeof this.hybridIdentity.publicIdentity !== 'function'
        || typeof this.hybridIdentity.sign !== 'function') {
        throw new VlockTransportError('HYBRID_IDENTITY_REQUIRED', 'Hybrid transport requires a validator ML-DSA identity.');
      }
      const identities = options.trustedHybridIdentities || {};
      for (const [validatorId, publicIdentity] of Object.entries(identities)) {
        try { this.trustedHybridIdentities.set(validatorId, normalizePublicIdentity(publicIdentity).identity); } catch (error) {
          throw new VlockTransportError('INVALID_HYBRID_TRUST', `Hybrid trust identity for ${validatorId} is invalid.`, { cause: error.message });
        }
      }
      const ownIdentity = this.trustedHybridIdentities.get(this.validatorId);
      if (!ownIdentity || !canonicalBytes(ownIdentity).equals(canonicalBytes(this.hybridIdentity.publicIdentity()))) {
        throw new VlockTransportError('HYBRID_IDENTITY_MISMATCH', 'Local hybrid transport identity differs from the genesis identity.');
      }
      const ownNormalized = normalizePublicIdentity(ownIdentity);
      const ownEd25519 = ownNormalized.keys.ed25519.export({ format: 'der', type: 'spki' }).subarray(-32);
      if (!Buffer.from(this.identity.publicBytes()).equals(ownEd25519)) {
        throw new VlockTransportError('HYBRID_IDENTITY_MISMATCH', 'Hybrid transport Ed25519 key differs from VLOCK identity.');
      }
    }
    this.server = null;
    this.listenerServer = null;
    this.connections = new Set();
    this.byPeer = new Map();
    this.metrics = { opened: 0, closed: 0, sent: 0, accepted: 0, denied: 0, rateLimited: 0, backpressured: 0 };
  }

  helloPayload() {
    return Object.freeze({
      kind: 'KONAET_SOVEREIGN_HELLO_V1',
      validatorId: this.validatorId,
      genesisId: this.genesisId,
      ...this.helloProvider(),
    });
  }

  async listen(options = {}) {
    if (this.server) return this.server.address();
    const host = options.host || '127.0.0.1';
    const port = Number(options.port ?? 0);
    await new Promise((resolve, reject) => {
      const listener = this.tls ? https.createServer({
        key: this.tls.key,
        cert: this.tls.cert,
        ca: this.tls.ca,
        requestCert: true,
        rejectUnauthorized: true,
        minVersion: this.tls.minVersion,
      }) : null;
      const server = this.tls
        ? new WebSocket.Server({ server: listener, maxPayload: this.maxWireBytes })
        : new WebSocket.Server({ host, port, maxPayload: this.maxWireBytes });
      server.once('listening', resolve);
      server.once('error', reject);
      server.on('connection', (socket, request) => this.attach(socket, {
        direction: 'inbound',
        tlsPeerId: this.tls ? certificateValidatorId(request?.socket) : null,
      }));
      this.server = server;
      this.listenerServer = listener;
      if (listener) {
        listener.once('error', reject);
        listener.listen(port, host);
      }
    });
    return this.server.address();
  }

  async connect(url, options = {}) {
    const expectedPeerId = options.expectedPeerId || null;
    const parsed = new URL(url);
    if (this.tls && parsed.protocol !== 'wss:') {
      throw new VlockTransportError('TLS_REQUIRED', 'Mutual TLS transport requires a wss:// endpoint.');
    }
    if (!this.tls && parsed.protocol !== 'ws:') {
      throw new VlockTransportError('UNEXPECTED_TLS', 'Plain local transport requires a ws:// endpoint.');
    }
    const socket = new WebSocket(url, {
      maxPayload: this.maxWireBytes,
      handshakeTimeout: this.handshakeTimeoutMs,
      ...(this.tls ? {
        key: this.tls.key,
        cert: this.tls.cert,
        ca: this.tls.ca,
        rejectUnauthorized: true,
        minVersion: this.tls.minVersion,
        checkServerIdentity: (hostname, certificate) => {
          const standardError = tls.checkServerIdentity(hostname, certificate);
          if (standardError) return standardError;
          if (expectedPeerId && certificate?.subject?.CN !== expectedPeerId) {
            return new Error(`TLS certificate identity does not match ${expectedPeerId}.`);
          }
          return undefined;
        },
      } : {}),
    });
    this.attach(socket, {
      direction: 'outbound',
      expectedPeerId,
      tlsPeerId: this.tls ? expectedPeerId : null,
    });
    await waitForOpen(socket, this.handshakeTimeoutMs);
    if (options.waitForHello !== false) await this.waitForPeer(options.expectedPeerId, this.handshakeTimeoutMs);
    return socket;
  }

  attach(socket, options = {}) {
    if (this.connections.size >= this.maxConnections) {
      socket.close(1013, 'connection limit');
      return null;
    }
    const record = {
      socket,
      direction: options.direction || 'unknown',
      expectedPeerId: options.expectedPeerId || null,
      tlsPeerId: options.tlsPeerId || null,
      peerId: null,
      hello: false,
      windowStartedAt: Date.now(),
      windowMessages: 0,
      handshakeTimer: null,
    };
    this.connections.add(record);
    record.handshakeTimer = setTimeout(() => {
      if (!record.hello) socket.close(1008, 'hello timeout');
    }, this.handshakeTimeoutMs);
    const onOpen = () => {
      this.metrics.opened += 1;
      try { this.sendRecord(record, 'HELLO', this.helloPayload(), { requireHello: false }); } catch (error) {
        this.emit('denied', { error, outbound: true });
        socket.close(1011, 'hello failed');
      }
    };
    socket.on('open', onOpen);
    if (socket.readyState === WebSocket.OPEN) onOpen();
    socket.on('message', (data, isBinary) => this.handleMessage(record, data, isBinary));
    socket.on('close', () => {
      clearTimeout(record.handshakeTimer);
      this.connections.delete(record);
      if (record.peerId && this.byPeer.get(record.peerId) === record) this.byPeer.delete(record.peerId);
      this.metrics.closed += 1;
      this.emit('peerClosed', { peerId: record.peerId });
    });
    socket.on('error', (error) => this.emit('socketError', { error, peerId: record.peerId }));
    return record;
  }

  rateAllowed(record) {
    const now = Date.now();
    if (now - record.windowStartedAt >= this.rateWindowMs) {
      record.windowStartedAt = now;
      record.windowMessages = 0;
    }
    record.windowMessages += 1;
    return record.windowMessages <= this.rateLimit;
  }

  handleMessage(record, data, isBinary) {
    try {
      if (!isBinary) throw new VlockTransportError('TEXT_FRAME_REFUSED', 'Sovereign transport accepts binary frames only.');
      if (!this.rateAllowed(record)) {
        this.metrics.rateLimited += 1;
        throw new VlockTransportError('RATE_LIMITED', 'Peer exceeded the message rate limit.');
      }
      let envelopeBytes = Buffer.from(data);
      let hybridSenderId = null;
      if (this.hybridTransportRequired) {
        const frame = this.decodeHybridFrame(envelopeBytes);
        envelopeBytes = frame.envelopeBytes;
        hybridSenderId = frame.senderId;
      }
      const verified = this.verifier.verify(envelopeBytes);
      if (hybridSenderId !== null && verified.senderId !== hybridSenderId) {
        throw new VlockTransportError('HYBRID_SENDER_MISMATCH', 'Hybrid frame signer differs from its VLOCK envelope sender.');
      }
      if (!record.hello && verified.type !== 'HELLO') {
        throw new VlockTransportError('HELLO_REQUIRED', 'Peer must complete HELLO before other messages.');
      }
      if (verified.type === 'HELLO') {
        const payload = verified.payload;
        if (!payload || payload.kind !== 'KONAET_SOVEREIGN_HELLO_V1'
          || payload.validatorId !== verified.senderId
          || payload.genesisId !== this.genesisId) {
          throw new VlockTransportError('HELLO_INVALID', 'Peer HELLO does not match sender or genesis.');
        }
        if (verified.senderId === this.validatorId) throw new VlockTransportError('SELF_CONNECTION', 'Self connection refused.');
        if (this.tls && record.tlsPeerId !== verified.senderId) {
          throw new VlockTransportError('TLS_IDENTITY_MISMATCH', 'mTLS certificate identity differs from VLOCK sender.');
        }
        if (record.expectedPeerId && record.expectedPeerId !== verified.senderId) {
          throw new VlockTransportError('UNEXPECTED_PEER', 'Connected peer id differs from expected peer.');
        }
        record.peerId = verified.senderId;
        record.hello = true;
        clearTimeout(record.handshakeTimer);
        this.byPeer.set(record.peerId, record);
        this.emit('peerReady', { peerId: record.peerId, payload, record });
      }
      this.metrics.accepted += 1;
      this.emit('message', { ...verified, record });
      this.emit(verified.type, { ...verified, record });
    } catch (error) {
      this.metrics.denied += 1;
      this.emit('denied', { error, peerId: record.peerId });
      record.socket.close(1008, String(error.code || 'protocol error').slice(0, 120));
    }
  }

  sendRecord(record, type, payload, options = {}) {
    if (!record || record.socket.readyState !== WebSocket.OPEN) {
      throw new VlockTransportError('SOCKET_NOT_OPEN', 'Peer socket is not open.');
    }
    if (options.requireHello !== false && !record.hello) {
      throw new VlockTransportError('HELLO_REQUIRED', 'Cannot send application data before HELLO.');
    }
    if (record.socket.bufferedAmount > this.maxBufferedBytes) {
      this.metrics.backpressured += 1;
      throw new VlockTransportError('BACKPRESSURE', 'Peer send buffer exceeded the configured limit.');
    }
    const envelope = createEnvelope({
      networkId: this.networkId,
      protocolVersion: this.protocolVersion,
      type,
      senderId: this.validatorId,
      nonce: this.nonce.next(),
      timestampMs: Date.now(),
      payload,
      privateKey: this.identity.privateKeyObject(),
    });
    const envelopeBytes = encodeEnvelope(envelope, { maxEnvelopeBytes: this.maxEnvelopeBytes });
    const wireBytes = this.hybridTransportRequired
      ? this.encodeHybridFrame(envelopeBytes)
      : envelopeBytes;
    record.socket.send(wireBytes, { binary: true });
    this.metrics.sent += 1;
    return envelope.id;
  }

  hybridTransportStatement(senderId, envelopeBytes) {
    return Object.freeze({
      profile: this.transportSignatureProfile,
      schema: this.hybridTransportBinary ? HYBRID_BINARY_TRANSPORT_SCHEMA : HYBRID_TRANSPORT_SCHEMA,
      version: this.hybridTransportBinary ? 2 : 1,
      networkId: this.networkId,
      protocolVersion: this.protocolVersion,
      genesisId: this.genesisId,
      senderId,
      envelopeBytesLength: envelopeBytes.length,
      envelopeSha3_512: createHash('sha3-512').update(envelopeBytes).digest('hex'),
    });
  }

  encodeHybridFrame(envelopeBytes) {
    const statement = this.hybridTransportStatement(this.validatorId, envelopeBytes);
    const signature = this.hybridIdentity.sign(canonicalBytes(statement));
    if (this.hybridTransportBinary) return this.encodeCompactHybridFrame(this.validatorId, envelopeBytes, signature);
    const frame = {
      schema: HYBRID_TRANSPORT_SCHEMA,
      version: 1,
      profile: this.transportSignatureProfile,
      senderId: this.validatorId,
      envelopeBase64: envelopeBytes.toString('base64'),
      signature,
    };
    const wireBytes = Buffer.from(JSON.stringify(frame), 'utf8');
    if (wireBytes.length > this.maxWireBytes) {
      throw new VlockTransportError('HYBRID_FRAME_TOO_LARGE', 'Hybrid transport frame exceeds the wire size limit.');
    }
    return wireBytes;
  }

  encodeCompactHybridFrame(senderId, envelopeBytes, signature) {
    const sender = Buffer.from(senderId, 'utf8');
    if (sender.length < 1 || sender.length > 255 || sender.toString('utf8') !== senderId
      || !Buffer.isBuffer(envelopeBytes) || envelopeBytes.length < 1 || envelopeBytes.length > this.maxEnvelopeBytes) {
      throw new VlockTransportError('HYBRID_FRAME_INVALID', 'Compact hybrid frame identity or envelope is invalid.');
    }
    const fingerprint = signature?.signerFingerprint;
    const digest = signature?.messageSha3_512;
    if (!/^[0-9a-f]{64}$/.test(String(fingerprint)) || !/^[0-9a-f]{128}$/.test(String(digest))) {
      throw new VlockTransportError('HYBRID_SIGNATURE_INVALID', 'Compact hybrid signature metadata is invalid.');
    }
    const decodeSignature = (value, label) => {
      if (typeof value !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
        throw new VlockTransportError('HYBRID_SIGNATURE_INVALID', `${label} is not canonical base64.`);
      }
      const decoded = Buffer.from(value, 'base64');
      if (!decoded.length || decoded.toString('base64') !== value) {
        throw new VlockTransportError('HYBRID_SIGNATURE_INVALID', `${label} is not canonical base64.`);
      }
      return decoded;
    };
    const ed25519 = decodeSignature(signature.ed25519Signature, 'Ed25519 signature');
    const mlDsa65 = decodeSignature(signature.mlDsa65Signature, 'ML-DSA-65 signature');
    if (ed25519.length !== 64 || mlDsa65.length > 0xffff) {
      throw new VlockTransportError('HYBRID_SIGNATURE_INVALID', 'Compact hybrid signature length is invalid.');
    }
    const header = Buffer.alloc(11);
    HYBRID_BINARY_MAGIC.copy(header, 0);
    header[4] = 2;
    header[5] = 2;
    header[6] = sender.length;
    header.writeUInt32BE(envelopeBytes.length, 7);
    const mlDsaLength = Buffer.alloc(2);
    mlDsaLength.writeUInt16BE(mlDsa65.length, 0);
    const wireBytes = Buffer.concat([header, sender, envelopeBytes,
      Buffer.from(fingerprint, 'hex'), Buffer.from(digest, 'hex'), ed25519, mlDsaLength, mlDsa65]);
    if (wireBytes.length > this.maxWireBytes) {
      throw new VlockTransportError('HYBRID_FRAME_TOO_LARGE', 'Compact hybrid frame exceeds the wire size limit.');
    }
    return wireBytes;
  }

  decodeCompactHybridFrame(wireBytes) {
    if (!Buffer.isBuffer(wireBytes) || wireBytes.length < 11 + 1 + 1 + 32 + 64 + 64 + 2
      || wireBytes.length > this.maxWireBytes || !wireBytes.subarray(0, 4).equals(HYBRID_BINARY_MAGIC)
      || wireBytes[4] !== 2 || wireBytes[5] !== 2) {
      throw new VlockTransportError('HYBRID_FRAME_REQUIRED', 'This genesis requires a version 2 compact hybrid frame.');
    }
    const senderLength = wireBytes[6];
    const envelopeLength = wireBytes.readUInt32BE(7);
    if (!senderLength || !envelopeLength || envelopeLength > this.maxEnvelopeBytes) {
      throw new VlockTransportError('HYBRID_FRAME_INVALID', 'Compact hybrid frame lengths are invalid.');
    }
    let offset = 11;
    const senderBytes = wireBytes.subarray(offset, offset + senderLength); offset += senderLength;
    if (senderBytes.length !== senderLength) throw new VlockTransportError('HYBRID_FRAME_INVALID', 'Compact frame sender length is truncated.');
    const senderId = senderBytes.toString('utf8');
    if (!senderId || !Buffer.from(senderId, 'utf8').equals(senderBytes)) {
      throw new VlockTransportError('HYBRID_FRAME_INVALID', 'Compact frame sender is not canonical UTF-8.');
    }
    const envelopeBytes = wireBytes.subarray(offset, offset + envelopeLength); offset += envelopeLength;
    if (envelopeBytes.length !== envelopeLength) throw new VlockTransportError('HYBRID_FRAME_INVALID', 'Compact frame envelope is truncated.');
    const fingerprint = wireBytes.subarray(offset, offset + 32); offset += 32;
    const messageHash = wireBytes.subarray(offset, offset + 64); offset += 64;
    const ed25519 = wireBytes.subarray(offset, offset + 64); offset += 64;
    if (fingerprint.length !== 32 || messageHash.length !== 64 || ed25519.length !== 64 || offset + 2 > wireBytes.length) {
      throw new VlockTransportError('HYBRID_FRAME_INVALID', 'Compact hybrid frame signature fields are truncated.');
    }
    const mlDsaLength = wireBytes.readUInt16BE(offset); offset += 2;
    const mlDsa65 = wireBytes.subarray(offset, offset + mlDsaLength); offset += mlDsaLength;
    if (!mlDsaLength || mlDsa65.length !== mlDsaLength || offset !== wireBytes.length) {
      throw new VlockTransportError('HYBRID_FRAME_INVALID', 'Compact hybrid frame has invalid ML-DSA length or trailing bytes.');
    }
    const signature = { schema: SIGNATURE_SCHEMA, version: 1, policy: HYBRID_POLICY,
      signerFingerprint: fingerprint.toString('hex'), messageSha3_512: messageHash.toString('hex'),
      ed25519Signature: ed25519.toString('base64'), mlDsa65Signature: mlDsa65.toString('base64') };
    const identity = this.trustedHybridIdentities.get(senderId);
    if (!identity) throw new VlockTransportError('HYBRID_SENDER_UNTRUSTED', 'Hybrid transport sender is not in the genesis roster.');
    const statement = this.hybridTransportStatement(senderId, envelopeBytes);
    if (!verifyHybridSignature(identity, canonicalBytes(statement), signature)) {
      throw new VlockTransportError('HYBRID_SIGNATURE_INVALID', 'Compact hybrid transport signature verification failed.');
    }
    return Object.freeze({ senderId, envelopeBytes });
  }

  decodeHybridFrame(wireBytes) {
    if (this.hybridTransportBinary) return this.decodeCompactHybridFrame(wireBytes);
    if (!Buffer.isBuffer(wireBytes) || wireBytes.length > this.maxWireBytes) {
      throw new VlockTransportError('HYBRID_FRAME_TOO_LARGE', 'Hybrid transport frame exceeds the wire size limit.');
    }
    let frame;
    try { frame = JSON.parse(wireBytes.toString('utf8')); } catch {
      throw new VlockTransportError('HYBRID_FRAME_REQUIRED', 'This genesis requires a hybrid-signed transport frame.');
    }
    const fields = ['schema', 'version', 'profile', 'senderId', 'envelopeBase64', 'signature'];
    if (!frame || typeof frame !== 'object' || Array.isArray(frame)
      || Object.keys(frame).sort().join('\0') !== [...fields].sort().join('\0')
      || frame.schema !== HYBRID_TRANSPORT_SCHEMA || frame.version !== 1
      || frame.profile !== this.transportSignatureProfile || typeof frame.senderId !== 'string'
      || typeof frame.envelopeBase64 !== 'string' || !frame.signature || typeof frame.signature !== 'object'
      || Array.isArray(frame.signature)) {
      throw new VlockTransportError('HYBRID_FRAME_REQUIRED', 'This genesis requires a canonical hybrid-signed transport frame.');
    }
    const signatureFields = ['schema', 'version', 'policy', 'signerFingerprint', 'messageSha3_512',
      'ed25519Signature', 'mlDsa65Signature'];
    const signature = frame.signature;
    if (Object.keys(signature).sort().join('\0') !== [...signatureFields].sort().join('\0')) {
      throw new VlockTransportError('HYBRID_SIGNATURE_INVALID', 'Hybrid transport signature has unexpected fields.');
    }
    const canonicalFrame = Buffer.from(JSON.stringify({
      schema: frame.schema,
      version: frame.version,
      profile: frame.profile,
      senderId: frame.senderId,
      envelopeBase64: frame.envelopeBase64,
      signature: Object.fromEntries(signatureFields.map((field) => [field, signature[field]])),
    }), 'utf8');
    if (!canonicalFrame.equals(wireBytes)) {
      throw new VlockTransportError('HYBRID_FRAME_NONCANONICAL', 'Hybrid transport frame encoding is not canonical.');
    }
    const encoded = frame.envelopeBase64;
    if (!encoded || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded)) {
      throw new VlockTransportError('HYBRID_ENVELOPE_ENCODING_INVALID', 'Hybrid transport envelope encoding is invalid.');
    }
    const envelopeBytes = Buffer.from(encoded, 'base64');
    if (!envelopeBytes.length || envelopeBytes.length > this.maxEnvelopeBytes || envelopeBytes.toString('base64') !== encoded) {
      throw new VlockTransportError('HYBRID_ENVELOPE_ENCODING_INVALID', 'Hybrid transport envelope encoding is invalid.');
    }
    const identity = this.trustedHybridIdentities.get(frame.senderId);
    if (!identity) throw new VlockTransportError('HYBRID_SENDER_UNTRUSTED', 'Hybrid transport sender is not in the genesis roster.');
    const statement = this.hybridTransportStatement(frame.senderId, envelopeBytes);
    if (!verifyHybridSignature(identity, canonicalBytes(statement), signature)) {
      throw new VlockTransportError('HYBRID_SIGNATURE_INVALID', 'Hybrid transport signature verification failed.');
    }
    return Object.freeze({ senderId: frame.senderId, envelopeBytes });
  }

  sendTo(peerId, type, payload) {
    const record = this.byPeer.get(String(peerId));
    if (!record) throw new VlockTransportError('PEER_NOT_CONNECTED', `Peer ${peerId} is not connected.`);
    return this.sendRecord(record, type, payload);
  }

  broadcast(type, payload) {
    const sent = [];
    const errors = [];
    for (const record of this.connections) {
      if (!record.hello || record.socket.readyState !== WebSocket.OPEN) continue;
      try { sent.push({ peerId: record.peerId, envelopeId: this.sendRecord(record, type, payload) }); } catch (error) {
        errors.push({ peerId: record.peerId, code: error.code || 'SEND_FAILED' });
      }
    }
    return Object.freeze({ sent: Object.freeze(sent), errors: Object.freeze(errors) });
  }

  waitForPeer(peerId, timeoutMs = 5000) {
    const expected = String(peerId || '');
    if (expected && this.byPeer.has(expected)) return Promise.resolve(this.byPeer.get(expected));
    if (!expected && this.byPeer.size) return Promise.resolve(this.byPeer.values().next().value);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        cleanup();
        reject(new VlockTransportError('HELLO_TIMEOUT', `Peer ${expected || '(any)'} did not complete HELLO.`));
      }, timeoutMs);
      const onReady = ({ peerId: readyId, record }) => {
        if (expected && readyId !== expected) return;
        cleanup();
        resolve(record);
      };
      const cleanup = () => { clearTimeout(timer); this.off('peerReady', onReady); };
      this.on('peerReady', onReady);
    });
  }

  async waitForPeers(count, timeoutMs = 10000) {
    if (!Number.isSafeInteger(count) || count < 0) throw new VlockTransportError('INVALID_COUNT', 'Peer count is invalid.');
    if (this.byPeer.size >= count) return this.byPeer.size;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        cleanup();
        reject(new VlockTransportError('PEER_COUNT_TIMEOUT', `Expected ${count} peers, found ${this.byPeer.size}.`));
      }, timeoutMs);
      const onReady = () => {
        if (this.byPeer.size < count) return;
        cleanup();
        resolve(this.byPeer.size);
      };
      const cleanup = () => { clearTimeout(timer); this.off('peerReady', onReady); };
      this.on('peerReady', onReady);
    });
  }

  status() {
    return Object.freeze({
      listening: Boolean(this.server),
      address: this.server ? this.server.address() : null,
      validatorId: this.validatorId,
      peers: Object.freeze([...this.byPeer.keys()].sort()),
      metrics: Object.freeze({ ...this.metrics }),
      security: this.hybridTransportRequired
        ? (this.hybridTransportBinary
          ? (this.tls ? 'mutual-tls-v1.3-plus-vlock-ed25519-plus-ml-dsa-65-compact-v2'
            : 'vlock-ed25519-plus-ml-dsa-65-compact-v2')
          : (this.tls ? 'mutual-tls-v1.3-plus-vlock-ed25519-plus-ml-dsa-65'
            : 'vlock-ed25519-plus-ml-dsa-65'))
        : this.tls ? 'mutual-tls-v1.3-plus-vlock-ed25519' : 'vlock-ed25519-only',
    });
  }

  async close() {
    for (const record of [...this.connections]) {
      clearTimeout(record.handshakeTimer);
      try { record.socket.terminate(); } catch { /* best effort */ }
    }
    this.connections.clear();
    this.byPeer.clear();
    if (this.server) {
      const server = this.server;
      this.server = null;
      await new Promise((resolve) => server.close(resolve));
    }
    if (this.listenerServer) {
      const listener = this.listenerServer;
      this.listenerServer = null;
      if (listener.listening) await new Promise((resolve) => listener.close(resolve));
    }
  }
}

module.exports = Object.freeze({ VlockWebSocketTransport, VlockTransportError, renameWithRetry });
