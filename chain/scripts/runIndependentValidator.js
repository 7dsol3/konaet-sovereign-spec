'use strict';

// One private testnet validator per operator. Never loads the production keyring or SQL.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const http = require('node:http');
const net = require('node:net');
const path = require('node:path');
const { crypto: vcrypto, HybridIdentity } = require('../vlock7sin-js/src');
const { canonicalBytes } = require('../vlock7sin-js/src/causalGraph');
const { SovereignNode, validateGenesis, HYBRID_PROFILE } = require('../network/sovereign');

function privateAddress(host) {
  if (net.isIP(host) !== 4) return false;
  const [a, b] = host.split('.').map(Number);
  return a === 127 || a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
}

function validateShape(config) {
  const allowed = ['schema', 'scope', 'mutualTlsRequired', 'host', 'validatorId', 'genesisSha256',
    'port', 'statusPort', 'peers', 'genesisFile', 'seedFile', 'consensusIdentityFile',
    'caFile', 'certificateFile', 'tlsKeyFile', 'submitTokenFile', 'dataDirectory'];
  assert.ok(config && typeof config === 'object' && !Array.isArray(config), 'INVALID_CONFIG_OBJECT');
  assert.ok(Object.keys(config).every(key => allowed.includes(key)), 'UNEXPECTED_CONFIG_FIELD');
  assert.equal(config.schema, 'konaet.independent-validator.config.v1');
  assert.equal(config.scope, 'private-testnet-no-value');
  assert.equal(config.mutualTlsRequired, true, 'MUTUAL_TLS_REQUIRED');
  assert.ok(privateAddress(config.host), 'PRIVATE_INTERFACE_REQUIRED');
  assert.match(config.validatorId, /^validator-[0-9]+$/);
  assert.match(config.genesisSha256, /^[a-f0-9]{64}$/);
  for (const field of ['port', 'statusPort']) assert.ok(Number.isSafeInteger(config[field]) && config[field] >= 1024 && config[field] <= 65535);
  assert.notEqual(config.port, config.statusPort);
  assert.ok(Array.isArray(config.peers) && config.peers.length >= 2 && config.peers.length <= 63);
  assert.equal(new Set(config.peers.map(row => row.validatorId)).size, config.peers.length);
  for (const row of config.peers) {
    assert.match(row.validatorId, /^validator-[0-9]+$/);
    assert.notEqual(row.validatorId, config.validatorId);
    const url = new URL(row.url);
    assert.equal(url.protocol, 'wss:', 'WSS_REQUIRED');
    assert.ok(privateAddress(url.hostname), 'PRIVATE_PEER_REQUIRED');
    assert.ok(Number.isSafeInteger(Number(url.port)) && Number(url.port) >= 1024 && Number(url.port) <= 65535, 'EXPLICIT_PEER_PORT_REQUIRED');
    assert.ok(!url.username && !url.password && !url.search && !url.hash && url.pathname === '/');
  }
  return config;
}

function readConfiguration(file) {
  const absolute = path.resolve(file), base = path.dirname(absolute);
  assert.ok(fs.statSync(absolute).size <= 65536);
  const config = validateShape(JSON.parse(fs.readFileSync(absolute, 'utf8')));
  function owned(relative, maximum) {
    assert.ok(typeof relative === 'string' && !path.isAbsolute(relative) && !relative.includes(':') && !relative.split(/[\\/]/).includes('..'));
    const target = path.resolve(base, relative);
    assert.ok(target.startsWith(base + path.sep), 'OPERATOR_DIRECTORY_REQUIRED');
    for (let cursor = target; cursor !== base; cursor = path.dirname(cursor)) {
      if (fs.existsSync(cursor)) assert.equal(fs.lstatSync(cursor).isSymbolicLink(), false, 'OPERATOR_SYMLINK_REFUSED');
    }
    if (maximum) assert.ok(fs.statSync(target).isFile() && fs.statSync(target).size <= maximum);
    return target;
  }
  const genesisBytes = fs.readFileSync(owned(config.genesisFile, 262144));
  assert.equal(crypto.createHash('sha256').update(genesisBytes).digest('hex'), config.genesisSha256);
  const genesis = validateGenesis(JSON.parse(genesisBytes.toString('utf8')));
  assert.ok(genesis.validators.some(row => row.id === config.validatorId));
  assert.equal(config.peers.length, genesis.validators.length - 1, 'COMPLETE_PEER_ROSTER_REQUIRED');
  assert.ok(config.peers.every(peer => genesis.validators.some(row => row.id === peer.validatorId)));
  const seedText = fs.readFileSync(owned(config.seedFile, 128), 'utf8').trim();
  assert.match(seedText, /^[a-f0-9]{64}$/);
  const seed = Buffer.from(seedText, 'hex');
  let identity;
  try { identity = vcrypto.IdentityKeypair.fromSeed(seed); } finally { seed.fill(0); }
  const validator = genesis.validators.find(row => row.id === config.validatorId);
  assert.equal(identity.publicBytes().toString('hex'), validator.publicKey);
  let consensusIdentity = null;
  if (genesis.consensusSignatureProfile === HYBRID_PROFILE) {
    assert.ok(typeof config.consensusIdentityFile === 'string', 'HYBRID_CONSENSUS_SECRET_REQUIRED');
    const secret = JSON.parse(fs.readFileSync(owned(config.consensusIdentityFile, 32768), 'utf8'));
    assert.deepEqual(Object.keys(secret).sort(), ['mlDsa65PrivateKeyPkcs8', 'mlKem768PrivateKeyPkcs8',
      'publicIdentityFingerprint', 'schema', 'validatorId'].sort(), 'INVALID_HYBRID_CONSENSUS_SECRET_FIELDS');
    assert.equal(secret.schema, 'konaet.operator-hybrid-consensus-secret.v1');
    assert.equal(secret.validatorId, config.validatorId);
    assert.equal(secret.publicIdentityFingerprint, validator.publicIdentity?.fingerprint);
    const privateKey = (text, label) => {
      assert.equal(typeof text, 'string', `${label}_REQUIRED`);
      const bytes = Buffer.from(text, 'base64');
      assert.ok(bytes.length > 0 && bytes.toString('base64') === text, `${label}_INVALID_BASE64`);
      try { return crypto.createPrivateKey({ key: bytes, format: 'der', type: 'pkcs8' }); }
      finally { bytes.fill(0); }
    };
    consensusIdentity = new HybridIdentity({
      ed25519PrivateKey: identity.privateKeyObject(),
      mlDsa65PrivateKey: privateKey(secret.mlDsa65PrivateKeyPkcs8, 'ML_DSA_65_PRIVATE_KEY'),
      mlKem768PrivateKey: privateKey(secret.mlKem768PrivateKeyPkcs8, 'ML_KEM_768_PRIVATE_KEY'),
    });
    assert.ok(canonicalBytes(consensusIdentity.publicIdentity()).equals(canonicalBytes(validator.publicIdentity)),
      'HYBRID_CONSENSUS_IDENTITY_MISMATCH');
  } else {
    assert.equal(config.consensusIdentityFile, undefined, 'UNEXPECTED_HYBRID_CONSENSUS_SECRET');
  }
  const tls = { ca: fs.readFileSync(owned(config.caFile, 16384)), cert: fs.readFileSync(owned(config.certificateFile, 16384)),
    key: fs.readFileSync(owned(config.tlsKeyFile, 16384)) };
  const cert = new crypto.X509Certificate(tls.cert), ca = new crypto.X509Certificate(tls.ca);
  assert.ok(cert.subject.split('\n').includes(`CN=${config.validatorId}`), 'CERTIFICATE_VALIDATOR_MISMATCH');
  assert.equal(cert.verify(ca.publicKey), true, 'CERTIFICATE_CA_MISMATCH');
  assert.equal(cert.checkPrivateKey(crypto.createPrivateKey(tls.key)), true, 'CERTIFICATE_KEY_MISMATCH');
  assert.ok(cert.checkIP(config.host), 'CERTIFICATE_INTERFACE_MISMATCH');
  assert.ok(Date.parse(cert.validFrom) <= Date.now() && Date.parse(cert.validTo) > Date.now(), 'CERTIFICATE_EXPIRED');
  assert.ok(ca.ca && !cert.ca && Date.parse(ca.validFrom) <= Date.now() && Date.parse(ca.validTo) > Date.now(), 'INVALID_CA_OR_LEAF');
  const submitToken = fs.readFileSync(owned(config.submitTokenFile, 128), 'utf8').trim();
  assert.match(submitToken, /^[a-f0-9]{64}$/);
  return { config, genesis, identity, consensusIdentity, tls, submitToken, dataDir: owned(config.dataDirectory), base };
}

async function start(file) {
  const loaded = readConfiguration(file);
  const { config, genesis, identity, consensusIdentity, tls, dataDir, submitToken } = loaded;
  const node = new SovereignNode({ genesis, validatorId: config.validatorId, identity, consensusIdentity,
    dataDir, automaticConsensus: true, transportTls: tls });
  const errors = [];
  node.on('protocolError', () => { if (errors.length < 20) errors.push('PROTOCOL_ERROR'); });
  const connecting = new Set();
  let closing = false;
  const status = () => ({ schema: 'konaet.independent-validator-status.v1', scope: config.scope,
    validatorId: config.validatorId, genesisId: genesis.genesisId,
    hybridTransferAuthorizationRequired: node.ledger.requireHybridTransferAuthorization,
    hybridTransportSignatureRequired: node.transport.hybridTransportRequired,
    ...node.status(),
    allValidatorKeysLoaded: false, administrativeIndependenceVerified: false,
    publicNetwork: false, monetaryValue: false, errors: [...errors] });
  let submitWindow = Date.now(), submissions = 0;
  const server = http.createServer(async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Content-Type', 'application/json');
    if (req.method === 'GET' && req.url === '/status') { res.end(JSON.stringify(status())); return; }
    if (req.method !== 'POST' || req.url !== '/submit') { res.writeHead(404).end(); return; }
    const provided = Buffer.from(String(req.headers.authorization || '').replace(/^Bearer /, ''));
    const expected = Buffer.from(submitToken);
    if (provided.length !== expected.length || !crypto.timingSafeEqual(provided, expected)) {
      req.resume(); res.writeHead(403).end(JSON.stringify({ code: 'OPERATOR_TOKEN_REQUIRED' })); return;
    }
    if (Date.now() - submitWindow > 60000) { submitWindow = Date.now(); submissions = 0; }
    if (++submissions > 10) { req.resume(); res.writeHead(429).end(); return; }
    const hybridRequired = node.ledger.requireHybridTransferAuthorization;
    const expectedContentType = hybridRequired ? 'application/json' : 'application/octet-stream';
    if (req.headers['content-type'] !== expectedContentType) { req.resume(); res.writeHead(415).end(); return; }
    try {
      const chunks = []; let bytes = 0;
      for await (const chunk of req) {
        bytes += chunk.length;
        if (bytes > 131072) throw Error('TRANSFER_TOO_LARGE');
        chunks.push(chunk);
      }
      let transactionId;
      if (hybridRequired) {
        const envelope = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        assert.deepEqual(Object.keys(envelope).sort(), ['authorization', 'eventBase64', 'publicIdentity'].sort());
        assert.equal(typeof envelope.eventBase64, 'string');
        const eventBytes = Buffer.from(envelope.eventBase64, 'base64');
        assert.ok(eventBytes.length > 0 && eventBytes.toString('base64') === envelope.eventBase64);
        transactionId = node.submitTransfer(eventBytes, { authorization: envelope.authorization,
          publicIdentity: envelope.publicIdentity });
      } else {
        transactionId = node.submitTransfer(Buffer.concat(chunks));
      }
      res.writeHead(202).end(JSON.stringify({ accepted: true, transactionId, finalized: false }));
    } catch { if (!res.destroyed) res.writeHead(400).end(JSON.stringify({ code: 'INVALID_SIGNED_TRANSFER' })); }
  });
  async function connect() {
    for (const peer of config.peers) {
      if (closing || connecting.has(peer.validatorId) || node.status().peers.includes(peer.validatorId)) continue;
      connecting.add(peer.validatorId);
      void node.connect(peer.url, peer.validatorId).catch(() => {}).finally(() => connecting.delete(peer.validatorId));
    }
  }
  let timer;
  async function close() {
    if (closing) return;
    closing = true; clearInterval(timer);
    await new Promise(resolve => server.close(resolve));
    await node.close();
  }
  try {
    await node.start({ host: config.host, port: config.port });
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen(config.statusPort, '127.0.0.1', resolve); });
    timer = setInterval(() => { void connect(); }, 5000);
    void connect();
    return { status, close };
  } catch (error) { await close(); throw error; }
}

if (require.main === module) {
  const [action, file] = process.argv.slice(2);
  (async () => {
    if (action === 'check') {
      const { config } = readConfiguration(file);
      console.log(JSON.stringify({ configuration: 'PASS', validatorId: config.validatorId, mutualTlsRequired: true,
        administrativeIndependenceVerified: false, started: false }));
    } else if (action === 'run') {
      const runtime = await start(file);
      console.log(JSON.stringify({ started: true, validatorId: runtime.status().validatorId, scope: 'private-testnet-no-value' }));
      for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => { void runtime.close().then(() => process.exit(0)); });
    } else throw Error('Usage: node scripts/runIndependentValidator.js check|run operator-config.json');
  })().catch(() => { console.error('INDEPENDENT_VALIDATOR_FAILED; inspect the operator configuration locally'); process.exitCode = 1; });
}

module.exports = { privateAddress, validateShape, readConfiguration, start };
