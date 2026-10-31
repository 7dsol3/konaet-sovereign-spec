import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const { validateGenesis } = require('../chain/network/sovereign/SovereignGenesis.js');
const { validateContract, validateContractState } = require('../chain/ko-program/runtime.js');
const { decodeEvent } = require('../chain/vlock7sin-js/src/event.js');
const MAX_TRANSACTION_BYTES = 65536;
const MAX_RESPONSE_BYTES = 8 * 1024 * 1024;
const HEX = /^[0-9a-f]{64}$/;
const DECIMAL = /^(0|[1-9][0-9]{0,38})$/;
const VALIDATOR = /^validator-[0-9]{1,10}$/;
const REASONS = new Set(['READY', 'QUORUM_UNAVAILABLE', 'CONSENSUS_STALLED', 'CERTIFICATE_EXPIRING', 'STOPPING']);

function check(value, code) { if (!value) { const error = Error(code); error.code = code; throw error; } }
function record(value) { return value && typeof value === 'object' && !Array.isArray(value); }
function integer(value, minimum, maximum) { return Number.isSafeInteger(value) && value >= minimum && value <= maximum; }
function boundedText(value, maximum = 128) { return typeof value === 'string' && value.length <= maximum && /^[\x20-\x7e]*$/.test(value); }
function exactKeys(value, allowed) {
  check(record(value) && Object.keys(value).every(key => allowed.includes(key)), 'GATEWAY_CONFIG_INVALID');
}
function upstreamUrl(text) {
  check(typeof text === 'string' && /^http:\/\/127\.0\.0\.1:[1-9][0-9]{0,4}\/?$/.test(text), 'LOOPBACK_UPSTREAM_REQUIRED');
  const url = new URL(text);
  check(integer(Number(url.port), 1024, 65535), 'EXPLICIT_UPSTREAM_PORT_REQUIRED');
  return url.origin;
}
function publicOrigin(text) {
  if (text === undefined) return undefined;
  check(typeof text === 'string' && text.length <= 255, 'HTTPS_PUBLIC_ORIGIN_REQUIRED');
  const url = new URL(text);
  check(url.protocol === 'https:' && url.origin === text && !url.username && !url.password, 'HTTPS_PUBLIC_ORIGIN_REQUIRED');
  return text;
}

// The local operator token is never accepted from a caller or sent on GETs.
export function readGatewayConfiguration(file) {
  const absolute = path.resolve(file), base = path.dirname(absolute);
  check(fs.statSync(absolute).isFile() && fs.statSync(absolute).size <= 4096, 'GATEWAY_CONFIG_INVALID');
  check(!fs.lstatSync(absolute).isSymbolicLink(), 'GATEWAY_SYMLINK_REFUSED');
  const config = JSON.parse(fs.readFileSync(absolute, 'utf8'));
  exactKeys(config, ['schema', 'port', 'upstream', 'tokenFile', 'publicOrigin', 'allowSubmissions']);
  check(config.schema === 'konaet.operator-gateway.v1' && integer(config.port, 1024, 65535), 'GATEWAY_CONFIG_INVALID');
  check(config.allowSubmissions === undefined || typeof config.allowSubmissions === 'boolean', 'GATEWAY_CONFIG_INVALID');
  check(typeof config.tokenFile === 'string' && config.tokenFile.length <= 255 && !path.isAbsolute(config.tokenFile)
    && !config.tokenFile.includes(':') && !config.tokenFile.split(/[\\/]/).some(part => ['..', ''].includes(part)), 'GATEWAY_TOKEN_PATH_INVALID');
  const tokenPath = path.resolve(base, config.tokenFile);
  check(tokenPath.startsWith(base + path.sep), 'GATEWAY_TOKEN_PATH_INVALID');
  for (let cursor = tokenPath; cursor !== base; cursor = path.dirname(cursor)) {
    check(!fs.lstatSync(cursor).isSymbolicLink(), 'GATEWAY_SYMLINK_REFUSED');
  }
  check(fs.statSync(tokenPath).isFile() && fs.statSync(tokenPath).size <= 128, 'GATEWAY_TOKEN_INVALID');
  const submitToken = fs.readFileSync(tokenPath, 'utf8').trim();
  check(HEX.test(submitToken), 'GATEWAY_TOKEN_INVALID');
  return { port: config.port, upstream: upstreamUrl(config.upstream), submitToken, publicOrigin: publicOrigin(config.publicOrigin), allowSubmissions: config.allowSubmissions ?? false };
}

function statusView(data) {
  check(record(data) && VALIDATOR.test(data.validatorId) && HEX.test(data.genesisId) && HEX.test(data.root)
    && typeof data.sequence === 'string' && DECIMAL.test(data.sequence) && boundedText(data.protocolVersion, 80), 'UPSTREAM_INVALID_RESPONSE');
  check(integer(Number(data.networkId), 1, 0xffffffff) && integer(data.accountCount, 0, Number.MAX_SAFE_INTEGER)
    && Array.isArray(data.peers) && data.peers.length <= 63 && data.peers.every(id => VALIDATOR.test(id)), 'UPSTREAM_INVALID_RESPONSE');
  const result = { schema: 'konaet.gateway-status.v1', validatorId: data.validatorId, genesisId: data.genesisId,
    networkId: data.networkId, protocolVersion: data.protocolVersion, sequence: data.sequence, root: data.root,
    accountCount: data.accountCount, connectedValidators: data.peers.length + 1,
    administrativeIndependenceVerified: false, monetaryValue: false };
  if (data.contractRuntime) {
    const runtime = data.contractRuntime;
    check(runtime.profile === 'KONAET_KO_PROGRAM_V1' && runtime.enforced === true && integer(runtime.contracts, 0, 128)
      && HEX.test(runtime.contractsRoot) && HEX.test(runtime.receiptsRoot), 'UPSTREAM_INVALID_RESPONSE');
    result.contractRuntime = { profile: runtime.profile, enforced: true, contracts: runtime.contracts,
      contractsRoot: runtime.contractsRoot, receiptsRoot: runtime.receiptsRoot };
  }
  return result;
}
function readyView(data) {
  check(record(data) && typeof data.ready === 'boolean' && VALIDATOR.test(data.validatorId)
    && HEX.test(data.genesisId) && HEX.test(data.root) && typeof data.sequence === 'string' && DECIMAL.test(data.sequence)
    && integer(data.connectedValidators, 1, 64) && integer(data.requiredValidators, 1, 64)
    && integer(data.pendingTransactions, 0, Number.MAX_SAFE_INTEGER)
    && integer(data.pendingAgeMs, 0, Number.MAX_SAFE_INTEGER)
    && typeof data.tlsExpiresAt === 'string' && data.tlsExpiresAt.length <= 40
    && Number.isFinite(Date.parse(data.tlsExpiresAt)) && REASONS.has(data.reason), 'UPSTREAM_INVALID_RESPONSE');
  return Object.fromEntries(['ready', 'validatorId', 'genesisId', 'root', 'sequence', 'connectedValidators', 'requiredValidators',
    'pendingTransactions', 'pendingAgeMs', 'tlsExpiresAt', 'reason'].map(key => [key, data[key]]));
}
function accountView(data, address) {
  check(record(data) && data.address === address && typeof data.balanceAtomic === 'string' && DECIMAL.test(data.balanceAtomic)
    && typeof data.nonce === 'string' && DECIMAL.test(data.nonce) && typeof data.sequence === 'string'
    && DECIMAL.test(data.sequence) && HEX.test(data.root), 'UPSTREAM_INVALID_RESPONSE');
  return { address, balanceAtomic: data.balanceAtomic, nonce: data.nonce, sequence: data.sequence, root: data.root };
}
function contractView(data, id) {
  check(record(data) && HEX.test(data.root) && typeof data.sequence === 'string' && DECIMAL.test(data.sequence), 'UPSTREAM_INVALID_RESPONSE');
  const artifact = validateContract(data.artifact), state = validateContractState(artifact, data.state);
  check(state.contractId === id, 'UPSTREAM_INVALID_RESPONSE');
  return { artifact, state, sequence: data.sequence, root: data.root };
}

function upstreamRequest(origin, route, { body, submitToken, timeoutMs }) {
  return new Promise((resolve, reject) => {
    let response, finished = false;
    const done = (error, value) => {
      if (finished) return; finished = true; clearTimeout(timer);
      if (error) { response?.destroy(); request.destroy(); reject(error); } else resolve(value);
    };
    const request = http.request(origin + route, { method: body ? 'POST' : 'GET', maxHeaderSize: 8192,
      headers: { Accept: 'application/json', ...(body ? { 'Content-Type': 'application/octet-stream', 'Content-Length': body.length,
        Authorization: `Bearer ${submitToken}` } : {}) } }, incoming => {
      response = incoming;
      if (!/^application\/json(?:\s*;|$)/i.test(incoming.headers['content-type'] || '')
        || Number(incoming.headers['content-length'] || 0) > MAX_RESPONSE_BYTES) { done(Error('UPSTREAM_INVALID_RESPONSE')); return; }
      const chunks = []; let bytes = 0;
      incoming.on('data', chunk => {
        bytes += chunk.length;
        if (bytes > MAX_RESPONSE_BYTES) { done(Error('UPSTREAM_RESPONSE_TOO_LARGE')); return; }
        chunks.push(chunk);
      });
      incoming.on('error', done);
      incoming.on('end', () => {
        if (finished) return;
        try { done(null, { status: incoming.statusCode, data: JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks))) }); }
        catch (error) { done(error); }
      });
    });
    const timer = setTimeout(() => done(Error('UPSTREAM_TIMEOUT')), timeoutMs);
    request.on('error', done);
    request.end(body);
  });
}

function readTransaction(req, timeoutMs) {
  return new Promise((resolve, reject) => {
    const chunks = []; let bytes = 0, finished = false;
    const done = (error, value) => {
      if (finished) return; finished = true; clearTimeout(timer);
      req.removeListener('data', data); req.removeListener('end', end); req.removeListener('aborted', aborted); req.removeListener('error', aborted);
      if (error) { req.pause(); reject(error); } else resolve(value);
    };
    const data = chunk => { bytes += chunk.length; if (bytes > MAX_TRANSACTION_BYTES) done(Error('TRANSACTION_TOO_LARGE')); else chunks.push(chunk); };
    const end = () => done(bytes === 0 ? Error('EMPTY_TRANSACTION') : null, Buffer.concat(chunks));
    const aborted = () => done(Error('TRANSACTION_INTERRUPTED'));
    const timer = setTimeout(() => done(Error('TRANSACTION_TIMEOUT')), timeoutMs);
    req.on('data', data); req.on('end', end); req.on('aborted', aborted); req.on('error', aborted);
  });
}

// Always binds loopback. A TLS reverse proxy is configured separately by an operator.
export async function startGateway(options) {
  exactKeys(options, ['upstream', 'submitToken', 'port', 'publicOrigin', 'timeoutMs', 'requestsPerMinute', 'transactionsPerMinute', 'maxConcurrent', 'allowSubmissions']);
  const upstream = upstreamUrl(options.upstream), origin = publicOrigin(options.publicOrigin), submitToken = options.submitToken;
  check(typeof options.submitToken === 'string' && HEX.test(options.submitToken), 'GATEWAY_TOKEN_INVALID');
  const port = options.port ?? 0, timeoutMs = options.timeoutMs ?? 5000;
  const requestsPerMinute = options.requestsPerMinute ?? 120, transactionsPerMinute = options.transactionsPerMinute ?? 8;
  const maxConcurrent = options.maxConcurrent ?? 16;
  const allowSubmissions = options.allowSubmissions ?? false;
  check(integer(port, 0, 65535) && integer(timeoutMs, 25, 15000) && integer(requestsPerMinute, 1, 10000)
    && integer(transactionsPerMinute, 1, 100) && integer(maxConcurrent, 1, 64) && typeof allowSubmissions === 'boolean', 'GATEWAY_CONFIG_INVALID');
  let active = 0, closing = false, windowStart = Date.now(), requests = 0, submissions = 0;
  const ipRequests = new Map();
  const server = http.createServer({ maxHeaderSize: 8192 }, async (req, res) => {
    res.setHeader('Content-Type', 'application/json'); res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff'); res.setHeader('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'");
    const reply = (status, body, closeRequest = false) => {
      if (res.destroyed || res.writableEnded) return;
      if (closeRequest) {
        res.setHeader('Connection', 'close');
        req.on('error', () => {}); req.resume();
        const socket = req.socket, timer = setTimeout(() => socket.destroy(), 4000);
        timer.unref(); socket.once('close', () => clearTimeout(timer));
      }
      res.writeHead(status).end(JSON.stringify(body));
    };
    if (closing) { reply(503, { code: 'GATEWAY_STOPPING' }, true); return; }
    if (req.headers.host !== `127.0.0.1:${server.address().port}` || (req.headers.origin && req.headers.origin !== origin)) {
      reply(403, { code: 'GATEWAY_ORIGIN_REFUSED' }, true); return;
    }
    if (Date.now() - windowStart >= 60000) { windowStart = Date.now(); requests = 0; submissions = 0; ipRequests.clear(); }
    const ip = req.socket.remoteAddress, perIp = (ipRequests.get(ip) || 0) + 1;
    if (ipRequests.size >= 128 && !ipRequests.has(ip)) { reply(429, { code: 'RATE_LIMITED' }, true); return; }
    ipRequests.set(ip, perIp);
    if (++requests > requestsPerMinute || perIp > requestsPerMinute) { reply(429, { code: 'RATE_LIMITED' }, true); return; }
    if (active >= maxConcurrent) { reply(503, { code: 'GATEWAY_BUSY' }, true); return; }
    const isSubmission = req.method === 'POST' && req.url === '/api/transactions';
    let route;
    if (req.method === 'GET' && req.url === '/api/status') route = '/status';
    else if (req.method === 'GET' && req.url === '/api/genesis') route = '/genesis';
    else if (req.method === 'GET' && req.url === '/health/ready') route = '/health/ready';
    else if (req.method === 'GET' && /^\/api\/account\/v7[a-z2-7]{32}$/.test(req.url)) route = req.url.slice(4);
    else if (req.method === 'GET' && /^\/api\/contract\/[0-9a-f]{64}$/.test(req.url)) route = req.url.slice(4);
    else if (isSubmission) route = '/submit';
    else { reply(404, { code: 'ENDPOINT_NOT_FOUND' }, true); return; }
    if (isSubmission && !allowSubmissions) { reply(403, { code: 'READ_ONLY_GATEWAY' }, true); return; }
    if (!isSubmission && (req.headers['transfer-encoding'] || Number(req.headers['content-length'] || 0) > 0)) {
      reply(400, { code: 'GET_BODY_REFUSED' }, true); return;
    }
    if (isSubmission && ++submissions > transactionsPerMinute) { reply(429, { code: 'TRANSACTION_RATE_LIMITED' }, true); return; }
    if (isSubmission && req.headers['content-type'] !== 'application/octet-stream') { reply(415, { code: 'SIGNED_WIRE_REQUIRED' }, true); return; }
    if (isSubmission && Number(req.headers['content-length'] || 0) > MAX_TRANSACTION_BYTES) { reply(413, { code: 'TRANSACTION_TOO_LARGE' }, true); return; }
    active++;
    try {
      const body = isSubmission ? await readTransaction(req, timeoutMs) : undefined;
      if (isSubmission) {
        try {
          const event = decodeEvent(body);
          event.assertValid({ expectedNetworkId: event.networkId, expectedStateSuite: event.stateSuite });
        } catch { reply(400, { code: 'INVALID_SIGNED_TRANSACTION' }); return; }
      }
      const result = await upstreamRequest(upstream, route, { body, submitToken, timeoutMs });
      if (route === '/health/ready' && [200, 503].includes(result.status)) {
        const ready = readyView(result.data);
        check(ready.ready === (result.status === 200) && (ready.ready ? ready.reason === 'READY' : ready.reason !== 'READY'), 'UPSTREAM_INVALID_RESPONSE');
        reply(result.status, ready);
      } else if (isSubmission && result.status === 202) {
        check(result.data?.accepted === true && result.data.finalized === false && HEX.test(result.data.transactionId), 'UPSTREAM_INVALID_RESPONSE');
        reply(202, { accepted: true, transactionId: result.data.transactionId, finalized: false });
      } else if (isSubmission && [400, 403, 415, 429].includes(result.status)) {
        reply(result.status, { code: result.status === 429 ? 'OPERATOR_RATE_LIMITED' : 'TRANSACTION_REFUSED' });
      } else if (result.status === 404 && /^\/(account|contract)\//.test(route)) reply(404, { code: 'RESOURCE_NOT_FOUND' });
      else {
        check(result.status === 200 && !isSubmission, 'UPSTREAM_INVALID_RESPONSE');
        if (route === '/status') reply(200, statusView(result.data));
        else if (route === '/genesis') reply(200, validateGenesis(result.data));
        else if (route.startsWith('/account/')) reply(200, accountView(result.data, route.slice('/account/'.length)));
        else if (route.startsWith('/contract/')) reply(200, contractView(result.data, route.slice('/contract/'.length)));
      }
    } catch (error) {
      const code = error.message;
      if (code === 'TRANSACTION_TOO_LARGE') reply(413, { code }, true);
      else if (code === 'TRANSACTION_TIMEOUT') reply(408, { code }, true);
      else if (['EMPTY_TRANSACTION', 'TRANSACTION_INTERRUPTED'].includes(code)) reply(400, { code }, true);
      else reply(503, { code: 'UPSTREAM_UNAVAILABLE' });
    } finally { active--; }
  });
  server.requestTimeout = 20000; server.headersTimeout = 5000; server.keepAliveTimeout = 1000; server.maxRequestsPerSocket = 100;
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, '127.0.0.1', resolve); });
  let closePromise;
  return { url: `http://127.0.0.1:${server.address().port}`, close: () => {
    if (closePromise) return closePromise;
    closing = true;
    closePromise = new Promise((resolve, reject) => {
      const timer = setTimeout(() => server.closeAllConnections(), 4000);
      timer.unref();
      server.close(error => { clearTimeout(timer); if (error) reject(error); else resolve(); });
    });
    return closePromise;
  } };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    check(process.argv.length === 3, 'USAGE: node tools/operator-gateway.mjs gateway-config.json');
    const app = await startGateway(readGatewayConfiguration(process.argv[2]));
    console.log(JSON.stringify({ started: true, url: app.url, signingKeysLoaded: false }));
    for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => { void app.close().then(() => process.exit(0)); });
  } catch { console.error('OPERATOR_GATEWAY_FAILED; inspect the local configuration'); process.exitCode = 1; }
}
