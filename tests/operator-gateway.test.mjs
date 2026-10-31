import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import test from 'node:test';
import { readGatewayConfiguration, startGateway } from '../tools/operator-gateway.mjs';
const require = createRequire(import.meta.url);
const { crypto: vcrypto, createTransfer, UNIT } = require('../chain/vlock7sin-js/src');
const { createGenesis, stateFromGenesis } = require('../chain/network/sovereign');
const { PROFILE, FORMAT } = require('../chain/vlock7sin-js/src/koConsensusProfile');
const { compileKoPolicy } = require('../chain/vlock7sin-js/src/koPolicy');
const runtime = require('../chain/ko-program/runtime');
const token = 'b'.repeat(64), digest = 'a'.repeat(64), address = 'v7' + 'a'.repeat(32);
const status = { validatorId: 'validator-0', genesisId: digest, root: digest, sequence: '0', networkId: 77992233,
  protocolVersion: '0.6.0-sovereign-ko-program.1', accountCount: 1, peers: ['validator-1', 'validator-2'],
  voteJournal: { path: '/private/operator/journal', submitToken: token }, transport: { host: '10.77.0.1' } };
const readiness = { ready: true, validatorId: 'validator-0', genesisId: digest, root: digest, sequence: '0',
  connectedValidators: 3, requiredValidators: 3, pendingTransactions: 0, pendingAgeMs: 0,
  tlsExpiresAt: '2099-01-01T00:00:00.000Z', reason: 'READY' };

async function mock(t, handler) {
  const sockets = new Set();
  const server = http.createServer(handler);
  server.on('connection', socket => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => { sockets.forEach(socket => socket.destroy()); await new Promise(resolve => server.close(resolve)); });
  return `http://127.0.0.1:${server.address().port}`;
}
async function gateway(t, upstream, options = {}) {
  const app = await startGateway({ upstream, submitToken: token, ...options });
  t.after(() => app.close()); return app;
}
function json(res, body, code = 200) { res.writeHead(code, { 'Content-Type': 'application/json' }).end(JSON.stringify(body)); }
function fixture() {
  const keys = Array.from({ length: 4 }, () => vcrypto.IdentityKeypair.generate());
  const nativePolicy = compileKoPolicy(fs.readFileSync(new URL('../chain/contracts-ko/SindraRuntime.ko', import.meta.url), 'utf8'));
  const owner = vcrypto.IdentityKeypair.generate();
  const genesis = createGenesis({ format: FORMAT, contractRuntime: PROFILE, nativePolicy,
    networkId: 77992233, createdAt: '2026-10-30T00:00:00.000Z', threshold: 3,
    validators: keys.map((key, i) => ({ id: `validator-${i}`, publicKey: key.publicBytes() })),
    allocations: [{ address: owner.address(), amountAtomic: UNIT.initialSupplyAtomic }] });
  const state = stateFromGenesis(genesis);
  const event = createTransfer({ networkId: 77992233, sequence: 1n, nonce: 1n, timestampMs: 0n,
    previousRoot: state.root(), amountAtomic: 1n, senderPublicKey: owner.publicBytes(), receiverAddress: address }, owner);
  const artifact = runtime.compileContract(fs.readFileSync(new URL('../chain/ko-program/examples/Counter.ko', import.meta.url), 'utf8'));
  const contract = runtime.deployContract(artifact, { caller: owner.address(), networkId: '77992233', salt: '0', gasLimit: 10000 });
  return { genesis, event, artifact, contract: contract.state };
}

test('gateway restricts upstream, configuration and token paths to explicit local resources', async t => {
  for (const upstream of ['http://example.com:57110', 'https://127.0.0.1:57110', 'http://127.0.0.1', 'http://localhost:57110',
    'http://127.0.0.1:57110/submit', 'http://127.1:57110', 'http://127.0.0.1:65536', 'http://127.0.0.1:80']) {
    await assert.rejects(startGateway({ upstream, submitToken: token }));
  }
  for (const options of [{ host: '0.0.0.0' }, { publicOrigin: 'http://example.com' }, { timeoutMs: 1 }, { allowSubmissions: 'yes' }]) {
    await assert.rejects(startGateway({ upstream: 'http://127.0.0.1:57110', submitToken: token, ...options }));
  }
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'konaet-gateway-config-'));
  t.after(() => { assert.equal(path.dirname(base), path.resolve(os.tmpdir())); fs.rmSync(base, { recursive: true }); });
  const config = { schema: 'konaet.operator-gateway.v1', upstream: 'http://127.0.0.1:57110', port: 58120, tokenFile: 'submit.token', allowSubmissions: false };
  fs.writeFileSync(path.join(base, 'submit.token'), token, { mode: 0o600 });
  const file = path.join(base, 'gateway.json'); fs.writeFileSync(file, JSON.stringify(config));
  assert.equal(readGatewayConfiguration(file).submitToken, token); assert.equal(readGatewayConfiguration(file).allowSubmissions, false);
  for (const tokenFile of ['../outside.token', '/outside.token', 'C:/outside.token', 'sub/../submit.token']) {
    fs.writeFileSync(file, JSON.stringify({ ...config, tokenFile })); assert.throws(() => readGatewayConfiguration(file));
  }
});

test('read-only routes validate public data and redact operator internals and credentials', async t => {
  const f = fixture(), seen = [];
  const upstream = await mock(t, (req, res) => {
    seen.push({ path: req.url, auth: req.headers.authorization });
    if (req.url === '/status') json(res, status);
    else if (req.url === '/genesis') json(res, f.genesis);
    else if (req.url === '/health/ready') json(res, readiness);
    else if (req.url === `/account/${address}`) json(res, { address, balanceAtomic: '12', nonce: '1', sequence: '2', root: digest, token });
    else if (req.url === `/contract/${f.contract.contractId}`) json(res, { artifact: f.artifact, state: f.contract, sequence: '2', root: digest, token });
    else json(res, { token }, 404);
  });
  const app = await gateway(t, upstream);
  const publicStatus = await (await fetch(app.url + '/api/status')).json();
  assert.equal(publicStatus.connectedValidators, 3); assert.equal(publicStatus.voteJournal, undefined); assert.equal(publicStatus.transport, undefined);
  assert.equal(JSON.stringify(publicStatus).includes(token), false);
  assert.deepEqual(await (await fetch(app.url + '/api/genesis')).json(), f.genesis);
  assert.deepEqual(await (await fetch(app.url + '/health/ready')).json(), readiness);
  const account = await (await fetch(app.url + `/api/account/${address}`)).json(); assert.equal(account.balanceAtomic, '12'); assert.equal(account.token, undefined);
  const contract = await (await fetch(app.url + `/api/contract/${f.contract.contractId}`)).json();
  assert.deepEqual(contract.state, f.contract); assert.equal(contract.token, undefined);
  const missing = await fetch(app.url + `/api/contract/${'c'.repeat(64)}`); assert.equal(missing.status, 404);
  assert.ok(seen.length >= 6 && seen.every(row => row.auth === undefined));
  for (const response of [await fetch(app.url + '/api/status'), await fetch(app.url + '/health/ready')]) {
    assert.equal(response.headers.get('access-control-allow-origin'), null); assert.equal(response.headers.get('cache-control'), 'no-store');
  }
});

test('transactions require explicit activation, canonical signed bytes and never report admission as finality', async t => {
  const f = fixture(), forwarded = [];
  const upstream = await mock(t, async (req, res) => {
    const chunks = []; for await (const chunk of req) chunks.push(chunk);
    forwarded.push({ route: req.url, auth: req.headers.authorization, body: Buffer.concat(chunks), custom: req.headers['x-client-secret'] });
    json(res, { accepted: true, finalized: false, transactionId: digest, token, operatorPath: '/private' }, 202);
  });
  const readonly = await gateway(t, upstream);
  const headers = { 'Content-Type': 'application/octet-stream', Authorization: 'Bearer caller-controlled', 'X-Client-Secret': 'do-not-forward' };
  const blocked = await fetch(readonly.url + '/api/transactions', { method: 'POST', headers, body: f.event.canonicalBytes() });
  assert.equal(blocked.status, 403); assert.equal((await blocked.json()).code, 'READ_ONLY_GATEWAY'); assert.equal(forwarded.length, 0);
  const app = await gateway(t, upstream, { allowSubmissions: true });
  for (const body of [Buffer.from('bad'), Buffer.alloc(65537)]) {
    const response = await fetch(app.url + '/api/transactions', { method: 'POST', headers, body }); assert.ok([400, 413].includes(response.status));
  }
  const jsonBody = await fetch(app.url + '/api/transactions', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' }); assert.equal(jsonBody.status, 415);
  assert.equal(forwarded.length, 0);
  const accepted = await fetch(app.url + '/api/transactions', { method: 'POST', headers, body: f.event.canonicalBytes() });
  assert.equal(accepted.status, 202); assert.deepEqual(await accepted.json(), { accepted: true, finalized: false, transactionId: digest });
  assert.equal(forwarded.length, 1); assert.equal(forwarded[0].auth, `Bearer ${token}`); assert.equal(forwarded[0].custom, undefined);
  assert.ok(forwarded[0].body.equals(f.event.canonicalBytes()));
});

test('gateway refuses hostile origins, Host values, encoded paths and proxy-header rate-limit evasion', async t => {
  let seen = 0;
  const upstream = await mock(t, (req, res) => { seen++; json(res, status); });
  const app = await gateway(t, upstream, { publicOrigin: 'https://konaet.example' });
  assert.equal((await fetch(app.url + '/api/status', { headers: { Origin: 'https://foreign.example' } })).status, 403);
  const badHost = await new Promise((resolve, reject) => {
    const req = http.get(app.url + '/api/status', { headers: { Host: 'attacker.example' } }, res => { res.resume(); resolve(res.statusCode); });
    req.on('error', reject);
  });
  assert.equal(badHost, 403);
  for (const route of ['/api/status?upstream=http://other', '/api/%73tatus', '/status', '/api/closure/1', '/api/contracts', '/api/transactions']) {
    assert.equal((await fetch(app.url + route)).status, 404);
  }
  assert.equal(seen, 0);
  assert.equal((await fetch(app.url + '/api/status', { headers: { Origin: 'https://konaet.example' } })).status, 200);
  const limited = await gateway(t, upstream, { requestsPerMinute: 2 });
  for (const ip of ['1.1.1.1', '2.2.2.2']) assert.equal((await fetch(limited.url + '/api/status', { headers: { 'X-Forwarded-For': ip } })).status, 200);
  assert.equal((await fetch(limited.url + '/api/status', { headers: { 'X-Forwarded-For': '3.3.3.3' } })).status, 429);
});

test('upstream errors, redirects, invalid content and oversized responses fail closed without relaying details', async t => {
  let mode = 'error';
  const upstream = await mock(t, (req, res) => {
    if (mode === 'error') json(res, { token, path: '/private' }, 500);
    else if (mode === 'redirect') res.writeHead(302, { 'Content-Type': 'application/json', Location: 'http://example.com/' }).end('{}');
    else if (mode === 'html') res.writeHead(200, { 'Content-Type': 'text/html' }).end(token);
    else if (mode === 'oversize') res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': 8 * 1024 * 1024 + 1 }).end();
    else if (mode === 'invalid-json') res.writeHead(200, { 'Content-Type': 'application/json' }).end('{');
    else if (mode === 'invalid-status') json(res, { ...status, root: token + 'z' });
    else if (mode === 'unready') json(res, { ...readiness, ready: false, connectedValidators: 1, reason: 'QUORUM_UNAVAILABLE' }, 503);
    else if (mode === 'timeout') return;
  });
  const app = await gateway(t, upstream, { timeoutMs: 100 });
  for (mode of ['error', 'redirect', 'html', 'oversize', 'invalid-json', 'invalid-status', 'timeout']) {
    const response = await fetch(app.url + '/api/status'); assert.equal(response.status, 503, mode);
    assert.deepEqual(await response.json(), { code: 'UPSTREAM_UNAVAILABLE' });
  }
  mode = 'unready'; const response = await fetch(app.url + '/health/ready'); assert.equal(response.status, 503);
  assert.equal((await response.json()).reason, 'QUORUM_UNAVAILABLE');
});

test('request deadlines and concurrency ceilings bound stalled clients and upstream requests', async t => {
  let entered = 0;
  const upstream = await mock(t, () => { entered++; });
  const app = await gateway(t, upstream, { timeoutMs: 100, maxConcurrent: 1, allowSubmissions: true });
  const first = fetch(app.url + '/api/status');
  while (!entered) await new Promise(resolve => setTimeout(resolve, 2));
  assert.equal((await fetch(app.url + '/api/status')).status, 503); assert.equal((await first).status, 503);
  const slow = await new Promise((resolve, reject) => {
    const req = http.request(app.url + '/api/transactions', { method: 'POST', headers: { 'Content-Type': 'application/octet-stream', 'Content-Length': '100' } }, res => {
      const chunks = []; res.on('data', chunk => chunks.push(chunk)); res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(Buffer.concat(chunks).toString()) }));
    });
    req.on('error', reject); req.write('x');
  });
  assert.equal(slow.status, 408); assert.equal(slow.body.code, 'TRANSACTION_TIMEOUT');
  await app.close(); await app.close();
});
