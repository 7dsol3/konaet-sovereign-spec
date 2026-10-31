import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import crypto from 'node:crypto';
import { spawn, execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { context, keyAt, check, sha256, writeJson, readJson, signed, verified, REPORT_DOMAIN, CONTROL_DOMAIN,
  NETWORK_DOMAIN, endpoint, pause, jsonRequest, childEnvironment } from './common.mjs';
import { incomingRelay, outgoingProxy } from './relay.mjs';
const ctx = context(), root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
fs.mkdirSync(ctx.privateDir, { recursive: true, mode: 0o700 }); fs.mkdirSync(ctx.publicDir, { recursive: true, mode: 0o700 });
const key = keyAt(path.join(ctx.privateDir, 'own.seed')), controlKey = ctx.index === 0 ? keyAt(path.join(ctx.privateDir, 'control.seed')) : null;
const workerPort = 58400, statusPort = 58401;
const ownDirectory = path.join(ctx.privateDir, 'operator'); fs.mkdirSync(ownDirectory, { mode: 0o700 });
const ssl = args => execFileSync('openssl', args, { cwd: ownDirectory, stdio: 'pipe' });
ssl(['req', '-newkey', 'rsa:2048', '-nodes', '-subj', `/CN=validator-${ctx.index}`, '-keyout', 'own.key', '-out', 'own.csr']);
const hostHash = sha256([os.hostname(), fs.readFileSync('/proc/sys/kernel/random/boot_id', 'utf8'), process.env.RUNNER_NAME].join('\n'));
let worker, workerPlanned = false, network, configFile, lastStatus = null, lastControl = 0, finished = false, closing;
let lastExit = null, unexpectedExits = 0, peakRssKb = 0, tunnel, publicEndpoint;
const proxies = [], faults = [], started = Date.now();
let controlChain = Promise.resolve();
async function sample() {
  let online = false;
  if (worker && worker.exitCode === null && worker.signalCode === null) {
    try {
      const state = await jsonRequest(`http://127.0.0.1:${statusPort}/status`, {}, 3000);
      if (state.status === 200) { lastStatus = state.body; online = true; }
      const memory = /VmRSS:\s+(\d+)/.exec(fs.readFileSync(`/proc/${worker.pid}/status`, 'utf8'));
      if (memory) peakRssKb = Math.max(peakRssKb, Number(memory[1]));
    } catch { /* A stopped/starting validator remains explicitly offline. */ }
  }
  return { schema: 'konaet.remote-status.v1', runId: ctx.key, commit: ctx.commit, index: ctx.index, hostHash,
    online, sequence: lastStatus?.sequence ?? null, root: lastStatus?.root ?? null, genesisId: lastStatus?.genesisId ?? null,
    peers: lastStatus?.peers ?? [], observedAt: Date.now(), uptimeMs: Date.now() - started, peakRssKb, unexpectedExits, lastExit };
}
async function startWorker() {
  check(configFile && !finished, 'NODE_NOT_CONFIGURED');
  if (worker && worker.exitCode === null && worker.signalCode === null) return;
  workerPlanned = false;
  const log = fs.openSync(path.join(ctx.privateDir, 'validator.log'), 'a', 0o600);
  worker = spawn(process.execPath, [path.join(root, 'chain/scripts/runIndependentValidator.js'), 'run', configFile],
    { env: childEnvironment(), stdio: ['ignore', log, log] }); fs.closeSync(log);
  worker.once('exit', (code, signal) => { lastExit = { code, signal, at: Date.now(), planned: workerPlanned }; if (!workerPlanned) unexpectedExits++; });
}
async function stopWorker(force = false) {
  if (!worker || worker.exitCode !== null || worker.signalCode !== null) return true;
  workerPlanned = true; const child = worker;
  const exited = new Promise(resolve => child.once('exit', resolve)); child.kill(force ? 'SIGKILL' : 'SIGTERM');
  let forced = force;
  const timer = setTimeout(() => { forced = true; child.kill('SIGKILL'); }, 10000);
  await exited; clearTimeout(timer); return force || !forced;
}
async function command(body) {
  check(network && body.schema === 'konaet.remote-control.v1' && body.runId === ctx.key
    && Object.keys(body).sort().join(',') === 'action,issuedAt,payload,runId,schema,seq'
    && Number.isSafeInteger(body.seq) && body.seq > lastControl && Number.isSafeInteger(body.issuedAt)
    && Math.abs(Date.now() - body.issuedAt) <= 30000, 'CONTROL_REPLAY_OR_CONTEXT_REJECTED');
  lastControl = body.seq;
  check(['start', 'stop', 'kill', 'finish', 'abort'].includes(body.action), 'CONTROL_ACTION_REJECTED');
  if (body.action === 'start') { faults.push({ action: 'start', at: Date.now() }); await startWorker(); }
  if (['stop', 'kill'].includes(body.action)) { faults.push({ action: body.action, at: Date.now() }); await sample(); await stopWorker(body.action === 'kill'); }
  if (['finish', 'abort'].includes(body.action)) {
    const state = await sample(); finished = true; const stoppedCleanly = await stopWorker();
    const passed = body.action === 'finish' && stoppedCleanly && unexpectedExits === 0 && state.online
      && state.root === body.payload.root && state.sequence === body.payload.sequence;
    const result = signed(REPORT_DOMAIN, { schema: 'konaet.remote-node-result.v1', runId: ctx.key, commit: ctx.commit,
      index: ctx.index, hostHash, passed, stoppedCleanly, state, faults, publicKey: key.publicBytes().toString('hex') }, key.privateKeyObject());
    writeJson(path.join(ctx.publicDir, `result-${ctx.index}.json`), result); writeJson(path.join(ctx.privateDir, 'done.json'), { passed });
  }
  return { accepted: true, action: body.action };
}
const server = http.createServer({ maxHeaderSize: 8192 }, async (req, res) => {
  res.setHeader('Content-Type', 'application/json'); res.setHeader('Cache-Control', 'no-store');
  try {
    if (req.method === 'GET' && req.url === '/status') { res.end(JSON.stringify(signed(REPORT_DOMAIN, await sample(), key.privateKeyObject()))); return; }
    if (req.method !== 'POST' || req.url !== '/control' || !network) { req.resume(); res.writeHead(404).end('{}'); return; }
    const chunks = []; let size = 0;
    for await (const chunk of req) { size += chunk.length; check(size <= 16384, 'CONTROL_BODY_TOO_LARGE'); chunks.push(chunk); }
    const body = verified(CONTROL_DOMAIN, JSON.parse(Buffer.concat(chunks).toString('utf8')), network.controlPublicKey);
    const operation = controlChain.then(() => command(body)); controlChain = operation.catch(() => {});
    res.end(JSON.stringify(await operation));
  } catch { if (!res.destroyed) res.writeHead(403).end('{"code":"CONTROL_REJECTED"}'); }
});
server.headersTimeout = 5000; server.requestTimeout = 10000; server.maxConnections = 32;
const closeRelay = incomingRelay(server, workerPort);
await new Promise((resolve, reject) => { server.once('error', reject); server.listen(58402, '127.0.0.1', resolve); });
async function cleanup() {
  if (closing) return closing;
  closing = (async () => {
    clearInterval(watcher); clearTimeout(lifetime);
    await stopWorker(); tunnel?.kill('SIGTERM'); await Promise.allSettled(proxies.map(proxy => proxy.close())); await closeRelay();
    server.closeAllConnections(); await new Promise(resolve => server.close(resolve));
  })(); return closing;
}
let configuring = false;
const watcher = setInterval(async () => {
  if (configuring || network || !fs.existsSync(path.join(ctx.publicDir, 'network.json'))) return;
  configuring = true;
  try {
    const packet = readJson(path.join(ctx.publicDir, 'network.json'));
    network = verified(NETWORK_DOMAIN, packet, packet.body.controlPublicKey);
    check(network.runId === ctx.key && network.commit === ctx.commit && network.nodes[ctx.index].body.publicKey === key.publicBytes().toString('hex'), 'NETWORK_CONTEXT_MISMATCH');
    for (const node of network.nodes) if (node.body.index !== ctx.index) proxies.push(await outgoingProxy(endpoint(node.body.endpoint).replace('https:', 'wss:') + '/transport', 58500 + node.body.index));
    fs.copyFileSync(path.join(ctx.privateDir, 'own.seed'), path.join(ownDirectory, 'own.seed'));
    fs.writeFileSync(path.join(ownDirectory, 'ca.pem'), network.ca, { mode: 0o600 });
    fs.writeFileSync(path.join(ownDirectory, 'own.pem'), network.certificates[ctx.index], { mode: 0o600 });
    writeJson(path.join(ownDirectory, 'genesis.json'), network.genesis);
    check(sha256(fs.readFileSync(path.join(ownDirectory, 'genesis.json'))) === network.genesisSha256, 'GENESIS_BYTES_MISMATCH');
    fs.writeFileSync(path.join(ownDirectory, 'submit.token'), crypto.randomBytes(32).toString('hex'), { mode: 0o600 });
    writeJson(path.join(ownDirectory, 'operator-config.json'), { schema: 'konaet.independent-validator.config.v1', scope: 'private-testnet-no-value',
      mutualTlsRequired: true, validatorId: `validator-${ctx.index}`, host: '127.0.0.1', port: workerPort, statusPort,
      genesisFile: 'genesis.json', genesisSha256: network.genesisSha256, seedFile: 'own.seed', caFile: 'ca.pem', certificateFile: 'own.pem',
      tlsKeyFile: 'own.key', submitTokenFile: 'submit.token', dataDirectory: 'data',
      peers: network.nodes.filter(node => node.body.index !== ctx.index).map(node => ({ validatorId: `validator-${node.body.index}`, url: `wss://127.0.0.1:${58500 + node.body.index}` })) });
    configFile = path.join(ownDirectory, 'operator-config.json'); await startWorker();
  } catch (error) { writeJson(path.join(ctx.privateDir, 'fatal.json'), { code: error.message }); }
}, 500);
const lifetime = setTimeout(() => { void cleanup().then(() => process.exit(1)); }, (ctx.seconds + 900) * 1000);
process.once('SIGTERM', () => { void cleanup().then(() => process.exit(0)); });
process.once('SIGINT', () => { void cleanup().then(() => process.exit(0)); });
const cfLog = fs.openSync(path.join(ctx.privateDir, 'cloudflared.log'), 'a', 0o600);
tunnel = spawn(path.join(ctx.privateDir, 'cloudflared'), ['tunnel', '--no-autoupdate', '--protocol', 'http2', '--url', 'http://127.0.0.1:58402'],
  { env: childEnvironment(), stdio: ['ignore', 'pipe', 'pipe'] });
const tunnelOutput = chunk => {
  fs.writeSync(cfLog, chunk);
  for (const url of chunk.toString().match(/https:\/\/[a-z0-9-]+\.trycloudflare\.com/g) ?? []) {
    if (publicEndpoint || url.includes('://api.')) continue;
    publicEndpoint = endpoint(url);
    const body = { schema: 'konaet.remote-bootstrap.v1', runId: ctx.key, commit: ctx.commit, index: ctx.index, endpoint: publicEndpoint,
      publicKey: key.publicBytes().toString('hex'), controlPublicKey: controlKey?.publicBytes().toString('hex') ?? null,
      csr: fs.readFileSync(path.join(ownDirectory, 'own.csr'), 'utf8'), hostHash, hostname: os.hostname(), os: os.release(), architecture: os.arch() };
    writeJson(path.join(ctx.publicDir, `node-${ctx.index}.json`), signed(REPORT_DOMAIN, body, key.privateKeyObject()));
  }
};
tunnel.stdout.on('data', tunnelOutput); tunnel.stderr.on('data', tunnelOutput);
tunnel.once('exit', code => { if (!closing && !finished) writeJson(path.join(ctx.privateDir, 'fatal.json'), { code: 'TUNNEL_EXITED_' + code }); });
