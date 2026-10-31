import fs from 'node:fs';
import path from 'node:path';
import { spawn, execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { context, check, writeJson, readJson, sha256, pause, artifact, github, keyAt, signed, verified,
  REPORT_DOMAIN, NETWORK_DOMAIN, childEnvironment, require } from './common.mjs';
const ctx = context(), mode = process.argv[2], root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
fs.mkdirSync(ctx.privateDir, { recursive: true, mode: 0o700 }); fs.mkdirSync(ctx.publicDir, { recursive: true, mode: 0o700 });
const agentFile = path.join(root, 'tools/remote/agent.mjs');
async function initialize() {
  check(process.platform === 'linux' && process.arch === 'x64', 'LINUX_X64_RUNNER_REQUIRED');
  const repository = await github(ctx, ''); check(repository.private === false, 'PUBLIC_REPOSITORY_REQUIRED');
  const executable = path.join(ctx.privateDir, 'cloudflared');
  const response = await fetch('https://github.com/cloudflare/cloudflared/releases/download/2026.10.7/cloudflared-linux-amd64', { signal: AbortSignal.timeout(90000) });
  check(response.ok, 'CLOUDFLARED_DOWNLOAD_FAILED'); const bytes = Buffer.from(await response.arrayBuffer());
  check(sha256(bytes) === '1f99fb518b83dec2ba8d870a7cc991d82a77e6196295a3d2754ba17ab9f91872', 'CLOUDFLARED_CHECKSUM_MISMATCH');
  fs.writeFileSync(executable, bytes, { flag: 'wx', mode: 0o700 });
  const log = fs.openSync(path.join(ctx.privateDir, 'agent.log'), 'a', 0o600);
  const child = spawn(process.execPath, [agentFile], { detached: true, env: childEnvironment(), stdio: ['ignore', log, log] });
  fs.closeSync(log); child.unref(); writeJson(path.join(ctx.privateDir, 'agent-process.json'), { pid: child.pid });
  const until = Date.now() + 180000;
  while (Date.now() < until) {
    if (fs.existsSync(path.join(ctx.publicDir, `node-${ctx.index}.json`))) return;
    if (fs.existsSync(path.join(ctx.privateDir, 'fatal.json'))) throw Error(readJson(path.join(ctx.privateDir, 'fatal.json')).code);
    try { process.kill(child.pid, 0); } catch { throw Error('REMOTE_AGENT_START_FAILED'); }
    await pause(500);
  }
  throw Error('TUNNEL_BOOTSTRAP_TIMEOUT');
}
function validateBootstrap(packet, index) {
  const body = verified(REPORT_DOMAIN, packet, packet?.body?.publicKey);
  check(body.schema === 'konaet.remote-bootstrap.v1' && body.runId === ctx.key && body.commit === ctx.commit
    && body.index === index && /^[0-9a-f]{64}$/.test(body.hostHash), 'BOOTSTRAP_CONTEXT_MISMATCH');
  return packet;
}
async function prepareNetwork() {
  if (ctx.index !== 0) {
    const origin = validateBootstrap(await artifact(ctx, `konaet-node-0-${ctx.key}`, 'node-0.json'), 0);
    const packet = await artifact(ctx, `konaet-network-${ctx.key}`, 'network.json');
    const body = verified(NETWORK_DOMAIN, packet, origin.body.controlPublicKey);
    check(body.runId === ctx.key && body.commit === ctx.commit && body.controlPublicKey === origin.body.controlPublicKey, 'NETWORK_CONTEXT_MISMATCH');
    writeJson(path.join(ctx.publicDir, 'network.json'), packet); return;
  }
  const nodes = await Promise.all([0, 1, 2, 3].map(async index => validateBootstrap(await artifact(ctx, `konaet-node-${index}-${ctx.key}`, `node-${index}.json`), index)));
  check(new Set(nodes.map(node => node.body.publicKey)).size === 4 && new Set(nodes.map(node => node.body.hostHash)).size === 4, 'DISTINCT_RUNNER_IDENTITIES_REQUIRED');
  const caDirectory = path.join(ctx.privateDir, 'ca'); fs.mkdirSync(caDirectory, { mode: 0o700 });
  const ssl = args => execFileSync('openssl', args, { cwd: caDirectory, stdio: 'pipe' });
  ssl(['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-subj', `/CN=KonaetValidation-${ctx.key}`,
    '-keyout', 'ca.key', '-out', 'ca.pem', '-days', '1', '-addext', 'basicConstraints=critical,CA:TRUE']);
  fs.writeFileSync(path.join(caDirectory, 'extensions.cnf'), 'basicConstraints=CA:FALSE\nsubjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth,clientAuth\n');
  const certificates = [];
  for (let index = 0; index < 4; index++) {
    check(typeof nodes[index].body.csr === 'string' && nodes[index].body.csr.length < 16384
      && nodes[index].body.csr.startsWith('-----BEGIN CERTIFICATE REQUEST-----'), 'CSR_INVALID');
    fs.writeFileSync(path.join(caDirectory, `node-${index}.csr`), nodes[index].body.csr);
    ssl(['req', '-in', `node-${index}.csr`, '-noout', '-verify']);
    ssl(['x509', '-req', '-in', `node-${index}.csr`, '-CA', 'ca.pem', '-CAkey', 'ca.key', '-subj', `/CN=validator-${index}`,
      '-set_serial', String(index + 1), '-days', '1', '-extfile', 'extensions.cnf', '-out', `node-${index}.pem`]);
    certificates.push(fs.readFileSync(path.join(caDirectory, `node-${index}.pem`), 'utf8'));
  }
  const alice = keyAt(path.join(ctx.privateDir, 'alice.seed')), bob = keyAt(path.join(ctx.privateDir, 'bob.seed'));
  const control = keyAt(path.join(ctx.privateDir, 'control.seed'));
  check(control.publicBytes().toString('hex') === nodes[0].body.controlPublicKey, 'CONTROL_KEY_MISMATCH');
  const { createGenesis } = require('../../chain/network/sovereign');
  const { UNIT } = require('../../chain/vlock7sin-js/src');
  const { compileKoPolicy } = require('../../chain/vlock7sin-js/src/koPolicy');
  const { AUTHORIZED_PROFILE } = require('../../chain/vlock7sin-js/src/koConsensusProfile');
  const nativePolicy = compileKoPolicy(fs.readFileSync(path.join(root, 'chain/contracts-ko/SindraRuntime.ko'), 'utf8'));
  const genesis = createGenesis({ contractRuntime: AUTHORIZED_PROFILE, nativePolicy, networkId: 78000000 + (Number(ctx.runId) % 1000000),
    chainName: 'Konaet remote operational validation', createdAt: new Date().toISOString(), threshold: 3,
    validators: nodes.map((packet, index) => ({ id: `validator-${index}`, publicKey: packet.body.publicKey })),
    deploymentPolicy: { schema: 'konaet.contract-deployment-policy.v1', deployers: [alice, bob].map(key => ({ address: key.address(), maxContracts: 64 })) },
    allocations: [{ address: alice.address(), amountAtomic: UNIT.initialSupplyAtomic }],
    parameters: { maxActs: 64, maxBytes: 262144, stateSyncChunk: 4, messageRateLimit: 512 } });
  const body = { schema: 'konaet.remote-network.v1', runId: ctx.key, commit: ctx.commit, seconds: ctx.seconds,
    controlPublicKey: control.publicBytes().toString('hex'), nodes, ca: fs.readFileSync(path.join(caDirectory, 'ca.pem'), 'utf8'), certificates,
    genesis, genesisSha256: sha256(Buffer.from(JSON.stringify(genesis, null, 2) + '\n')) };
  writeJson(path.join(ctx.publicDir, 'network.json'), signed(NETWORK_DOMAIN, body, control.privateKeyObject()));
}
async function execute() {
  if (ctx.index === 0) { const { runController } = await import('./controller.mjs'); await runController(ctx); return; }
  const until = Date.now() + (ctx.seconds + 900) * 1000;
  while (Date.now() < until) {
    if (fs.existsSync(path.join(ctx.privateDir, 'fatal.json'))) throw Error(readJson(path.join(ctx.privateDir, 'fatal.json')).code);
    if (fs.existsSync(path.join(ctx.privateDir, 'done.json'))) { check(readJson(path.join(ctx.privateDir, 'done.json')).passed, 'REMOTE_NODE_FAILED'); return; }
    await pause(1000);
  }
  throw Error('REMOTE_RUN_TIMEOUT');
}
async function cleanup() {
  const file = path.join(ctx.privateDir, 'agent-process.json'); if (!fs.existsSync(file)) return;
  const { pid } = readJson(file);
  try {
    const command = fs.readFileSync(`/proc/${pid}/cmdline`, 'utf8');
    if (command.includes(agentFile)) process.kill(pid, 'SIGTERM');
  } catch { /* Runner cleanup also owns all remaining tracked processes. */ }
}
try {
  if (mode === 'init') await initialize();
  else if (mode === 'network') await prepareNetwork();
  else if (mode === 'run') await execute();
  else if (mode === 'cleanup') await cleanup();
  else throw Error('REMOTE_COMMAND_INVALID');
} catch (error) { console.error(error.message); process.exitCode = 1; }
