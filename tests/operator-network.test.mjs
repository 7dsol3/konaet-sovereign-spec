import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { startGateway } from '../tools/operator-gateway.mjs';
const require = createRequire(import.meta.url);
const { crypto: vcrypto, UNIT, PermissionedQuorum, recoverWal } = require('../chain/vlock7sin-js/src');
const { compileKoPolicy } = require('../chain/vlock7sin-js/src/koPolicy');
const { PROFILE } = require('../chain/vlock7sin-js/src/koConsensusProfile');
const { ContractEvent } = require('../chain/vlock7sin-js/src/contractEvent');
const { runtime, auth } = require('../chain/vlock7sin-js/src/koProgramRuntime');
const { build } = require('../chain/scripts/buildIndependentGenesis');
const { start } = require('../chain/scripts/runIndependentValidator');
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

async function eventually(check, description, timeout = 20000) {
  const until = Date.now() + timeout;
  while (Date.now() < until) { if (await check()) return; await new Promise(resolve => setTimeout(resolve, 80)); }
  assert.fail(description);
}

test('signed .ko passes the gateway, finalizes over real operator mTLS, and recovers quorum after restart', { timeout: 90000 }, async t => {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'konaet-gateway-network-'));
  const nodes = [], configs = [], ports = new Set(); let gateway;
  t.after(async () => {
    if (gateway) await gateway.close();
    await Promise.all(nodes.map(node => node?.close()));
    const target = path.resolve(base);
    assert.equal(path.dirname(target), path.resolve(os.tmpdir()));
    assert.match(path.basename(target), /^konaet-gateway-network-/);
    fs.rmSync(target, { recursive: true, force: true });
  });
  async function port() {
    for (;;) {
      const socket = net.createServer();
      await new Promise(resolve => socket.listen(0, '127.0.0.1', resolve));
      const candidate = socket.address().port;
      await new Promise(resolve => socket.close(resolve));
      if (!ports.has(candidate)) { ports.add(candidate); return candidate; }
    }
  }
  const openssl = ['openssl', ...(process.env.ProgramFiles ? [path.join(process.env.ProgramFiles, 'Git', 'usr', 'bin', 'openssl.exe')] : [])]
    .find(candidate => spawnSync(candidate, ['version'], { windowsHide: true, encoding: 'utf8' }).status === 0);
  assert.ok(openssl, 'OpenSSL is required for the real mTLS integration test');
  function ssl(args, cwd = base) {
    const result = spawnSync(openssl, args, { cwd, encoding: 'utf8', windowsHide: true, timeout: 15000 });
    assert.equal(result.status, 0, result.stderr);
  }
  ssl(['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=KonaetGatewayTestCA',
    '-keyout', 'ca.key', '-out', 'ca.pem', '-days', '1', '-addext', 'basicConstraints=critical,CA:TRUE']);
  const identities = Array.from({ length: 4 }, (_, index) => {
    const directory = path.join(base, `validator-${index}`); fs.mkdirSync(directory);
    const seed = crypto.randomBytes(32), identity = vcrypto.IdentityKeypair.fromSeed(seed);
    fs.writeFileSync(path.join(directory, 'own.seed'), seed.toString('hex')); seed.fill(0);
    return identity;
  });
  const owner = vcrypto.IdentityKeypair.generate();
  const nativePolicy = compileKoPolicy(fs.readFileSync(path.join(ROOT, 'chain/contracts-ko/SindraRuntime.ko'), 'utf8'));
  const genesis = build({ scope: 'private-testnet-no-value', networkId: 77111234, createdAt: '2026-10-30T00:00:00.000Z',
    contractRuntime: PROFILE, nativePolicy,
    validators: identities.map((identity, index) => ({ id: `validator-${index}`, administratorId: `test-admin-${index}`, publicKey: identity.publicBytes().toString('hex') })),
    allocations: [{ address: owner.address(), amountAtomic: UNIT.initialSupplyAtomic.toString() }] });
  const genesisBytes = Buffer.from(JSON.stringify(genesis)), meshPorts = await Promise.all(identities.map(() => port()));
  const tokens = identities.map(() => crypto.randomBytes(32).toString('hex'));
  for (let index = 0; index < 4; index++) {
    const directory = path.join(base, `validator-${index}`);
    ssl(['req', '-newkey', 'rsa:2048', '-nodes', '-subj', `/CN=validator-${index}`, '-keyout', 'own.key', '-out', 'own.csr'], directory);
    fs.writeFileSync(path.join(directory, 'extensions.cnf'), 'subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth,clientAuth\nbasicConstraints=CA:FALSE\n');
    ssl(['x509', '-req', '-in', 'own.csr', '-CA', path.join(base, 'ca.pem'), '-CAkey', path.join(base, 'ca.key'),
      '-set_serial', String(index + 100), '-out', 'own.pem', '-days', '1', '-extfile', 'extensions.cnf'], directory);
    fs.copyFileSync(path.join(base, 'ca.pem'), path.join(directory, 'ca.pem'));
    fs.writeFileSync(path.join(directory, 'genesis.json'), genesisBytes);
    fs.writeFileSync(path.join(directory, 'submit.token'), tokens[index]);
    const config = { schema: 'konaet.independent-validator.config.v1', scope: 'private-testnet-no-value', mutualTlsRequired: true,
      validatorId: `validator-${index}`, host: '127.0.0.1', port: meshPorts[index], statusPort: await port(),
      genesisFile: 'genesis.json', genesisSha256: crypto.createHash('sha256').update(genesisBytes).digest('hex'),
      seedFile: 'own.seed', caFile: 'ca.pem', certificateFile: 'own.pem', tlsKeyFile: 'own.key', submitTokenFile: 'submit.token', dataDirectory: 'data',
      peers: meshPorts.flatMap((peerPort, peer) => peer === index ? [] : [{ validatorId: `validator-${peer}`, url: `wss://127.0.0.1:${peerPort}/` }]) };
    const file = path.join(directory, 'operator.json'); fs.writeFileSync(file, JSON.stringify(config)); configs.push({ file, ...config });
    nodes.push(await start(file));
  }
  await eventually(() => nodes.every(node => node.readiness().ready), 'All operator runtimes must observe a connected quorum');
  gateway = await startGateway({ upstream: `http://127.0.0.1:${configs[0].statusPort}`, submitToken: tokens[0], allowSubmissions: true });
  const get = async route => { const response = await fetch(gateway.url + route); assert.equal(response.status, 200, await response.clone().text()); return response.json(); };
  assert.equal((await get('/api/genesis')).genesisId, genesis.genesisId);
  assert.equal((await get('/health/ready')).ready, true);
  const source = fs.readFileSync(path.join(ROOT, 'chain/ko-program/examples/Counter.ko'), 'utf8'), artifact = runtime.compileContract(source);
  async function submit(envelope, sourceText, nonce) {
    const status = await get('/api/status');
    const event = new ContractEvent({ envelope, source: sourceText, nonce: String(nonce), sequence: String(BigInt(status.sequence) + 1n), previousRoot: status.root, signature: '' }).sign(owner);
    const response = await fetch(gateway.url + '/api/transactions', { method: 'POST', headers: { 'Content-Type': 'application/octet-stream' }, body: event.canonicalBytes() });
    assert.equal(response.status, 202, await response.clone().text());
    const accepted = await response.json(); assert.equal(accepted.finalized, false); assert.equal(accepted.transactionId, event.id().toString('hex'));
    await eventually(() => nodes.every(node => node.status().sequence === event.sequence.toString()), 'The four operators must finalize the same closure');
    assert.equal(new Set(nodes.map(node => node.status().root)).size, 1);
    return event;
  }
  const deployment = auth.signDeployment(artifact, { networkId: genesis.networkId, salt: '0', gasLimit: 10000 }, owner.privateKeyObject());
  const deployed = await submit(deployment, source, 1), contractId = deployed.contractId;
  const record = await get('/api/contract/' + contractId);
  const call = auth.signCall(artifact, record.state, { method: 'increment', args: ['7'], gasLimit: 10000 }, owner.privateKeyObject());
  await submit(call, null, 2);
  assert.equal((await get('/api/contract/' + contractId)).state.storage.total, '14');
  assert.equal((await get('/api/account/' + owner.address())).nonce, '2');
  const quorum = new PermissionedQuorum({ networkId: genesis.networkId, protocolVersion: genesis.protocolVersion, threshold: 3, validators: genesis.validators });
  const wal = recoverWal(path.join(base, 'validator-0/data/ledger.v7wal'), { decodeRecords: true });
  assert.equal(wal.clean, true);
  const closures = wal.frames.map(row => row.record).filter(row => row.certificate);
  assert.equal(closures.length, 2);
  for (const closure of closures) { quorum.verifyCertificate(closure.certificate, closure); assert.ok(closure.certificate.signatures.length >= 3); }
  const publicData = JSON.stringify(await get('/api/status'));
  for (const token of tokens) assert.equal(publicData.includes(token), false);
  assert.equal(publicData.includes('voteJournal'), false);
  await nodes[3].close(); nodes[3] = undefined;
  await nodes[2].close(); nodes[2] = undefined;
  await eventually(() => !nodes[0].readiness().ready, 'Loss of quorum must change readiness');
  const unavailable = await fetch(gateway.url + '/health/ready'); assert.equal(unavailable.status, 503);
  assert.equal((await unavailable.json()).reason, 'QUORUM_UNAVAILABLE');
  nodes[2] = await start(configs[2].file); nodes[3] = await start(configs[3].file);
  await eventually(() => nodes.every(node => node.readiness().ready && node.status().sequence === '2'), 'Restart must recover contracts and connected quorum');
  assert.equal(new Set(nodes.map(node => node.status().root)).size, 1);
  assert.equal((await get('/api/contract/' + contractId)).state.storage.total, '14');
});
