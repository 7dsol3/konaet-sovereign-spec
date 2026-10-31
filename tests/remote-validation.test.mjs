import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import net from 'node:net';
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { createRequire } from 'node:module';
import { signed, verified, endpoint, REPORT_DOMAIN, CONTROL_DOMAIN } from '../tools/remote/common.mjs';
import { incomingRelay, outgoingProxy } from '../tools/remote/relay.mjs';
import { verifyRemoteResults } from '../tools/remote/verify-report.mjs';
const require = createRequire(import.meta.url);
const { crypto: vcrypto, UNIT } = require('../chain/vlock7sin-js/src');
const { createGenesis, SovereignNode } = require('../chain/network/sovereign');
const { AUTHORIZED_PROFILE } = require('../chain/vlock7sin-js/src/koConsensusProfile');
const { compileKoPolicy } = require('../chain/vlock7sin-js/src/koPolicy');

test('signed reports from the four-VM run verify and reject tampering or a different workflow identity', () => {
  const read = name => JSON.parse(fs.readFileSync(new URL('../evidence/remote-smoke-2026-10-31/' + name, import.meta.url), 'utf8'));
  const controller = read('controller.json'), packets = [0, 1, 2, 3].map(index => read('result-' + index + '.json'));
  const commit = '8cdf7e01767e3b9e4df92323e4fd7ca1d350ef91', run = '41210093390-1';
  assert.deepEqual(verifyRemoteResults(controller, packets, commit, run), read('verified-summary.json'));
  assert.throws(() => verifyRemoteResults(controller, [packets[0], packets[0], ...packets.slice(2)], commit, run));
  assert.throws(() => verifyRemoteResults(controller, packets, '0'.repeat(40), run));
  assert.throws(() => verifyRemoteResults(controller, packets, commit, 'other-run'));
  const changed = structuredClone(controller); changed.body.elapsedMs = 3600000;
  assert.throws(() => verifyRemoteResults(changed, packets, commit, run));
  const modifiedNode = structuredClone(packets); modifiedNode[0].body.state.root = '0'.repeat(64);
  assert.throws(() => verifyRemoteResults(controller, modifiedNode, commit, run));
});

test('remote control signatures bind domain, run, action and key', () => {
  const key = vcrypto.IdentityKeypair.generate(), other = vcrypto.IdentityKeypair.generate();
  const body = { runId: '123-1', action: 'stop', seq: 1 };
  const packet = signed(CONTROL_DOMAIN, body, key.privateKeyObject());
  assert.deepEqual(verified(CONTROL_DOMAIN, packet, key.publicBytes().toString('hex')), body);
  assert.throws(() => verified(REPORT_DOMAIN, packet, key.publicBytes().toString('hex')));
  assert.throws(() => verified(CONTROL_DOMAIN, packet, other.publicBytes().toString('hex')));
  assert.throws(() => verified(CONTROL_DOMAIN, { ...packet, body: { ...body, action: 'start' } }, key.publicBytes().toString('hex')));
  assert.throws(() => endpoint('https://api.trycloudflare.com/'));
  assert.throws(() => endpoint('http://127.0.0.1/')); assert.throws(() => endpoint('https://one.trycloudflare.com/?x=1'));
});

test('the one-hour four-VM report verifies finality, duration, supply and stateful contract totals', () => {
  const read = name => JSON.parse(fs.readFileSync(new URL('../evidence/remote-hour-2026-10-31/' + name, import.meta.url), 'utf8'));
  const controller = read('controller.json'), nodes = [0, 1, 2, 3].map(index => read(`result-${index}.json`));
  const result = verifyRemoteResults(controller, nodes, '8cdf7e01767e3b9e4df92323e4fd7ca1d350ef91', '41210381147-1');
  assert.deepEqual(result, read('verified-summary.json')); assert.ok(result.observedMs >= 3600000);
  assert.equal(result.transfers, 415); assert.equal(result.calls, 138); assert.equal(result.sequence, '554');
});

test('a remote TCP-over-WebSocket relay preserves byte order and backpressure', async t => {
  const echo = net.createServer(socket => { socket.on('error', () => {}); socket.pipe(socket); });
  await new Promise(resolve => echo.listen(0, '127.0.0.1', resolve));
  const server = http.createServer(), closeRelay = incomingRelay(server, echo.address().port);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const proxy = await outgoingProxy(`ws://127.0.0.1:${server.address().port}/transport`);
  t.after(async () => { await proxy.close(); await closeRelay(); await new Promise(resolve => server.close(resolve)); await new Promise(resolve => echo.close(resolve)); });
  const bytes = crypto.randomBytes(2 * 1024 * 1024), chunks = [];
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(Error('RELAY_TIMEOUT')), 5000);
    const client = net.connect(proxy.port, '127.0.0.1'); let size = 0;
    client.once('error', reject); client.once('connect', () => client.write(bytes));
    client.on('data', chunk => { chunks.push(chunk); size += chunk.length; if (size === bytes.length) { clearTimeout(timer); client.destroy(); resolve(); } });
  });
  assert.deepEqual(Buffer.concat(chunks), bytes);
});

test('pending work resumes when a stopped quorum reconnects without another submission', async t => {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'konaet-quorum-resume-'));
  const keys = Array.from({ length: 4 }, () => vcrypto.IdentityKeypair.generate());
  const alice = vcrypto.IdentityKeypair.generate(), bob = vcrypto.IdentityKeypair.generate();
  const nativePolicy = compileKoPolicy(fs.readFileSync(new URL('../chain/contracts-ko/SindraRuntime.ko', import.meta.url), 'utf8'));
  const genesis = createGenesis({ contractRuntime: AUTHORIZED_PROFILE, nativePolicy, networkId: 78001111,
    createdAt: '2026-10-31T00:00:00.000Z', threshold: 3,
    validators: keys.map((key, index) => ({ id: `validator-${index}`, publicKey: key.publicBytes() })),
    deploymentPolicy: { schema: 'konaet.contract-deployment-policy.v1', deployers: [{ address: alice.address(), maxContracts: 64 }] },
    allocations: [{ address: alice.address(), amountAtomic: UNIT.initialSupplyAtomic }] });
  const nodes = keys.map((identity, index) => new SovereignNode({ genesis, identity, validatorId: `validator-${index}`,
    dataDir: path.join(base, 'node-' + index), automaticConsensus: true, roundTimeoutMs: 200, proposalDelayMs: 20 }));
  t.after(async () => {
    await Promise.allSettled(nodes.map(node => node.close()));
    const target = path.resolve(base); assert.ok(target.startsWith(path.resolve(os.tmpdir()) + path.sep) && path.basename(target).startsWith('konaet-quorum-resume-'));
    fs.rmSync(target, { recursive: true, force: true });
  });
  const ports = [];
  for (let index = 0; index < 2; index++) ports[index] = (await nodes[index].start({ host: '127.0.0.1', port: 0 })).address.port;
  await nodes[0].connect(`ws://127.0.0.1:${ports[1]}`, 'validator-1');
  nodes[0].submitTransfer(nodes[0].createTransfer({ sender: alice, receiverAddress: bob.address(), amountAtomic: 1n }));
  await new Promise(resolve => setTimeout(resolve, 1400)); assert.equal(nodes[0].ledger.sequence, 0n);
  for (let index = 2; index < 4; index++) ports[index] = (await nodes[index].start({ host: '127.0.0.1', port: 0 })).address.port;
  for (let i = 0; i < 4; i++) for (let j = Math.max(i + 1, 2); j < 4; j++) await nodes[i].connect(`ws://127.0.0.1:${ports[j]}`, `validator-${j}`);
  await Promise.all(nodes.map(node => node.waitForSequence(1n, 2500)));
  assert.equal(new Set(nodes.map(node => node.ledger.root)).size, 1);
});
