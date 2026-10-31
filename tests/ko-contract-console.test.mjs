import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { createRequire } from 'node:module';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { startConsole } from '../tools/console.mjs';
const require = createRequire(import.meta.url);
const { verifyContractReceipt, parseTrustArguments } = require('../tools/verify-contract-receipt.cjs');
test('the console finalizes stateful .ko across four OS processes and exports a tamper-resistant quorum receipt', { timeout: 90000 }, async t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'konaet-contract-console-')); let app;
  t.after(async () => { if (app) await app.close(); const target = path.resolve(directory);
    assert.ok(target.startsWith(path.resolve(os.tmpdir()) + path.sep)); assert.match(path.basename(target), /^konaet-contract-console-/); fs.rmSync(target, { recursive: true, force: true }); });
  app = await startConsole({ dataDirectory: directory });
  const html = await (await fetch(app.url)).text(), token = html.match(/name="konaet-token" content="([a-f0-9]{64})"/)[1];
  const post = (url, body, headers = {}) => fetch(app.url + url, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Konaet-Token': token, ...headers }, body: JSON.stringify(body) });
  const before = await (await fetch(app.url + '/api/network')).json(); assert.equal(before.contractRuntime.enforced, true);
  assert.equal(new Set(before.validators.map(row => row.pid)).size, 4);
  const { examples } = await (await fetch(app.url + '/api/program')).json();
  const deployment = { from: 'alice', source: examples.RegistryToken, salt: '0', gasLimit: 10000 };
  assert.equal((await post('/api/contracts/deploy', deployment, { 'X-Konaet-Token': '' })).status, 403);
  assert.equal((await post('/api/contracts/deploy', deployment, { Origin: 'https://foreign.example' })).status, 403);
  const response = await post('/api/contracts/deploy', deployment); assert.equal(response.status, 200, await response.clone().text());
  const deployed = await response.json(), contractId = deployed.receipt.contractId;
  assert.equal(verifyContractReceipt(deployed.receipt.bundle).verified, true);
  const mint = await post('/api/contracts/call', { from: 'alice', contractId, method: 'mint', args: [before.accounts[0].address, '100'], gasLimit: 10000 });
  assert.equal(mint.status, 200, await mint.clone().text()); const minted = await mint.json(); assert.equal(verifyContractReceipt(minted.receipt.bundle).receipts[0].events[0].name, 'Minted');
  const transfer = await post('/api/contracts/call', { from: 'alice', contractId, method: 'transfer', args: [before.accounts[1].address, '7'], gasLimit: 10000 });
  assert.equal(transfer.status, 200, await transfer.clone().text()); const moved = await transfer.json(), bundle = moved.receipt.bundle;
  const verified = verifyContractReceipt(bundle); assert.equal(verified.verified, true); assert.ok(verified.signers.length >= 3);
  assert.equal(verified.genesisPinned, false); assert.equal(verified.previousStatePinned, false);
  const trust = { expectedGenesisId: bundle.genesis.genesisId, expectedPreviousRoot: bundle.beforeState.root };
  const pinned = verifyContractReceipt(bundle, trust);
  assert.equal(pinned.genesisPinned, true); assert.equal(pinned.previousStatePinned, true);
  assert.throws(() => verifyContractReceipt(bundle, { ...trust, expectedGenesisId: '0'.repeat(64) }), /RECEIPT_UNEXPECTED_GENESIS/);
  assert.throws(() => verifyContractReceipt(bundle, { ...trust, expectedPreviousRoot: '0'.repeat(64) }), /RECEIPT_UNEXPECTED_PREVIOUS_ROOT/);
  const receiptFile = path.join(directory, 'receipt.json'); fs.writeFileSync(receiptFile, JSON.stringify(bundle));
  const wrongPolicy = structuredClone(bundle); wrongPolicy.beforeState.deploymentPolicy.deployers[0].maxContracts++;
  assert.throws(() => verifyContractReceipt(wrongPolicy));
  const verifier = new URL('../tools/verify-contract-receipt.cjs', import.meta.url);
  const cli = spawnSync(process.execPath, [fileURLToPath(verifier), receiptFile,
    '--genesis-id', trust.expectedGenesisId, '--previous-root', trust.expectedPreviousRoot], { encoding: 'utf8', windowsHide: true });
  assert.equal(cli.status, 0, cli.stderr); assert.equal(JSON.parse(cli.stdout).genesisPinned, true);
  assert.equal(verified.receipts[0].result, '93'); assert.equal(verified.receipts[0].events[0].name, 'Moved');
  for (const mutate of [b => { b.afterState.contracts[0].state.storage.supply = '999'; }, b => { b.certificate.signatures[0].signature = '0'.repeat(128); },
    b => { b.events[0] = b.events[0].slice(0, -4) + 'AAAA'; }, b => { b.afterState.receipts[0].result = '99'; }]) {
    const corrupted = structuredClone(bundle); mutate(corrupted); assert.throws(() => verifyContractReceipt(corrupted));
  }
  const denied = await post('/api/contracts/call', { from: 'bob', contractId, method: 'mint', args: [before.accounts[1].address, '1'], gasLimit: 10000 }); assert.equal(denied.status, 422);
  const after = await (await fetch(app.url + '/api/network')).json(); assert.equal(after.root, verified.stateRoot); assert.equal(after.accounts[0].balanceAtomic, before.accounts[0].balanceAtomic);
  await app.close(); app = undefined; app = await startConsole({ dataDirectory: directory });
  const restored = await (await fetch(app.url + '/api/network')).json(); assert.equal(restored.root, after.root); assert.deepEqual(restored.contracts, after.contracts);
  const record = await (await fetch(app.url + '/api/contracts/' + contractId)).json(); assert.equal(record.state.storage.supply, '100');
});

test('receipt trust anchors reject malformed, duplicate and unsupported CLI options', () => {
  const digest = 'a'.repeat(64);
  assert.deepEqual(parseTrustArguments(['--genesis-id', digest]), { expectedGenesisId: digest });
  for (const args of [['--genesis-id'], ['--genesis-id', 'invalid'], ['--other', digest],
    ['--genesis-id', digest, '--genesis-id', digest], ['constructor', digest]]) {
    assert.throws(() => parseTrustArguments(args), /RECEIPT_TRUST_/);
  }
  assert.throws(() => verifyContractReceipt({}, { unrelated: digest }), /RECEIPT_TRUST_OPTIONS_INVALID/);
});
