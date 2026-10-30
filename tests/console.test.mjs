import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { atomic } from '../tools/demo-network.mjs';
import { startConsole } from '../tools/console.mjs';

test('SND decimal amounts preserve all nine places and reject ambiguous or excessive values', () => {
  assert.equal(atomic('1.000000001'), 1000000001n);
  assert.equal(atomic('0.000000001'), 1n);
  for (const value of ['0', '-1', '01', '1e9', '1,5', '1.0000000001', '1000000001', 1]) assert.throws(() => atomic(value));
});
test('the extracted-console flow finalizes signed transfers in four processes and recovers WAL', { timeout: 90000 }, async t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'konaet-public-console-'));
  let app;
  t.after(async () => { if (app) await app.close();
    const target = path.resolve(directory); assert.ok(target.startsWith(path.resolve(os.tmpdir()) + path.sep));
    assert.match(path.basename(target), /^konaet-public-console-/); fs.rmSync(target, { recursive: true, force: true }); });
  app = await startConsole({ dataDirectory: directory });
  async function get(url) { const response = await fetch(app.url + url); assert.equal(response.status, 200); return response.json(); }
  const page = await fetch(app.url); const html = await page.text();
  assert.match(page.headers.get('content-security-policy'), /frame-ancestors 'none'/);
  const token = html.match(/name="konaet-token" content="([a-f0-9]{64})"/)[1];
  async function post(url, body, headers = {}) { return fetch(app.url + url, { method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Konaet-Token': token, ...headers }, body: JSON.stringify(body) }); }
  const before = await get('/api/network');
  assert.equal(before.converged, true); assert.equal(before.validators.length, 4);
  assert.equal(new Set(before.validators.map(v => v.pid)).size, 4);
  assert.ok(before.validators.every(v => v.pid !== process.pid && v.policyEnforced));
  assert.equal(before.accounts[1].balanceAtomic, '0');
  assert.equal((await post('/api/transfer', { from: 'alice', amount: '1' }, { 'X-Konaet-Token': '' })).status, 403);
  assert.equal((await post('/api/transfer', { from: 'alice', amount: '1' }, { Origin: 'https://foreign.example' })).status, 403);
  assert.equal((await get('/api/network')).root, before.root);
  const sent = await post('/api/transfer', { from: 'alice', amount: '1.25' }); assert.equal(sent.status, 200);
  const receipt = (await sent.json()).receipt; assert.equal(receipt.signaturesVerifiedByValidators, true);
  const after = await get('/api/network'); assert.equal(after.accounts[1].balanceAtomic, '1250000000');
  assert.equal(after.converged, true); assert.equal(after.sequence, '1');
  assert.equal((await post('/api/transfer', { from: 'bob', amount: '100' })).status, 422);
  assert.equal((await get('/api/network')).root, after.root);
  assert.equal((await post('/api/transfer', { from: 'bob', amount: '0.25' })).status, 200);
  const settled = await get('/api/network'); assert.equal(settled.accounts[1].balanceAtomic, '1000000000');
  const runtime = await get('/api/runtime');
  assert.equal((await post('/api/ko', { source: runtime.source, phase: 'closure', context: { 'closure.actCount': '1', 'closure.byteLength': '400' } })).status, 200);
  assert.equal((await post('/api/ko', { source: runtime.source, phase: 'closure', context: { 'closure.actCount': '65', 'closure.byteLength': '400' } })).status, 422);
  await app.close(); app = undefined;
  assert.equal(fs.existsSync(path.join(directory, 'console.lock')), false);
  app = await startConsole({ dataDirectory: directory });
  const restored = await get('/api/network');
  assert.equal(restored.root, settled.root); assert.deepEqual(restored.accounts, settled.accounts);
  assert.equal(restored.history.length, 2); assert.equal(restored.genesisId, before.genesisId);
  assert.ok(restored.validators.every(v => !before.validators.some(old => old.pid === v.pid)));
});
