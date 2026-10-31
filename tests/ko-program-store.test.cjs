'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { spawnSync, spawn } = require('node:child_process');
const { compileContract } = require('../chain/ko-program/runtime');
const { createStore, recoverStore, callStore } = require('../chain/ko-program/store');
const root = path.resolve(__dirname, '..'), cli = path.join(root, 'chain/ko-program/cli.js');
const source = fs.readFileSync(path.join(root, 'chain/ko-program/examples/Counter.ko'), 'utf8');
const artifact = compileContract(source), caller = 'v7' + 'a'.repeat(32);
const options = { caller, networkId: '77' };
function directory(t) {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'konaet-program-store-'));
  t.after(() => { const target = path.resolve(base); assert.ok(target.startsWith(path.resolve(os.tmpdir()) + path.sep));
    assert.match(path.basename(target), /^konaet-program-store-/); fs.rmSync(target, { recursive: true, force: true }); });
  return base;
}
function request(revision = '0', amount = '7') { return { caller, method: 'increment', args: [amount], expectedRevision: revision, gasLimit: 10000 }; }
test('durable store replays committed calls and preserves storage and root across a new process', t => {
  const base = directory(t), store = path.join(base, 'contract');
  createStore(store, artifact, options);
  const receipt = callStore(store, request());
  assert.equal(receipt.result, '14');
  const restored = recoverStore(store);
  assert.deepEqual(restored.state, receipt.state); assert.equal(restored.committedCalls, 1);
  const child = spawnSync(process.execPath, [cli, 'status', store], { encoding: 'utf8', windowsHide: true, timeout: 10000 });
  assert.equal(child.status, 0, child.stderr); assert.equal(JSON.parse(child.stdout).state.stateRoot, receipt.state.stateRoot);
  const view = callStore(store, { caller, method: 'readTotal', args: [], expectedRevision: '1' });
  assert.equal(view.result, '14'); assert.equal(recoverStore(store).committedCalls, 1);
});
test('stale calls and contract failures never publish a new revision or overwrite an existing deployment', t => {
  const base = directory(t), store = path.join(base, 'contract');
  createStore(store, artifact, options); const first = callStore(store, request());
  const bytes = fs.readFileSync(path.join(store, '00000000000000000001.json'));
  assert.throws(() => callStore(store, request()), { code: 'KO_STALE_STATE' });
  assert.throws(() => callStore(store, { ...request('1'), caller: 'v7' + 'b'.repeat(32) }), { code: 'KO_REQUIRE_FAILED' });
  assert.throws(() => createStore(store, artifact, options), { code: 'KO_STORE_EXISTS' });
  assert.deepEqual(fs.readFileSync(path.join(store, '00000000000000000001.json')), bytes);
  assert.equal(recoverStore(store).state.stateRoot, first.state.stateRoot);
});
test('unpublished temporary records are ignored, while committed corruption and missing revisions fail closed', t => {
  const base = directory(t), store = path.join(base, 'contract'); createStore(store, artifact, options);
  const first = callStore(store, request());
  fs.writeFileSync(path.join(store, '.pending-crash-fixture.json'), '{partial');
  assert.equal(recoverStore(store).state.stateRoot, first.state.stateRoot);
  const record = path.join(store, '00000000000000000001.json'), bytes = fs.readFileSync(record);
  fs.writeFileSync(record, bytes.toString().replace('"result": "14"', '"result": "99"'));
  assert.throws(() => recoverStore(store), { code: 'KO_STORE_RECORD_CORRUPT' });
  fs.writeFileSync(record, bytes); callStore(store, request('1', '1')); fs.unlinkSync(record);
  assert.throws(() => recoverStore(store), { code: 'KO_STORE_HISTORY_GAP' });
});
test('two independent writer processes cannot both commit the same expected revision', async t => {
  const base = directory(t), store = path.join(base, 'contract'), file = path.join(base, 'call.json');
  createStore(store, artifact, options); fs.writeFileSync(file, JSON.stringify(request()));
  const run = () => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [cli, 'call', store, file], { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '', stderr = '';
    const timeout = setTimeout(() => { child.kill(); reject(Error('CHILD_TIMEOUT')); }, 10000);
    child.stdout.on('data', bytes => { stdout += bytes; }); child.stderr.on('data', bytes => { stderr += bytes; });
    child.on('error', error => { clearTimeout(timeout); reject(error); });
    child.on('exit', code => { clearTimeout(timeout); resolve({ code, stdout, stderr }); });
  });
  const results = await Promise.all([run(), run()]);
  assert.equal(results.filter(result => result.code === 0).length, 1);
  assert.equal(JSON.parse(results.find(result => result.code !== 0).stderr).code, 'KO_STALE_STATE');
  const state = recoverStore(store); assert.equal(state.committedCalls, 1); assert.equal(state.state.storage.total, '14');
});
test('CLI compilation, deployment and execution work from files and refuse overwriting compiled artifacts', t => {
  const base = directory(t), sourceFile = path.join(base, 'Counter.ko'), artifactFile = path.join(base, 'Counter.json'), deployment = path.join(base, 'deployment.json'), call = path.join(base, 'call.json'), store = path.join(base, 'state');
  fs.writeFileSync(sourceFile, source); fs.writeFileSync(deployment, JSON.stringify(options)); fs.writeFileSync(call, JSON.stringify(request()));
  const run = args => spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8', windowsHide: true, timeout: 10000 });
  assert.equal(run(['compile', sourceFile, artifactFile]).status, 0);
  assert.equal(run(['compile', sourceFile, artifactFile]).status, 1);
  assert.equal(run(['deploy', artifactFile, store, deployment]).status, 0);
  const receipt = run(['call', store, call]); assert.equal(receipt.status, 0, receipt.stderr);
  assert.equal(JSON.parse(receipt.stdout).state.storage.total, '14');
});
test('disk failure before the atomic commit leaves the recovered state unchanged', t => {
  const base = directory(t), store = path.join(base, 'contract');
  const original = createStore(store, artifact, options).state;
  const link = fs.linkSync;
  t.mock.method(fs, 'linkSync', (from, to) => {
    if (path.basename(to) === '00000000000000000001.json') { const error = Error('No disk space'); error.code = 'ENOSPC'; throw error; }
    return link(from, to);
  });
  assert.throws(() => callStore(store, request()), { code: 'ENOSPC' });
  assert.deepEqual(recoverStore(store).state, original);
  assert.ok(!fs.readdirSync(store).some(name => name.startsWith('.pending-')));
});
