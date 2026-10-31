'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { spawn } = require('node:child_process');
const { pathToFileURL } = require('node:url');
const test = require('node:test');
const { crypto: vcrypto, UNIT, VlockLedger, WalStore, recoverWal, recoverAbandonedWriterLock } = require('../chain/vlock7sin-js/src');
const { createGenesis, validateGenesis, stateFromGenesis, SovereignNode } = require('../chain/network/sovereign');
const { compileKoPolicy } = require('../chain/vlock7sin-js/src/koPolicy');
const { ContractEvent } = require('../chain/vlock7sin-js/src/contractEvent');
const { KoGlobalState, verifyKoAccountProof } = require('../chain/vlock7sin-js/src/koState');
const { AUTHORIZED_FORMAT, AUTHORIZED_PROTOCOL, AUTHORIZED_PROFILE, FORMAT, PROFILE, normalizeDeploymentPolicy } = require('../chain/vlock7sin-js/src/koConsensusProfile');
const runtime = require('../chain/ko-program/runtime');
const auth = require('../chain/ko-program/auth');
const store = require('../chain/ko-program/store');
const root = path.resolve(__dirname, '..');
const source = fs.readFileSync(path.join(root, 'chain/ko-program/examples/Counter.ko'), 'utf8');
const artifact = runtime.compileContract(source);
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
function directory(t) {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'konaet-recovery-capacity-'));
  t.after(() => { const target = path.resolve(base); assert.ok(target.startsWith(path.resolve(os.tmpdir()) + path.sep)
    && path.basename(target).startsWith('konaet-recovery-capacity-')); fs.rmSync(target, { recursive: true, force: true }); });
  return base;
}
function fixture() {
  const seeds = Array.from({ length: 4 }, () => require('node:crypto').randomBytes(32));
  const keys = seeds.map(seed => vcrypto.IdentityKeypair.fromSeed(seed));
  const a = vcrypto.IdentityKeypair.generate(), b = vcrypto.IdentityKeypair.generate(), stranger = vcrypto.IdentityKeypair.generate();
  const nativePolicy = compileKoPolicy(fs.readFileSync(path.join(root, 'chain/contracts-ko/SindraRuntime.ko'), 'utf8'));
  const options = { format: AUTHORIZED_FORMAT, contractRuntime: AUTHORIZED_PROFILE, networkId: 77110778,
    createdAt: '2026-10-31T00:00:00.000Z', threshold: 3, nativePolicy,
    deploymentPolicy: { schema: 'konaet.contract-deployment-policy.v1', deployers: [a, b].map(key => ({ address: key.address(), maxContracts: 1 })) },
    validators: keys.map((key, index) => ({ id: `validator-${index}`, publicKey: key.publicBytes() })),
    allocations: [{ address: a.address(), amountAtomic: UNIT.initialSupplyAtomic }],
    parameters: { maxActs: 64, maxBytes: 262144, stateSyncChunk: 2, messageRateLimit: 512 } };
  const genesis = createGenesis(options);
  return { seeds, keys, a, b, stranger, options, genesis, nativePolicy,
    ledger: () => new VlockLedger({ state: stateFromGenesis(genesis), protocolVersion: AUTHORIZED_PROTOCOL, nativePolicy }) };
}
function deployment(f, ledger, signer, salt = '0') {
  const state = ledger.getState(), envelope = auth.signDeployment(artifact, { networkId: f.genesis.networkId, salt, gasLimit: 10000 }, signer.privateKeyObject());
  return new ContractEvent({ source, envelope, sequence: String(state.sequence + 1n), nonce: String(state.getNonce(signer.address()) + 1n),
    previousRoot: state.root().toString('hex'), signature: '' }).sign(signer);
}
async function until(check) {
  const end = Date.now() + 10000;
  while (!check()) { if (Date.now() > end) throw Error('TEST_WAIT_TIMEOUT'); await pause(10); }
}
async function killedWriter(t, base, walName = 'crash.v7wal') {
  const target = path.join(base, walName);
  const child = spawn(process.execPath, ['-e', "const {WalStore}=require(process.argv[1]);const wal=new WalStore(process.argv[2]);wal.appendRecord({kind:'fixture',value:1});process.stdout.write('READY\\n');setInterval(()=>{},1000)",
    path.join(root, 'chain/vlock7sin-js/src'), target], { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
  t.after(() => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); });
  await new Promise((resolve, reject) => { const timer = setTimeout(() => reject(Error('CHILD_TIMEOUT')), 5000);
    child.once('error', error => { clearTimeout(timer); reject(error); }); child.stdout.once('data', () => { clearTimeout(timer); resolve(); });
    child.once('exit', code => { clearTimeout(timer); if (code !== null) reject(Error('CHILD_EXITED')); }); });
  const exited = new Promise(resolve => child.once('exit', resolve)); child.kill('SIGKILL'); await exited;
  return target;
}

test('v8 commits deployment permissions and quotas without changing v7 genesis semantics', () => {
  const f = fixture(); assert.equal(validateGenesis(f.genesis).genesisId, f.genesis.genesisId);
  assert.equal(f.genesis.protocolVersion, AUTHORIZED_PROTOCOL);
  const changed = createGenesis({ ...f.options, deploymentPolicy: { ...f.options.deploymentPolicy,
    deployers: f.options.deploymentPolicy.deployers.map(row => ({ ...row, maxContracts: 2 })) } });
  assert.notEqual(changed.parametersRoot, f.genesis.parametersRoot); assert.notEqual(changed.stateRoot, f.genesis.stateRoot);
  const legacyOptions = { ...f.options, format: FORMAT, contractRuntime: PROFILE }; delete legacyOptions.deploymentPolicy;
  const legacy = createGenesis(legacyOptions); assert.equal(legacy.format, FORMAT);
  assert.equal(stateFromGenesis(legacy).deploymentPolicy, null);
  assert.throws(() => createGenesis({ ...legacyOptions, deploymentPolicy: f.options.deploymentPolicy }), { code: 'KO_DEPLOYMENT_POLICY_VERSION' });
  assert.throws(() => new VlockLedger({ state: stateFromGenesis(f.genesis), protocolVersion: legacy.protocolVersion, nativePolicy: f.nativePolicy }), { code: 'KO_PROGRAM_PROFILE_REQUIRED' });
  assert.throws(() => normalizeDeploymentPolicy({ schema: 'konaet.contract-deployment-policy.v1', deployers: [{ address: f.a.address(), maxContracts: 128 }, { address: f.b.address(), maxContracts: 1 }] }), { code: 'KO_DEPLOYMENT_POLICY_INVALID' });
  assert.throws(() => normalizeDeploymentPolicy({ schema: 'konaet.contract-deployment-policy.v1', deployers: [{ address: f.a.address(), maxContracts: 1 }, { address: f.a.address(), maxContracts: 1 }] }), { code: 'KO_DEPLOYMENT_POLICY_INVALID' });
});

test('an unlisted signer cannot consume contract slots and one authorized deployer cannot consume another quota', () => {
  const f = fixture(), ledger = f.ledger(), before = ledger.root;
  for (let index = 0; index < 8; index++) assert.throws(() => ledger.submitAct(deployment(f, ledger, vcrypto.IdentityKeypair.generate(), String(index))), /not authorized/);
  assert.equal(ledger.root, before); assert.equal(ledger.getState().contracts().length, 0);
  ledger.submitAct(deployment(f, ledger, f.a)); ledger.closeConstellation();
  assert.throws(() => ledger.submitAct(deployment(f, ledger, f.a, '1')), /quota exhausted/);
  assert.equal(ledger.getState().getBalance(f.b.address()), 0n);
  ledger.submitAct(deployment(f, ledger, f.b)); ledger.closeConstellation();
  assert.equal(ledger.getState().contracts().length, 2);
  const state = ledger.getState(), snapshot = state.snapshot();
  assert.equal(VlockLedger.fromSnapshot(ledger.snapshot(), { nativePolicy: f.nativePolicy }).root, ledger.root);
  assert.equal(KoGlobalState.fromSnapshot(snapshot).root().toString('hex'), ledger.root);
  const proof = state.createInclusionProof(f.a.address()); assert.equal(verifyKoAccountProof(proof, ledger.root), true);
  assert.equal(verifyKoAccountProof({ ...proof, deploymentPolicyHash: '0'.repeat(64) }, ledger.root), false);
  const edited = structuredClone(snapshot); edited.deploymentPolicy.deployers[0].maxContracts++;
  assert.throws(() => KoGlobalState.fromSnapshot(edited));
});

test('indexed WAL reads check selected hashes and avoid scanning unrelated history', t => {
  const base = directory(t), wal = new WalStore(path.join(base, 'indexed.wal')); t.after(() => wal.close());
  const frames = Array.from({ length: 30 }, (_, index) => wal.appendRecord({ index, text: 'x'.repeat(256) }));
  const original = fs.readSync; let readBytes = 0;
  t.mock.method(fs, 'readSync', function() { const count = original.apply(this, arguments); readBytes += count; return count; });
  assert.deepEqual(wal.readFrames([frames[29]]).map(record => record.index), [29]);
  assert.ok(readBytes < fs.statSync(wal.path).size / 10);
  assert.throws(() => wal.readFrames([frames[29]], { maxBytes: 1 }), { code: 'RECORD_LIMIT_EXCEEDED' });
  const write = fs.openSync(wal.path, 'r+'); fs.writeSync(write, Buffer.from([0]), 0, 1, frames[29].endOffset - 1); fs.closeSync(write);
  assert.throws(() => wal.readFrames([frames[29]]), { code: 'INVALID_RECORD' });
});

test('four v8 validators finalize quotas, discard expired caches, use bounded sync and recover a killed validator', async t => {
  const f = fixture(), base = directory(t), half = UNIT.initialSupplyAtomic / 2n;
  const genesis = createGenesis({ ...f.options, allocations: [{ address: f.a.address(), amountAtomic: half }, { address: f.b.address(), amountAtomic: UNIT.initialSupplyAtomic - half }] });
  const nodes = f.keys.map((identity, index) => new SovereignNode({ genesis, identity, validatorId: `validator-${index}`,
    dataDir: path.join(base, `node-${index}`), automaticConsensus: false }));
  let restarted;
  t.after(async () => { if (restarted) await restarted.close(); await Promise.allSettled(nodes.map(node => node.close())); });
  const ports = []; for (const node of nodes) ports.push((await node.start({ host: '127.0.0.1', port: 0 })).address.port);
  for (let i = 0; i < 4; i++) for (let j = i + 1; j < 4; j++) await nodes[i].connect(`ws://127.0.0.1:${ports[j]}`, `validator-${j}`);
  assert.throws(() => new SovereignNode({ genesis, identity: f.keys[0], validatorId: 'validator-0', dataDir: path.join(base, 'node-0') }), { code: 'WRITER_LOCKED' });
  assert.throws(() => nodes[0].submitContract(nodes[0].createContractDeployment({ sender: f.stranger, source })), /not authorized/);
  const contract = nodes[0].createContractDeployment({ sender: f.a, source }); nodes[0].submitContract(contract);
  await until(() => nodes.every(node => node.actBytes.size === 1));
  await nodes.find(node => node.validatorId === node.expectedLeader()).proposeNext({ timeoutMs: 5000 });
  await Promise.all(nodes.map(node => node.waitForSequence(1n, 5000)));
  assert.throws(() => nodes[0].submitContract(nodes[0].createContractDeployment({ sender: f.a, source, salt: '1' })), /quota exhausted/);
  for (let index = 0; index < 3; index++) {
    for (const sender of [f.a, f.b]) nodes[0].submitTransfer(nodes[0].createTransfer({ sender, receiverAddress: f.stranger.address(), amountAtomic: 1n }));
    await until(() => nodes.every(node => node.actBytes.size === 2));
    await nodes.find(node => node.validatorId === node.expectedLeader()).proposeNext({ timeoutMs: 5000 });
    await Promise.all(nodes.map(node => node.waitForSequence(BigInt(index + 2), 5000)));
    assert.ok(nodes.every(node => node.actBytes.size === 0 && node.rounds.size === 0));
  }
  assert.equal(nodes[0].closureRecords('1').length, 2); assert.equal(nodes[0].closureRecords('4').length, 1);
  assert.equal(new Set(nodes.map(node => node.ledger.root)).size, 1);
  const before = nodes[0].ledger.root;
  await nodes[3].close();
  const config = path.join(base, 'child.json'); fs.writeFileSync(config, JSON.stringify({ genesis, seed: f.seeds[3].toString('hex'), dataDir: path.join(base, 'node-3') }), { mode: 0o600 });
  const child = spawn(process.execPath, ['-e', "const fs=require('node:fs');const {SovereignNode}=require(process.argv[1]);const {crypto:v}=require(process.argv[2]);const c=JSON.parse(fs.readFileSync(process.argv[3]));new SovereignNode({genesis:c.genesis,identity:v.IdentityKeypair.fromSeed(Buffer.from(c.seed,'hex')),validatorId:'validator-3',dataDir:c.dataDir});process.stdout.write('READY\\n');setInterval(()=>{},1000)",
    path.join(root, 'chain/network/sovereign'), path.join(root, 'chain/vlock7sin-js/src'), config], { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
  t.after(() => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); });
  await new Promise((resolve, reject) => { const timer = setTimeout(() => reject(Error('CHILD_TIMEOUT')), 5000); child.once('error', reject);
    child.stdout.once('data', () => { clearTimeout(timer); resolve(); }); child.once('exit', () => { clearTimeout(timer); reject(Error('CHILD_EXITED')); }); });
  const exited = new Promise(resolve => child.once('exit', resolve)); child.kill('SIGKILL'); await exited;
  restarted = new SovereignNode({ genesis, identity: f.keys[3], validatorId: 'validator-3', dataDir: path.join(base, 'node-3') });
  assert.equal(restarted.ledger.root, before); assert.equal(restarted.lockRecoveries.length, 3);
  assert.equal(restarted.ledger.getState().contract(contract.contractId).state.storage.total, '0');
  const port = (await restarted.start({ host: '127.0.0.1', port: 0 })).address.port;
  for (let index = 0; index < 3; index++) await nodes[index].connect(`ws://127.0.0.1:${port}`, 'validator-3');
  const call = nodes[0].createContractCall({ sender: f.a, contractId: contract.contractId, method: 'increment', args: ['7'] }); nodes[0].submitContract(call);
  const live = [...nodes.slice(0, 3), restarted]; await until(() => live.every(node => node.actBytes.size === 1));
  await live.find(node => node.validatorId === node.expectedLeader()).proposeNext({ timeoutMs: 5000 });
  await Promise.all(live.map(node => node.waitForSequence(5n, 5000)));
  assert.equal(new Set(live.map(node => node.ledger.root)).size, 1);
  assert.equal(restarted.ledger.getState().contract(contract.contractId).state.storage.total, '14');
});

test('lock recovery preserves live and malformed owners and refuses a corrupt WAL', async t => {
  const base = directory(t), file = await killedWriter(t, base), original = fs.readFileSync(file + '.lock');
  const result = recoverAbandonedWriterLock(file); assert.equal(result.recovered, true);
  assert.deepEqual(fs.readFileSync(path.join(base, result.archive)), original);
  const wal = new WalStore(file); assert.throws(() => recoverAbandonedWriterLock(file), { code: 'WRITER_LOCKED' }); wal.close();
  fs.writeFileSync(file + '.lock', 'unknown-owner'); assert.throws(() => recoverAbandonedWriterLock(file), { code: 'LOCK_RECOVERY_REFUSED' });
  assert.equal(fs.readFileSync(file + '.lock', 'utf8'), 'unknown-owner'); fs.unlinkSync(file + '.lock');
  const corrupt = await killedWriter(t, base, 'corrupt.wal'), token = fs.readFileSync(corrupt + '.lock');
  const bytes = fs.readFileSync(corrupt); bytes[bytes.length - 1] ^= 1; fs.writeFileSync(corrupt, bytes);
  assert.throws(() => recoverAbandonedWriterLock(corrupt), { code: 'LOCK_RECOVERY_REFUSED' });
  assert.deepEqual(fs.readFileSync(corrupt + '.lock'), token); assert.deepEqual(fs.readFileSync(corrupt), bytes);
});

test('failed validator initialization releases only its own writer locks', t => {
  const f = fixture(), base = directory(t), dataDir = path.join(base, 'node');
  assert.throws(() => new SovereignNode({ genesis: f.genesis, identity: f.keys[0], validatorId: 'validator-0', dataDir, roundTimeoutMs: -1 }), { code: 'INVALID_TIMEOUT_POLICY' });
  for (const name of ['ledger.v7wal', 'votes.v7wal', 'round-changes.v7wal']) assert.equal(fs.existsSync(path.join(dataDir, name + '.lock')), false);
  const node = new SovereignNode({ genesis: f.genesis, identity: f.keys[0], validatorId: 'validator-0', dataDir });
  t.after(async () => node.close()); assert.equal(node.ledger.sequence, 0n);
});

test('initial deployment is one atomic record and a disk failure can be retried without overwriting committed data', t => {
  const base = directory(t), dir = path.join(base, 'contract'), options = { caller: 'v7' + 'a'.repeat(32), networkId: '77' };
  const link = fs.linkSync; let injected = false;
  t.mock.method(fs, 'linkSync', function(from, to) { if (!injected && path.basename(to) === 'deployment.json') { injected = true; const error = Error('Disk full'); error.code = 'ENOSPC'; throw error; } return link.apply(this, arguments); });
  assert.throws(() => store.createStore(dir, artifact, options), { code: 'ENOSPC' });
  const committed = store.createStore(dir, artifact, options); assert.deepEqual(store.recoverStore(dir).state, committed.state);
  assert.deepEqual(fs.readdirSync(dir), ['deployment.json']);
  assert.throws(() => store.createStore(dir, artifact, options), { code: 'KO_STORE_EXISTS' });
  const legacy = path.join(base, 'legacy'); fs.mkdirSync(legacy);
  fs.writeFileSync(path.join(legacy, 'program.json'), JSON.stringify(artifact));
  fs.writeFileSync(path.join(legacy, 'deployment.json'), JSON.stringify({ schema: 'konaet.ko-program-deployment.v1', options, state: committed.state }));
  assert.deepEqual(store.recoverStore(legacy).state, committed.state);
});

test('independent deployment processes cannot overwrite each other during initialization', async t => {
  const base = directory(t), dir = path.join(base, 'contract');
  const artifactFile = path.join(base, 'artifact.json'), optionsFile = path.join(base, 'options.json');
  fs.writeFileSync(artifactFile, JSON.stringify(artifact)); fs.writeFileSync(optionsFile, JSON.stringify({ caller: 'v7' + 'a'.repeat(32), networkId: '77' }));
  const run = () => new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [path.join(root, 'chain/ko-program/cli.js'), 'deploy', artifactFile, dir, optionsFile], { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
    let stderr = ''; child.stdout.resume(); child.stderr.on('data', bytes => { stderr += bytes; });
    const timer = setTimeout(() => { child.kill(); reject(Error('CHILD_TIMEOUT')); }, 5000);
    child.once('error', error => { clearTimeout(timer); reject(error); }); child.once('exit', code => { clearTimeout(timer); resolve({ code, stderr }); });
  });
  const results = await Promise.all([run(), run()]); assert.equal(results.filter(row => row.code === 0).length, 1);
  assert.equal(JSON.parse(results.find(row => row.code !== 0).stderr).code, 'KO_STORE_EXISTS');
  assert.equal(store.recoverStore(dir).state.revision, '0');
});

test('console shutdown has a deadline even if an authenticated client never finishes its body', async t => {
  const { startConsole } = await import(pathToFileURL(path.join(root, 'tools/console.mjs')).href);
  const app = await startConsole({ dataDirectory: path.join(directory(t), 'console'), shutdownGraceMs: 100, bodyTimeoutMs: 10000 });
  let req; t.after(async () => { req?.destroy(); await app.close(); });
  const html = await (await fetch(app.url)).text(), token = html.match(/name="konaet-token" content="([a-f0-9]{64})"/)[1];
  req = http.request(app.url + '/api/ko', { method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': '32', 'X-Konaet-Token': token } });
  req.on('error', () => {}); req.on('response', res => res.resume()); req.write('{'); await pause(50);
  const started = Date.now(), closing = app.close(); assert.equal(app.close(), closing); await closing;
  assert.ok(Date.now() - started < 6500); await assert.rejects(() => fetch(app.url));
});

test('an incomplete authenticated body reaches its absolute deadline while the console remains available', async t => {
  const { startConsole } = await import(pathToFileURL(path.join(root, 'tools/console.mjs')).href);
  const app = await startConsole({ dataDirectory: path.join(directory(t), 'console'), bodyTimeoutMs: 100 });
  let req; t.after(async () => { req?.destroy(); await app.close(); });
  const html = await (await fetch(app.url)).text(), token = html.match(/name="konaet-token" content="([a-f0-9]{64})"/)[1];
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => { req?.destroy(); reject(Error('BODY_DEADLINE_NOT_ENFORCED')); }, 3000);
    req = http.request(app.url + '/api/ko', { method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': '32', 'X-Konaet-Token': token } });
    req.on('error', () => {}); req.on('response', res => res.resume());
    req.once('close', () => { clearTimeout(timer); resolve(); }); req.write('{');
  });
  assert.equal((await fetch(app.url)).status, 200);
});
