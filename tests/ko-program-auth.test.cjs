'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');
const test = require('node:test');
const { compileContract } = require('../chain/ko-program/runtime');
const { signDeployment, signCall, deploySignedContract, callSignedContract } = require('../chain/ko-program/auth');
const { createSignedStore, callSignedStore, recoverStore, callStore } = require('../chain/ko-program/store');
const { signingText, envelope: checkEnvelope } = require('../chain/ko-program/messages');
const { encodeAddress } = require('../chain/vlock7sin-js/src/crypto');
const root = path.resolve(__dirname, '..');
const artifact = compileContract(fs.readFileSync(path.join(root, 'chain/ko-program/examples/Counter.ko'), 'utf8'));
const alice = crypto.generateKeyPairSync('ed25519').privateKey, bob = crypto.generateKeyPairSync('ed25519').privateKey;
const options = { networkId: '77', salt: '0', gasLimit: 10000 };
const request = { method: 'increment', args: ['7'], gasLimit: 10000 };
const deployment = signDeployment(artifact, options, alice), initial = deploySignedContract(artifact, deployment).state;
function copy(value) { return JSON.parse(JSON.stringify(value)); }
function temporary(t) {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'konaet-signed-program-'));
  t.after(() => { const target = path.resolve(base); assert.ok(target.startsWith(path.resolve(os.tmpdir()) + path.sep));
    assert.match(path.basename(target), /^konaet-signed-program-/); fs.rmSync(target, { force: true, recursive: true }); });
  return base;
}
test('signed deployment derives owner from the Ed25519 key; signed mutation changes its state', () => {
  assert.equal(initial.deployer, encodeAddress(crypto.createPublicKey(alice)));
  assert.equal(initial.storage.owner, initial.deployer);
  const receipt = callSignedContract(artifact, initial, signCall(artifact, initial, request, alice));
  assert.equal(receipt.signatureVerified, true); assert.equal(receipt.result, '14'); assert.equal(receipt.caller, initial.deployer);
});
test('signature binds operation, key, program, arguments, gas, root, revision, network and contract', () => {
  const signed = signCall(artifact, initial, request, alice);
  for (const field of ['programSha256', 'networkId', 'contractId', 'expectedRevision', 'expectedStateRoot', 'method', 'args', 'gasLimit']) {
    const forged = copy(signed);
    const values = { programSha256: 'f'.repeat(64), networkId: '78', contractId: 'f'.repeat(64), expectedRevision: '1',
      expectedStateRoot: 'f'.repeat(64), method: 'readTotal', args: ['8'], gasLimit: 9999 };
    forged.payload[field] = values[field];
    assert.throws(() => callSignedContract(artifact, initial, forged), { code: field === 'programSha256' ? 'KO_PROGRAM_MISMATCH' : 'KO_SIGNATURE_INVALID' });
  }
  const forged = copy(signed); forged.publicKey = signCall(artifact, initial, request, bob).publicKey;
  assert.throws(() => callSignedContract(artifact, initial, forged), { code: 'KO_SIGNATURE_INVALID' });
  assert.throws(() => deploySignedContract(artifact, signed), { code: 'KO_SIGNING_DOMAIN' });
  assert.throws(() => callSignedContract(artifact, initial, deployment), { code: 'KO_SIGNING_DOMAIN' });
});
test('a valid signature from a different key cannot acquire the owners permissions', () => {
  assert.throws(() => callSignedContract(artifact, initial, signCall(artifact, initial, request, bob)), { code: 'KO_REQUIRE_FAILED' });
});
test('replay and signed calls to another deployment or network are rejected', () => {
  const signed = signCall(artifact, initial, request, alice), receipt = callSignedContract(artifact, initial, signed);
  assert.throws(() => callSignedContract(artifact, receipt.state, signed), { code: 'KO_STALE_STATE' });
  const other = deploySignedContract(artifact, signDeployment(artifact, { ...options, salt: '1' }, alice)).state;
  assert.throws(() => callSignedContract(artifact, other, signed), { code: 'KO_CONTRACT_MISMATCH' });
  const network = deploySignedContract(artifact, signDeployment(artifact, { ...options, networkId: '78' }, alice)).state;
  assert.throws(() => callSignedContract(artifact, network, signed), { code: 'KO_NETWORK_MISMATCH' });
});
test('canonical signatures tolerate JSON key order but reject noncanonical fields and unsafe object data', () => {
  const signed = signCall(artifact, initial, request, alice);
  const reordered = Object.fromEntries(Object.entries(signed).reverse());
  reordered.payload = Object.fromEntries(Object.entries(signed.payload).reverse());
  assert.equal(callSignedContract(artifact, initial, reordered).result, '14');
  for (const mutate of [e => { e.caller = initial.deployer; }, e => { e.payload.caller = initial.deployer; },
    e => { e.payload.networkId = '077'; }, e => { e.signature = e.signature.toUpperCase(); }, e => { e.payload.args = Array(1); }]) {
    const bad = copy(signed); mutate(bad); assert.throws(() => checkEnvelope(bad), { code: 'KO_ENVELOPE_INVALID' });
  }
  let accessed = false; const getter = copy(signed); Object.defineProperty(getter, 'signature', { enumerable: true, get() { accessed = true; return signed.signature; } });
  assert.throws(() => checkEnvelope(getter), { code: 'KO_ENVELOPE_INVALID' }); assert.equal(accessed, false);
  assert.equal(signingText(signed.schema, signed.publicKey, signed.payload), signingText(reordered.schema, reordered.publicKey, reordered.payload));
});
test('authenticated disk replay rechecks deployment and call signatures and refuses unsigned calls', t => {
  const base = temporary(t), store = path.join(base, 'state'); createSignedStore(store, artifact, deployment);
  assert.throws(() => callStore(store, { caller: initial.deployer, ...request, expectedRevision: '0' }), { code: 'KO_ENVELOPE_INVALID' });
  const receipt = callSignedStore(store, signCall(artifact, initial, request, alice));
  const restored = recoverStore(store); assert.equal(restored.authenticated, true); assert.deepEqual(restored.state, receipt.state);
  const record = path.join(store, '00000000000000000001.json'), corrupted = JSON.parse(fs.readFileSync(record));
  corrupted.request.signature = '0'.repeat(128);
  const payload = { schema: corrupted.schema, request: corrupted.request, receipt: corrupted.receipt };
  corrupted.recordHash = crypto.createHash('sha256').update(JSON.stringify(payload)).digest('hex'); fs.writeFileSync(record, JSON.stringify(corrupted));
  assert.throws(() => recoverStore(store), { code: 'KO_SIGNATURE_INVALID' });
});
test('encrypted key CLI signs and executes without exposing its key or accepting an overwrite', t => {
  const base = temporary(t), cli = path.join(root, 'chain/ko-program/cli.js'), key = path.join(base, 'owner.pem');
  const env = { ...process.env, KONAET_KO_KEY_PASSPHRASE: crypto.randomBytes(24).toString('hex') };
  const run = args => spawnSync(process.execPath, [cli, ...args], { env, windowsHide: true, encoding: 'utf8', timeout: 15000 });
  const created = run(['keygen', key]); assert.equal(created.status, 0, created.stderr);
  assert.ok(fs.readFileSync(key, 'utf8').startsWith(['-----BEGIN ENCRYPTED', 'PRIVATE KEY-----'].join(' ')));
  assert.ok(!created.stdout.includes(env.KONAET_KO_KEY_PASSPHRASE)); assert.ok(!created.stdout.includes('PRIVATE KEY'));
  assert.equal(run(['keygen', key]).status, 1);
  const program = path.join(base, 'program.json'), config = path.join(base, 'deploy.json'), deploy = path.join(base, 'signed-deploy.json');
  const call = path.join(base, 'call.json'), signed = path.join(base, 'signed-call.json'), store = path.join(base, 'state');
  fs.writeFileSync(program, JSON.stringify(artifact)); fs.writeFileSync(config, JSON.stringify(options)); fs.writeFileSync(call, JSON.stringify(request));
  for (const args of [['sign-deploy', program, config, key, deploy], ['deploy-signed', program, store, deploy],
    ['sign-call', store, call, key, signed], ['call-signed', store, signed]]) {
    const result = run(args); assert.equal(result.status, 0, result.stderr); assert.ok(!result.stdout.includes('PRIVATE KEY'));
  }
  assert.equal(recoverStore(store).state.storage.total, '14');
  assert.equal(run(['call-signed', store, signed]).status, 1);
});
