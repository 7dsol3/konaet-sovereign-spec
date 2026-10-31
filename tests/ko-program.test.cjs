'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { createHash } = require('node:crypto');
const { compileContract, validateContract, deployContract, callContract, PROFILE } = require('../chain/ko-program/runtime');
const root = path.resolve(__dirname, '..');
const counter = fs.readFileSync(path.join(root, 'chain/ko-program/examples/Counter.ko'), 'utf8');
const token = fs.readFileSync(path.join(root, 'chain/ko-program/examples/RegistryToken.ko'), 'utf8');
const alice = 'v7' + 'a'.repeat(32), bob = 'v7' + 'b'.repeat(32);
const max = ((1n << 128n) - 1n).toString();
function deploy(source = counter, config = {}) { const artifact = compileContract(source); return { artifact, state: deployContract(artifact, { caller: alice, networkId: '77', ...config }).state }; }
function call(fixture, method, args = [], options = {}) { return callContract(fixture.artifact, fixture.state, { caller: alice, method, args, expectedRevision: fixture.state.revision, ...options }); }
function minimal(body, declarations = '') { return `contract Example v1\nruntime: ${PROFILE}\n${declarations}\nfn run() -> u128 { ${body} }\nend`; }

test('stateful .ko compiles deterministically and binds its complete typed program to source', () => {
  const artifact = compileContract(counter);
  assert.deepEqual(artifact, compileContract(counter));
  assert.equal(artifact.profile, PROFILE); assert.equal(artifact.program.functions.length, 4);
  assert.deepEqual(validateContract(JSON.parse(JSON.stringify(artifact))), artifact);
  assert.ok(Object.isFrozen(artifact.program.functions[0].body));
  const altered = structuredClone(artifact); altered.program.functions[1].body = [];
  assert.throws(() => validateContract(altered), { code: 'KO_ARTIFACT_MISMATCH' });
});
test('deployment binds program, caller, salt and network with canonical typed initial values', () => {
  const fixture = deploy();
  assert.equal(fixture.state.storage.owner, alice); assert.equal(fixture.state.storage.total, '0');
  assert.equal(fixture.state.revision, '0');
  assert.notEqual(deploy(counter, { networkId: '78' }).state.contractId, fixture.state.contractId);
  assert.notEqual(deploy(counter, { salt: '1' }).state.contractId, fixture.state.contractId);
  assert.throws(() => deploy(counter, { networkId: '0' }), { code: 'KO_NETWORK_INVALID' });
});
test('public and internal functions execute with permission checks and typed event values', () => {
  const fixture = deploy(), before = JSON.stringify(fixture.state);
  const result = call(fixture, 'increment', ['7']);
  assert.equal(result.result, '14'); assert.equal(result.state.storage.total, '14'); assert.equal(result.state.revision, '1');
  assert.deepEqual(result.events, [{ name: 'Changed', values: [alice, '14'] }]);
  assert.equal(JSON.stringify(fixture.state), before);
  assert.throws(() => call(fixture, 'increment', ['7'], { caller: bob }), { code: 'KO_REQUIRE_FAILED' });
  assert.throws(() => call(fixture, 'twice', ['7']), { code: 'KO_ENTRYPOINT_INVALID' });
});
test('view functions preserve the exact state and require the expected revision', () => {
  const fixture = deploy(); fixture.state = call(fixture, 'increment', ['2']).state;
  const result = call(fixture, 'readTotal');
  assert.equal(result.result, '4'); assert.equal(result.readOnly, true); assert.deepEqual(result.state, fixture.state);
  assert.throws(() => call(fixture, 'increment', ['1'], { expectedRevision: '0' }), { code: 'KO_STALE_STATE' });
});
test('mapping operations support issuance, transfer, pauses and exact quantities without affecting SND', () => {
  const fixture = deploy(token); fixture.state = call(fixture, 'mint', [alice, '100']).state;
  const moved = call(fixture, 'transfer', [bob, '7']); fixture.state = moved.state;
  assert.equal(call(fixture, 'balanceOf', [alice]).result, '93'); assert.equal(call(fixture, 'balanceOf', [bob]).result, '7');
  assert.equal(call(fixture, 'totalSupply').result, '100');
  assert.deepEqual(moved.events[0], { name: 'Moved', values: [alice, bob, '7'] });
  fixture.state = call(fixture, 'setPaused', [true]).state;
  assert.throws(() => call(fixture, 'transfer', [bob, '1']), { code: 'KO_REQUIRE_FAILED' });
  assert.throws(() => call(fixture, 'mint', [bob, '10'], { caller: bob }), { code: 'KO_REQUIRE_FAILED' });
});
test('unsigned arithmetic rejects overflow, underflow and zero division without state changes', () => {
  for (const [expression, code] of [[`${max} + 1`, 'KO_OVERFLOW'], ['0 - 1', 'KO_UNDERFLOW'], ['3 / 0', 'KO_DIVISION_BY_ZERO'], ['3 % 0', 'KO_DIVISION_BY_ZERO']]) {
    const fixture = deploy(minimal(`set value = 8; return ${expression};`, 'storage value: u128 = 0;'));
    const state = JSON.stringify(fixture.state); assert.throws(() => call(fixture, 'run'), { code }); assert.equal(JSON.stringify(fixture.state), state);
  }
});
test('failed requirements and exhausted gas roll back storage and staged events', () => {
  const fixture = deploy(minimal('set value = 4; emit Changed(value); require false; return value;', 'storage value: u128 = 0; event Changed(quantity: u128);'));
  const original = JSON.stringify(fixture.state); assert.throws(() => call(fixture, 'run'), { code: 'KO_REQUIRE_FAILED' });
  assert.equal(JSON.stringify(fixture.state), original);
  const counterFixture = deploy(); assert.throws(() => call(counterFixture, 'increment', ['2'], { gasLimit: 15 }), { code: 'KO_OUT_OF_GAS' });
  assert.equal(counterFixture.state.storage.total, '0');
});
test('repeat bounds and branches have deterministic work and metered execution', () => {
  const fixture = deploy(), first = call(fixture, 'boundedBatch', ['3']), second = call(fixture, 'boundedBatch', ['3']);
  assert.equal(first.result, '9'); assert.deepEqual(first, second);
  const branch = deploy(minimal('if network == 77 { return 5; } else { return 9; } return 0;'));
  assert.equal(call(branch, 'run').result, '5');
  assert.throws(() => compileContract(minimal('repeat 257 { require true; } return 1;')), { code: 'KO_LOOP_LIMIT' });
});
test('type checking rejects unsafe control, recursion, type confusion and view side effects', () => {
  const sources = [
    minimal('return true;'), minimal('require 1; return 0;'), minimal('set absent = 1; return 0;'),
    minimal('return run();'), minimal('return "v7' + 'a'.repeat(32) + '" + 1;'),
    minimal('let value: bool = 1; return 0;'), minimal('return process();'),
    `contract X v1\nruntime: ${PROFILE}\nstorage value: u128 = 0;\nview fn read() -> u128 { return update(); }\ninternal fn update() -> u128 { set value = 1; return value; }\nend`,
    `contract X v1\nruntime: ${PROFILE}\nevent Found(value: u128);\nview fn read() -> u128 { emit Found(1); return 1; }\nend`,
  ];
  for (const source of sources) assert.throws(() => compileContract(source));
});
test('source and context enforce canonical values, limits and absence of ambient code execution', () => {
  const fixture = deploy();
  for (const value of [7, '01', '-1', '1.2', '1e9', max + '0']) assert.throws(() => call(fixture, 'increment', [value]));
  assert.throws(() => call(fixture, 'increment', ['7'], { caller: '0x0000' }));
  for (const source of [counter.replace(/\n/g, '\r\n'), counter + ' trailing', 'x'.repeat(65537), counter.replace('owner', '__proto__')]) assert.throws(() => compileContract(source));
  let executed = false; const options = { method: 'readTotal', args: [], expectedRevision: '0' };
  Object.defineProperty(options, 'caller', { get() { executed = true; return alice; }, enumerable: true });
  assert.throws(() => callContract(fixture.artifact, fixture.state, options), { code: 'KO_DATA_INVALID' }); assert.equal(executed, false);
});
test('state corruption, program replacement and duplicate mapping rows are rejected', () => {
  const fixture = deploy(token); fixture.state = call(fixture, 'mint', [alice, '10']).state;
  const tampered = structuredClone(fixture.state); tampered.storage.supply = '900';
  assert.throws(() => callContract(fixture.artifact, tampered, { caller: alice, method: 'totalSupply', args: [], expectedRevision: '1' }), { code: 'KO_STATE_ROOT_MISMATCH' });
  const other = compileContract(token.replace('amount > 0', 'amount > 1'));
  assert.throws(() => callContract(other, fixture.state, {}), { code: 'KO_STATE_PROFILE' });
  const duplicate = structuredClone(fixture.state); duplicate.mappings.balances.push({ ...duplicate.mappings.balances[0] });
  const fields = { ...duplicate }; delete fields.stateRoot; duplicate.stateRoot = createHash('sha256').update(JSON.stringify(fields)).digest('hex');
  assert.throws(() => callContract(fixture.artifact, duplicate, { caller: alice, method: 'totalSupply', args: [], expectedRevision: '1' }), { code: 'KO_STATE_ORDER' });
});
test('state JSON key ordering cannot create a second commitment for the same state', () => {
  const fixture = deploy();
  const reordered = Object.fromEntries(Object.entries(fixture.state).reverse());
  reordered.storage = Object.fromEntries(Object.entries(reordered.storage).reverse());
  const call = { caller: alice, method: 'readTotal', args: [], expectedRevision: '0' };
  assert.equal(callContract(fixture.artifact, reordered, call).state.stateRoot, fixture.state.stateRoot);
  const changed = { ...reordered }; delete changed.stateRoot;
  reordered.stateRoot = createHash('sha256').update(JSON.stringify(changed)).digest('hex');
  assert.throws(() => callContract(fixture.artifact, reordered, call), { code: 'KO_STATE_ROOT_MISMATCH' });
});
test('short-circuit expressions avoid invalid branches and integer comparisons remain exact', () => {
  const fixture = deploy(minimal('require true || 1 / 0 == 0; if false && 1 / 0 == 0 { return 0; } return 9007199254740993 + 2;'));
  assert.equal(call(fixture, 'run').result, '9007199254740995');
});
test('nested finite loops stop at the runtime gas bound without publishing state', () => {
  const fixture = deploy(minimal('repeat 256 { repeat 256 { set value = value + 1; } } return value;', 'storage value: u128 = 0;'));
  assert.throws(() => call(fixture, 'run', [], { gasLimit: 1000 }), { code: 'KO_OUT_OF_GAS' });
  assert.equal(fixture.state.storage.value, '0');
  for (const gasLimit of [0, -1, 1000001, '1000']) assert.throws(() => call(fixture, 'run', [], { gasLimit }), { code: 'KO_GAS_INVALID' });
  assert.throws(() => call(fixture, 'run', [], { gasLimit: 1.5 }), { code: 'KO_DATA_INVALID' });
});
test('bounded source mutations either reject with typed errors or reproduce the same artifact', () => {
  let seed = 44213, accepted = 0, rejected = 0;
  const alphabet = '{}[]();:#@"+-*/ abcdef0123456789';
  for (let index = 0; index < 250; index++) {
    seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
    const position = seed % counter.length;
    const source = counter.slice(0, position) + alphabet[seed % alphabet.length] + counter.slice(position + 1);
    try {
      const artifact = compileContract(source); assert.deepEqual(validateContract(JSON.parse(JSON.stringify(artifact))), artifact); accepted++;
    } catch (error) { assert.equal(error.name, 'KoProgramError'); rejected++; }
  }
  assert.ok(rejected > 200); assert.equal(accepted + rejected, 250);
  assert.throws(() => compileContract(minimal(`return ${Array(80).fill('1').join(' + ')};`)), { code: 'KO_SOURCE_LIMIT' });
});
