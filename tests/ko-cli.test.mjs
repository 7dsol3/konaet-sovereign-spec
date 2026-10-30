import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
function cli(...args) { return spawnSync(process.execPath, ['tools/ko.mjs', ...args], { cwd: root, encoding: 'utf8', windowsHide: true, timeout: 10000 }); }
function temporary(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'konaet-ko-project-'));
  t.after(() => { const target = path.resolve(directory);
    assert.ok(target.startsWith(path.resolve(os.tmpdir()) + path.sep));
    assert.match(path.basename(target), /^konaet-ko-project-/);
    fs.rmSync(target, { recursive: true, force: true }); });
  return directory;
}
test('the .ko CLI compiles the shipped source and executes the shipped transfer context', () => {
  const compiled = cli('compile', 'runtime/SindraRuntime.ko');
  assert.equal(compiled.status, 0, compiled.stderr);
  const policy = JSON.parse(compiled.stdout);
  const executed = cli('run', 'runtime/SindraRuntime.ko', 'examples/ko-transfer-context.json');
  assert.equal(executed.status, 0, executed.stderr);
  const result = JSON.parse(executed.stdout);
  assert.equal(result.accepted, true); assert.equal(result.rulesExecuted, 6);
  assert.equal(result.programSha256, policy.programSha256); assert.equal(result.execution, 'local');
});
test('init creates runnable transfer and closure examples without replacing an existing project', t => {
  const base = temporary(t), project = path.join(base, 'my-policy');
  const initialized = cli('init', project);
  assert.equal(initialized.status, 0, initialized.stderr);
  assert.equal(JSON.parse(initialized.stdout).files.length, 4);
  const source = path.join(project, 'SindraRuntime.ko');
  for (const phase of ['transfer', 'closure']) {
    const result = cli('run', source, path.join(project, `${phase}.json`), phase);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(JSON.parse(result.stdout).rulesExecuted, phase === 'transfer' ? 6 : 3);
  }
  fs.writeFileSync(source, 'user-owned-source');
  const repeated = cli('init', project);
  assert.equal(repeated.status, 1);
  assert.equal(fs.readFileSync(source, 'utf8'), 'user-owned-source');
  assert.equal(cli('init', path.join(base, 'missing', 'nested')).status, 1);
});
test('saved policy artifacts are verified by recompilation and output creation never overwrites files', t => {
  const directory = temporary(t), output = path.join(directory, 'policy.json');
  const built = cli('compile', 'runtime/SindraRuntime.ko', '--out', output);
  assert.equal(built.status, 0, built.stderr);
  const original = fs.readFileSync(output);
  const verified = cli('verify', output);
  assert.equal(verified.status, 0, verified.stderr);
  assert.equal(JSON.parse(verified.stdout).programSha256, JSON.parse(built.stdout).programSha256);
  assert.equal(cli('compile', 'runtime/SindraRuntime.ko', '--out', output).status, 1);
  assert.deepEqual(fs.readFileSync(output), original);
  const tampered = JSON.parse(original.toString('utf8'));
  tampered.program.rules[0].operator = '<';
  fs.writeFileSync(output, JSON.stringify(tampered));
  assert.equal(cli('verify', output).status, 1);
});
test('the documented Node integration example executes the distributed core', () => {
  const result = spawnSync(process.execPath, ['examples/ko-use.cjs'], { cwd: root, encoding: 'utf8', windowsHide: true, timeout: 10000 });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).accepted, true);
});
test('the .ko CLI returns failure for overdraw, numeric coercion and excessive input files', t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'konaet-ko-cli-'));
  const contextFile = path.join(dir, 'context.json'), sourceFile = path.join(dir, 'large.ko');
  t.after(() => { assert.ok(path.resolve(dir).startsWith(path.resolve(os.tmpdir()) + path.sep));
    for (const file of [contextFile, sourceFile]) if (fs.existsSync(file)) fs.unlinkSync(file); fs.rmdirSync(dir); });
  const context = JSON.parse(fs.readFileSync(path.join(root, 'examples/ko-transfer-context.json'), 'utf8'));
  fs.writeFileSync(contextFile, JSON.stringify({ ...context, 'transfer.amountAtomic': '101' }));
  const overdraw = cli('run', 'runtime/SindraRuntime.ko', contextFile);
  assert.equal(overdraw.status, 1); assert.equal(JSON.parse(overdraw.stderr).code, 'KO_RULE_REJECTED');
  fs.writeFileSync(contextFile, JSON.stringify({ ...context, 'transfer.amountAtomic': 7 }));
  const coerced = cli('run', 'runtime/SindraRuntime.ko', contextFile);
  assert.equal(coerced.status, 1); assert.equal(JSON.parse(coerced.stderr).code, 'KO_CONTEXT_INVALID');
  fs.writeFileSync(sourceFile, 'x'.repeat(16385));
  assert.equal(cli('compile', sourceFile).status, 1);
  assert.equal(cli('run', 'runtime/SindraRuntime.ko', contextFile, 'unknown').status, 1);
});
