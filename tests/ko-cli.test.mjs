import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
function cli(...args) { return spawnSync(process.execPath, ['tools/ko.mjs', ...args], { cwd: root, encoding: 'utf8', windowsHide: true, timeout: 10000 }); }
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
