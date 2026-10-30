import fs from 'node:fs';
import assert from 'node:assert/strict';
import test from 'node:test';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const { compileKoPolicy, validateKoPolicy, executeKoPolicy } = require('../runtime/ko-policy.cjs');
const source = fs.readFileSync(new URL('../runtime/SindraRuntime.ko', import.meta.url), 'utf8');
const context = { 'transfer.amountAtomic': '7', 'transfer.nonce': '1', 'transfer.networkId': '28673',
  'transfer.previousRoot': 'a'.repeat(64), 'state.senderBalance': '100', 'state.nextNonce': '1',
  'state.networkId': '28673', 'state.root': 'a'.repeat(64) };

test('.ko compiles deterministically and accepts its valid transfer context', () => {
  const p = compileKoPolicy(source);
  assert.deepEqual(p, compileKoPolicy(source));
  assert.equal(p.program.rules.length, 9);
  assert.equal(executeKoPolicy(p, 'transfer', context), true);
});
test('.ko refuses overdraw, replay context, root mismatch and floating-point quantities', () => {
  const p = compileKoPolicy(source);
  for (const change of [{ 'transfer.amountAtomic': '101' }, { 'transfer.nonce': '2' },
    { 'state.root': 'b'.repeat(64) }, { 'transfer.amountAtomic': 7 }]) {
    assert.throws(() => executeKoPolicy(p, 'transfer', { ...context, ...change }));
  }
});
test('.ko enforces closure limits and rejects a forged executable descriptor', () => {
  const p = compileKoPolicy(source);
  assert.equal(executeKoPolicy(p, 'closure', { 'closure.actCount': '1', 'closure.byteLength': '400' }), true);
  assert.throws(() => executeKoPolicy(p, 'closure', { 'closure.actCount': '65', 'closure.byteLength': '400' }));
  const forged = structuredClone(p); forged.program.rules = [];
  assert.throws(() => validateKoPolicy(forged));
  assert.throws(() => executeKoPolicy(forged, 'transfer', context));
});
test('.ko refuses arbitrary code and noncanonical sources', () => {
  for (const modified of [source.replace('> 0', '> process.exit()'), source.replace(/\n/g, '\r\n'), source + 'extra']) {
    assert.throws(() => compileKoPolicy(modified));
  }
});
