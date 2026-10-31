import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { startDemo } from '../tools/demo-network.mjs';
const require = createRequire(import.meta.url);
const { processFrame } = require('./node/receipt.cjs');
const { verifySocialReceipt } = require('../tools/social-receipt.cjs');
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const language = process.argv[2];
assert.ok(['c', 'cpp', 'csharp', 'python', 'rust', 'perl', 'go', 'shell', 'node'].includes(language), 'LANGUAGE_REQUIRED');
const destination = fs.mkdtempSync(path.join(os.tmpdir(), 'konaet-polyglot-'));
let network;
const started = Date.now();
const versions = {};
function execute(command, args, options = {}) {
  return spawnSync(command, args, { cwd: root, windowsHide: true, encoding: 'utf8', timeout: 120000,
    maxBuffer: 1048576, env: { ...process.env, CARGO_TARGET_DIR: path.join(destination, 'rust'),
      DOTNET_CLI_TELEMETRY_OPTOUT: '1', DOTNET_NOLOGO: '1', GOTOOLCHAIN: 'local' }, ...options });
}
function build(command, args, options) {
  const run = execute(command, args, options); assert.equal(run.status, 0, `${command} build failed: ${run.error?.message || ''}\n${run.stderr}\n${run.stdout}`); return run;
}
function tool(name) { return process.env['KONAET_TOOL_' + name.toUpperCase()] || (name === 'cxx' ? 'c++' : name); }
function version(command, args) { const run = build(command, args); return (run.stdout || run.stderr).trim().split(/\r?\n/)[0]; }
try {
  let command, args;
  if (language === 'c' || language === 'shell') {
    versions.compiler = version(tool('cc'), ['--version']); const binary = path.join(destination, 'receipt-c');
    build(tool('cc'), ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
      'polyglot/c/receipt.c', '-lcrypto', '-o', binary]);
    if (language === 'shell') { command = tool('sh'); args = ['polyglot/shell/receipt.sh', binary]; versions.entrypoint = 'POSIX sh -> checked C implementation'; }
    else { command = binary; args = []; }
  } else if (language === 'cpp') {
    command = path.join(destination, 'receipt-cpp'); args = []; versions.compiler = version(tool('cxx'), ['--version']);
    build(tool('cxx'), ['-std=c++17', '-O2', '-Wall', '-Wextra', '-Werror', '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
      'polyglot/cpp/receipt.cpp', '-lcrypto', '-o', command]);
  } else if (language === 'go') {
    command = path.join(destination, 'receipt-go' + (process.platform === 'win32' ? '.exe' : '')); args = [];
    versions.compiler = version(tool('go'), ['version']); build(tool('go'), ['build', '-trimpath', '-o', command, 'polyglot/go/main.go']);
  } else if (language === 'csharp') {
    command = tool('dotnet'); versions.compiler = version(command, ['--version']);
    build(command, ['build', 'polyglot/csharp/Konaet.Receipt.csproj', '--configuration', 'Release', '--output', path.join(destination, 'csharp'),
      '-p:BaseIntermediateOutputPath=' + path.join(destination, 'obj') + path.sep]); args = [path.join(destination, 'csharp/Konaet.Receipt.dll')];
  } else if (language === 'rust') {
    command = path.join(destination, 'rust/release/konaet-receipt' + (process.platform === 'win32' ? '.exe' : '')); args = [];
    versions.compiler = version(tool('cargo'), ['--version']);
    build(tool('cargo'), ['build', '--locked', '--release', '--manifest-path', 'polyglot/rust/Cargo.toml']);
  } else if (language === 'python') {
    command = tool('python'); args = ['polyglot/python/receipt.py']; versions.interpreter = version(command, ['--version']);
  } else if (language === 'perl') {
    command = tool('perl'); args = ['polyglot/perl/receipt.pl']; versions.interpreter = version(command, ['-e', 'print "$^V"']);
  } else { command = process.execPath; args = ['polyglot/node/receipt.cjs']; versions.interpreter = process.version; }
  const vectors = JSON.parse(fs.readFileSync(path.join(root, 'polyglot/vectors.json'), 'utf8'));
  let valid = 0, negative = 0;
  function check(input, code, expected) {
    const result = execute(command, args, { input, timeout: 15000 });
    assert.equal(result.status, code, `${language}: unexpected exit ${result.error?.message || ''}: ${result.stderr}`);
    if (code === 2) { assert.equal(result.stdout, '', 'Invalid data must not produce a commitment'); negative++; }
    else { assert.deepEqual(JSON.parse(result.stdout), expected); valid++; }
  }
  for (const row of vectors.cases) {
    const input = `${row.salt}\n${row.documentHex}\n${row.commitment}\n`;
    assert.deepEqual(processFrame(Buffer.from(input)), { commitment: row.commitment, args: row.args, matches: true });
    check(input, 0, { commitment: row.commitment, args: row.args, matches: true });
    check(`${row.salt}\n${row.documentHex}\n-\n`, 0, { commitment: row.commitment, args: row.args, matches: null });
    const changed = (row.commitment[0] === '0' ? '1' : '0') + row.commitment.slice(1);
    check(`${row.salt}\n${row.documentHex}\n${changed}\n`, 1, { commitment: row.commitment, args: row.args, matches: false });
  }
  const first = vectors.cases[0], frame = `${first.salt}\n${first.documentHex}\n${first.commitment}\n`;
  const bad = ['', frame.slice(0, -1), frame + '\n', frame + 'x', frame.replaceAll('\n', '\r\n'),
    'A'.repeat(64) + frame.slice(64), first.salt.slice(1) + frame.slice(64), 'g' + frame.slice(1), '\0' + frame.slice(1),
    `${first.salt}\n7\n-\n`, `${first.salt}\n00\n-\n`, `${first.salt}\n\n-\n`, `${first.salt}\n7g7d\n-\n`,
    `${first.salt}\n7B7D\n-\n`, `${first.salt}\n7b7d\n${'A'.repeat(64)}\n`, `${first.salt}\n7b7d\n${'f'.repeat(63)}\n`,
    `${first.salt}\n7b7d\n--\n`, `${first.salt}\n${'00'.repeat(16385)}\n-\n`, '0'.repeat(32901), Buffer.from([255, 10, 10, 10])];
  for (const value of bad) check(value, 2);
  const maximum = `${first.salt}\n${'00'.repeat(16384)}\n-\n`;
  check(maximum, 0, processFrame(Buffer.from(maximum)));
  network = await startDemo({ directory: path.join(destination, 'network'), programs: true });
  const status = await network.status();
  const source = fs.readFileSync(path.join(root, 'chain/ko-program/examples/SocialReceiptRegistry.ko'), 'utf8');
  const deployment = await network.contractTransition({ operation: 'deploy', from: 'alice', source, salt: '773', gasLimit: 10000 });
  const computed = JSON.parse(execute(command, args, { input: frame }).stdout);
  const finalized = await network.contractTransition({ operation: 'call', from: 'alice', contractId: deployment.contractId,
    method: 'record', args: computed.args, gasLimit: 10000 });
  const verification = verifySocialReceipt(finalized.bundle, { expectedGenesisId: status.genesisId,
    expectedContractId: deployment.contractId, expectedCommitment: computed.commitment });
  assert.ok(verification.signers.length >= 3); assert.equal((await network.status()).converged, true);
  const report = { schema: 'konaet.polyglot-conformance.v1', language, platform: process.platform, versions,
    checkedAt: new Date().toISOString(), elapsedMs: Date.now() - started, vectorCases: vectors.cases.length,
    validAndMismatchChecks: valid, malformedFramesRejected: negative, realFourProcessFinality: true,
    finalityVerification: verification, receiptBundle: finalized.bundle,
    scope: 'commitment-interoperability-plus-existing-node-finality-verifier' };
  if (process.env.KONAET_POLYGLOT_REPORT) fs.writeFileSync(process.env.KONAET_POLYGLOT_REPORT, JSON.stringify(report, null, 2) + '\n');
  console.log(JSON.stringify(report, null, 2));
} finally {
  if (network) await network.close();
  assert.equal(path.dirname(path.resolve(destination)), path.resolve(os.tmpdir())); assert.match(path.basename(destination), /^konaet-polyglot-/);
  fs.rmSync(destination, { recursive: true, force: true });
}
