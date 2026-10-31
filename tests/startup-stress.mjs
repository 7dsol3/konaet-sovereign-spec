import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
const rounds = Number(process.argv[2] ?? 12);
assert.ok(Number.isSafeInteger(rounds) && rounds >= 1 && rounds <= 20, 'ROUNDS_MUST_BE_1_TO_20');
for (let round = 0; round < rounds; round++) {
  const result = spawnSync(process.execPath, ['--test', '--test-name-pattern=independent deployment processes|temporary disappearing',
    'tests/recovery-and-capacity.test.cjs'], { cwd: new URL('..', import.meta.url), windowsHide: true, encoding: 'utf8', timeout: 20000 });
  assert.equal(result.status, 0, `Startup stress round ${round + 1} failed\n${result.stdout}\n${result.stderr}`);
}
console.log(JSON.stringify({ concurrentDeploymentRounds: rounds, competingWritersPerRound: 2,
  deterministicTemporaryDisappearanceRounds: rounds, passed: true }));
