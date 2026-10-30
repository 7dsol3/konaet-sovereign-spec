'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {
  OptimizerError,
  buildOptimizationPlan,
  verifyOptimizationPlan,
} = require('../src/optimizer');

function candidate(id, metrics, extra = {}) {
  return {
    id,
    path: id,
    deterministic: true,
    available: true,
    capabilities: ['canonical-v7'],
    metrics,
    ...extra,
  };
}

const CPU = candidate('cpu', {
  latencyMs: 8,
  energyJ: 4,
  memoryBytes: 100,
  failureRisk: 0.01,
  queueDepth: 1,
});
const FPGA = candidate('fpga', {
  latencyMs: 2,
  energyJ: 1,
  memoryBytes: 30,
  failureRisk: 0.03,
  queueDepth: 2,
});

test('optimizer produces a deterministic auditable plan', () => {
  const options = {
    requirements: { deterministic: true, capabilities: ['canonical-v7'] },
    context: { actType: 'trace' },
  };
  const first = buildOptimizationPlan([CPU, FPGA], options);
  const second = buildOptimizationPlan([FPGA, CPU], options);

  assert.equal(first.selected.id, 'fpga');
  assert.deepEqual(first.ranking, second.ranking);
  assert.equal(first.auditDigest, second.auditDigest);
  assert.equal(verifyOptimizationPlan(first), true);
  assert.equal(first.evidence.performanceClaim, null);
});

test('tie breaking is bytewise and independent of input order', () => {
  const metrics = CPU.metrics;
  const plan = buildOptimizationPlan([
    candidate('z-path', metrics),
    candidate('a-path', metrics),
  ]);
  assert.equal(plan.selected.id, 'a-path');
});

test('constraints fail closed and explain why candidates were rejected', () => {
  const plan = buildOptimizationPlan([
    CPU,
    candidate('fast-unsafe', FPGA.metrics, { deterministic: false }),
  ], { requirements: { deterministic: true, maxLatencyMs: 10 } });
  assert.equal(plan.selected.id, 'cpu');
  assert.deepEqual(plan.rejected[0].reasons, ['determinism-required']);

  assert.throws(
    () => buildOptimizationPlan([CPU], { requirements: { maxLatencyMs: 1 } }),
    (error) => error instanceof OptimizerError && error.code === 'NO_ELIGIBLE_CANDIDATE',
  );
});

test('tampered plans do not retain a valid audit digest', () => {
  const plan = buildOptimizationPlan([CPU, FPGA]);
  const tampered = { ...plan, selected: { ...plan.selected, id: 'cpu' } };
  assert.equal(verifyOptimizationPlan(tampered), false);
});

test('invalid metrics and duplicate candidates are rejected', () => {
  assert.throws(
    () => buildOptimizationPlan([candidate('bad', { ...CPU.metrics, latencyMs: Number.NaN })]),
    (error) => error instanceof OptimizerError && error.code === 'INVALID_METRIC',
  );
  assert.throws(
    () => buildOptimizationPlan([CPU, CPU]),
    (error) => error instanceof OptimizerError && error.code === 'DUPLICATE_ID',
  );
});
