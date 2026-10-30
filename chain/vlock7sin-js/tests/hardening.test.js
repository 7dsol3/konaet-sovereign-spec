'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
  UINT64_MAX,
  ActumError,
  ActumMachine,
  encodeActumFrame,
} = require('../src/actum');
const {
  OptimizerError,
  buildOptimizationPlan,
  verifyOptimizationPlan,
} = require('../src/optimizer');

function candidate(id, overrides = {}) {
  return {
    id,
    path: id,
    deterministic: true,
    capabilities: ['canonical-v7'],
    metrics: {
      latencyMs: 4,
      energyJ: 2,
      memoryBytes: 64,
      failureRisk: 0.01,
      queueDepth: 1,
    },
    ...overrides,
  };
}

function assertAnchorsUnchangedExceptException(before, after) {
  for (let index = 0; index < before.anchors.length; index += 1) {
    if (index === 13 || index === 14) continue;
    assert.equal(after.anchors[index], before.anchors[index], `anchor ${index} changed on failed commit`);
  }
}

test('Actum architectural state cannot be shadowed or mutated through getters', () => {
  const initial = { OR1: 42n, AN16: 7n };
  const machine = new ActumMachine({ initialAnchors: initial, maxSteps: 4 });
  initial.OR1 = 999n;
  assert.equal(machine.readAnchor('OR1'), 42n);

  const exposed = machine.anchors;
  assert.equal(Object.isFrozen(exposed), true);
  assert.throws(() => { exposed[0] = 9n; }, TypeError);
  assert.throws(() => { machine.anchors = []; }, TypeError);
  assert.throws(() => { machine.steps = 99; }, TypeError);
  assert.throws(() => { machine.attempts = 99; }, TypeError);
  assert.throws(() => { machine.requireFrame = false; }, TypeError);
  assert.throws(() => { machine.maxSteps = 999; }, TypeError);
  assert.throws(() => Object.defineProperty(machine, 'anchors', { value: [] }), TypeError);

  assert.equal(machine.readAnchor('AZ0'), 0n);
  assert.equal(machine.readAnchor('TM15'), 0n);
  assert.equal(machine.steps, 0);
  assert.equal(machine.attempts, 0);
});

test('setAnchor permits only pre-execution general-anchor initialization', () => {
  const machine = new ActumMachine({ initialAnchors: { OR1: 5n } });
  machine.setAnchor('AN16', 12n);
  assert.equal(machine.readAnchor('AN16'), 12n);
  assert.throws(
    () => machine.setAnchor('AZ0', 1n),
    (error) => error instanceof ActumError && error.code === 'READ_ONLY_ANCHOR',
  );
  assert.throws(
    () => machine.setAnchor('OR1', 8n),
    (error) => error instanceof ActumError && error.code === 'UNSAFE_OPERAND',
  );

  machine.execute(encodeActumFrame({ mnemonic: 'ACT.NOP' }));
  assert.throws(
    () => machine.setAnchor('AN17', 1n),
    (error) => error instanceof ActumError && error.code === 'UNSAFE_OPERAND',
  );
  assert.throws(
    () => machine.reset(),
    (error) => error instanceof ActumError && error.code === 'UNSAFE_OPERAND',
  );
});

test('SYS.TRAP and step-limit failures only commit architectural exception state', () => {
  const trapMachine = new ActumMachine({ initialAnchors: { OR1: 9n, PC10: 3n, AN16: 77n } });
  const beforeTrap = trapMachine.snapshot();
  assert.throws(
    () => trapMachine.execute(encodeActumFrame({ mnemonic: 'SYS.TRAP', immediate: 23 })),
    (error) => error instanceof ActumError && error.code === 'TRAP',
  );
  const afterTrap = trapMachine.snapshot();
  assertAnchorsUnchangedExceptException(beforeTrap, afterTrap);
  assert.equal(trapMachine.steps, 0);
  assert.equal(trapMachine.attempts, 1);
  assert.equal(Object.isFrozen(afterTrap), true);
  assert.equal(Object.isFrozen(afterTrap.anchors), true);
  assert.equal(Object.isFrozen(trapMachine.lastException), true);
  assert.throws(() => { trapMachine.lastException.details.reason = 99; }, TypeError);
  assert.equal(trapMachine.lastException.details.reason, 23);

  const limited = new ActumMachine({ maxSteps: 1 });
  const nop = encodeActumFrame({ mnemonic: 'ACT.NOP' });
  limited.execute(nop);
  const beforeLimit = limited.snapshot();
  assert.throws(
    () => limited.execute(nop),
    (error) => error instanceof ActumError && error.code === 'STEP_LIMIT',
  );
  const afterLimit = limited.snapshot();
  assertAnchorsUnchangedExceptException(beforeLimit, afterLimit);
  assert.equal(limited.steps, 1);
  assert.equal(limited.attempts, 2);
});

test('pulse and PC overflow never partially commit an instruction', () => {
  const pulseOverflow = new ActumMachine({
    initialAnchors: { PX2: UINT64_MAX, PC10: 7n, AN16: 11n },
  });
  const beforePulse = pulseOverflow.snapshot();
  assert.throws(
    () => pulseOverflow.execute(encodeActumFrame({ mnemonic: 'ACT.NOP' })),
    (error) => error instanceof ActumError && error.code === 'INVALID_FIELD',
  );
  const afterPulse = pulseOverflow.snapshot();
  assertAnchorsUnchangedExceptException(beforePulse, afterPulse);
  assert.equal(pulseOverflow.steps, 0);

  const pcOverflow = new ActumMachine({
    initialAnchors: { OR1: 42n, PC10: UINT64_MAX, AN16: 3n },
  });
  const beforePc = pcOverflow.snapshot();
  const move = encodeActumFrame({ mnemonic: 'VEY.MOV', rd: 16, rs1: 1 });
  assert.throws(
    () => pcOverflow.execute(move),
    (error) => error instanceof ActumError && error.code === 'INVALID_FIELD',
  );
  const afterPc = pcOverflow.snapshot();
  assertAnchorsUnchangedExceptException(beforePc, afterPc);
  assert.equal(pcOverflow.readAnchor('AN16'), 3n);
  assert.equal(pcOverflow.steps, 0);
});

test('optimizer plan is deeply frozen and detached from caller inputs', () => {
  const inputCandidate = candidate('cpu');
  const context = { nested: { labels: ['trace'], profile: { revision: 1 } } };
  const requirements = { deterministic: true, capabilities: ['canonical-v7'] };
  const plan = buildOptimizationPlan([inputCandidate], { context, requirements });
  const digest = plan.auditDigest;

  assert.equal(Object.isFrozen(plan), true);
  assert.equal(Object.isFrozen(plan.context.nested), true);
  assert.equal(Object.isFrozen(plan.context.nested.labels), true);
  assert.equal(Object.isFrozen(plan.ranking[0].metrics), true);
  assert.equal(Object.isFrozen(plan.requirements.capabilities), true);
  assert.throws(() => { plan.context.nested.profile.revision = 2; }, TypeError);
  assert.throws(() => { plan.ranking[0].metrics.latency = 999; }, TypeError);
  assert.throws(() => plan.requirements.capabilities.push('unsafe'), TypeError);

  inputCandidate.metrics.latencyMs = 999;
  context.nested.labels.push('mutated-after-plan');
  requirements.capabilities.push('mutated-after-plan');
  assert.equal(plan.ranking[0].metrics.latency, 4);
  assert.deepEqual(plan.context.nested.labels, ['trace']);
  assert.deepEqual(plan.requirements.capabilities, ['canonical-v7']);
  assert.equal(plan.auditDigest, digest);
  assert.equal(verifyOptimizationPlan(plan), true);
});

test('optimizer canonicalizes NFC and rejects normalized duplicates or ambiguous metrics', () => {
  const composed = '\u00e9';
  const decomposed = 'e\u0301';
  const first = buildOptimizationPlan([candidate('cpu')], { context: { label: composed } });
  const second = buildOptimizationPlan([candidate('cpu')], { context: { label: decomposed } });
  assert.equal(first.context.label, composed);
  assert.equal(first.auditDigest, second.auditDigest);

  assert.throws(
    () => buildOptimizationPlan([candidate(composed), candidate(decomposed)]),
    (error) => error instanceof OptimizerError && error.code === 'DUPLICATE_ID',
  );

  const collidingKeys = { [composed]: 1, [decomposed]: 2 };
  assert.throws(
    () => buildOptimizationPlan([candidate('cpu')], { context: collidingKeys }),
    (error) => error instanceof OptimizerError && error.code === 'DUPLICATE_KEY',
  );

  const duplicateMetric = candidate('ambiguous');
  duplicateMetric.metrics.latency = duplicateMetric.metrics.latencyMs;
  assert.throws(
    () => buildOptimizationPlan([duplicateMetric]),
    (error) => error instanceof OptimizerError && error.code === 'DUPLICATE_METRIC',
  );
});

test('optimizer rejects non-finite canonical data and malformed verification fails closed', () => {
  assert.throws(
    () => buildOptimizationPlan([candidate('cpu')], { context: { temperature: Number.NaN } }),
    (error) => error instanceof OptimizerError && error.code === 'INVALID_VALUE',
  );

  const malformed = { auditDigest: '0'.repeat(64), context: { value: Number.NaN } };
  assert.equal(verifyOptimizationPlan(malformed), false);

  const cyclic = { auditDigest: '0'.repeat(64) };
  cyclic.self = cyclic;
  assert.equal(verifyOptimizationPlan(cyclic), false);

  const prototypeKey = JSON.parse('{"__proto__":{"polluted":true}}');
  const plan = buildOptimizationPlan([candidate('cpu')], { context: prototypeKey });
  assert.equal(Object.prototype.polluted, undefined);
  assert.equal(Object.hasOwn(plan.context, '__proto__'), true);
  assert.equal(plan.context.__proto__.polluted, true);
  assert.equal(verifyOptimizationPlan(plan), true);
});
