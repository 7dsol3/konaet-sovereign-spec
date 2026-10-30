'use strict';

const { createHash } = require('node:crypto');

const OPTIMIZER_NAMESPACE = 'VLOCK7SIN/OLIVEIRA-OPTIMIZER/v0.1';
const OPTIMIZER_VERSION = '0.1.0';
const NORMALIZATION_SCALE = 1_000_000_000;
const WEIGHT_SCALE = 1_000_000;

// J = alpha*L + beta*E + gamma*M + delta*R + epsilon*Q.
// Every metric is a cost: lower is better.  Weights are policy, not a
// performance claim, and are written into every generated plan.
const METRIC_DEFINITIONS = Object.freeze([
  Object.freeze({ name: 'latency', symbol: 'L', direction: 'min', defaultWeight: 0.35,
    aliases: Object.freeze(['latencyMs', 'L']) }),
  Object.freeze({ name: 'energy', symbol: 'E', direction: 'min', defaultWeight: 0.15,
    aliases: Object.freeze(['energyJ', 'E']) }),
  Object.freeze({ name: 'memory', symbol: 'M', direction: 'min', defaultWeight: 0.15,
    aliases: Object.freeze(['memoryBytes', 'M']) }),
  Object.freeze({ name: 'risk', symbol: 'R', direction: 'min', defaultWeight: 0.25,
    aliases: Object.freeze(['failureRisk', 'R']) }),
  Object.freeze({ name: 'queue', symbol: 'Q', direction: 'min', defaultWeight: 0.10,
    aliases: Object.freeze(['queueDepth', 'Q']) }),
]);

function deepFreeze(value, seen = new Set()) {
  if (!value || typeof value !== 'object' || seen.has(value)) return value;
  seen.add(value);
  for (const child of Object.values(value)) deepFreeze(child, seen);
  return Object.freeze(value);
}

function normalizeText(value) {
  return value.normalize('NFC');
}

function defineCanonicalProperty(target, key, value) {
  Object.defineProperty(target, key, {
    value,
    enumerable: true,
    configurable: true,
    writable: true,
  });
}

class OptimizerError extends Error {
  constructor(code, message, details = {}) {
    super(message);
    this.name = 'OptimizerError';
    this.code = code;
    this.deterministic = true;
    // Error construction must never fail while describing the value that
    // caused the error (NaN/Infinity are common malformed metric inputs).
    this.details = deepFreeze(canonicalErrorDetails(details));
  }

  toJSON() {
    return {
      name: this.name,
      code: this.code,
      message: this.message,
      deterministic: true,
      details: this.details,
    };
  }
}

function canonicalErrorDetails(value, seen = new Set()) {
  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'string') return normalizeText(value);
  if (typeof value === 'number') return Number.isFinite(value) ? (Object.is(value, -0) ? 0 : value) : String(value);
  if (typeof value === 'bigint') return value.toString(10);
  if (value === undefined) return null;
  if (Array.isArray(value)) {
    if (seen.has(value)) return '[cyclic]';
    seen.add(value);
    const output = value.map((item) => canonicalErrorDetails(item, seen));
    seen.delete(value);
    return output;
  }
  if (value && typeof value === 'object') {
    if (seen.has(value)) return '[cyclic]';
    seen.add(value);
    const output = {};
    const entries = Object.keys(value)
      .map((original) => ({ original, normalized: normalizeText(original) }))
      .sort((left, right) => compareText(left.normalized, right.normalized));
    for (const entry of entries) {
      defineCanonicalProperty(
        output,
        entry.normalized,
        canonicalErrorDetails(value[entry.original], seen),
      );
    }
    seen.delete(value);
    return output;
  }
  return String(value);
}

function fail(code, message, details) {
  throw new OptimizerError(code, message, details);
}

function canonicalValue(value, seen = new Set()) {
  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'string') return normalizeText(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) fail('INVALID_VALUE', 'non-finite numbers are not canonical', { value: String(value) });
    return Object.is(value, -0) ? 0 : value;
  }
  if (typeof value === 'bigint') return value.toString(10);
  if (value === undefined) return null;
  if (Array.isArray(value)) {
    if (seen.has(value)) fail('INVALID_VALUE', 'cyclic data cannot be canonicalized', {});
    seen.add(value);
    const output = value.map((item) => canonicalValue(item, seen));
    seen.delete(value);
    return output;
  }
  if (typeof value === 'object') {
    if (seen.has(value)) fail('INVALID_VALUE', 'cyclic data cannot be canonicalized', {});
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      fail('INVALID_VALUE', 'only plain objects are accepted as auditable plan data', {
        constructor: prototype && prototype.constructor ? prototype.constructor.name : null,
      });
    }
    if (Object.getOwnPropertySymbols(value).length !== 0) {
      fail('INVALID_VALUE', 'symbol keys are not auditable plan data', {});
    }
    seen.add(value);
    const output = {};
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const normalizedKeys = new Map();
    for (const originalKey of Object.keys(descriptors)) {
      const descriptor = descriptors[originalKey];
      if (!descriptor.enumerable) continue;
      if (!Object.prototype.hasOwnProperty.call(descriptor, 'value')) {
        fail('INVALID_VALUE', 'accessor properties are not auditable plan data', { key: originalKey });
      }
      const key = normalizeText(originalKey);
      if (normalizedKeys.has(key)) {
        fail('DUPLICATE_KEY', 'object keys collide after NFC normalization', {
          first: normalizedKeys.get(key),
          second: originalKey,
          normalized: key,
        });
      }
      normalizedKeys.set(key, originalKey);
    }
    for (const key of [...normalizedKeys.keys()].sort(compareText)) {
      const originalKey = normalizedKeys.get(key);
      const item = descriptors[originalKey].value;
      if (typeof item === 'function' || typeof item === 'symbol') {
        fail('INVALID_VALUE', 'functions and symbols are not auditable plan data', { key });
      }
      if (item !== undefined) defineCanonicalProperty(output, key, canonicalValue(item, seen));
    }
    seen.delete(value);
    return output;
  }
  fail('INVALID_VALUE', 'unsupported value in auditable plan data', { type: typeof value });
}

function canonicalJson(value) {
  return JSON.stringify(canonicalValue(value));
}

function digest(value) {
  return createHash('sha256')
    .update(`${OPTIMIZER_NAMESPACE}\0`, 'utf8')
    .update(canonicalJson(value), 'utf8')
    .digest('hex');
}

function numericMetric(value, candidateId, metricName) {
  if (typeof value === 'bigint') {
    if (value < 0n || value > BigInt(Number.MAX_SAFE_INTEGER)) {
      fail('INVALID_METRIC', 'BigInt metric must fit the JavaScript safe-integer range', {
        candidateId,
        metric: metricName,
        value,
      });
    }
    return Number(value);
  }
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
    fail('INVALID_METRIC', 'optimizer metrics must be finite non-negative numbers', {
      candidateId,
      metric: metricName,
      value,
    });
  }
  return Object.is(value, -0) ? 0 : value;
}

function readMetric(metrics, definition, candidateId) {
  const acceptedNames = [definition.name, ...definition.aliases];
  const supplied = acceptedNames.filter((name) => Object.prototype.hasOwnProperty.call(metrics, name));
  if (supplied.length > 1) {
    fail('DUPLICATE_METRIC', 'metric was supplied through more than one alias', {
      candidateId,
      metric: definition.name,
      fields: supplied,
    });
  }
  if (supplied.length === 1) {
    return numericMetric(metrics[supplied[0]], candidateId, definition.name);
  }
  fail('MISSING_METRIC', `candidate is missing metric ${definition.name}`, {
    candidateId,
    metric: definition.name,
  });
}

function normalizeCandidate(candidate, index) {
  if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)
    || (Object.getPrototypeOf(candidate) !== Object.prototype && Object.getPrototypeOf(candidate) !== null)) {
    fail('INVALID_CANDIDATE', 'each candidate must be an object', { index });
  }
  const id = typeof candidate.id === 'string' ? normalizeText(candidate.id) : candidate.id;
  if (typeof id !== 'string' || id.length === 0 || Buffer.byteLength(id, 'utf8') > 256) {
    fail('INVALID_CANDIDATE', 'candidate id must be a non-empty string of at most 256 characters', { index });
  }
  if (!candidate.metrics || typeof candidate.metrics !== 'object' || Array.isArray(candidate.metrics)
    || (Object.getPrototypeOf(candidate.metrics) !== Object.prototype
      && Object.getPrototypeOf(candidate.metrics) !== null)) {
    fail('INVALID_CANDIDATE', 'candidate.metrics must be a plain object', { candidateId: id });
  }
  const knownMetricFields = new Set(METRIC_DEFINITIONS.flatMap((definition) => (
    [definition.name, ...definition.aliases]
  )));
  const unknownMetricFields = Object.keys(candidate.metrics).filter((key) => !knownMetricFields.has(key));
  if (unknownMetricFields.length !== 0) {
    fail('INVALID_METRIC', 'candidate.metrics contains unknown fields', {
      candidateId: id,
      fields: unknownMetricFields.sort(compareText),
    });
  }
  const metrics = {};
  for (const definition of METRIC_DEFINITIONS) {
    metrics[definition.name] = readMetric(candidate.metrics, definition, id);
  }
  const capabilities = candidate.capabilities === undefined
    ? []
    : candidate.capabilities;
  if (!Array.isArray(capabilities) || capabilities.some((item) => typeof item !== 'string' || item.length === 0)) {
    fail('INVALID_CANDIDATE', 'candidate.capabilities must be an array of non-empty strings', {
      candidateId: id,
    });
  }
  const normalizedCapabilities = capabilities.map(normalizeText);
  if (new Set(normalizedCapabilities).size !== normalizedCapabilities.length) {
    fail('DUPLICATE_CAPABILITY', 'candidate capabilities must be unique after NFC normalization', {
      candidateId: id,
    });
  }
  return deepFreeze({
    id,
    path: typeof candidate.path === 'string' && candidate.path.length > 0
      ? normalizeText(candidate.path)
      : id,
    metrics,
    capabilities: normalizedCapabilities.sort(compareText),
    deterministic: candidate.deterministic === true,
    privacy: canonicalValue(candidate.privacy ?? null),
    available: candidate.available !== false,
    metadata: canonicalValue(candidate.metadata ?? {}),
    sourceIndex: index,
  });
}

function normalizeCandidates(candidates) {
  if (!Array.isArray(candidates) || candidates.length === 0) {
    fail('INVALID_CANDIDATE', 'at least one candidate is required', {});
  }
  const normalized = candidates.map(normalizeCandidate);
  const ids = new Set();
  for (const candidate of normalized) {
    if (ids.has(candidate.id)) fail('DUPLICATE_ID', 'candidate ids must be unique', { id: candidate.id });
    ids.add(candidate.id);
  }
  return Object.freeze(normalized);
}

function compareText(left, right) {
  return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
}

function normalizeWeights(weights = {}) {
  if (!weights || typeof weights !== 'object' || Array.isArray(weights)
    || (Object.getPrototypeOf(weights) !== Object.prototype && Object.getPrototypeOf(weights) !== null)) {
    fail('INVALID_POLICY', 'weights must be an object', {});
  }
  const knownWeightFields = new Set(METRIC_DEFINITIONS.flatMap((definition) => (
    [definition.name, definition.symbol]
  )));
  const unknownWeightFields = Object.keys(weights).filter((key) => !knownWeightFields.has(key));
  if (unknownWeightFields.length !== 0) {
    fail('INVALID_POLICY', 'weights contains unknown fields', { fields: unknownWeightFields.sort(compareText) });
  }
  const raw = {};
  let sum = 0;
  for (const definition of METRIC_DEFINITIONS) {
    const suppliedFields = [definition.name, definition.symbol]
      .filter((key) => Object.prototype.hasOwnProperty.call(weights, key));
    if (suppliedFields.length > 1) {
      fail('DUPLICATE_WEIGHT', 'weight was supplied by both name and symbol', {
        metric: definition.name,
        fields: suppliedFields,
      });
    }
    const value = suppliedFields.length === 0
      ? definition.defaultWeight
      : weights[suppliedFields[0]];
    if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) {
      fail('INVALID_POLICY', 'weights must be finite non-negative numbers', {
        metric: definition.name,
        value,
      });
    }
    raw[definition.name] = value;
    sum += value;
  }
  if (!Number.isFinite(sum)) fail('INVALID_POLICY', 'sum of optimizer weights must be finite', {});
  if (!(sum > 0)) fail('INVALID_POLICY', 'at least one optimizer weight must be positive', {});

  // Largest-remainder apportionment makes the integer weights sum exactly to
  // WEIGHT_SCALE without assigning rounding error to one special metric.
  const units = {};
  const remainders = [];
  let allocated = 0;
  for (let index = 0; index < METRIC_DEFINITIONS.length; index += 1) {
    const definition = METRIC_DEFINITIONS[index];
    const exact = (raw[definition.name] / sum) * WEIGHT_SCALE;
    const base = Math.floor(exact);
    units[definition.name] = base;
    allocated += base;
    remainders.push({ name: definition.name, fraction: exact - base, index });
  }
  remainders.sort((left, right) => (right.fraction - left.fraction) || (left.index - right.index));
  for (let remaining = WEIGHT_SCALE - allocated, index = 0; remaining > 0; remaining -= 1, index += 1) {
    units[remainders[index % remainders.length].name] += 1;
  }
  return deepFreeze(units);
}

function constraintReasons(candidate, requirements = {}) {
  if (!requirements || typeof requirements !== 'object' || Array.isArray(requirements)) {
    fail('INVALID_REQUIREMENT', 'requirements must be an object', {});
  }
  const reasons = [];
  if (!candidate.available) reasons.push('unavailable');
  if (requirements.deterministic === true && !candidate.deterministic) reasons.push('determinism-required');

  if (requirements.deadlineMs !== undefined) {
    const deadline = numericMetric(requirements.deadlineMs, candidate.id, 'deadlineMs');
    if (candidate.metrics.latency > deadline) reasons.push('deadline-exceeded');
  }
  const maximums = [
    ['maxLatency', 'latency'], ['maxLatencyMs', 'latency'],
    ['maxEnergy', 'energy'], ['maxEnergyJ', 'energy'],
    ['maxMemory', 'memory'], ['maxMemoryBytes', 'memory'],
    ['maxRisk', 'risk'], ['maxQueue', 'queue'], ['maxQueueDepth', 'queue'],
  ];
  for (const [requirementName, metricName] of maximums) {
    if (requirements[requirementName] !== undefined) {
      const maximum = numericMetric(requirements[requirementName], candidate.id, requirementName);
      if (candidate.metrics[metricName] > maximum) reasons.push(`${requirementName}-exceeded`);
    }
  }

  if (Object.prototype.hasOwnProperty.call(requirements, 'capabilities')
    && Object.prototype.hasOwnProperty.call(requirements, 'requiredCapabilities')) {
    fail('INVALID_REQUIREMENT', 'use capabilities or requiredCapabilities, not both', {});
  }
  const requiredCapabilities = requirements.capabilities ?? requirements.requiredCapabilities ?? [];
  if (!Array.isArray(requiredCapabilities)
    || requiredCapabilities.some((item) => typeof item !== 'string' || item.length === 0)) {
    fail('INVALID_REQUIREMENT', 'required capabilities must be an array of non-empty strings', {});
  }
  const normalizedRequiredCapabilities = requiredCapabilities.map(normalizeText);
  if (new Set(normalizedRequiredCapabilities).size !== normalizedRequiredCapabilities.length) {
    fail('DUPLICATE_CAPABILITY', 'required capabilities must be unique after NFC normalization', {});
  }
  for (const capability of normalizedRequiredCapabilities.sort(compareText)) {
    if (!candidate.capabilities.includes(capability)) reasons.push(`missing-capability:${capability}`);
  }

  if (requirements.privacy !== undefined) {
    const requiredPrivacy = canonicalJson(requirements.privacy);
    const candidatePrivacy = canonicalJson(candidate.privacy);
    if (candidatePrivacy !== requiredPrivacy) reasons.push('privacy-policy-mismatch');
  }
  return deepFreeze([...new Set(reasons)].sort(compareText));
}

function partitionCandidates(candidates, requirements) {
  const eligible = [];
  const rejected = [];
  for (const candidate of candidates) {
    const reasons = constraintReasons(candidate, requirements);
    if (reasons.length === 0) eligible.push(candidate);
    else rejected.push(deepFreeze({ id: candidate.id, path: candidate.path, reasons }));
  }
  return { eligible, rejected: deepFreeze(rejected.sort((a, b) => compareText(a.id, b.id))) };
}

function normalizedMetricUnits(value, minimum, maximum, direction) {
  if (maximum === minimum) return 0;
  const ratio = direction === 'max'
    ? (maximum - value) / (maximum - minimum)
    : (value - minimum) / (maximum - minimum);
  return Math.max(0, Math.min(NORMALIZATION_SCALE, Math.round(ratio * NORMALIZATION_SCALE)));
}

function normalizePreparedMetrics(normalizedCandidates) {
  if (!Array.isArray(normalizedCandidates) || normalizedCandidates.length === 0) {
    fail('NO_ELIGIBLE_CANDIDATE', 'there are no candidates to normalize', {});
  }
  const ranges = {};
  for (const definition of METRIC_DEFINITIONS) {
    const values = normalizedCandidates.map((candidate) => candidate.metrics[definition.name]);
    ranges[definition.name] = deepFreeze({
      min: Math.min(...values),
      max: Math.max(...values),
      direction: definition.direction,
    });
  }

  const frozenRanges = deepFreeze(ranges);
  return deepFreeze(normalizedCandidates.map((candidate) => {
    const units = {};
    const normalized = {};
    for (const definition of METRIC_DEFINITIONS) {
      const range = ranges[definition.name];
      const metricUnits = normalizedMetricUnits(
        candidate.metrics[definition.name],
        range.min,
        range.max,
        definition.direction,
      );
      units[definition.name] = metricUnits;
      normalized[definition.name] = metricUnits / NORMALIZATION_SCALE;
    }
    return deepFreeze({
      id: candidate.id,
      path: candidate.path,
      metrics: candidate.metrics,
      normalized,
      normalizedUnits: units,
      ranges: frozenRanges,
      candidate,
    });
  }));
}

function normalizeMetrics(candidates) {
  return normalizePreparedMetrics(normalizeCandidates(candidates));
}

function rankNormalized(normalized, weightUnits) {
  const internal = normalized.map((entry) => {
    let numerator = 0n;
    const contributionUnits = {};
    for (const definition of METRIC_DEFINITIONS) {
      const contribution = BigInt(entry.normalizedUnits[definition.name])
        * BigInt(weightUnits[definition.name]);
      numerator += contribution;
      contributionUnits[definition.name] = contribution.toString(10);
    }
    const scoreUnits = Number((numerator + BigInt(WEIGHT_SCALE / 2)) / BigInt(WEIGHT_SCALE));
    return {
      id: entry.id,
      path: entry.path,
      metrics: entry.metrics,
      normalized: entry.normalized,
      normalizedUnits: entry.normalizedUnits,
      contributionUnits: deepFreeze(contributionUnits),
      score: scoreUnits / NORMALIZATION_SCALE,
      scoreUnits,
      _sourceIndex: entry.candidate.sourceIndex,
    };
  });

  internal.sort((left, right) => {
    if (left.scoreUnits !== right.scoreUnits) return left.scoreUnits - right.scoreUnits;
    const byId = compareText(left.id, right.id);
    if (byId !== 0) return byId;
    return left._sourceIndex - right._sourceIndex;
  });
  return deepFreeze(internal.map((entry, index) => ({
    rank: index + 1,
    id: entry.id,
    path: entry.path,
    metrics: entry.metrics,
    normalized: entry.normalized,
    normalizedUnits: entry.normalizedUnits,
    contributionUnits: entry.contributionUnits,
    score: entry.score,
    scoreUnits: entry.scoreUnits,
    tieBreak: 'utf8-id-ascending',
  })));
}

function rankCandidates(candidates, options = {}) {
  if (!options || typeof options !== 'object' || Array.isArray(options)) {
    fail('INVALID_POLICY', 'optimizer options must be an object', {});
  }
  const normalizedCandidates = normalizeCandidates(candidates);
  const requirements = deepFreeze(canonicalValue(options.requirements ?? {}));
  const partitioned = partitionCandidates(normalizedCandidates, requirements);
  if (partitioned.eligible.length === 0) {
    fail('NO_ELIGIBLE_CANDIDATE', 'no candidate satisfies the declared requirements', {
      rejected: partitioned.rejected,
    });
  }
  const weightUnits = normalizeWeights(options.weights ?? {});
  const normalized = normalizePreparedMetrics(partitioned.eligible);
  return rankNormalized(normalized, weightUnits);
}

function unpackPlanArguments(candidatesOrConfig, options) {
  if (Array.isArray(candidatesOrConfig)) {
    if (options !== undefined
      && (!options || typeof options !== 'object' || Array.isArray(options))) {
      fail('INVALID_POLICY', 'optimizer options must be an object', {});
    }
    return { candidates: candidatesOrConfig, options: options || {} };
  }
  if (!candidatesOrConfig || typeof candidatesOrConfig !== 'object'
    || Object.getPrototypeOf(candidatesOrConfig) !== Object.prototype) {
    fail('INVALID_CANDIDATE', 'plan input must be a candidate array or configuration object', {});
  }
  return {
    candidates: candidatesOrConfig.candidates,
    options: {
      weights: candidatesOrConfig.weights,
      requirements: candidatesOrConfig.requirements,
      context: candidatesOrConfig.context,
    },
  };
}

function buildOptimizationPlan(candidatesOrConfig, options) {
  const unpacked = unpackPlanArguments(candidatesOrConfig, options);
  const candidates = normalizeCandidates(unpacked.candidates);
  const requirements = deepFreeze(canonicalValue(unpacked.options.requirements ?? {}));
  const context = deepFreeze(canonicalValue(unpacked.options.context ?? {}));
  const weightUnits = normalizeWeights(unpacked.options.weights ?? {});
  const partitioned = partitionCandidates(candidates, requirements);
  if (partitioned.eligible.length === 0) {
    fail('NO_ELIGIBLE_CANDIDATE', 'no candidate satisfies the declared requirements', {
      rejected: partitioned.rejected,
    });
  }
  const normalized = normalizePreparedMetrics(partitioned.eligible);
  const ranking = rankNormalized(normalized, weightUnits);
  const policy = deepFreeze({
    equation: 'J = alpha*L + beta*E + gamma*M + delta*R + epsilon*Q',
    objective: 'minimize-normalized-observable-cost',
    normalization: 'per-plan-min-max-fixed-1e9',
    weightsUnits: weightUnits,
    weightsScale: WEIGHT_SCALE,
    scoreScale: NORMALIZATION_SCALE,
    tieBreak: 'utf8-id-ascending',
  });
  const payload = deepFreeze({
    schema: 'vlock7sin.optimizer.plan.v0.1',
    namespace: OPTIMIZER_NAMESPACE,
    version: OPTIMIZER_VERSION,
    deterministic: true,
    selected: ranking[0],
    ranking,
    rejected: partitioned.rejected,
    requirements,
    context,
    policy,
    evidence: {
      performanceClaim: null,
      measurementsAreCallerSupplied: true,
      reproducibleBenchmarkRequiredForClaims: true,
    },
  });
  return deepFreeze({
    ...payload,
    auditDigest: digest(payload),
  });
}

function verifyOptimizationPlan(plan) {
  if (!plan || typeof plan !== 'object' || typeof plan.auditDigest !== 'string') return false;
  try {
    const { auditDigest, ...payload } = plan;
    return /^[0-9a-f]{64}$/.test(auditDigest) && digest(payload) === auditDigest;
  } catch (_error) {
    return false;
  }
}

class OliveiraOptimizer {
  #weights;

  #requirements;

  constructor(options = {}) {
    this.#weights = deepFreeze(canonicalValue(options.weights ?? {}));
    this.#requirements = deepFreeze(canonicalValue(options.requirements ?? {}));
    // Validate policy at construction time instead of waiting for the first
    // plan, then prevent public property shadowing.
    normalizeWeights(this.#weights);
    Object.seal(this);
  }

  get weights() {
    return this.#weights;
  }

  get requirements() {
    return this.#requirements;
  }

  normalize(candidates) {
    return normalizeMetrics(candidates);
  }

  rank(candidates, options = {}) {
    return rankCandidates(candidates, {
      weights: options.weights ?? this.#weights,
      requirements: options.requirements ?? this.#requirements,
    });
  }

  plan(candidates, options = {}) {
    return buildOptimizationPlan(candidates, {
      weights: options.weights ?? this.#weights,
      requirements: options.requirements ?? this.#requirements,
      context: options.context ?? {},
    });
  }
}

module.exports = Object.freeze({
  OPTIMIZER_NAMESPACE,
  OPTIMIZER_VERSION,
  NORMALIZATION_SCALE,
  WEIGHT_SCALE,
  METRIC_DEFINITIONS,
  OptimizerError,
  OliveiraOptimizer,
  DeterministicOptimizer: OliveiraOptimizer,
  canonicalJson,
  normalizeMetrics,
  rankCandidates,
  buildOptimizationPlan,
  optimize: buildOptimizationPlan,
  verifyOptimizationPlan,
});
