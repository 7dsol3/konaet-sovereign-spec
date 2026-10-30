'use strict';

const { createHash } = require('node:crypto');

const KO_PROFILE = 'KONAET_KO_ASSERT_V1';
const KO_SCHEMA = 'konaet.ko-native-policy.v1';
const MAX_SOURCE_BYTES = 16384;
const MAX_RULES = 32;
const MAX_U128 = (1n << 128n) - 1n;
const NUMERIC_FIELDS = new Set(['transfer.amountAtomic', 'transfer.nonce', 'transfer.networkId',
  'state.senderBalance', 'state.nextNonce', 'state.networkId', 'closure.actCount', 'closure.byteLength']);
const HASH_FIELDS = new Set(['transfer.previousRoot', 'state.root']);
const METADATA = Object.freeze({ runtime: KO_PROFILE, symbol: 'SND', decimals: '9',
  supplyAtomic: '1000000000000000000' });
const compiledPolicies = new WeakSet();

class KoPolicyError extends Error {
  constructor(code, message) { super(message); this.name = 'KoPolicyError'; this.code = code; }
}
function fail(code, message) { throw new KoPolicyError(code, message); }
function frozen(value) {
  if (value && typeof value === 'object') { Object.values(value).forEach(frozen); Object.freeze(value); }
  return value;
}
function digest(value) { return createHash('sha256').update(value).digest('hex'); }
function operand(value, phase) {
  if (/^(0|[1-9][0-9]{0,38})$/.test(value) && BigInt(value) <= MAX_U128) return { kind: 'integer', value };
  if (!NUMERIC_FIELDS.has(value) && !HASH_FIELDS.has(value)) fail('KO_UNKNOWN_OPERAND', 'Unknown .ko operand.');
  if ((phase === 'transfer' && value.startsWith('closure.'))
      || (phase === 'closure' && !value.startsWith('closure.'))) fail('KO_PHASE_MISMATCH', 'Operand belongs to another phase.');
  return { kind: HASH_FIELDS.has(value) ? 'hash-field' : 'integer-field', value };
}

// A deliberately bounded executable assertion language, not JavaScript/eval,
// arbitrary smart contracts, signing, issuance or an unrestricted VM.
function compileKoPolicy(source) {
  if (typeof source !== 'string' || !source.length || Buffer.byteLength(source) > MAX_SOURCE_BYTES
      || source.includes('\r') || /[^\t\n -~]/.test(source)) {
    fail('KO_SOURCE_INVALID', '.ko source must be bounded canonical LF ASCII.');
  }
  const lines = source.split('\n').map(line => line.trim()).filter(line => line && !line.startsWith('#'));
  if (lines.shift() !== 'contract SindraRuntime v1' || lines.pop() !== 'end') fail('KO_HEADER_INVALID', 'Unsupported .ko executable profile.');
  const metadata = {}, rules = [], names = new Set();
  for (const line of lines) {
    const match = line.match(/^rule ([A-Za-z][A-Za-z0-9_]{0,47}): (transfer\.[A-Za-z]+|closure\.[A-Za-z]+) (==|<=|>=|>|<) ([A-Za-z][A-Za-z0-9.]*|[0-9]+)$/);
    if (match) {
      if (names.has(match[1]) || rules.length >= MAX_RULES) fail('KO_DUPLICATE_OR_EXCESS_RULE', 'Duplicate or excessive .ko rules.');
      names.add(match[1]);
      const phase = match[2].split('.')[0];
      const left = operand(match[2], phase), right = operand(match[4], phase);
      if ((left.kind === 'hash-field' || right.kind === 'hash-field')
          && (left.kind !== 'hash-field' || right.kind !== 'hash-field' || match[3] !== '==')) {
        fail('KO_TYPE_MISMATCH', 'Hash operands support only field equality.');
      }
      rules.push({ name: match[1], phase, left, operator: match[3], right });
      continue;
    }
    const field = line.match(/^([A-Za-z][A-Za-z0-9]*): ([A-Za-z0-9_]+)$/);
    if (!field || !Object.hasOwn(METADATA, field[1]) || Object.hasOwn(metadata, field[1])) fail('KO_SYNTAX_INVALID', 'Unsupported or duplicate .ko declaration.');
    metadata[field[1]] = field[2];
  }
  if (Object.keys(metadata).length !== Object.keys(METADATA).length
      || Object.entries(METADATA).some(([key, value]) => metadata[key] !== value)
      || !rules.some(rule => rule.phase === 'transfer') || !rules.some(rule => rule.phase === 'closure')) {
    fail('KO_POLICY_INCOMPLETE', '.ko policy must preserve SND identity and define both validation phases.');
  }
  const program = { profile: KO_PROFILE, metadata: { ...METADATA }, rules };
  const result = frozen({ schema: KO_SCHEMA, profile: KO_PROFILE, source,
    sourceSha256: digest(source), programSha256: digest(JSON.stringify(program)), program });
  compiledPolicies.add(result);
  return result;
}

function validateKoPolicy(policy) {
  if (!policy || typeof policy !== 'object' || Array.isArray(policy)) fail('KO_DESCRIPTOR_INVALID', '.ko policy descriptor required.');
  const rebuilt = compileKoPolicy(policy.source);
  if (Object.keys(policy).sort().join(',') !== Object.keys(rebuilt).sort().join(',')
      || policy.schema !== rebuilt.schema || policy.profile !== rebuilt.profile
      || policy.sourceSha256 !== rebuilt.sourceSha256 || policy.programSha256 !== rebuilt.programSha256
      || JSON.stringify(policy.program) !== JSON.stringify(rebuilt.program)) {
    fail('KO_DESCRIPTOR_MISMATCH', '.ko source, program or commitments do not match.');
  }
  return rebuilt;
}

function executeKoPolicy(policy, phase, context) {
  if (!compiledPolicies.has(policy)) policy = validateKoPolicy(policy);
  if (!['transfer', 'closure'].includes(phase)) fail('KO_PHASE_INVALID', 'Unsupported .ko validation phase.');
  for (const rule of policy.program.rules.filter(item => item.phase === phase)) {
    const read = (item) => {
      if (item.kind === 'integer') return BigInt(item.value);
      const value = context[item.value];
      if (item.kind === 'hash-field') {
        if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) fail('KO_CONTEXT_INVALID', 'Canonical hash context required.');
        return value;
      }
      if (!['string', 'bigint'].includes(typeof value) || !/^(0|[1-9][0-9]*)$/.test(String(value))) fail('KO_CONTEXT_INVALID', 'Exact unsigned integer context required.');
      const number = BigInt(value);
      if (number > MAX_U128) fail('KO_CONTEXT_INVALID', 'Integer context exceeds uint128.');
      return number;
    };
    const left = read(rule.left), right = read(rule.right);
    const accepted = rule.operator === '==' ? left === right : rule.operator === '<=' ? left <= right
      : rule.operator === '>=' ? left >= right : rule.operator === '>' ? left > right : left < right;
    if (!accepted) fail('KO_RULE_REJECTED', `.ko rule rejected: ${rule.name}`);
  }
  return true;
}

module.exports = { KO_PROFILE, KO_SCHEMA, KoPolicyError, compileKoPolicy, validateKoPolicy, executeKoPolicy };
