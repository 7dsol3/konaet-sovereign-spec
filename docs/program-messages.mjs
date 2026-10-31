// Generated from chain/ko-program/messages.js. Signing format is unchanged.
const module = { exports: {} };
'use strict';
// Portable, canonical signing codec. No keys, clocks, filesystem or network.
const DEPLOY_SCHEMA = 'konaet.ko-program-signed-deploy.v1';
const CALL_SCHEMA = 'konaet.ko-program-signed-call.v1';
function invalid(message) { const error = Error(message); error.code = 'KO_ENVELOPE_INVALID'; throw error; }
function data(value, budget = { nodes: 0 }, depth = 0) {
  if (++budget.nodes > 4096 || depth > 16) invalid('Envelope exceeds structural bounds.');
  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'string') { if (value.length > 65536) invalid('String exceeds bounds.'); return value; }
  if (typeof value === 'number' && Number.isSafeInteger(value)) return value;
  if (!value || typeof value !== 'object' || (!Array.isArray(value) && ![Object.prototype, null].includes(Object.getPrototypeOf(value)))
    || Object.getOwnPropertySymbols(value).length) invalid('Plain JSON envelope required.');
  const output = Array.isArray(value) ? [] : {};
  for (const key of Object.getOwnPropertyNames(value).sort()) {
    if (Array.isArray(value) && key === 'length') continue;
    const item = Object.getOwnPropertyDescriptor(value, key);
    if (!item.enumerable || !Object.hasOwn(item, 'value') || key === '__proto__') invalid('Accessors and hidden fields are not supported.');
    if (Array.isArray(value) && (!/^(0|[1-9][0-9]*)$/.test(key) || Number(key) >= value.length)) invalid('Dense array required.');
    Object.defineProperty(output, key, { value: data(item.value, budget, depth + 1), enumerable: true, writable: true, configurable: true });
  }
  if (Array.isArray(value) && (output.length !== value.length || Object.keys(output).length !== value.length)) invalid('Dense array required.');
  return output;
}
function exact(value, fields) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...fields].sort())) invalid('Unexpected or missing envelope fields.');
}
function uint(value, max) {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,38})$/.test(value) || BigInt(value) > max) invalid('Canonical bounded unsigned integer required.');
  return value;
}
function digest(value) { if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) invalid('Canonical SHA-256 digest required.'); }
function gas(value) { if (!Number.isSafeInteger(value) || value < 1 || value > 1000000) invalid('Gas must be an integer in 1..1000000.'); }
function validatePayload(schema, payload) {
  if (schema === DEPLOY_SCHEMA) {
    exact(payload, ['programSha256', 'networkId', 'salt', 'gasLimit']);
    uint(payload.salt, (1n << 128n) - 1n);
  } else if (schema === CALL_SCHEMA) {
    exact(payload, ['programSha256', 'networkId', 'contractId', 'expectedRevision', 'expectedStateRoot', 'method', 'args', 'gasLimit']);
    digest(payload.contractId); digest(payload.expectedStateRoot); uint(payload.expectedRevision, (1n << 64n) - 1n);
    if (typeof payload.method !== 'string' || !/^[a-zA-Z_][a-zA-Z0-9_]{0,63}$/.test(payload.method)
      || !Array.isArray(payload.args) || payload.args.length > 16
      || !payload.args.every(item => typeof item === 'string' && item.length <= 128 || typeof item === 'boolean')) invalid('Invalid method or arguments.');
  } else invalid('Unknown signing domain.');
  digest(payload.programSha256); uint(payload.networkId, 0xffffffffn);
  if (payload.networkId === '0') invalid('Network id must be positive.');
  gas(payload.gasLimit);
  return payload;
}
function deploymentPayload(artifact, options) {
  const input = data(options); exact(input, ['networkId', 'salt', 'gasLimit']);
  return validatePayload(DEPLOY_SCHEMA, data({ programSha256: artifact.programSha256, ...input }));
}
function callPayload(artifact, state, request) {
  const input = data(request); exact(input, ['method', 'args', 'gasLimit']);
  return validatePayload(CALL_SCHEMA, data({ programSha256: artifact.programSha256, networkId: state.networkId,
    contractId: state.contractId, expectedRevision: state.revision, expectedStateRoot: state.stateRoot, ...input }));
}
function signingText(schema, publicKey, payload) {
  if (typeof publicKey !== 'string' || !/^[0-9a-f]{64}$/.test(publicKey)) invalid('Canonical Ed25519 public key required.');
  const canonical = validatePayload(schema, data(payload));
  return 'KONAET_KO_SIGNED_PROGRAM_V1\n' + JSON.stringify(data({ schema, publicKey, payload: canonical }));
}
function envelope(input) {
  const result = data(input); exact(result, ['schema', 'publicKey', 'payload', 'signature']);
  if (typeof result.signature !== 'string' || !/^[0-9a-f]{128}$/.test(result.signature)) invalid('Canonical Ed25519 signature required.');
  signingText(result.schema, result.publicKey, result.payload);
  return result;
}
module.exports = Object.freeze({ DEPLOY_SCHEMA, CALL_SCHEMA, deploymentPayload, callPayload, signingText, envelope });

export { DEPLOY_SCHEMA, CALL_SCHEMA, deploymentPayload, callPayload, signingText, envelope };
