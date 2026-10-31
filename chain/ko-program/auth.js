'use strict';
const { encodeAddress, rawPublicKey, sign, verify } = require('../vlock7sin-js/src/crypto');
const { validateContract, deployContract, callContract, KoProgramError } = require('./runtime');
const codec = require('./messages');
function fail(code, message) { throw new KoProgramError(code, message); }
function signed(schema, payload, privateKey) {
  const publicKey = rawPublicKey(require('node:crypto').createPublicKey(privateKey)).toString('hex');
  const bytes = Buffer.from(codec.signingText(schema, publicKey, payload), 'utf8');
  return { schema, publicKey, payload, signature: sign(privateKey, bytes).toString('hex') };
}
function signDeployment(artifact, options, privateKey) {
  const policy = validateContract(artifact);
  return signed(codec.DEPLOY_SCHEMA, codec.deploymentPayload(policy, options), privateKey);
}
function signCall(artifact, state, request, privateKey) {
  const policy = validateContract(artifact);
  return signed(codec.CALL_SCHEMA, codec.callPayload(policy, state, request), privateKey);
}
function authenticate(input, schema, artifact) {
  const message = codec.envelope(input);
  if (message.schema !== schema) fail('KO_SIGNING_DOMAIN', 'Envelope is for a different operation.');
  if (message.payload.programSha256 !== artifact.programSha256) fail('KO_PROGRAM_MISMATCH', 'Envelope targets another program.');
  const publicKey = Buffer.from(message.publicKey, 'hex');
  if (!verify(publicKey, Buffer.from(codec.signingText(message.schema, message.publicKey, message.payload), 'utf8'), Buffer.from(message.signature, 'hex'))) fail('KO_SIGNATURE_INVALID', 'Ed25519 signature did not verify.');
  return { message, caller: encodeAddress(publicKey) };
}
function deploySignedContract(input, envelope) {
  const artifact = validateContract(input), { message, caller } = authenticate(envelope, codec.DEPLOY_SCHEMA, artifact);
  const { networkId, salt, gasLimit } = message.payload;
  const receipt = deployContract(artifact, { caller, networkId, salt, gasLimit });
  return { ...receipt, signatureVerified: true, caller };
}
function callSignedContract(input, state, envelope) {
  const artifact = validateContract(input), { message, caller } = authenticate(envelope, codec.CALL_SCHEMA, artifact);
  const { networkId, contractId, expectedRevision, expectedStateRoot, method, args, gasLimit } = message.payload;
  if (networkId !== state.networkId) fail('KO_NETWORK_MISMATCH', 'Envelope targets another network.');
  if (contractId !== state.contractId) fail('KO_CONTRACT_MISMATCH', 'Envelope targets another contract.');
  if (expectedStateRoot !== state.stateRoot) fail('KO_STALE_STATE', 'Envelope targets a different state root.');
  const receipt = callContract(artifact, state, { caller, method, args, expectedRevision, gasLimit });
  return { ...receipt, signatureVerified: true, caller };
}
module.exports = Object.freeze({ signDeployment, signCall, deploySignedContract, callSignedContract });
