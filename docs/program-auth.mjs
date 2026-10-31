import { sha3_256 } from './vendor/hashes/sha3.js';
import { compileContract, validateContract, deployContract, callContract } from './program-runtime.mjs';
import { DEPLOY_SCHEMA, CALL_SCHEMA, deploymentPayload, callPayload, signingText, envelope } from './program-messages.mjs';
const utf8 = new TextEncoder();
const hex = bytes => Array.from(new Uint8Array(bytes), byte => byte.toString(16).padStart(2, '0')).join('');
const bytes = value => Uint8Array.from(value.match(/../g), item => parseInt(item, 16));
function fail(code) { const error = Error(code); error.code = code; throw error; }
export function addressFromKey(publicKey) {
  if (!/^[0-9a-f]{64}$/.test(publicKey)) fail('KO_ENVELOPE_INVALID');
  const domain = utf8.encode('VLOCK7SIN/IDENTITY/v0.1'), key = bytes(publicKey), message = new Uint8Array(domain.length + key.length);
  message.set(domain); message.set(key, domain.length);
  let value = 0, count = 0, output = 'v7';
  for (const byte of sha3_256(message).slice(0, 20)) {
    value = (value << 8) | byte; count += 8;
    while (count >= 5) { count -= 5; output += 'abcdefghijklmnopqrstuvwxyz234567'[(value >>> count) & 31]; value &= (1 << count) - 1; }
  }
  return output;
}
export async function generateIdentity() {
  const key = await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']);
  const publicKey = hex(await crypto.subtle.exportKey('raw', key.publicKey));
  return { publicKey, address: addressFromKey(publicKey), privateKey: key.privateKey };
}
async function signed(schema, payload, identity) {
  const signature = hex(await crypto.subtle.sign('Ed25519', identity.privateKey, utf8.encode(signingText(schema, identity.publicKey, payload))));
  return { schema, publicKey: identity.publicKey, payload, signature };
}
export async function signDeployment(artifact, options, identity) {
  return signed(DEPLOY_SCHEMA, deploymentPayload(validateContract(artifact), options), identity);
}
export async function signCall(artifact, state, request, identity) {
  return signed(CALL_SCHEMA, callPayload(validateContract(artifact), state, request), identity);
}
async function authenticate(input, schema, artifact) {
  const message = envelope(input);
  if (message.schema !== schema) fail('KO_SIGNING_DOMAIN');
  if (message.payload.programSha256 !== artifact.programSha256) fail('KO_PROGRAM_MISMATCH');
  const key = await crypto.subtle.importKey('raw', bytes(message.publicKey), 'Ed25519', false, ['verify']);
  if (!await crypto.subtle.verify('Ed25519', key, bytes(message.signature), utf8.encode(signingText(message.schema, message.publicKey, message.payload)))) fail('KO_SIGNATURE_INVALID');
  return { message, caller: addressFromKey(message.publicKey) };
}
export async function deploySignedContract(input, packet) {
  const artifact = validateContract(input), { message, caller } = await authenticate(packet, DEPLOY_SCHEMA, artifact);
  const { networkId, salt, gasLimit } = message.payload;
  return { ...deployContract(artifact, { caller, networkId, salt, gasLimit }), signatureVerified: true, caller };
}
export async function callSignedContract(input, state, packet) {
  const artifact = validateContract(input), { message, caller } = await authenticate(packet, CALL_SCHEMA, artifact);
  const { networkId, contractId, expectedRevision, expectedStateRoot, method, args, gasLimit } = message.payload;
  if (networkId !== state.networkId) fail('KO_NETWORK_MISMATCH');
  if (contractId !== state.contractId) fail('KO_CONTRACT_MISMATCH');
  if (expectedStateRoot !== state.stateRoot) fail('KO_STALE_STATE');
  return { ...callContract(artifact, state, { caller, method, args, expectedRevision, gasLimit }), signatureVerified: true, caller };
}
export { compileContract };
