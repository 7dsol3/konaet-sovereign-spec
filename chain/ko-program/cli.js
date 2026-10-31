'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { compileContract, validateContract } = require('./runtime');
const { createStore, recoverStore, callStore, createSignedStore, callSignedStore } = require('./store');
const { signDeployment, signCall } = require('./auth');
const { encodeAddress, rawPublicKey } = require('../vlock7sin-js/src/crypto');
const USAGE = 'compile SOURCE ARTIFACT | keygen ENCRYPTED.pem | sign-deploy ARTIFACT OPTIONS.json KEY.pem ENVELOPE.json | deploy-signed ARTIFACT DIRECTORY ENVELOPE.json | sign-call DIRECTORY CALL.json KEY.pem ENVELOPE.json | call-signed DIRECTORY ENVELOPE.json | status DIRECTORY | deploy ARTIFACT DIRECTORY OPTIONS.json | call DIRECTORY CALL.json';
function read(file, maximum = 2097152) {
  const stat = fs.statSync(file); if (!stat.isFile() || stat.size > maximum) throw Error('FILE_SIZE_LIMIT');
  const bytes = fs.readFileSync(file); if (bytes.length > maximum) throw Error('FILE_SIZE_LIMIT');
  return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
}
function passphrase() {
  const value = process.env.KONAET_KO_KEY_PASSPHRASE;
  if (!value || value.length < 12 || value.length > 1024) throw Error('KONAET_KO_KEY_PASSPHRASE must contain 12..1024 characters.');
  return value;
}
function privateKey(file) {
  const pem = read(file, 16384);
  if (!pem.startsWith(['-----BEGIN ENCRYPTED', 'PRIVATE KEY-----'].join(' '))) throw Error('ENCRYPTED_PKCS8_REQUIRED');
  const key = crypto.createPrivateKey({ key: pem, passphrase: passphrase() });
  if (key.asymmetricKeyType !== 'ed25519') throw Error('ED25519_KEY_REQUIRED');
  return key;
}
function writeEnvelope(file, envelope) {
  fs.writeFileSync(file, JSON.stringify(envelope, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  return { signed: true, schema: envelope.schema, publicKey: envelope.publicKey, envelope: path.resolve(file) };
}
function main(args) {
  const [command, first, second, third] = args;
  if (command === 'keygen' && args.length === 2) {
    const secret = passphrase(), { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
    fs.writeFileSync(first, privateKey.export({ format: 'pem', type: 'pkcs8', cipher: 'aes-256-cbc', passphrase: secret }), { flag: 'wx', mode: 0o600 });
    return { created: true, encrypted: true, publicKey: rawPublicKey(publicKey).toString('hex'), address: encodeAddress(publicKey) };
  }
  if (command === 'sign-deploy' && args.length === 5) return writeEnvelope(args[4], signDeployment(validateContract(JSON.parse(read(first))), JSON.parse(read(second, 16384)), privateKey(third)));
  if (command === 'sign-call' && args.length === 5) {
    const restored = recoverStore(first);
    if (!restored.authenticated) throw Error('AUTHENTICATED_STORE_REQUIRED');
    return writeEnvelope(args[4], signCall(restored.artifact, restored.state, JSON.parse(read(second, 16384)), privateKey(third)));
  }
  if (command === 'deploy-signed' && args.length === 4) return createSignedStore(second, validateContract(JSON.parse(read(first))), JSON.parse(read(third, 16384)));
  if (command === 'call-signed' && args.length === 3) return callSignedStore(first, JSON.parse(read(second, 16384)));
  if (command === 'compile' && args.length === 3) {
    const artifact = compileContract(read(first, 65536));
    fs.writeFileSync(second, JSON.stringify(artifact, null, 2) + '\n', { flag: 'wx' });
    return { compiled: true, profile: artifact.profile, contract: artifact.program.contract,
      programSha256: artifact.programSha256, artifact: path.resolve(second), functions: artifact.program.functions.map(fn => ({ name: fn.name, view: fn.view, internal: fn.internal })) };
  }
  if (command === 'deploy' && args.length === 4) return createStore(second, validateContract(JSON.parse(read(first))), JSON.parse(read(third, 16384)));
  if (command === 'call' && args.length === 3) return callStore(first, JSON.parse(read(second, 16384)));
  if (command === 'status' && args.length === 2) { const state = recoverStore(first); return { state: state.state, authenticated: state.authenticated, committedCalls: state.committedCalls, recoveryGas: state.recoveryGas }; }
  throw Error(USAGE);
}
if (require.main === module) {
  try { console.log(JSON.stringify(main(process.argv.slice(2)), null, 2)); }
  catch (error) { console.error(JSON.stringify({ accepted: false, code: error.code || 'KO_PROGRAM_CLI_ERROR', message: error.message })); process.exitCode = 1; }
}
module.exports = { main };
