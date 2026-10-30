'use strict';
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { crypto: vcrypto } = require('../vlock7sin-js/src');
const { HybridIdentity } = require('../vlock7sin-js/src/hybridCrypto');

function generate(directory, validatorId) {
  assert.match(validatorId, /^validator-[0-9]+$/);
  const base = path.resolve(directory);
  assert.ok(fs.statSync(base).isDirectory() && !fs.lstatSync(base).isSymbolicLink());
  const seedPath = path.join(base, `${validatorId}.seed`);
  const publicPath = path.join(base, `${validatorId}.public.json`);
  const consensusSecretPath = path.join(base, `${validatorId}.consensus.secret.json`);
  assert.ok(!fs.existsSync(seedPath) && !fs.existsSync(publicPath) && !fs.existsSync(consensusSecretPath), 'PRESERVE_EXISTING_IDENTITY');
  const seed = crypto.randomBytes(32);
  const mlDsa65 = crypto.generateKeyPairSync('ml-dsa-65');
  const mlKem768 = crypto.generateKeyPairSync('ml-kem-768');
  let mlDsa65PrivateDer;
  let mlKem768PrivateDer;
  try {
    const identity = vcrypto.IdentityKeypair.fromSeed(seed);
    const hybridIdentity = new HybridIdentity({ ed25519PrivateKey: identity.privateKeyObject(),
      mlDsa65PrivateKey: mlDsa65.privateKey, mlKem768PrivateKey: mlKem768.privateKey });
    const publicIdentity = { schema: 'konaet.operator-public-identity.v2', validatorId,
      publicKey: identity.publicBytes().toString('hex'), address: identity.address(),
      publicIdentity: hybridIdentity.publicIdentity(),
      scope: 'private-testnet-no-value', administrativeIndependenceVerified: false };
    mlDsa65PrivateDer = mlDsa65.privateKey.export({ format: 'der', type: 'pkcs8' });
    mlKem768PrivateDer = mlKem768.privateKey.export({ format: 'der', type: 'pkcs8' });
    const consensusSecret = { schema: 'konaet.operator-hybrid-consensus-secret.v1', validatorId,
      publicIdentityFingerprint: hybridIdentity.publicIdentity().fingerprint,
      mlDsa65PrivateKeyPkcs8: mlDsa65PrivateDer.toString('base64'),
      mlKem768PrivateKeyPkcs8: mlKem768PrivateDer.toString('base64') };
    fs.writeFileSync(seedPath, seed.toString('hex') + '\n', { flag: 'wx', mode: 0o600 });
    fs.writeFileSync(publicPath, JSON.stringify(publicIdentity, null, 2) + '\n', { flag: 'wx' });
    fs.writeFileSync(consensusSecretPath, JSON.stringify(consensusSecret, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
    return publicIdentity;
  } finally {
    seed.fill(0);
    mlDsa65PrivateDer?.fill(0);
    mlKem768PrivateDer?.fill(0);
  }
}

if (require.main === module) {
  try { console.log(JSON.stringify(generate(process.argv[2], process.argv[3]), null, 2)); }
  catch (error) { console.error(error.message); process.exitCode = 1; }
}
module.exports = { generate };
