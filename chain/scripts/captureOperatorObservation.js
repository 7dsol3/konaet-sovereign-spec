'use strict';

// Capture a signed statement from the local status endpoint. The signer can
// still make false claims: an independent reviewer must verify the operator,
// host, key custody and relationship between the package and running process.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const { readConfiguration } = require('./runIndependentValidator');
const { sign } = require('./verifyOperatorAttestations');

function regularFile(file, maximum) {
  assert.equal(fs.lstatSync(file).isSymbolicLink(), false, 'SYMLINK_REFUSED');
  const stat = fs.statSync(file);
  assert.ok(stat.isFile() && stat.size > 0 && stat.size <= maximum, 'BOUNDED_FILE_REQUIRED');
  return stat;
}

function hashBundle(file) {
  const before = regularFile(file, 512 * 1024 * 1024);
  const fd = fs.openSync(file, 'r');
  try {
    const hash = crypto.createHash('sha256');
    const chunk = Buffer.allocUnsafe(1024 * 1024);
    let read;
    while ((read = fs.readSync(fd, chunk, 0, chunk.length, null)) !== 0) hash.update(chunk.subarray(0, read));
    const after = fs.fstatSync(fd);
    assert.equal(after.size, before.size, 'BUNDLE_CHANGED');
    assert.equal(after.mtimeMs, before.mtimeMs, 'BUNDLE_CHANGED');
    return hash.digest('hex');
  } finally { fs.closeSync(fd); }
}

function validateMetadata(metadata) {
  assert.ok(metadata && typeof metadata === 'object' && !Array.isArray(metadata));
  const fields = ['schema', 'operatorId', 'administratorId', 'machineId', 'providerId'];
  assert.deepEqual(Object.keys(metadata).sort(), [...fields].sort(), 'EXACT_METADATA_FIELDS_REQUIRED');
  assert.equal(metadata.schema, 'konaet.operator-capture-metadata.v1');
  for (const field of fields.slice(1)) assert.match(metadata[field], /^[a-zA-Z0-9][a-zA-Z0-9._-]{2,79}$/);
  return metadata;
}

async function localStatus(port) {
  const response = await fetch(`http://127.0.0.1:${port}/status`, {
    redirect: 'error', signal: AbortSignal.timeout(5000),
  });
  assert.equal(response.status, 200, 'STATUS_UNAVAILABLE');
  const chunks = []; let total = 0;
  for await (const chunk of response.body) {
    total += chunk.length;
    assert.ok(total <= 65536, 'STATUS_TOO_LARGE');
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

async function capture(configPath, metadata, privateKeyPath, bundlePath) {
  validateMetadata(metadata);
  const loaded = readConfiguration(configPath);
  const keyStat = regularFile(privateKeyPath, 8192);
  assert.ok(keyStat.size > 0);
  const bundleSha256 = hashBundle(bundlePath);
  const status = await localStatus(loaded.config.statusPort);
  assert.equal(status.validatorId, loaded.config.validatorId, 'VALIDATOR_STATUS_MISMATCH');
  assert.equal(status.genesisId, loaded.genesis.genesisId, 'GENESIS_STATUS_MISMATCH');
  assert.equal(status.scope, 'private-testnet-no-value');
  assert.equal(status.publicNetwork, false);
  assert.equal(status.monetaryValue, false);
  assert.equal(status.administrativeIndependenceVerified, false);
  assert.ok(Array.isArray(status.errors) && status.errors.length === 0, 'PROTOCOL_ERRORS_PRESENT');
  assert.match(status.root, /^[a-f0-9]{64}$/);
  assert.match(status.sequence, /^[1-9][0-9]*$/, 'COMMITTED_SEQUENCE_REQUIRED');
  const statement = { schema: 'konaet.operator-observation.v1', operatorId: metadata.operatorId,
    administratorId: metadata.administratorId, machineId: metadata.machineId, providerId: metadata.providerId,
    genesisId: status.genesisId, sourceBundleSha256: bundleSha256, stateRoot: status.root,
    sequence: status.sequence, observedAtUtc: new Date().toISOString(), publicNetwork: false };
  return sign(statement, fs.readFileSync(privateKeyPath));
}

if (require.main === module) {
  (async () => {
    const [configPath, metadataPath, keyPath, bundlePath, output] = process.argv.slice(2);
    assert.ok(configPath && metadataPath && keyPath && bundlePath && output
      && process.argv.length === 7, 'USAGE: config.json metadata.json attestation-private.pem bundle.zip receipt.json');
    regularFile(metadataPath, 65536);
    const metadata = JSON.parse(fs.readFileSync(metadataPath, 'utf8'));
    const receipt = await capture(configPath, metadata, keyPath, bundlePath);
    fs.writeFileSync(output, JSON.stringify(receipt, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
    console.log('LOCAL_OBSERVATION_SIGNED; organizational independence and running-source identity are not established');
  })().catch(error => { console.error(error.message); process.exitCode = 1; });
}
module.exports = { capture, hashBundle, validateMetadata };
