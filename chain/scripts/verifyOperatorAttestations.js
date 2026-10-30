'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');

function canonical(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number' && Number.isSafeInteger(value)) return String(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  assert.ok(value && typeof value === 'object', 'INVALID_ATTESTATION_VALUE');
  return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
}

function message(statement) {
  assert.equal(statement.schema, 'konaet.operator-observation.v1');
  for (const field of ['operatorId', 'administratorId', 'machineId', 'providerId']) {
    assert.match(statement[field], /^[a-zA-Z0-9][a-zA-Z0-9._-]{2,79}$/);
  }
  for (const field of ['genesisId', 'stateRoot', 'sourceBundleSha256']) assert.match(statement[field], /^[a-f0-9]{64}$/);
  assert.match(statement.sequence, /^(0|[1-9][0-9]*)$/);
  assert.ok(Number.isFinite(Date.parse(statement.observedAtUtc)), 'INVALID_OBSERVATION_TIME');
  assert.equal(statement.publicNetwork, false, 'TESTNET_OBSERVATIONS_ONLY');
  return Buffer.from(`KONAET/OPERATOR-OBSERVATION/v1\0${canonical(statement)}`, 'utf8');
}

function sign(statement, privateKeyPem) {
  const key = crypto.createPrivateKey(privateKeyPem);
  assert.equal(key.asymmetricKeyType, 'ed25519');
  return { schema: 'konaet.operator-signed-observation.v1', statement,
    signatureBase64: crypto.sign(null, message(statement), key).toString('base64') };
}

function verify(roster, receipts, { now = Date.now(), maximumAgeMs = 3600000 } = {}) {
  assert.equal(roster.schema, 'konaet.operator-roster.v1');
  assert.ok(Array.isArray(roster.operators) && roster.operators.length >= 3, 'THREE_EXPECTED_OPERATORS_REQUIRED');
  assert.ok(Array.isArray(receipts) && receipts.length === roster.operators.length, 'MISSING_OPERATOR_RECEIPT');
  const unique = field => new Set(roster.operators.map(row => row[field])).size;
  for (const field of ['operatorId', 'administratorId', 'machineId', 'publicKeyPem']) {
    assert.equal(unique(field), roster.operators.length, `DUPLICATE_${field}`);
  }
  const observed = new Set();
  for (const receipt of receipts) {
    assert.equal(receipt.schema, 'konaet.operator-signed-observation.v1');
    const statement = receipt.statement;
    const expected = roster.operators.find(row => row.operatorId === statement.operatorId);
    assert.ok(expected && !observed.has(statement.operatorId), 'UNKNOWN_OR_DUPLICATE_OPERATOR');
    observed.add(statement.operatorId);
    for (const field of ['administratorId', 'machineId', 'providerId']) assert.equal(statement[field], expected[field]);
    for (const field of ['genesisId', 'sourceBundleSha256']) assert.equal(statement[field], roster[field]);
    const timestamp = Date.parse(statement.observedAtUtc);
    assert.ok(now - timestamp >= -30000 && now - timestamp <= maximumAgeMs, 'STALE_OR_FUTURE_OBSERVATION');
    const key = crypto.createPublicKey(expected.publicKeyPem);
    assert.equal(key.asymmetricKeyType, 'ed25519');
    assert.equal(crypto.verify(null, message(statement), key, Buffer.from(receipt.signatureBase64, 'base64')), true,
      'INVALID_OPERATOR_SIGNATURE');
  }
  const keys = roster.operators.map(row => crypto.createPublicKey(row.publicKeyPem).export({ type: 'spki', format: 'der' }).toString('hex'));
  assert.equal(new Set(keys).size, receipts.length, 'DUPLICATE_SIGNING_ROOT');
  for (const field of ['stateRoot', 'sequence']) assert.equal(new Set(receipts.map(row => row.statement[field])).size, 1, `DIVERGENT_${field}`);
  return { schema: 'konaet.operator-observation-assessment.v1', status: 'SIGNED_OBSERVATIONS_VERIFIED',
    observations: receipts.length, distinctClaimedAdministrators: unique('administratorId'),
    distinctClaimedMachines: unique('machineId'), distinctClaimedProviders: unique('providerId'),
    matchingRoot: true, matchingSequence: true, privateKeysExported: false,
    organizationalIndependence: 'EXTERNAL_IDENTITY_AND_CUSTODY_REVIEW_REQUIRED',
    publicSecurity: 'NOT_ESTABLISHED', generalSuperiority: 'NOT_ESTABLISHED' };
}

function read(file) {
  assert.ok(fs.statSync(file).size <= 65536, 'BOUNDED_INPUT_REQUIRED');
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

if (require.main === module) {
  try {
    const [action, ...args] = process.argv.slice(2);
    if (action === 'sign' && args.length === 3) {
      const [statementPath, keyPath, output] = args;
      assert.ok(fs.statSync(keyPath).size <= 8192, 'BOUNDED_PRIVATE_KEY_REQUIRED');
      fs.writeFileSync(output, JSON.stringify(sign(read(statementPath), fs.readFileSync(keyPath)), null, 2) + '\n', { flag: 'wx' });
      console.log('SIGNED_OBSERVATION_WRITTEN; private key not exported');
    } else if (action === 'verify' && args.length >= 4) {
      console.log(JSON.stringify(verify(read(args[0]), args.slice(1).map(read)), null, 2));
    } else throw Error('Usage: sign statement.json private-key.pem output.json | verify roster.json receipt1.json receipt2.json receipt3.json [...]');
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}

module.exports = { canonical, message, sign, verify };
