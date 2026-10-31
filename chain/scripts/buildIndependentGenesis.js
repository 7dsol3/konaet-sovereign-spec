'use strict';
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const { createGenesis, HYBRID_PROFILE, HYBRID_TRANSFER_PROFILE, HYBRID_TRANSPORT_PROFILE,
  HYBRID_BINARY_TRANSPORT_PROFILE } = require('../network/sovereign');

function build(roster) {
  assert.equal(roster.scope, 'private-testnet-no-value');
  assert.ok(Number.isSafeInteger(roster.networkId) && roster.networkId > 0 && roster.networkId <= 0xffffffff);
  assert.equal(roster.validators.length, 4, 'INITIAL_PROFILE_REQUIRES_FOUR_VALIDATORS');
  assert.equal(new Set(roster.validators.map(row => row.administratorId)).size, 4, 'FOUR_CLAIMED_ADMINISTRATORS_REQUIRED');
  for (const row of roster.validators) {
    assert.match(row.publicKey, /^[a-f0-9]{64}$/);
    assert.match(row.administratorId, /^[a-zA-Z0-9._-]{3,80}$/);
  }
  const hybridTransfers = roster.transferAuthorizationProfile === HYBRID_TRANSFER_PROFILE;
  const hybridTransport = [HYBRID_TRANSPORT_PROFILE, HYBRID_BINARY_TRANSPORT_PROFILE]
    .includes(roster.transportSignatureProfile);
  if (roster.transferAuthorizationProfile !== undefined && !hybridTransfers) {
    throw new Error('UNSUPPORTED_TRANSFER_AUTHORIZATION_PROFILE');
  }
  if (roster.transportSignatureProfile !== undefined && !hybridTransport) {
    throw new Error('UNSUPPORTED_TRANSPORT_SIGNATURE_PROFILE');
  }
  if (hybridTransport) assert.equal(hybridTransfers, true, 'HYBRID_TRANSFER_PROFILE_REQUIRED');
  if (hybridTransfers) {
    assert.equal(roster.consensusSignatureProfile, HYBRID_PROFILE, 'HYBRID_CONSENSUS_PROFILE_REQUIRED');
    for (const row of roster.validators) assert.ok(row.publicIdentity && typeof row.publicIdentity === 'object', 'HYBRID_PUBLIC_IDENTITY_REQUIRED');
  }
  return createGenesis({ chainName: 'Konaet private independent testnet no value',
    networkId: roster.networkId, createdAt: roster.createdAt, threshold: 3,
    ...(hybridTransfers ? { consensusSignatureProfile: HYBRID_PROFILE, transferAuthorizationProfile: HYBRID_TRANSFER_PROFILE } : {}),
    ...(hybridTransport ? { transportSignatureProfile: roster.transportSignatureProfile } : {}),
    ...(roster.nativePolicy ? { nativePolicy: roster.nativePolicy } : {}),
    ...(roster.contractRuntime ? { contractRuntime: roster.contractRuntime } : {}),
    validators: roster.validators.map(row => ({ id: row.id, publicKey: row.publicKey,
      ...(hybridTransfers ? { publicIdentity: row.publicIdentity } : {}) })),
    allocations: roster.allocations, parameters: roster.parameters });
}

if (require.main === module) {
  try {
    const [input, output] = process.argv.slice(2);
    assert.ok(input && output && fs.statSync(input).size <= 65536, 'PUBLIC_ROSTER_AND_NEW_OUTPUT_REQUIRED');
    const genesis = build(JSON.parse(fs.readFileSync(input, 'utf8')));
    const bytes = Buffer.from(JSON.stringify(genesis, null, 2) + '\n');
    fs.writeFileSync(output, bytes, { flag: 'wx' });
    console.log(JSON.stringify({ genesisId: genesis.genesisId,
      genesisSha256: crypto.createHash('sha256').update(bytes).digest('hex'),
      scope: 'private-testnet-no-value', independentOperatorsVerified: false, privateKeysRead: false }));
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
module.exports = { build };
