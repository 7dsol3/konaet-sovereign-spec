'use strict';
const { createHash } = require('node:crypto');
const FORMAT = 'konaet-sovereign-genesis-v7-ko-program';
const PROTOCOL = '0.6.0-sovereign-ko-program.1';
const PROFILE = Object.freeze({ profile: 'KONAET_KO_PROGRAM_V1', eventFormat: 'vlock7sin-ko-event-v1',
  stateFormat: 'vlock7sin-ko-state-v1', sourceBytes: 16384, transactionBytes: 65536,
  gasPerTransaction: 100000, gasPerClosure: 1000000, actsPerClosure: 64, closureBytes: 262144, contracts: 128, stateBytes: 4194304 });
const PROFILE_HASH = createHash('sha256').update(JSON.stringify(PROFILE)).digest('hex');
const AUTHORIZED_FORMAT = 'konaet-sovereign-genesis-v8-ko-admission';
const AUTHORIZED_PROTOCOL = '0.7.0-sovereign-ko-admission.1';
const AUTHORIZED_PROFILE = Object.freeze({ ...PROFILE, stateFormat: 'vlock7sin-ko-state-v2', deploymentAuthorization: 'genesis-quota-v1' });
const AUTHORIZED_PROFILE_HASH = createHash('sha256').update(JSON.stringify(AUTHORIZED_PROFILE)).digest('hex');
function normalizeDeploymentPolicy(input) {
  const fail = () => { const error = Error('Deployment policy requires unique genesis-authorized addresses and reserved quotas totaling at most 128.'); error.code = 'KO_DEPLOYMENT_POLICY_INVALID'; throw error; };
  if (!input || Object.keys(input).sort().join(',') !== 'deployers,schema'
    || input.schema !== 'konaet.contract-deployment-policy.v1' || !Array.isArray(input.deployers)
    || input.deployers.length < 1 || input.deployers.length > PROFILE.contracts) fail();
  let total = 0;
  const deployers = input.deployers.map(row => {
    if (!row || Object.keys(row).sort().join(',') !== 'address,maxContracts' || typeof row.address !== 'string'
      || !/^v7[a-z2-7]{32}$/.test(row.address) || !Number.isSafeInteger(row.maxContracts) || row.maxContracts < 1 || row.maxContracts > PROFILE.contracts) fail();
    total += row.maxContracts; return Object.freeze({ address: row.address, maxContracts: row.maxContracts });
  }).sort((a, b) => a.address < b.address ? -1 : a.address > b.address ? 1 : 0);
  if (total > PROFILE.contracts || new Set(deployers.map(row => row.address)).size !== deployers.length) fail();
  return Object.freeze({ schema: input.schema, deployers: Object.freeze(deployers) });
}
function deploymentPolicyHash(policy) { return createHash('sha3-256').update('VLOCK7SIN/KO-DEPLOYMENT-POLICY/v1\0').update(JSON.stringify(normalizeDeploymentPolicy(policy))).digest('hex'); }
module.exports = Object.freeze({ FORMAT, PROTOCOL, PROFILE, PROFILE_HASH, AUTHORIZED_FORMAT, AUTHORIZED_PROTOCOL,
  AUTHORIZED_PROFILE, AUTHORIZED_PROFILE_HASH, normalizeDeploymentPolicy, deploymentPolicyHash });
