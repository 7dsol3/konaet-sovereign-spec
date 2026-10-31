'use strict';
const assert = require('node:assert/strict');
const test = require('node:test');
const { operatorReadiness } = require('../chain/scripts/runIndependentValidator');
const now = 1800000000000;
function fixture() {
  const node = { genesis: { threshold: 3, validators: [0, 1, 2, 3] }, roundTimeoutMs: 1200,
    actBytes: new Map(), pendingSince: new Map(),
    status: () => ({ genesisId: 'a'.repeat(64), validatorId: 'validator-0', sequence: '4', root: 'b'.repeat(64), peers: ['validator-1', 'validator-2'] }) };
  const options = { now, tlsExpiresAt: new Date(now + 86400000).toISOString() };
  return { node, options };
}
test('readiness requires connected quorum, detects stalled pending work, and permits an idle healthy chain', () => {
  const { node, options } = fixture();
  assert.equal(operatorReadiness(node, options).ready, true);
  const status = node.status(); node.status = () => ({ ...status, peers: ['validator-1', 'validator-1'] });
  assert.equal(operatorReadiness(node, options).reason, 'QUORUM_UNAVAILABLE');
  node.status = () => status;
  node.actBytes.set('event', Buffer.alloc(1)); node.pendingSince.set('5', now - 61000);
  assert.equal(operatorReadiness(node, options).reason, 'CONSENSUS_STALLED');
  node.actBytes.clear(); assert.equal(operatorReadiness(node, options).ready, true);
});
test('readiness fails before certificate expiry and during shutdown without disclosing keys', () => {
  const { node, options } = fixture();
  assert.equal(operatorReadiness(node, { ...options, tlsExpiresAt: new Date(now + 3599999).toISOString() }).reason, 'CERTIFICATE_EXPIRING');
  assert.equal(operatorReadiness(node, { ...options, tlsExpiresAt: 'invalid' }).ready, false);
  const result = operatorReadiness(node, { ...options, closing: true });
  assert.equal(result.reason, 'STOPPING'); assert.equal(result.localObservationOnly, true);
  assert.equal(JSON.stringify(result).includes('secret'), false);
});
