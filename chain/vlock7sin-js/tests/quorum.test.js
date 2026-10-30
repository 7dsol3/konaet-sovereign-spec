'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { IdentityKeypair, sha3 } = require('../src/crypto');
const {
  PermissionedQuorum,
  PermissionedQuorumError,
} = require('../src/quorum');

function key(label) {
  return IdentityKeypair.fromTestSeed(Buffer.from(`quorum:${label}`));
}

function proposal(overrides = {}) {
  const hash = (label) => sha3(Buffer.from(label)).toString('hex');
  return {
    networkId: '28673',
    protocolVersion: '0.2.0',
    sequence: '1',
    constellationId: hash('constellation'),
    previousRoot: hash('previous'),
    nextRoot: hash('next'),
    transitionTrace: hash('transition'),
    pcc: hash('pcc'),
    ...overrides,
  };
}

function fixture() {
  const alpha = key('alpha');
  const beta = key('beta');
  const gamma = key('gamma');
  const quorum = new PermissionedQuorum({
    networkId: '28673',
    protocolVersion: '0.2.0',
    threshold: 2,
    validators: [
      { id: 'alpha', publicKey: alpha.publicBytes() },
      { id: 'beta', publicKey: beta.publicBytes() },
      { id: 'gamma', publicKey: gamma.publicBytes() },
    ],
  });
  return { quorum, alpha, beta, gamma };
}

test('k-of-n certificate requires distinct allowlisted Ed25519 signatures', () => {
  const { quorum, alpha, beta } = fixture();
  const closure = proposal();
  const votes = [
    quorum.createVote(closure, 'alpha', alpha.privateKeyObject()),
    quorum.createVote(closure, 'beta', beta.privateKeyObject()),
  ];
  const certificate = quorum.assembleCertificate(closure, votes);
  assert.equal(certificate.scope, 'permissioned-k-of-n');
  assert.equal(certificate.threshold, 2);
  assert.equal(quorum.verifyCertificate(certificate, closure), true);
});

test('one key cannot count twice and threshold is enforced', () => {
  const { quorum, alpha } = fixture();
  const closure = proposal();
  const vote = quorum.createVote(closure, 'alpha', alpha.privateKeyObject());
  assert.throws(
    () => quorum.assembleCertificate(closure, [vote]),
    (error) => error instanceof PermissionedQuorumError && error.code === 'THRESHOLD_NOT_MET',
  );
  assert.throws(
    () => quorum.assembleCertificate(closure, [vote, vote]),
    (error) => error instanceof PermissionedQuorumError && error.code === 'DUPLICATE_SIGNER',
  );
});

test('votes cannot cross a network, proposal or validator set', () => {
  const { quorum, alpha, gamma } = fixture();
  const closure = proposal();
  const vote = quorum.createVote(closure, 'alpha', alpha.privateKeyObject());
  assert.throws(
    () => quorum.verifyVote(proposal({ nextRoot: sha3(Buffer.from('other')).toString('hex') }), vote),
    (error) => error instanceof PermissionedQuorumError && error.code === 'STATEMENT_MISMATCH',
  );
  assert.throws(
    () => quorum.createVote(closure, 'beta', gamma.privateKeyObject()),
    (error) => error instanceof PermissionedQuorumError && error.code === 'KEY_MISMATCH',
  );

  const other = new PermissionedQuorum({
    networkId: 'other',
    protocolVersion: '0.2.0',
    threshold: 1,
    validators: [{ id: 'alpha', publicKey: alpha.publicBytes() }],
  });
  assert.throws(
    () => other.verifyVote({ ...closure, networkId: 'other' }, vote),
    (error) => error instanceof PermissionedQuorumError && error.code === 'ALLOWLIST_MISMATCH',
  );
});

test('duplicate validator keys are rejected during policy creation', () => {
  const alpha = key('alpha');
  assert.throws(
    () => new PermissionedQuorum({
      threshold: 1,
      validators: [
        { id: 'alpha', publicKey: alpha.publicBytes() },
        { id: 'alias', publicKey: alpha.publicBytes() },
      ],
    }),
    (error) => error instanceof PermissionedQuorumError && error.code === 'DUPLICATE_KEY',
  );
});
