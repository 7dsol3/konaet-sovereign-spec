'use strict';

const assert = require('node:assert/strict');
const { generateKeyPairSync } = require('node:crypto');
const test = require('node:test');
const core = require('../src');

function hash(label) {
  return core.crypto.sha3(Buffer.from(label, 'utf8')).toString('hex');
}

function proposal(overrides = {}) {
  return {
    networkId: String(core.NETWORK_ID),
    protocolVersion: core.VERSION_STRING,
    sequence: '1',
    constellationId: hash('hybrid-constellation'),
    previousRoot: hash('hybrid-previous'),
    nextRoot: hash('hybrid-next'),
    transitionTrace: hash('hybrid-transition'),
    pcc: hash('hybrid-pcc'),
    ...overrides,
  };
}

function fixture() {
  const one = core.HybridIdentity.generate();
  const two = core.HybridIdentity.generate();
  const three = core.HybridIdentity.generate();
  const quorum = new core.HybridPermissionedQuorum({
    networkId: String(core.NETWORK_ID),
    protocolVersion: core.VERSION_STRING,
    threshold: 2,
    validators: [
      { id: 'one', publicIdentity: one.publicIdentity() },
      { id: 'two', publicIdentity: two.publicIdentity() },
      { id: 'three', publicIdentity: three.publicIdentity() },
    ],
  });
  return { quorum, one, two, three };
}

function mutateBase64(value) {
  const bytes = Buffer.from(value, 'base64');
  bytes[0] ^= 1;
  return bytes.toString('base64');
}

test('hybrid quorum certificate requires distinct AND-policy validator votes', () => {
  const { quorum, one, two } = fixture();
  const closure = proposal();
  const votes = [
    quorum.createVote(closure, 'one', one),
    quorum.createVote(closure, 'two', two),
  ];
  const certificate = quorum.assembleCertificate(closure, votes);

  assert.equal(certificate.scope, 'hybrid-permissioned-k-of-n');
  assert.equal(certificate.signaturePolicy, 'ED25519_AND_ML_DSA_65_V1');
  assert.equal(quorum.verifyCertificate(certificate, closure), true);
  assert.throws(() => quorum.assembleCertificate(closure, [votes[0]]), { code: 'THRESHOLD_NOT_MET' });
  assert.throws(() => quorum.assembleCertificate(closure, [votes[0], votes[0]]), { code: 'DUPLICATE_SIGNER' });
});

test('hybrid quorum rejects validator identities sharing either signing key', () => {
  const ed1 = generateKeyPairSync('ed25519').privateKey;
  const ed2 = generateKeyPairSync('ed25519').privateKey;
  const ml1 = generateKeyPairSync('ml-dsa-65').privateKey;
  const ml2 = generateKeyPairSync('ml-dsa-65').privateKey;
  const kem1 = generateKeyPairSync('ml-kem-768').privateKey;
  const kem2 = generateKeyPairSync('ml-kem-768').privateKey;
  const make = (ed, ml, kem) => new core.HybridIdentity({
    ed25519PrivateKey: ed, mlDsa65PrivateKey: ml, mlKem768PrivateKey: kem,
  }).publicIdentity();
  const first = make(ed1, ml1, kem1);
  for (const alias of [make(ed1, ml1, kem2), make(ed1, ml2, kem2), make(ed2, ml1, kem2)]) {
    assert.notEqual(alias.fingerprint, first.fingerprint);
    assert.throws(() => new core.HybridPermissionedQuorum({
      validators: [{ id: 'one', publicIdentity: first }, { id: 'two', publicIdentity: alias }],
      threshold: 2,
    }), { code: 'DUPLICATE_SIGNING_KEY' });
  }
});

test('mutating either signature component invalidates a hybrid vote and certificate', () => {
  const { quorum, one, two } = fixture();
  const closure = proposal();
  const voteOne = quorum.createVote(closure, 'one', one);
  const voteTwo = quorum.createVote(closure, 'two', two);
  const certificate = quorum.assembleCertificate(closure, [voteOne, voteTwo]);
  const changedVote = {
    ...voteOne,
    signature: {
      ...voteOne.signature,
      mlDsa65Signature: mutateBase64(voteOne.signature.mlDsa65Signature),
    },
  };
  assert.throws(() => quorum.verifyVote(closure, changedVote), { code: 'INVALID_SIGNATURE' });

  const changedCertificate = {
    ...certificate,
    signatures: [
      {
        ...certificate.signatures[0],
        signature: {
          ...certificate.signatures[0].signature,
          ed25519Signature: mutateBase64(certificate.signatures[0].signature.ed25519Signature),
        },
      },
      certificate.signatures[1],
    ],
  };
  assert.throws(() => quorum.verifyCertificate(changedCertificate, closure), { code: 'INVALID_SIGNATURE' });
});

test('VLOCK ledger accepts a valid hybrid quorum closure without changing JS-v1 event bytes', () => {
  const sender = core.crypto.IdentityKeypair.fromTestSeed(Buffer.from('hybrid-ledger-sender'));
  const receiver = core.crypto.IdentityKeypair.fromTestSeed(Buffer.from('hybrid-ledger-receiver'));
  const { quorum, one, two } = fixture();
  const state = new core.GlobalState({ balances: [[sender.address(), 500n]] });
  const ledger = new core.VlockLedger({ state, quorum });
  const event = core.createTransfer({
    sequence: 1n,
    nonce: 1n,
    timestampMs: 1_788_041_600_000n,
    amountAtomic: 50n,
    previousRoot: state.root(),
    senderPublicKey: sender.publicBytes(),
    receiverAddress: receiver.address(),
    memo: 'JS-v1 event under hybrid closure',
  }, sender);
  const before = event.canonicalBytes();
  ledger.submitAct(event);
  const prepared = ledger.prepareConstellation();
  const certificate = quorum.assembleCertificate(prepared, [
    quorum.createVote(prepared, 'one', one),
    quorum.createVote(prepared, 'two', two),
  ]);
  const closure = ledger.commitPrepared(prepared, { certificate });

  assert.equal(closure.closureScope, 'hybrid-permissioned-k-of-n');
  assert.equal(quorum.verifyCertificate(closure.certificate, prepared), true);
  assert.deepEqual(event.canonicalBytes(), before);
  assert.equal(core.ledger.stateFromSnapshot(ledger.snapshot().state).getBalance(receiver.address()), 50n);
});

test('VLOCK ledger requires positive certificate acceptance instead of treating false as success', () => {
  const sender = core.crypto.IdentityKeypair.fromTestSeed(Buffer.from('false-verifier-sender'));
  const receiver = core.crypto.IdentityKeypair.fromTestSeed(Buffer.from('false-verifier-receiver'));
  const state = new core.GlobalState({ balances: [[sender.address(), 100n]] });
  const ledger = new core.VlockLedger({
    state,
    quorum: { verifyCertificate: () => false },
  });
  ledger.submitAct(core.createTransfer({
    sequence: 1n,
    nonce: 1n,
    timestampMs: 1_788_041_600_000n,
    amountAtomic: 10n,
    previousRoot: state.root(),
    senderPublicKey: sender.publicBytes(),
    receiverAddress: receiver.address(),
    memo: 'false verifier must fail closed',
  }, sender));
  const prepared = ledger.prepareConstellation();
  const rootBefore = ledger.root;

  assert.throws(() => ledger.commitPrepared(prepared, { certificate: { scope: 'fake' } }), {
    code: 'INVALID_CERTIFICATE',
  });
  assert.equal(ledger.root, rootBefore);
  assert.equal(ledger.sequence, 0n);
});
