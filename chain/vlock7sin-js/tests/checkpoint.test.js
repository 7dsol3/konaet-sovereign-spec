'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const core = require('../src');
const { canonicalBytes } = require('../src/causalGraph');

function identity(label) {
  return core.crypto.IdentityKeypair.fromTestSeed(Buffer.from(`checkpoint:${label}`, 'utf8'));
}

function certifiedClosure() {
  const alice = identity('alice');
  const bob = identity('bob');
  const validatorOne = identity('validator-one');
  const validatorTwo = identity('validator-two');
  const validatorThree = identity('validator-three');
  const state = new core.GlobalState({ balances: [[alice.address(), 1000n]] });
  const quorum = new core.PermissionedQuorum({
    networkId: String(core.NETWORK_ID),
    protocolVersion: core.VERSION_STRING,
    threshold: 2,
    validators: [
      { id: 'one', publicKey: validatorOne.publicBytes() },
      { id: 'two', publicKey: validatorTwo.publicBytes() },
      { id: 'three', publicKey: validatorThree.publicBytes() },
    ],
  });
  const ledger = new core.VlockLedger({ state, quorum });
  const event = core.createTransfer({
    networkId: core.NETWORK_ID,
    sequence: 1n,
    nonce: 1n,
    timestampMs: 1_788_041_600_000n,
    amountAtomic: 75n,
    previousRoot: state.root(),
    senderPublicKey: alice.publicBytes(),
    receiverAddress: bob.address(),
    memo: 'certified checkpoint transfer',
  }, alice);
  ledger.submitAct(event);
  const proposal = ledger.prepareConstellation();
  const votes = [
    quorum.createVote(proposal, 'one', validatorOne.privateKeyObject()),
    quorum.createVote(proposal, 'two', validatorTwo.privateKeyObject()),
  ];
  const certificate = quorum.assembleCertificate(proposal, votes);
  return { closure: ledger.commitPrepared(proposal, { certificate }), quorum };
}

test('certified closure becomes a deterministic causal checkpoint with event proof', () => {
  const { closure, quorum } = certifiedClosure();
  const checkpoint = core.createCheckpointFromClosure(closure, {
    quorum,
    createdAtUnixMs: 1_788_041_600_000n,
    policyRoot: core.crypto.sha3(Buffer.from('policy-v1')).toString('hex'),
    privacyRoot: core.computePrivacyRoot([]),
  });
  const proof = core.checkpoint.createEventProof(closure.actIds, 0);

  assert.equal(core.verifyCheckpoint(checkpoint), true);
  assert.equal(core.checkpoint.verifyEventProof(proof, checkpoint.eventRoot), true);
  assert.equal(checkpoint.stateRoot, closure.nextRoot);
  assert.equal(checkpoint.closureCertificateId, closure.certificate.id);
  assert.equal(checkpoint.eventCount, 1);
  assert.equal(canonicalBytes(core.createCheckpoint(checkpoint)).equals(canonicalBytes(checkpoint)), true);
  assert.throws(() => core.createCheckpointFromClosure(closure, {
    quorum: { verifyCertificate: () => false },
    createdAtUnixMs: 1_788_041_600_000n,
    policyRoot: core.crypto.sha3(Buffer.from('policy-v1')).toString('hex'),
    privacyRoot: core.computePrivacyRoot([]),
  }), { code: 'INVALID_CLOSURE_CERTIFICATE' });
});

test('hybrid signed checkpoint fails closed after any state or signature mutation', () => {
  const { closure, quorum } = certifiedClosure();
  const checkpoint = core.createCheckpointFromClosure(closure, {
    quorum,
    createdAtUnixMs: 1_788_041_600_000n,
    policyRoot: core.crypto.sha3(Buffer.from('policy-v1')).toString('hex'),
    privacyRoot: core.computePrivacyRoot([]),
  });
  const signer = core.HybridIdentity.generate();
  const signed = core.signCheckpoint(checkpoint, signer);

  assert.equal(core.verifySignedCheckpoint(signed), true);
  assert.equal(core.verifySignedCheckpoint({
    ...signed,
    checkpoint: { ...checkpoint, stateRoot: 'aa'.repeat(32) },
  }), false);
  assert.equal(core.verifySignedCheckpoint({
    ...signed,
    signature: { ...signed.signature, messageSha3_512: 'bb'.repeat(64) },
  }), false);
});

test('external anchor intents are deterministic and never claim external truth from caller data', () => {
  const { closure, quorum } = certifiedClosure();
  const checkpoint = core.createCheckpointFromClosure(closure, {
    quorum,
    createdAtUnixMs: 1_788_041_600_000n,
    policyRoot: core.crypto.sha3(Buffer.from('policy-v1')).toString('hex'),
    privacyRoot: core.computePrivacyRoot([]),
  });
  const bitcoin = core.createAnchorIntent(checkpoint, {
    anchorType: 'bitcoin-op-return-v1',
    network: 'bitcoin-signet',
    requiredConfirmations: 6,
  });
  const evm = core.createAnchorIntent(checkpoint, {
    anchorType: 'evm-calldata-v1',
    network: 'ethereum-sepolia',
    destination: '0x0000000000000000000000000000000000000007',
    requiredConfirmations: 12,
  });

  assert.equal(core.verifyAnchorIntent(bitcoin), true);
  assert.equal(core.verifyAnchorIntent(evm), true);
  assert.throws(() => core.createAnchorIntent(checkpoint, {
    anchorType: 'bitcoin-op-return-v1',
    network: 'bitcoin-signet',
    requiredConfirmations: 0,
  }), { code: 'INVALID_CONFIRMATION_POLICY' });
  assert.equal(core.verifyAnchorIntent({ ...bitcoin, requiredConfirmations: 0 }), false);
  assert.throws(() => core.createAnchorIntent(checkpoint, {
    anchorType: 'bitcoin-op-return-v1',
    network: 'bitcoin-signet',
    destination: 'not-used',
  }), { code: 'INVALID_DESTINATION' });
  assert.throws(() => core.createAnchorIntent(checkpoint, {
    anchorType: 'evm-calldata-v1',
    network: 'ethereum-sepolia',
    destination: '0x0000000000000000000000000000000000000000',
  }), { code: 'INVALID_DESTINATION' });
  assert.equal(bitcoin.payloadHex.startsWith('6a255637435001'), true);
  assert.equal(evm.payloadHex, `641fa644${checkpoint.checkpointId}`);
  assert.equal(core.checkpoint.verifyAnchorObservation(bitcoin, {
    observedPayloadHex: bitcoin.payloadHex,
    confirmations: 6,
  }).externalTruthProven, false);
  assert.equal(core.checkpoint.verifyAnchorObservation(bitcoin, {
    observedPayloadHex: '00',
    confirmations: 100,
  }).confirmationGate, false);
});
