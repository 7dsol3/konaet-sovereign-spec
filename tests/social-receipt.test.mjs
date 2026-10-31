import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { createRequire } from 'node:module';
import { startDemo } from '../tools/demo-network.mjs';
const require = createRequire(import.meta.url);
const sdk = require('../tools/social-receipt.cjs');
const source = fs.readFileSync(new URL('../chain/ko-program/examples/SocialReceiptRegistry.ko', import.meta.url), 'utf8');
const { runtime, auth } = require('../chain/vlock7sin-js/src/koProgramRuntime');
const { crypto: vcrypto } = require('../chain/vlock7sin-js/src');

test('social commitments are canonical, domain-separated, salted and contain no document or salt', () => {
  const opening = sdk.createSocialOpening({ kind: 'post', contentDigest: 'a'.repeat(64), revision: 1 });
  const commitment = sdk.createSocialCommitment(opening);
  const reordered = { ...opening, document: { revision: 1, contentDigest: 'a'.repeat(64), kind: 'post' } };
  assert.deepEqual(sdk.createSocialCommitment(reordered), commitment);
  assert.equal(sdk.verifySocialOpening(opening, commitment.commitment), true);
  assert.notEqual(sdk.createSocialCommitment(sdk.createSocialOpening(opening.document)).commitment, commitment.commitment);
  assert.equal(sdk.verifySocialOpening({ ...opening, document: { ...opening.document, revision: 2 } }, commitment.commitment), false);
  assert.notEqual(crypto.createHash('sha256').update(JSON.stringify(opening.document)).digest('hex'), commitment.commitment);
  assert.equal(BigInt(commitment.args[0]).toString(16).padStart(32, '0') + BigInt(commitment.args[1]).toString(16).padStart(32, '0'), commitment.commitment);
  assert.equal(JSON.stringify(commitment).includes(opening.salt), false);
  assert.equal(Object.hasOwn(commitment, 'document'), false);
});

test('hostile and oversized social inputs are rejected without invoking accessors', () => {
  for (const input of [undefined, [], { x: NaN }, { x: Infinity }, { x: 1n }, { x: 'x'.repeat(8193) }, JSON.parse('{"__proto__":1}')])
    assert.throws(() => sdk.createSocialOpening(input), /SOCIAL_/);
  let invoked = false;
  assert.throws(() => sdk.createSocialOpening({ get x() { invoked = true; return 1; } }), /SOCIAL_/);
  assert.equal(invoked, false);
  assert.throws(() => sdk.createSocialCommitment({ ...sdk.createSocialOpening({ x: 1 }), salt: 'a' }), /SOCIAL_/);
});

test('registry denies foreign writers and stops at its explicit capacity without altering prior state', () => {
  const owner = vcrypto.IdentityKeypair.generate(), other = vcrypto.IdentityKeypair.generate(), artifact = runtime.compileContract(source);
  let state = auth.deploySignedContract(artifact, auth.signDeployment(artifact, { networkId: '17', salt: '0', gasLimit: 10000 }, owner.privateKeyObject())).state;
  const call = (identity, current) => auth.callSignedContract(artifact, current, auth.signCall(artifact, current,
    { method: 'record', args: ['1', '2'], gasLimit: 10000 }, identity.privateKeyObject()));
  assert.throws(() => call(other, state), { code: 'KO_REQUIRE_FAILED' });
  for (let i = 0; i < 128; i++) state = call(owner, state).state;
  assert.equal(state.storage.count, '128'); const root = state.stateRoot;
  assert.throws(() => call(owner, state), { code: 'KO_REQUIRE_FAILED' }); assert.equal(state.stateRoot, root);
});

test('social receipt finalizes through four validator processes, rejects tampering and survives restart', { timeout: 90000 }, async t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'konaet-social-receipt-'));
  let network;
  t.after(async () => { if (network) await network.close();
    assert.equal(path.dirname(path.resolve(directory)), path.resolve(os.tmpdir()));
    assert.match(path.basename(directory), /^konaet-social-receipt-/); fs.rmSync(directory, { recursive: true, force: true }); });
  network = await startDemo({ directory, programs: true });
  const before = await network.status();
  const deployed = await network.contractTransition({ operation: 'deploy', from: 'alice', source, salt: '17', gasLimit: 10000 });
  const opening = sdk.createSocialOpening({ schema: 'konaet.social.post.v1', contentDigest: crypto.createHash('sha256').update('post privado').digest('hex') });
  const commitment = sdk.createSocialCommitment(opening);
  const recorded = await network.contractTransition({ operation: 'call', from: 'alice', contractId: deployed.contractId,
    method: 'record', args: commitment.args, gasLimit: 10000 });
  const trust = { expectedGenesisId: before.genesisId, expectedContractId: deployed.contractId, expectedCommitment: commitment.commitment };
  const verified = sdk.verifySocialReceipt(recorded.bundle, trust);
  assert.ok(verified.signers.length >= 3); assert.equal(verified.index, '1'); assert.equal(verified.contentTruthVerified, false);
  assert.equal(JSON.stringify(recorded.bundle).includes('post privado'), false); assert.equal(JSON.stringify(recorded.bundle).includes(opening.salt), false);
  for (const key of ['expectedGenesisId', 'expectedContractId', 'expectedCommitment'])
    assert.throws(() => sdk.verifySocialReceipt(recorded.bundle, { ...trust, [key]: '0'.repeat(64) }));
  const corrupt = structuredClone(recorded.bundle); corrupt.certificate.signatures[0].signature = '0'.repeat(128);
  assert.throws(() => sdk.verifySocialReceipt(corrupt, trust));
  await assert.rejects(network.contractTransition({ operation: 'call', from: 'bob', contractId: deployed.contractId,
    method: 'record', args: commitment.args, gasLimit: 10000 }));
  const after = await network.status(); assert.ok(before.accounts.every(a => /^\d+$/.test(a.balanceAtomic)));
  assert.deepEqual(after.accounts.map(a => a.balanceAtomic), before.accounts.map(a => a.balanceAtomic));
  assert.equal(after.converged, true); assert.equal(new Set(after.validators.map(v => v.pid)).size, 4);
  await network.close(); network = await startDemo({ directory, programs: true });
  const restored = await network.status(); assert.equal(restored.root, after.root); assert.equal(restored.sequence, after.sequence);
  assert.equal((await network.contract(deployed.contractId)).state.storage.count, '1');
});
