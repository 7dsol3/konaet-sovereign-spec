'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const { HybridIdentity } = require('../src/hybridCrypto');
const {
  assertPublicLedgerSafe,
  computePrivacyRoot,
  createPrivatePayloadCommitment,
  verifyPrivatePayloadCommitment,
} = require('../src/privacy');

test('private payload produces a blinded commitment and PQ-encrypted reference without leaking PII', () => {
  const recipient = HybridIdentity.generate();
  const payload = {
    fullName: 'Pessoa Privada',
    email: 'private@example.test',
    cpf: '123.456.789-00',
    evidence: 'private bytes',
  };
  const result = createPrivatePayloadCommitment(payload, {
    salt: Buffer.alloc(32, 7),
    reference: 'vault://private/claim/42',
    recipient: recipient.publicIdentity(),
  });
  const serialized = JSON.stringify(result.publicRecord);

  assert.equal(serialized.includes('Pessoa Privada'), false);
  assert.equal(serialized.includes('private@example.test'), false);
  assert.equal(serialized.includes('123.456.789-00'), false);
  assert.equal(serialized.includes('vault://private/claim/42'), false);
  assert.equal(verifyPrivatePayloadCommitment(payload, result.opening, result.publicRecord), true);
  assert.equal(verifyPrivatePayloadCommitment({ ...payload, evidence: 'changed' }, result.opening, result.publicRecord), false);
  assert.equal(assertPublicLedgerSafe(result.publicRecord), true);

  const context = {
    commitment: result.publicRecord.commitment,
    purpose: 'private-off-ledger-reference',
  };
  assert.equal(recipient.open(result.publicRecord.encryptedReference, { context }).toString('utf8'), 'vault://private/claim/42');
});

test('public ledger boundary rejects direct identifiers, secrets, network identity and raw references', () => {
  const rejected = [
    { email: 'private@example.test' },
    { profile: { fullName: 'Pessoa Privada' } },
    { note: 'contato private@example.test agora' },
    { cpfHash: '123.456.789-00' },
    { ipAddress: '203.0.113.8' },
    { link: 'vault://private/item/1' },
    { password: 'do-not-store' },
    { note: ['-----BEGIN ', 'PRIVATE KEY-----'].join('') },
  ];
  for (const value of rejected) assert.throws(() => assertPublicLedgerSafe(value), undefined, JSON.stringify(value));

  assert.equal(assertPublicLedgerSafe({
    eventId: 'ab'.repeat(32),
    stateRoot: 'cd'.repeat(32),
    walletAddress: 'v7abcdefghijklmnopqrstuvwxyz234567',
  }), true);
});

test('public ledger boundary rejects hidden accessors, symbols, binary and non-JSON containers before reading them', () => {
  let getterReads = 0;
  const accessor = {};
  Object.defineProperty(accessor, 'value', {
    enumerable: true,
    get() {
      getterReads += 1;
      return 'should never be read';
    },
  });
  const symbolRecord = { eventId: 'ab'.repeat(32) };
  symbolRecord[Symbol('hidden')] = 'private@example.test';
  const sparse = Array(2);
  sparse[1] = 'value';

  assert.throws(() => assertPublicLedgerSafe(accessor), { code: 'AMBIGUOUS_PUBLIC_FIELD' });
  assert.equal(getterReads, 0);
  assert.throws(() => assertPublicLedgerSafe(Buffer.from('private@example.test')), { code: 'PUBLIC_BINARY_FORBIDDEN' });
  assert.throws(() => assertPublicLedgerSafe(symbolRecord), { code: 'PUBLIC_SYMBOL_FORBIDDEN' });
  assert.throws(() => assertPublicLedgerSafe(new Map([['eventId', 'ab'.repeat(32)]])), { code: 'NON_JSON_PUBLIC_CONTAINER' });
  assert.throws(() => assertPublicLedgerSafe(sparse), { code: 'AMBIGUOUS_PUBLIC_ARRAY' });
});

test('privacy root is deterministic, order independent and rejects duplicates', () => {
  const first = createPrivatePayloadCommitment({ value: 'one' }, { salt: Buffer.alloc(32, 1) }).publicRecord;
  const second = createPrivatePayloadCommitment({ value: 'two' }, { salt: Buffer.alloc(32, 2) }).publicRecord;
  assert.equal(computePrivacyRoot([first, second]), computePrivacyRoot([second, first]));
  assert.notEqual(computePrivacyRoot([first]), computePrivacyRoot([second]));
  assert.throws(() => computePrivacyRoot([first, first]), { code: 'DUPLICATE_COMMITMENT' });
});
