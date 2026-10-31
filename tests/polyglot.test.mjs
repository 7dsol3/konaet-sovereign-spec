import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const { processFrame } = require('../polyglot/node/receipt.cjs');
const { encodeSocialCommitmentFrame, createSocialCommitment } = require('../tools/social-receipt.cjs');
test('portable frames preserve SDK canonical bytes, all 256 digest bits and exact u128 arguments', () => {
  const vectors = JSON.parse(fs.readFileSync(new URL('../polyglot/vectors.json', import.meta.url), 'utf8'));
  assert.equal(vectors.cases.length, 12);
  for (const row of vectors.cases) {
    const opening = { schema: 'konaet.social-receipt-opening.v1', salt: row.salt, document: JSON.parse(Buffer.from(row.documentHex, 'hex')) };
    const frame = encodeSocialCommitmentFrame(opening);
    assert.equal(frame, `${row.salt}\n${row.documentHex}\n${row.commitment}\n`);
    assert.deepEqual(processFrame(Buffer.from(frame)), { commitment: row.commitment, args: row.args, matches: true });
    assert.equal(createSocialCommitment(opening).commitment, row.commitment);
    assert.equal(processFrame(Buffer.from(encodeSocialCommitmentFrame(opening, { verify: false }))).matches, null);
  }
});
test('portable frame parser rejects ambiguous encodings, trailing records and oversized data', () => {
  const good = encodeSocialCommitmentFrame({ schema: 'konaet.social-receipt-opening.v1', salt: 'a'.repeat(64), document: {} });
  for (const bad of [good + '\n', good.slice(0, -1), good.replaceAll('\n', '\r\n'), good.replace('7b7d', '7B7D'), good + '\0', 'x'.repeat(32901)])
    assert.throws(() => processFrame(Buffer.from(bad)));
  const changed = good.split('\n'); changed[2] = '0'.repeat(64);
  assert.equal(processFrame(Buffer.from(changed.join('\n'))).matches, false);
});
