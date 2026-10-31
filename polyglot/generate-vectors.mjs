import fs from 'node:fs';
import crypto from 'node:crypto';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const { encodeSocialCommitmentFrame, createSocialCommitment } = require('../tools/social-receipt.cjs');
const documents = [{}, { schema: 'konaet.social.post.v1', contentDigest: 'a'.repeat(64) },
  { a: 0, b: -1, c: 9007199254740991, bool: true, empty: null },
  { text: 'Konaet · São Paulo · ação · 日本語 · 🍥', nested: { b: 2, a: 1 } },
  { list: [null, false, true, 17, 'texto', { z: 'z', a: 'a' }] },
  { '10': 'dez', '2': 'dois', '': 'private-use', '😀': 'astral' },
  { quoted: '"aspas"\nlinha\t\\fim' }, { empty: [], object: {} },
  { boundary: 'x'.repeat(8192) }, { contentDigest: '0'.repeat(64), revision: 128 },
  { contentDigest: 'f'.repeat(64), revision: 1 }, { text: 'e\u0301 ≠ é' }];
const cases = documents.map((document, index) => {
  const salt = crypto.createHash('sha256').update(`Konaet public conformance vector ${index}`).digest('hex');
  const opening = { schema: 'konaet.social-receipt-opening.v1', salt, document };
  const frame = encodeSocialCommitmentFrame(opening), result = createSocialCommitment(opening);
  return { name: 'sdk-' + index, salt, documentHex: frame.split('\n')[1], commitment: result.commitment, args: result.args };
});
fs.writeFileSync(new URL('./vectors.json', import.meta.url), JSON.stringify({ schema: 'konaet.polyglot-vectors.v1',
  purpose: 'Public deterministic synthetic inputs; never reuse these salts for private documents.', cases }, null, 2) + '\n');
console.log(JSON.stringify({ vectorCases: cases.length }));
