import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { ROOT, inventory, verifyFilePolicy } from '../tools/files.mjs';

test('publication uses an explicit file set and refuses unplanned content', () => {
  const rows = inventory();
  verifyFilePolicy(rows);
  assert.throws(() => verifyFilePolicy([...rows, { path: 'wallet-backup.json' }]), /ALLOWLIST/);
  assert.throws(() => verifyFilePolicy(rows.slice(1)), /ALLOWLIST/);
});

test('all relative Markdown links and image references resolve inside the publication', () => {
  for (const row of inventory().filter(row => row.path.endsWith('.md'))) {
    const source = fs.readFileSync(path.join(ROOT, row.path), 'utf8');
    for (const [, target] of source.matchAll(/!?\[[^\]]*\]\(([^)]+)\)/g)) {
      if (/^https:\/\//.test(target) || target.startsWith('#')) continue;
      const absolute = path.resolve(path.dirname(path.join(ROOT, row.path)), decodeURIComponent(target.split('#')[0]));
      assert.ok(absolute.startsWith(ROOT + path.sep), `${row.path}: outside root`);
      assert.ok(fs.statSync(absolute).isFile(), `${row.path}: ${target}`);
    }
  }
});

test('source review separates maintainer reports from public-network proof', () => {
  const receipt = JSON.parse(fs.readFileSync(path.join(ROOT, 'evidence/source-review.json'), 'utf8'));
  assert.equal(receipt.sourceWorkingTree, 'modified-workspace');
  assert.equal(receipt.externalValidation.publicDeployment, false);
  assert.equal(receipt.externalValidation.generalSuperiorityEstablished, false);
  assert.equal(receipt.externalValidation.marketPriceEstablished, false);
  assert.ok(receipt.sourceFiles.length >= 8);
  for (const row of receipt.sourceFiles) assert.match(row.sha256, /^[0-9a-f]{64}$/);
});

test('the generated meme is included as a real PNG artifact', () => {
  const image = fs.readFileSync(path.join(ROOT, 'assets/puzzle-do-dia.png'));
  assert.equal(image.subarray(0, 8).toString('hex'), '89504e470d0a1a0a');
  assert.ok(image.length > 10000);
});
