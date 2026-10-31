import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { ROOT, inventory, verifyFilePolicy } from '../tools/files.mjs';
import { verifyVersionAgreement, verifyDocumentLinks, verifyPublicationMetadata, verifyLatestRequiredChecks } from '../tools/publication-checks.mjs';

test('distribution versions and documentation agree with the publication manifest', () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'publication-manifest.json'), 'utf8'));
  verifyPublicationMetadata(ROOT, manifest);
});

test('documentation verification catches broken HTML images and references outside the package', () => {
  assert.throws(() => verifyDocumentLinks(ROOT, 'README.md', '<img src="assets/missing-cover.png">'), /DOCUMENT_LINK_MISSING/);
  assert.throws(() => verifyDocumentLinks(ROOT, 'README.md', '[outside](../outside.md)'), /DOCUMENT_LINK_OUTSIDE_PUBLICATION/);
  verifyDocumentLinks(ROOT, 'README.md', '<img src="assets/puzzle-do-dia.png">');
});

test('a mismatched distribution version cannot be presented as the current edition', () => {
  assert.throws(() => verifyVersionAgreement({ package: '1.6.1', chain: '1.6.0' }), /PUBLICATION_VERSION_MISMATCH/);
  assert.throws(() => verifyVersionAgreement({ package: 'not-a-version' }), /PACKAGE_VERSION_INVALID/);
});

test('publication readiness uses the newest required check rather than hiding a later failure behind an earlier pass', () => {
  const pass = { id: 1, name: 'verify (ubuntu-latest)', app: { id: 15368 }, status: 'completed', conclusion: 'success' };
  const fail = { ...pass, id: 2, conclusion: 'failure' };
  assert.throws(() => verifyLatestRequiredChecks([pass, fail], [pass.name]), /LATEST_REQUIRED_CHECK_NOT_SUCCESSFUL/);
  assert.throws(() => verifyLatestRequiredChecks([pass, { ...fail, conclusion: 'cancelled' }], [pass.name]), /LATEST_REQUIRED_CHECK_NOT_SUCCESSFUL/);
  assert.throws(() => verifyLatestRequiredChecks([pass, { ...fail, status: 'in_progress', conclusion: null }], [pass.name]), /LATEST_REQUIRED_CHECK_NOT_SUCCESSFUL/);
  assert.throws(() => verifyLatestRequiredChecks([{ ...pass, app: { id: 99 } }], [pass.name]), /REQUIRED_CHECK_MISSING/);
  assert.equal(verifyLatestRequiredChecks([fail, { ...pass, id: 3 }], [pass.name])[0].id, 3);
});

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
