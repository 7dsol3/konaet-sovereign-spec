import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { ROOT, inventory, verifyFilePolicy } from './files.mjs';
import { verifyTransferVector } from '../lib/event.mjs';

try {
  const files = inventory();
  verifyFilePolicy(files);
  const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'publication-manifest.json'), 'utf8'));
  assert.equal(manifest.schema, 'konaet.spec.publication-manifest.v1');
  assert.equal(manifest.publicNetworkDeployed, false);
  assert.equal(manifest.containsProductionKeys, false);
  assert.deepEqual(manifest.files, files, 'PUBLICATION_INTEGRITY_MISMATCH');
  for (const row of files) {
    if (row.path.endsWith('.png')) continue;
    const text = fs.readFileSync(path.join(ROOT, row.path), 'utf8');
    assert.ok(!/-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/.test(text), 'PRIVATE_KEY_FORBIDDEN');
    assert.ok(!/\b(?:gh[pousr]_[a-zA-Z0-9]{30,}|github_pat_[a-zA-Z0-9_]{30,})\b/.test(text), 'CREDENTIAL_FORBIDDEN');
    assert.ok(!/[A-Z]:[\\/](?:Users|Windows)[\\/]/.test(text), 'LOCAL_PATH_FORBIDDEN');
  }
  const vector = JSON.parse(fs.readFileSync(path.join(ROOT, 'examples/signed-transfer.json'), 'utf8'));
  const result = verifyTransferVector(vector);
  console.log(JSON.stringify({ edition: manifest.edition, filesVerified: files.length,
    eventVerified: result.cryptographicallyValid, ledgerFinalityProven: false,
    sourceRunCountsIndependentlyReproduced: false, publicNetworkDeployed: false }, null, 2));
} catch (error) {
  console.error(`FAIL ${error.message}`);
  process.exitCode = 1;
}
