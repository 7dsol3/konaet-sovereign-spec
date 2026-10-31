import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { ROOT, inventory, verifyFilePolicy } from './files.mjs';
import { verifyTransferVector } from '../lib/event.mjs';
import { verifyPublicationMetadata } from './publication-checks.mjs';
import { verifyRemoteResults } from './remote/verify-report.mjs';

try {
  const files = inventory();
  verifyFilePolicy(files);
  const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'publication-manifest.json'), 'utf8'));
  assert.equal(manifest.schema, 'konaet.spec.publication-manifest.v1');
  assert.equal(manifest.publicNetworkDeployed, false);
  assert.equal(manifest.containsProductionKeys, false);
  assert.deepEqual(manifest.files, files, 'PUBLICATION_INTEGRITY_MISMATCH');
  verifyPublicationMetadata(ROOT, manifest);
  for (const row of files) {
    if (row.path.endsWith('.png')) continue;
    const text = fs.readFileSync(path.join(ROOT, row.path), 'utf8');
    assert.ok(!/-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/.test(text), 'PRIVATE_KEY_FORBIDDEN');
    assert.ok(!/\b(?:gh[pousr]_[a-zA-Z0-9]{30,}|github_pat_[a-zA-Z0-9_]{30,})\b/.test(text), 'CREDENTIAL_FORBIDDEN');
    assert.ok(!/[A-Z]:[\\/](?:Users|Windows)[\\/]/.test(text), 'LOCAL_PATH_FORBIDDEN');
  }
  const vector = JSON.parse(fs.readFileSync(path.join(ROOT, 'examples/signed-transfer.json'), 'utf8'));
  const result = verifyTransferVector(vector);
  const readRemote = name => JSON.parse(fs.readFileSync(path.join(ROOT, 'evidence/remote-smoke-2026-10-31', name), 'utf8'));
  const remote = verifyRemoteResults(readRemote('controller.json'), [0, 1, 2, 3].map(index => readRemote(`result-${index}.json`)),
    '8cdf7e01767e3b9e4df92323e4fd7ca1d350ef91', '41210093390-1');
  const readHour = name => JSON.parse(fs.readFileSync(path.join(ROOT, 'evidence/remote-hour-2026-10-31', name), 'utf8'));
  const hour = verifyRemoteResults(readHour('controller.json'), [0, 1, 2, 3].map(index => readHour(`result-${index}.json`)),
    '8cdf7e01767e3b9e4df92323e4fd7ca1d350ef91', '41210381147-1');
  console.log(JSON.stringify({ edition: manifest.edition, filesVerified: files.length,
    syntheticTransferVector: { signatureVerified: result.cryptographicallyValid, inclusionAndFinalityChecked: false },
    remoteSmokeValidation: remote,
    remoteConsensusValidation: hour,
    permanentPublicNetworkHosted: manifest.publicNetworkDeployed }, null, 2));
} catch (error) {
  console.error(`FAIL ${error.message}`);
  process.exitCode = 1;
}
