import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

export const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const ALLOWED_FILES = Object.freeze([
  '.gitattributes', '.github/workflows/check.yml', '.gitignore',
  'README.md', 'NOMENCLATURE.md', 'PROTOCOL.md', 'EVIDENCE.md', 'COMPARISON.md',
  'DEPLOYMENT.md', 'CONTRIBUTING.md', 'SECURITY.md', 'LICENSE', 'package.json',
  'assets/puzzle-do-dia.png', 'evidence/source-review.json', 'examples/signed-transfer.json',
  'lib/event.mjs', 'tools/files.mjs', 'tools/manifest.mjs', 'tools/verify-transfer.mjs',
  'tools/verify-publication.mjs', 'tests/event.test.mjs', 'tests/publication.test.mjs',
  'KO-RUNTIME.md', 'runtime/ko-policy.cjs', 'runtime/SindraRuntime.ko', 'runtime/LICENSE',
  'tests/ko.test.mjs', 'evidence/ko-runtime.json',
].sort());

export function sha256(bytes) { return createHash('sha256').update(bytes).digest('hex'); }

export function inventory(root = ROOT) {
  const files = [];
  function walk(directory) {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      if (['.git', 'node_modules'].includes(entry.name)) continue;
      const absolute = path.join(directory, entry.name);
      if (entry.isSymbolicLink()) throw new Error('PUBLICATION_SYMLINK_FORBIDDEN');
      if (entry.isDirectory()) { walk(absolute); continue; }
      if (!entry.isFile()) throw new Error('REGULAR_FILE_REQUIRED');
      const relative = path.relative(root, absolute).replace(/\\/g, '/');
      if (relative === 'publication-manifest.json') continue;
      const bytes = fs.readFileSync(absolute);
      files.push({ path: relative, bytes: bytes.length, sha256: sha256(bytes) });
    }
  }
  walk(root);
  return files.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : 0);
}

export function verifyFilePolicy(rows) {
  const actual = rows.map(row => row.path).sort();
  if (JSON.stringify(actual) !== JSON.stringify(ALLOWED_FILES)) throw new Error('PUBLICATION_ALLOWLIST_MISMATCH');
}
