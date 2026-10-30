import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
try {
  const manifest = JSON.parse(fs.readFileSync(path.join(root, 'package-manifest.json'), 'utf8'));
  if (manifest.schema !== 'konaet.windows-console-package.v1' || manifest.privateKeysIncluded !== false) throw Error('INVALID_PACKAGE_MANIFEST');
  for (const row of manifest.files) {
    if (typeof row.path !== 'string' || row.path.includes('..') || row.path.includes(':') || path.isAbsolute(row.path)) throw Error('INVALID_PACKAGE_PATH');
    const file = path.resolve(root, row.path); if (!file.startsWith(root + path.sep)) throw Error('OUTSIDE_PACKAGE');
    for (let current = file; current !== root; current = path.dirname(current)) if (fs.lstatSync(current).isSymbolicLink()) throw Error('SYMLINK_REFUSED');
    const bytes = fs.readFileSync(file);
    if (bytes.length !== row.bytes || crypto.createHash('sha256').update(bytes).digest('hex') !== row.sha256) throw Error(`FILE_MISMATCH: ${row.path}`);
  }
  console.log(`KONAET: ${manifest.files.length} arquivos conferidos. Pacote ${manifest.version}, Node ${manifest.nodeVersion}.`);
} catch (error) { console.error(`KONAET: ${error.message}`); process.exitCode = 1; }
