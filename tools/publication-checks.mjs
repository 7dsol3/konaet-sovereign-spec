import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

export function verifyVersionAgreement(versions) {
  assert.match(versions.package, /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/, 'PACKAGE_VERSION_INVALID');
  for (const [label, version] of Object.entries(versions)) {
    assert.equal(version, versions.package, `PUBLICATION_VERSION_MISMATCH: ${label}`);
  }
}

export function verifyDocumentLinks(root, relative, source) {
  const links = [...source.matchAll(/!?\[[^\]]*\]\(([^)]+)\)/g)].map(match => match[1]);
  links.push(...[...source.matchAll(/\b(?:src|href)\s*=\s*["']([^"']+)["']/gi)].map(match => match[1]));
  for (const target of links) {
    if (/^[a-z][a-z0-9+.-]*:/i.test(target) || target.startsWith('//') || target.startsWith('#')) continue;
    const file = decodeURIComponent(target.split(/[?#]/)[0]);
    if (!file) continue;
    const absolute = path.resolve(root, path.dirname(relative), file);
    assert.ok(absolute.startsWith(root + path.sep), `DOCUMENT_LINK_OUTSIDE_PUBLICATION: ${relative}`);
    assert.ok(fs.existsSync(absolute) && fs.statSync(absolute).isFile(), `DOCUMENT_LINK_MISSING: ${relative}: ${target}`);
  }
}

export function verifyPublicationMetadata(root, manifest) {
  const read = relative => JSON.parse(fs.readFileSync(path.join(root, relative), 'utf8'));
  const pkg = read('package.json'), chain = read('chain/package.json'), lock = read('package-lock.json');
  verifyVersionAgreement({ package: pkg.version, chain: chain.version, lock: lock.version,
    lockRoot: lock.packages[''].version, manifest: manifest.edition });
  for (const row of manifest.files.filter(row => row.path.endsWith('.md'))) {
    verifyDocumentLinks(root, row.path, fs.readFileSync(path.join(root, row.path), 'utf8'));
  }
}
