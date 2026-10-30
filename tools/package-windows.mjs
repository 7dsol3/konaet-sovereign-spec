import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { ROOT, ALLOWED_FILES, inventory, verifyFilePolicy } from './files.mjs';
if (process.platform !== 'win32') throw Error('WINDOWS_PACKAGER_REQUIRED');
verifyFilePolicy(inventory());
const node = path.resolve(process.argv[2] || process.execPath);
if (path.basename(node).toLowerCase() !== 'node.exe') throw Error('NODE_EXE_REQUIRED');
const runtime = spawnSync(node, ['--version'], { encoding: 'utf8', windowsHide: true });
if (runtime.status !== 0 || !/^v24\./.test(runtime.stdout)) throw Error('NODE_24_REQUIRED');
const stageRoot = path.join(ROOT, '.packaging');
fs.mkdirSync(stageRoot, { recursive: true });
const stage = path.join(fs.mkdtempSync(path.join(stageRoot, 'build-')), 'Konaet-Console');
fs.mkdirSync(stage);
const files = [];
function add(relative, bytes) {
  const target = path.join(stage, relative); fs.mkdirSync(path.dirname(target), { recursive: true }); fs.writeFileSync(target, bytes);
  files.push({ path: relative, bytes: bytes.length, sha256: crypto.createHash('sha256').update(bytes).digest('hex') });
}
for (const relative of [...ALLOWED_FILES, 'publication-manifest.json']) add(relative, fs.readFileSync(path.join(ROOT, relative)));
for (const row of ALLOWED_FILES.filter(name => name.startsWith('vendor/ws/'))) add(row.replace('vendor/ws/', 'node_modules/ws/'), fs.readFileSync(path.join(ROOT, row)));
add('bin/node.exe', fs.readFileSync(node));
add('bin/LICENSE', fs.readFileSync(path.join(path.dirname(node), 'LICENSE')));
fs.writeFileSync(path.join(stage, 'package-manifest.json'), JSON.stringify({ schema: 'konaet.windows-console-package.v1', version: '1.2.0',
  nodeVersion: runtime.stdout.trim(), privateKeysIncluded: false, files }, null, 2) + '\n');
const destination = path.join(ROOT, 'dist', 'Konaet-Console-Windows-x64.zip');
fs.mkdirSync(path.dirname(destination), { recursive: true });
if (fs.existsSync(destination)) throw Error('PACKAGE_ALREADY_EXISTS');
const result = spawnSync('powershell.exe', ['-NoProfile', '-Command',
  'Compress-Archive -LiteralPath $env:KONAET_PACKAGE_STAGE -DestinationPath $env:KONAET_PACKAGE_OUTPUT -CompressionLevel Optimal'],
{ env: { ...process.env, KONAET_PACKAGE_STAGE: stage, KONAET_PACKAGE_OUTPUT: destination }, windowsHide: true, encoding: 'utf8', timeout: 180000 });
if (result.status !== 0) throw Error(result.stderr || 'ARCHIVE_FAILED');
const bytes = fs.readFileSync(destination), sha256 = crypto.createHash('sha256').update(bytes).digest('hex');
fs.writeFileSync(destination + '.sha256', `${sha256}  Konaet-Console-Windows-x64.zip\n`);
console.log(JSON.stringify({ path: destination, sha256, bytes: bytes.length, files: files.length, nodeVersion: runtime.stdout.trim(), privateKeysIncluded: false }));
