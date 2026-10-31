import fs from 'node:fs';
import path from 'node:path';
import { ROOT } from './files.mjs';
const runtime = fs.readFileSync(path.join(ROOT, 'chain/ko-program/runtime.js'), 'utf8');
const messages = fs.readFileSync(path.join(ROOT, 'chain/ko-program/messages.js'), 'utf8');
const hashImport = "const { createHash } = require('node:crypto');";
if (runtime.split(hashImport).length !== 2 || !runtime.endsWith('\n')) throw Error('PROGRAM_BROWSER_INPUT_CHANGED');
const prefix = `// Generated from chain/ko-program/runtime.js by tools/build-program-browser.mjs.
// The interpreter body is unchanged. Only SHA-256 and UTF-8 size use browser adapters.
import { sha256 } from './vendor/hashes/sha256.js';
const module = { exports: {} };
const Buffer = { byteLength: value => new TextEncoder().encode(value).length };
function createHash(algorithm) {
  if (algorithm !== 'sha256') throw Error('HASH_ALGORITHM_UNSUPPORTED');
  const instance = sha256.create();
  const adapter = { update(value) { instance.update(value); return adapter; }, digest(encoding) {
    if (encoding !== 'hex') throw Error('HASH_ENCODING_UNSUPPORTED');
    return Array.from(instance.digest(), byte => byte.toString(16).padStart(2, '0')).join('');
  } }; return adapter;
}
`;
const runtimeOutput = prefix + runtime.replace(hashImport, '') + '\nexport { PROFILE, SCHEMA, STATE_SCHEMA, KoProgramError, compileContract, validateContract, deployContract, callContract };\n';
const messagesOutput = '// Generated from chain/ko-program/messages.js. Signing format is unchanged.\nconst module = { exports: {} };\n' + messages
  + '\nexport { DEPLOY_SCHEMA, CALL_SCHEMA, deploymentPayload, callPayload, signingText, envelope };\n';
const outputs = [['program-runtime.mjs', runtimeOutput], ['program-messages.mjs', messagesOutput]];
for (const [name, content] of outputs) {
  const file = path.join(ROOT, 'docs', name);
  if (process.argv.includes('--check')) {
    if (fs.readFileSync(file, 'utf8') !== content) throw Error('PROGRAM_BROWSER_OUT_OF_DATE: ' + name);
  } else fs.writeFileSync(file, content);
}
console.log('Browser runtime matches the Node interpreter and canonical signing codec.');
