import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const { compileKoPolicy, executeKoPolicy } = require('../chain/vlock7sin-js/src/koPolicy');
const ENDPOINT = 'https://konaet-ko-runtime.alkalipixie.chatgpt.site/api/ko';
function read(file, limit) {
  if (typeof file !== 'string') throw Error('FILE_REQUIRED');
  const stat = fs.statSync(file);
  if (!stat.isFile() || stat.size > limit) throw Error('FILE_SIZE_LIMIT');
  const bytes = fs.readFileSync(file);
  if (bytes.length > limit) throw Error('FILE_SIZE_LIMIT');
  return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
}
export async function runKo(args) {
  const [command, sourceFile, contextFile, phase = 'transfer'] = args;
  if (!['compile', 'run', 'online'].includes(command) || args.length < 2 || args.length > 4
      || (command === 'compile' && args.length !== 2)
      || (command !== 'compile' && args.length < 3)) throw Error('USAGE: ko compile SOURCE | ko run SOURCE CONTEXT [transfer|closure] | ko online SOURCE CONTEXT [transfer|closure]');
  const source = read(sourceFile, 16384);
  const policy = compileKoPolicy(source);
  if (command === 'compile') return policy;
  if (!['transfer', 'closure'].includes(phase)) throw Error('INVALID_PHASE');
  const context = JSON.parse(read(contextFile, 16384));
  if (!context || typeof context !== 'object' || Array.isArray(context)) throw Error('INVALID_CONTEXT');
  if (command === 'run') {
    executeKoPolicy(policy, phase, context);
    return { accepted: true, execution: 'local', profile: policy.profile, phase,
      sourceSha256: policy.sourceSha256, programSha256: policy.programSha256,
      rulesExecuted: policy.program.rules.filter(rule => rule.phase === phase).length };
  }
  const body = JSON.stringify({ source, phase, context });
  if (Buffer.byteLength(body) > 32768) throw Error('REQUEST_SIZE_LIMIT');
  const response = await fetch(ENDPOINT, { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body, redirect: 'error', signal: AbortSignal.timeout(15000) });
  const result = await response.json();
  if (!response.ok || result.accepted !== true) {
    const error = Error(result.message || result.code || `HTTP_${response.status}`);
    error.code = result.code || 'ONLINE_EXECUTION_REJECTED';
    throw error;
  }
  if (result.profile !== policy.profile || result.phase !== phase || result.sourceSha256 !== policy.sourceSha256
      || result.programSha256 !== policy.programSha256
      || result.rulesExecuted !== policy.program.rules.filter(rule => rule.phase === phase).length) throw Error('ONLINE_POLICY_MISMATCH');
  return { ...result, execution: 'online', endpoint: ENDPOINT };
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv[2] === '--help') {
    console.log('Konaet .ko\n\nko compile SOURCE\nko run SOURCE CONTEXT [transfer|closure]\nko online SOURCE CONTEXT [transfer|closure]\n\nO comando online envia o fonte e o contexto à API pública Konaet.');
  } else {
    try { console.log(JSON.stringify(await runKo(process.argv.slice(2)), null, 2)); }
    catch (error) { console.error(JSON.stringify({ accepted: false, code: error.code || 'KO_CLI_ERROR', message: error.message })); process.exitCode = 1; }
  }
}
