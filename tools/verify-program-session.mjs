import fs from 'node:fs';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
const require = createRequire(import.meta.url);
const { validateContract } = require('../chain/ko-program/runtime');
const { deploySignedContract, callSignedContract } = require('../chain/ko-program/auth');
export function verifySession(session) {
  if (!session || session.schema !== 'konaet.ko-studio-session.v1' || session.execution !== 'browser-session'
    || !Array.isArray(session.calls) || session.calls.length > 100) throw Error('SESSION_FORMAT_INVALID');
  const artifact = validateContract(session.artifact);
  let state = deploySignedContract(artifact, session.deployment).state;
  let gasUsed = 0;
  for (const call of session.calls) {
    const receipt = callSignedContract(artifact, state, call.envelope);
    if (JSON.stringify(receipt) !== JSON.stringify(call.receipt)) throw Error('SESSION_RECEIPT_MISMATCH');
    state = receipt.state; gasUsed += receipt.gasUsed;
    if (gasUsed > 10000000) throw Error('SESSION_GAS_LIMIT');
  }
  if (JSON.stringify(state) !== JSON.stringify(session.state)) throw Error('SESSION_STATE_MISMATCH');
  return { verified: true, profile: artifact.profile, signaturesVerified: session.calls.length + 1,
    execution: 'browser-session', calls: session.calls.length, gasUsed, contractId: state.contractId, revision: state.revision, stateRoot: state.stateRoot };
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.length !== 3) throw Error('USAGE: node tools/verify-program-session.mjs SESSION.json');
    const file = process.argv[2], stat = fs.statSync(file);
    if (!stat.isFile() || stat.size > 4194304) throw Error('SESSION_SIZE_LIMIT');
    const bytes = fs.readFileSync(file); if (bytes.length > 4194304) throw Error('SESSION_SIZE_LIMIT');
    console.log(JSON.stringify(verifySession(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))), null, 2));
  } catch (error) { console.error(JSON.stringify({ verified: false, code: error.code || error.message })); process.exitCode = 1; }
}
