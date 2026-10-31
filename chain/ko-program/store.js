'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { createHash, randomUUID } = require('node:crypto');
const { validateContract, deployContract, callContract, KoProgramError } = require('./runtime');
const { deploySignedContract, callSignedContract } = require('./auth');
const { envelope: validateEnvelope } = require('./messages');
const RECORD_SCHEMA = 'konaet.ko-program-commit.v1';
const MAX_FILE = 2097152;
const MAX_RECORDS = 1024;
function fail(code, message) { throw new KoProgramError(code, message); }
function hash(value) { return createHash('sha256').update(JSON.stringify(value)).digest('hex'); }
function directory(input) {
  const absolute = path.resolve(input);
  for (let cursor = absolute; ; cursor = path.dirname(cursor)) {
    if (fs.existsSync(cursor) && fs.lstatSync(cursor).isSymbolicLink()) fail('KO_STORE_SYMLINK', 'Symbolic link store paths are not supported.');
    if (path.dirname(cursor) === cursor) break;
  }
  return absolute;
}
function read(file) {
  const stat = fs.lstatSync(file);
  if (stat.isSymbolicLink() || !stat.isFile() || stat.size > MAX_FILE) fail('KO_STORE_FILE_INVALID', 'Bounded regular store file required.');
  const bytes = fs.readFileSync(file); if (bytes.length > MAX_FILE) fail('KO_STORE_FILE_INVALID', 'Store file exceeds limit.');
  return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
}
function syncDirectory(input) {
  let descriptor;
  try { descriptor = fs.openSync(input, 'r'); fs.fsyncSync(descriptor); }
  catch (error) {
    if (process.platform !== 'win32' || !['EACCES', 'EPERM', 'EISDIR', 'EINVAL', 'ENOTSUP'].includes(error.code)) throw error;
  } finally { if (descriptor !== undefined) fs.closeSync(descriptor); }
}
function durableCreate(file, value) {
  const bytes = Buffer.from(JSON.stringify(value, null, 2) + '\n');
  if (bytes.length > MAX_FILE) fail('KO_STORE_FILE_LIMIT', 'Commit exceeds file limit.');
  const temporary = path.join(path.dirname(file), `.pending-${randomUUID()}.json`);
  let descriptor;
  try {
    descriptor = fs.openSync(temporary, 'wx', 0o600); fs.writeFileSync(descriptor, bytes); fs.fsyncSync(descriptor); fs.closeSync(descriptor); descriptor = undefined;
    // Publishing a fully written hard link is exclusive and atomic: no partial
    // final record and no overwrite when two calls target the same revision.
    fs.linkSync(temporary, file);
    syncDirectory(path.dirname(file));
  } finally {
    if (descriptor !== undefined) fs.closeSync(descriptor);
    if (fs.existsSync(temporary)) fs.unlinkSync(temporary);
  }
}
function createStore(input, contract, options, signed = false) {
  const artifact = validateContract(contract);
  const result = signed ? deploySignedContract(artifact, options) : deployContract(artifact, options);
  const deployment = signed ? validateEnvelope(options) : JSON.parse(JSON.stringify(options)), absolute = directory(input);
  try { fs.mkdirSync(absolute, { mode: 0o700 }); syncDirectory(path.dirname(absolute)); }
  catch (error) { if (error.code !== 'EEXIST') throw error; }
  if (!fs.lstatSync(absolute).isDirectory()) fail('KO_STORE_EXISTS', 'Deployment path is not a directory.');
  // A crash before publication may leave an empty directory or unpublished
  // temporary files. A committed deployment or any unrelated file is never replaced.
  const entries = fs.readdirSync(absolute);
  if (entries.length > 16 || entries.some(name => !/^\.pending-[0-9a-f-]{36}\.json$/.test(name)
    || !fs.lstatSync(path.join(absolute, name)).isFile() || fs.lstatSync(path.join(absolute, name)).isSymbolicLink())) {
    fail('KO_STORE_EXISTS', 'Deployment directory contains committed or unrelated data.');
  }
  try {
    // One exclusive commit publishes program, intent and initial state together.
    durableCreate(path.join(absolute, 'deployment.json'), { schema: signed ? 'konaet.ko-program-authenticated-deployment.v2' : 'konaet.ko-program-deployment.v2',
      artifact, options: deployment, state: result.state });
  } catch (error) {
    if (error.code === 'EEXIST') fail('KO_STORE_EXISTS', 'Another writer published this deployment.');
    throw error;
  }
  return result;
}
function recoverStore(input) {
  const absolute = directory(input);
  const deployment = read(path.join(absolute, 'deployment.json'));
  const authenticated = ['konaet.ko-program-authenticated-deployment.v1', 'konaet.ko-program-authenticated-deployment.v2'].includes(deployment.schema);
  if (!authenticated && !['konaet.ko-program-deployment.v1', 'konaet.ko-program-deployment.v2'].includes(deployment.schema)) fail('KO_STORE_INVALID', 'Unknown deployment record.');
  const artifact = validateContract(deployment.schema.endsWith('.v2') ? deployment.artifact : read(path.join(absolute, 'program.json')));
  let state = (authenticated ? deploySignedContract(artifact, deployment.options) : deployContract(artifact, deployment.options)).state;
  if (JSON.stringify(state) !== JSON.stringify(deployment.state)) fail('KO_STORE_GENESIS_MISMATCH', 'Deployment state differs from recomputed state.');
  const records = fs.readdirSync(absolute).filter(name => /^[0-9]{20}\.json$/.test(name)).sort();
  if (records.length > MAX_RECORDS) fail('KO_STORE_HISTORY_LIMIT', 'History requires a checkpoint-capable future profile.');
  const receipts = []; let recoveryGas = 0;
  for (const [index, file] of records.entries()) {
    if (file !== `${String(index + 1).padStart(20, '0')}.json`) fail('KO_STORE_HISTORY_GAP', 'Store history is not contiguous.');
    const record = read(path.join(absolute, file));
    if (record.schema !== RECORD_SCHEMA || record.recordHash !== hash({ schema: record.schema, request: record.request, receipt: record.receipt })) fail('KO_STORE_RECORD_CORRUPT', 'Commit checksum mismatch.');
    const receipt = authenticated ? callSignedContract(artifact, state, record.request) : callContract(artifact, state, record.request);
    if (receipt.readOnly || JSON.stringify(receipt) !== JSON.stringify(record.receipt)) fail('KO_STORE_REPLAY_MISMATCH', 'Stored transition differs from replay.');
    recoveryGas += receipt.gasUsed;
    if (recoveryGas > 10000000) fail('KO_STORE_RECOVERY_LIMIT', 'Recovery work exceeds this store profile limit.');
    state = receipt.state; receipts.push(receipt);
  }
  return { artifact, state, receipts, authenticated, committedCalls: records.length, recoveryGas };
}
function callStore(input, request, requireSigned = false) {
  const absolute = directory(input), restored = recoverStore(absolute);
  if (requireSigned && !restored.authenticated) fail('KO_STORE_AUTH_REQUIRED', 'Authenticated deployment required.');
  // A signed deployment never accepts a caller-supplied address as authority.
  const canonical = restored.authenticated ? validateEnvelope(request) : request;
  const receipt = restored.authenticated ? callSignedContract(restored.artifact, restored.state, canonical) : callContract(restored.artifact, restored.state, canonical);
  if (receipt.readOnly) return receipt;
  if (restored.committedCalls >= MAX_RECORDS || restored.recoveryGas + receipt.gasUsed > 10000000) fail('KO_STORE_HISTORY_LIMIT', 'Store history limit reached.');
  const payload = { schema: RECORD_SCHEMA, request: canonical, receipt }, record = { ...payload, recordHash: hash(payload) };
  const file = path.join(absolute, `${receipt.state.revision.padStart(20, '0')}.json`);
  try { durableCreate(file, record); } catch (error) {
    if (error.code === 'EEXIST') fail('KO_STALE_STATE', 'Another call committed this revision. Reload the state.');
    throw error;
  }
  return receipt;
}
const createSignedStore = (directory, artifact, envelope) => createStore(directory, artifact, envelope, true);
const callSignedStore = (directory, envelope) => callStore(directory, envelope, true);
module.exports = Object.freeze({ createStore, recoverStore, callStore, createSignedStore, callSignedStore });
