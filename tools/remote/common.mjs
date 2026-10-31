import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
export const require = createRequire(import.meta.url);
export const { canonicalBytes } = require('../../chain/vlock7sin-js/src/causalGraph');
export const { crypto: vcrypto } = require('../../chain/vlock7sin-js/src');
export const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
export const sha256 = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
export function check(value, code) { if (!value) throw Error(code); }
export function context(env = process.env) {
  check(env.GITHUB_ACTIONS === 'true' && /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(env.GITHUB_REPOSITORY ?? ''), 'GITHUB_PUBLIC_RUNNER_REQUIRED');
  const index = Number(env.QA_NODE), seconds = Number(env.QA_SECONDS ?? '3600');
  check(Number.isInteger(index) && index >= 0 && index < 4 && Number.isInteger(seconds) && seconds >= 180 && seconds <= 7200, 'REMOTE_RUN_ARGUMENTS_INVALID');
  check(/^\d+$/.test(env.GITHUB_RUN_ID ?? '') && /^\d+$/.test(env.GITHUB_RUN_ATTEMPT ?? '') && /^[0-9a-f]{40}$/.test(env.GITHUB_SHA ?? ''), 'RUN_IDENTITY_INVALID');
  const base = path.join(env.RUNNER_TEMP, 'konaet-remote-validation');
  return { index, seconds, repository: env.GITHUB_REPOSITORY, runId: env.GITHUB_RUN_ID, attempt: env.GITHUB_RUN_ATTEMPT,
    commit: env.GITHUB_SHA, key: `${env.GITHUB_RUN_ID}-${env.GITHUB_RUN_ATTEMPT}`, base,
    publicDir: path.join(base, 'public'), privateDir: path.join(base, 'private') };
}
export function writeJson(file, value) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const temporary = `${file}.${crypto.randomBytes(8).toString('hex')}.tmp`;
  fs.writeFileSync(temporary, JSON.stringify(value, null, 2) + '\n', { flag: 'wx', mode: 0o600 }); fs.renameSync(temporary, file);
}
export function readJson(file, max = 1024 * 1024) {
  check(fs.statSync(file).size <= max && !fs.lstatSync(file).isSymbolicLink(), 'JSON_FILE_INVALID');
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}
export function publicKeyObject(hex) {
  check(typeof hex === 'string' && /^[0-9a-f]{64}$/.test(hex), 'PUBLIC_KEY_INVALID');
  return crypto.createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(hex, 'hex')]), format: 'der', type: 'spki' });
}
export function signed(domain, body, privateKey) {
  return { body, signature: crypto.sign(null, Buffer.concat([Buffer.from(domain + '\0'), canonicalBytes(body)]), privateKey).toString('hex') };
}
export function verified(domain, packet, publicKey) {
  check(packet && Object.keys(packet).sort().join(',') === 'body,signature' && /^[0-9a-f]{128}$/.test(packet.signature ?? ''), 'SIGNED_PACKET_INVALID');
  check(crypto.verify(null, Buffer.concat([Buffer.from(domain + '\0'), canonicalBytes(packet.body)]), publicKeyObject(publicKey), Buffer.from(packet.signature, 'hex')), 'SIGNED_PACKET_REJECTED');
  return packet.body;
}
export const REPORT_DOMAIN = 'KONAET/REMOTE-VALIDATION/REPORT/v1';
export const CONTROL_DOMAIN = 'KONAET/REMOTE-VALIDATION/CONTROL/v1';
export const NETWORK_DOMAIN = 'KONAET/REMOTE-VALIDATION/NETWORK/v1';
export function endpoint(input) {
  const url = new URL(input);
  check(url.protocol === 'https:' && /^[a-z0-9-]+\.trycloudflare\.com$/.test(url.hostname) && url.hostname !== 'api.trycloudflare.com'
    && !url.username && !url.password && !url.port && url.pathname === '/' && !url.search && !url.hash, 'REMOTE_ENDPOINT_INVALID');
  return url.origin;
}
export async function jsonRequest(url, options = {}, timeout = 20000) {
  const response = await fetch(url, { ...options, redirect: 'error', signal: AbortSignal.timeout(timeout),
    headers: { 'Content-Type': 'application/json', ...options.headers } });
  const chunks = []; let bytes = 0;
  for await (const chunk of response.body) { bytes += chunk.length; check(bytes <= 1024 * 1024, 'HTTP_RESPONSE_TOO_LARGE'); chunks.push(chunk); }
  let body;
  try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')); }
  catch { throw Error('HTTP_JSON_RESPONSE_INVALID_' + response.status); }
  return { status: response.status, body };
}
export async function github(ctx, suffix) {
  const response = await fetch(`https://api.github.com/repos/${ctx.repository}${suffix}`, {
    headers: { Authorization: `Bearer ${process.env.GH_TOKEN}`, Accept: 'application/vnd.github+json', 'User-Agent': 'Konaet-remote-validation' }, signal: AbortSignal.timeout(20000) });
  check(response.ok, 'GITHUB_API_' + response.status); return response.json();
}
export async function artifact(ctx, name, outputName, timeoutMs = 300000) {
  const until = Date.now() + timeoutMs;
  while (Date.now() < until) {
    const data = await github(ctx, `/actions/runs/${ctx.runId}/artifacts?per_page=100`);
    const match = data.artifacts.find(row => row.name === name && !row.expired);
    if (match) {
      check(match.size_in_bytes <= 2 * 1024 * 1024, 'PUBLIC_ARTIFACT_TOO_LARGE');
      const response = await fetch(`https://api.github.com/repos/${ctx.repository}/actions/artifacts/${match.id}/zip`, {
        headers: { Authorization: `Bearer ${process.env.GH_TOKEN}`, 'User-Agent': 'Konaet-remote-validation' }, signal: AbortSignal.timeout(30000) });
      check(response.ok, 'ARTIFACT_DOWNLOAD_FAILED'); const bytes = Buffer.from(await response.arrayBuffer());
      check(bytes.length <= 2 * 1024 * 1024, 'PUBLIC_ARTIFACT_TOO_LARGE');
      if (match.digest) check(match.digest === 'sha256:' + sha256(bytes), 'PUBLIC_ARTIFACT_DIGEST_MISMATCH');
      // Only the exact expected member is read; no paths from the ZIP are extracted.
      const script = "import io,sys,zipfile\nz=zipfile.ZipFile(io.BytesIO(sys.stdin.buffer.read()))\nn=sys.argv[1]\ni=z.getinfo(n)\nassert len(z.infolist())==1 and i.file_size<=1048576 and not i.is_dir()\nsys.stdout.buffer.write(z.read(i))\n";
      const decoded = spawnSync('python3', ['-c', script, outputName], { input: bytes, maxBuffer: 1100000 });
      check(decoded.status === 0, 'PUBLIC_ARTIFACT_MEMBERS_INVALID'); return JSON.parse(decoded.stdout.toString('utf8'));
    }
    await pause(2000);
  }
  throw Error('PUBLIC_ARTIFACT_TIMEOUT_' + name);
}
export function keyAt(file) {
  if (!fs.existsSync(file)) fs.writeFileSync(file, crypto.randomBytes(32).toString('hex') + '\n', { flag: 'wx', mode: 0o600 });
  const seed = Buffer.from(fs.readFileSync(file, 'utf8').trim(), 'hex'); check(seed.length === 32, 'PRIVATE_SEED_INVALID');
  try { return vcrypto.IdentityKeypair.fromSeed(seed); } finally { seed.fill(0); }
}
export function childEnvironment() {
  return Object.fromEntries(Object.entries(process.env).filter(([name]) => !/TOKEN|SECRET|PASSWORD|CREDENTIAL/.test(name)));
}
