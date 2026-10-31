import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';
import { startDemo } from './demo-network.mjs';
const require = createRequire(import.meta.url);
const { compileKoPolicy, executeKoPolicy } = require('../chain/vlock7sin-js/src/koPolicy');
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export async function startConsole({ dataDirectory = path.join(root, '.konaet-console-v7'), port = 0 } = {}) {
  const demo = await startDemo({ directory: dataDirectory, programs: true });
  const token = crypto.randomBytes(32).toString('hex');
  let origin;
  const source = fs.readFileSync(path.join(root, 'chain/contracts-ko/SindraRuntime.ko'), 'utf8');
  const server = http.createServer(async (req, res) => {
    res.setHeader('Cache-Control', 'no-store'); res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'");
    function json(status, body) { res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' }); res.end(JSON.stringify(body)); }
    if (req.headers.host !== new URL(origin).host) { req.resume(); json(403, { code: 'LOCAL_HOST_REQUIRED' }); return; }
    try {
      const assets = { '/': ['index.html', 'text/html; charset=utf-8'], '/app.js': ['app.js', 'application/javascript; charset=utf-8'],
        '/style.css': ['style.css', 'text/css; charset=utf-8'], '/favicon.svg': ['favicon.svg', 'image/svg+xml'] };
      if (req.method === 'GET' && assets[req.url]) {
        const [name, type] = assets[req.url];
        let bytes = fs.readFileSync(path.join(root, 'console', name));
        if (name === 'index.html') bytes = Buffer.from(bytes.toString('utf8').replace('__CSRF_TOKEN__', token));
        res.writeHead(200, { 'Content-Type': type }); res.end(bytes); return;
      }
      if (req.method === 'GET' && req.url === '/api/network') { json(200, await demo.status()); return; }
      if (req.method === 'GET' && req.url === '/api/program') {
        json(200, { examples: Object.fromEntries(['Counter', 'RegistryToken'].map(name => [name, fs.readFileSync(path.join(root, 'chain/ko-program/examples', name + '.ko'), 'utf8')])) }); return;
      }
      if (req.method === 'GET' && /^\/api\/contracts\/[0-9a-f]{64}$/.test(req.url)) {
        const record = await demo.contract(req.url.slice('/api/contracts/'.length)); json(record ? 200 : 404, record ?? { code: 'CONTRACT_NOT_FOUND' }); return;
      }
      if (req.method === 'GET' && req.url === '/api/runtime') {
        const policy = compileKoPolicy(source);
        json(200, { available: true, profile: policy.profile, rules: policy.program.rules.length, source, programSha256: policy.programSha256 }); return;
      }
      if (req.method !== 'POST' || !['/api/transfer', '/api/ko', '/api/contracts/deploy', '/api/contracts/call', '/api/shutdown'].includes(req.url)) { req.resume(); json(404, { code: 'NOT_FOUND' }); return; }
      if ((req.headers.origin && req.headers.origin !== origin) || req.headers['x-konaet-token'] !== token) {
        req.resume(); json(403, { code: 'LOCAL_SESSION_REQUIRED' }); return;
      }
      if (req.headers['content-type'] !== 'application/json') { req.resume(); json(415, { code: 'JSON_REQUIRED' }); return; }
      const chunks = []; let size = 0;
      for await (const chunk of req) { size += chunk.length; if (size > 65536) { json(413, { code: 'BODY_TOO_LARGE' }); req.resume(); return; } chunks.push(chunk); }
      const body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      if (req.url === '/api/shutdown') { json(200, { closed: true }); setTimeout(() => { void close(); }, 30); return; }
      if (req.url === '/api/transfer') {
        if (!body || Object.keys(body).sort().join(',') !== 'amount,from') throw Error('INVALID_TRANSFER');
        json(200, { accepted: true, receipt: await demo.transfer(body) }); return;
      }
      if (req.url === '/api/contracts/deploy' || req.url === '/api/contracts/call') {
        const deployment = req.url === '/api/contracts/deploy';
        if (!body || typeof body !== 'object' || Array.isArray(body) || Object.keys(body).sort().join(',') !==
          (deployment ? 'from,gasLimit,salt,source' : 'args,contractId,from,gasLimit,method')) throw Error('INVALID_CONTRACT_REQUEST');
        json(200, { accepted: true, finalized: true, receipt: await demo.contractTransition({ ...body, operation: deployment ? 'deploy' : 'call' }) }); return;
      }
      if (!body || Object.keys(body).sort().join(',') !== 'context,phase,source') throw Error('INVALID_POLICY_REQUEST');
      const policy = compileKoPolicy(body.source); executeKoPolicy(policy, body.phase, body.context);
      json(200, { accepted: true, programSha256: policy.programSha256,
        rulesExecuted: policy.program.rules.filter(rule => rule.phase === body.phase).length });
    } catch (error) { if (!res.writableEnded) json(422, { accepted: false, code: error.code || error.message }); }
  });
  let closing = false;
  async function close() { if (closing) return; closing = true; await new Promise(resolve => server.close(resolve)); await demo.close(); }
  try {
    await new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, '127.0.0.1', resolve); });
    origin = `http://127.0.0.1:${server.address().port}`;
    return { url: origin, close, demo };
  } catch (error) { await demo.close(); throw error; }
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const app = await startConsole();
    console.log(`\nKONAET CONSOLE 1.6.0\n\nConsole: ${app.url}\nQuatro processos validadores v7. Dados de teste em .konaet-console-v7\nFeche pelo console ou pressione Ctrl+C para encerrar.\n`);
    const stop = () => { void app.close().then(() => process.exit(0)); };
    process.on('SIGINT', stop); process.on('SIGTERM', stop);
    if (!process.argv.includes('--no-browser')) {
      const command = process.platform === 'win32' ? 'powershell.exe' : process.platform === 'darwin' ? 'open' : 'xdg-open';
      const args = process.platform === 'win32' ? ['-NoProfile', '-Command', `Start-Process -FilePath '${app.url}'`] : [app.url];
      const child = spawn(command, args, { windowsHide: true, stdio: 'ignore' });
      child.on('error', () => console.log(`Abra ${app.url} no navegador.`));
    }
  } catch (error) { console.error(`Konaet: ${error.message}\nSe houver outro console aberto, encerre-o antes de iniciar novamente.`); process.exitCode = 1; }
}
