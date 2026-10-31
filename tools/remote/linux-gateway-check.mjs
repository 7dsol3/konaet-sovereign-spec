import fs from 'node:fs';
import path from 'node:path';
import https from 'node:https';
import { check, writeJson } from './common.mjs';
check(process.env.GITHUB_ACTIONS === 'true' && process.platform === 'linux', 'ISOLATED_LINUX_CI_REQUIRED');
const directory = path.join(process.env.RUNNER_TEMP, 'konaet-nginx');
const ca = fs.readFileSync(path.join(directory, 'server.pem'));
const password = fs.readFileSync(path.join(directory, 'client-password'), 'utf8');
function request(route, { method = 'GET', authorized = false } = {}) {
  return new Promise((resolve, reject) => {
    const req = https.request({ hostname: '127.0.0.1', port: 58843, servername: 'rpc.validation.example', ca, path: route, method,
      headers: { Host: 'rpc.validation.example', ...(authorized ? { Authorization: 'Basic ' + Buffer.from('validation:' + password).toString('base64') } : {}) } }, res => {
      const chunks = []; res.on('data', bytes => chunks.push(bytes)); res.on('end', () => resolve({ status: res.statusCode,
        headers: res.headers, body: Buffer.concat(chunks).toString('utf8'), tlsAuthorized: req.socket.authorized }));
    });
    req.setTimeout(5000, () => req.destroy(Error('HTTPS_TIMEOUT'))); req.on('error', reject); req.end();
  });
}
const status = await request('/api/status'); check(status.status === 200 && status.tlsAuthorized === true, 'VERIFIED_TLS_GATEWAY_UNAVAILABLE');
const data = JSON.parse(status.body); check(data.schema === 'konaet.gateway-status.v1' && !status.body.includes('voteJournal')
  && !status.body.includes('network-nonce') && !status.body.includes('submit.token'), 'INTERNAL_STATUS_EXPOSED');
const readiness = await request('/health/ready'); check(readiness.status === 503 && JSON.parse(readiness.body).reason === 'QUORUM_UNAVAILABLE', 'READINESS_SHOULD_REPORT_NO_QUORUM');
check((await request('/api/transactions', { method: 'POST' })).status === 401, 'HTTPS_SUBMISSION_AUTH_NOT_ENFORCED');
check((await request('/api/transactions', { method: 'POST', authorized: true })).status === 403, 'READ_ONLY_GATEWAY_WAS_BYPASSED');
check((await request('/submit', { method: 'POST', authorized: true })).status === 404, 'RAW_OPERATOR_ROUTE_WAS_EXPOSED');
check(status.headers['x-content-type-options'] === 'nosniff', 'PROXY_SECURITY_HEADER_MISSING');
const result = { schema: 'konaet.linux-gateway-validation.v1', passed: true, commit: process.env.GITHUB_SHA,
  verifiedTls: true, basicAuthRequired: true, readOnlyEnforced: true, rawOperatorRouteBlocked: true,
  readinessReportsNoQuorum: true, statusSanitized: true, networkExposure: 'isolated-ci-loopback-only', at: new Date().toISOString() };
writeJson(path.join(process.env.RUNNER_TEMP, 'konaet-gateway-result.json'), result); console.log(JSON.stringify(result, null, 2));
