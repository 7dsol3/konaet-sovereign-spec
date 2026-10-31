import fs from 'node:fs';
import { execFileSync } from 'node:child_process';
import { check, pause, jsonRequest, writeJson } from './common.mjs';
check(process.env.GITHUB_ACTIONS === 'true' && process.platform === 'linux', 'ISOLATED_LINUX_CI_REQUIRED');
const unit = 'konaet-validator@0.service';
const ctl = (...args) => execFileSync('sudo', ['systemctl', ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
async function status() { const result = await jsonRequest('http://127.0.0.1:58601/status', {}, 3000); check(result.status === 200, 'STATUS_HTTP_FAILED'); return result.body; }
async function eventually(fn, name) { const until = Date.now() + 30000; while (Date.now() < until) { try { const result = await fn(); if (result) return result; } catch {} await pause(300); } throw Error(name); }
const before = await eventually(status, 'SERVICE_DID_NOT_START'), pidBefore = ctl('show', '--property=MainPID', '--value', unit);
check(ctl('is-active', unit) === 'active', 'SERVICE_NOT_ACTIVE');
const sandbox = Object.fromEntries(['NoNewPrivileges', 'PrivateTmp', 'ProtectSystem', 'ProtectHome', 'KillMode'].map(name => [name, ctl('show', '--property=' + name, '--value', unit)]));
check(sandbox.NoNewPrivileges === 'yes' && sandbox.ProtectSystem === 'strict' && sandbox.KillMode === 'control-group', 'SERVICE_SANDBOX_MISSING');
ctl('kill', '--signal=SIGKILL', '--kill-whom=main', unit);
await eventually(async () => { const pid = ctl('show', '--property=MainPID', '--value', unit); return pid !== '0' && pid !== pidBefore && ctl('is-active', unit) === 'active' && await status(); }, 'SUPERVISED_CRASH_RECOVERY_FAILED');
const recovered = await status(); check(recovered.root === before.root && recovered.sequence === before.sequence, 'SERVICE_RECOVERY_ROOT_CHANGED');
const pidAfter = ctl('show', '--property=MainPID', '--value', unit);
ctl('stop', unit); check(ctl('show', '--property=ActiveState', '--value', unit) === 'inactive', 'GRACEFUL_SERVICE_STOP_FAILED');
ctl('start', unit); const restarted = await eventually(status, 'SERVICE_RESTART_FAILED'); check(restarted.root === before.root, 'GRACEFUL_RESTART_ROOT_CHANGED');
ctl('stop', unit);
const summary = { schema: 'konaet.linux-service-validation.v1', passed: true, commit: process.env.GITHUB_SHA, runner: 'ubuntu-24.04-systemd',
  unit: 'deploy/validator/konaet-validator@.service', rootPreserved: true, processChangedAfterSigkill: pidBefore !== pidAfter,
  recoveredSequence: recovered.sequence, sandbox, independentNetworkValidated: false, at: new Date().toISOString() };
writeJson(process.env.RUNNER_TEMP + '/konaet-service-result.json', summary); console.log(JSON.stringify(summary, null, 2));
