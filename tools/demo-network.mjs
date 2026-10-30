import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fork } from 'node:child_process';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
const require = createRequire(import.meta.url);
const { crypto: vcrypto, UNIT, createTransfer, decodeEvent } = require('../chain/vlock7sin-js/src');
const { compileKoPolicy } = require('../chain/vlock7sin-js/src/koPolicy');
const { createGenesis, validateGenesis } = require('../chain/network/sovereign');
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export function atomic(text) {
  if (typeof text !== 'string' || !/^(?:0|[1-9][0-9]{0,17})(?:\.[0-9]{1,9})?$/.test(text)) throw Error('INVALID_AMOUNT');
  const [whole, decimal = ''] = text.split('.');
  const amount = BigInt(whole) * 1000000000n + BigInt(decimal.padEnd(9, '0'));
  if (amount <= 0n || amount > UNIT.initialSupplyAtomic) throw Error('INVALID_AMOUNT');
  return amount;
}
function seedIdentity(file) {
  const seed = Buffer.from(fs.readFileSync(file, 'utf8').trim(), 'hex');
  try { return vcrypto.IdentityKeypair.fromSeed(seed); } finally { seed.fill(0); }
}
export async function startDemo({ directory = path.join(root, '.konaet-demo') } = {}) {
  const dir = path.resolve(directory);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const lock = path.join(dir, 'console.lock');
  try { fs.writeFileSync(lock, String(process.pid), { flag: 'wx', mode: 0o600 }); }
  catch (error) {
    if (error.code !== 'EEXIST') throw error;
    const pid = Number(fs.readFileSync(lock, 'utf8'));
    if (!Number.isSafeInteger(pid) || pid <= 0) throw Error('INVALID_DEMO_LOCK');
    try { process.kill(pid, 0); throw Error('DEMO_ALREADY_RUNNING'); }
    catch (alive) { if (alive.code !== 'ESRCH') throw alive; }
    fs.writeFileSync(lock, String(process.pid), { mode: 0o600 });
  }
  const workers = [];
  let closed = false;
  let sending = false;
  let nextId = 1;
  async function close() {
    if (closed) return; closed = true;
    await Promise.all(workers.map(worker => new Promise(resolve => {
      if (worker.child.exitCode !== null) { resolve(); return; }
      const timeout = setTimeout(() => { worker.child.kill(); resolve(); }, 4000);
      worker.child.once('exit', () => { clearTimeout(timeout); resolve(); });
      if (worker.child.connected) worker.child.send({ id: nextId++, command: 'close' });
      else worker.child.kill();
    })));
    try { if (fs.readFileSync(lock, 'utf8') === String(process.pid)) fs.unlinkSync(lock); } catch {}
  }
  try {
    const genesisFile = path.join(dir, 'genesis.json');
    if (!fs.existsSync(genesisFile)) {
      if (fs.readdirSync(dir).some(name => name !== 'console.lock')) throw Error('INCOMPLETE_DEMO_DIRECTORY');
      const identities = [];
      for (const name of ['validator-0', 'validator-1', 'validator-2', 'validator-3', 'alice', 'bob']) {
        const seed = crypto.randomBytes(32);
        try { fs.writeFileSync(path.join(dir, `${name}.seed`), seed.toString('hex'), { flag: 'wx', mode: 0o600 });
          identities.push(vcrypto.IdentityKeypair.fromSeed(seed)); } finally { seed.fill(0); }
      }
      const nativePolicy = compileKoPolicy(fs.readFileSync(path.join(root, 'chain/contracts-ko/SindraRuntime.ko'), 'utf8'));
      const genesis = createGenesis({ networkId: crypto.randomInt(1000000, 0x7fffffff), createdAt: new Date().toISOString(),
        validators: identities.slice(0, 4).map((key, index) => ({ id: `validator-${index}`, publicKey: key.publicBytes() })),
        threshold: 3, allocations: [{ address: identities[4].address(), amountAtomic: UNIT.initialSupplyAtomic }],
        parameters: { maxActs: 64, maxBytes: 262144, stateSyncChunk: 4, messageRateLimit: 512 }, nativePolicy });
      fs.writeFileSync(genesisFile, JSON.stringify(genesis, null, 2) + '\n', { flag: 'wx' });
    }
    const genesis = validateGenesis(JSON.parse(fs.readFileSync(genesisFile, 'utf8')));
    const accounts = ['alice', 'bob'].map(name => ({ name, identity: seedIdentity(path.join(dir, `${name}.seed`)) }));
    const addresses = accounts.map(account => account.identity.address());
    for (let index = 0; index < 4; index++) {
      const child = fork(path.join(root, 'tools/validator-worker.cjs'), [dir, String(index)], { windowsHide: true,
        stdio: ['ignore', 'ignore', 'pipe', 'ipc'], execArgv: [] });
      const pending = new Map();
      child.stderr.on('data', () => {});
      child.on('message', message => { const item = pending.get(message.id); if (!item) return;
        pending.delete(message.id); clearTimeout(item.timer); message.error ? item.reject(Error(message.error)) : item.resolve(message.result); });
      child.on('error', error => { for (const item of pending.values()) { clearTimeout(item.timer); item.reject(error); } pending.clear(); });
      child.on('exit', () => { for (const item of pending.values()) { clearTimeout(item.timer); item.reject(Error('VALIDATOR_EXITED')); } pending.clear(); });
      const worker = { child, port: 0, request(command, body = {}) { return new Promise((resolve, reject) => {
        if (!child.connected) { reject(Error('VALIDATOR_OFFLINE')); return; }
        const id = nextId++; const timer = setTimeout(() => { pending.delete(id); reject(Error('VALIDATOR_TIMEOUT')); }, 20000);
        pending.set(id, { resolve, reject, timer }); child.send({ id, command, ...body }, error => {
          if (error) { clearTimeout(timer); pending.delete(id); reject(error); }
        });
      }); } };
      workers.push(worker);
      worker.port = (await worker.request('start')).port;
    }
    for (let left = 0; left < 4; left++) for (let right = left + 1; right < 4; right++)
      await workers[left].request('connect', { url: `ws://127.0.0.1:${workers[right].port}`, validatorId: `validator-${right}` });
    const historyFile = path.join(dir, 'transfers.jsonl');
    async function status() {
      const validators = await Promise.all(workers.map(worker => worker.request('status', { addresses })));
      const history = fs.existsSync(historyFile) ? fs.readFileSync(historyFile, 'utf8').trim().split('\n').filter(Boolean).slice(-100).map(line => JSON.parse(line)) : [];
      return { scope: 'local-demo-no-value', monetaryValue: false, independentAdministrators: false, processCount: 4,
        genesisId: genesis.genesisId, networkId: genesis.networkId, threshold: genesis.threshold,
        converged: new Set(validators.map(item => item.root)).size === 1,
        sequence: validators[0].sequence, root: validators[0].root, nativePolicy: validators[0].nativePolicy,
        accounts: validators[0].accounts.map((account, index) => ({ ...account, name: accounts[index].name })),
        validators: validators.map(item => ({ validatorId: item.validatorId, pid: item.pid, sequence: item.sequence,
          root: item.root, peers: item.peers.length, policyEnforced: item.nativePolicy?.enforced === true })), history };
    }
    async function transfer({ from = 'alice', amount } = {}) {
      if (closed) throw Error('DEMO_CLOSED');
      if (sending) throw Error('TRANSFER_IN_PROGRESS');
      sending = true;
      try {
        const senderIndex = accounts.findIndex(account => account.name === from);
        if (senderIndex < 0) throw Error('INVALID_ACCOUNT');
        const amountAtomic = atomic(amount);
        const current = await status();
        if (!current.converged) throw Error('VALIDATORS_SYNCING');
        const sender = accounts[senderIndex].identity, receiver = accounts[1 - senderIndex].identity;
        const bytes = createTransfer({ networkId: Number(genesis.networkId), sequence: BigInt(current.sequence) + 1n,
          nonce: BigInt(current.accounts[senderIndex].nonce) + 1n, timestampMs: BigInt(Date.now()),
          previousRoot: Buffer.from(current.root, 'hex'), amountAtomic, senderPublicKey: sender.publicBytes(),
          receiverAddress: receiver.address() }, sender).canonicalBytes();
        const transactionId = decodeEvent(bytes).id().toString('hex');
        const started = Date.now();
        await workers[0].request('submit', { base64: bytes.toString('base64') });
        await Promise.all(workers.map(worker => worker.request('wait', { sequence: (BigInt(current.sequence) + 1n).toString() })));
        const finalized = await status();
        if (!finalized.converged) throw Error('FINALITY_ROOT_MISMATCH');
        const receipt = { transactionId, from, to: accounts[1 - senderIndex].name, amountAtomic: amountAtomic.toString(),
          sequence: finalized.sequence, root: finalized.root, signaturesVerifiedByValidators: true,
          validatorProcesses: 4, elapsedMs: Date.now() - started, finalizedAt: new Date().toISOString() };
        fs.appendFileSync(historyFile, JSON.stringify(receipt) + '\n', { mode: 0o600 });
        return receipt;
      } finally { sending = false; }
    }
    return { status, transfer, close, directory: dir };
  } catch (error) { await close(); throw error; }
}
