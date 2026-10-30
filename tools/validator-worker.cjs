'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { crypto: vcrypto } = require('../chain/vlock7sin-js/src');
const { SovereignNode } = require('../chain/network/sovereign');
let node;
let stopping = false;
async function close() { if (stopping) return; stopping = true; if (node) await node.close(); process.exit(0); }
process.on('disconnect', () => { void close(); });
process.on('SIGTERM', () => { void close(); });
process.on('SIGINT', () => { void close(); });
process.on('message', async message => {
  if (!message || typeof message.id !== 'number') return;
  try {
    let result;
    if (message.command === 'start') {
      if (node) throw Error('ALREADY_STARTED');
      const directory = path.resolve(process.argv[2]);
      const index = Number(process.argv[3]);
      if (!Number.isInteger(index) || index < 0 || index > 3) throw Error('INVALID_VALIDATOR');
      const seed = Buffer.from(fs.readFileSync(path.join(directory, `validator-${index}.seed`), 'utf8').trim(), 'hex');
      let identity;
      try { identity = vcrypto.IdentityKeypair.fromSeed(seed); } finally { seed.fill(0); }
      node = new SovereignNode({ genesis: JSON.parse(fs.readFileSync(path.join(directory, 'genesis.json'), 'utf8')),
        validatorId: `validator-${index}`, identity, dataDir: path.join(directory, `wal-${index}`),
        automaticConsensus: true, proposalDelayMs: 80, roundTimeoutMs: 1200 });
      node.on('protocolError', () => {});
      const started = await node.start({ host: '127.0.0.1', port: 0 });
      result = { port: started.address.port, pid: process.pid };
    } else if (!node) throw Error('NOT_STARTED');
    else if (message.command === 'connect') result = await node.connect(message.url, message.validatorId).then(() => true);
    else if (message.command === 'status') {
      const state = node.ledger.getState();
      result = { ...node.status(), pid: process.pid, accounts: message.addresses.map(address => ({ address,
        balanceAtomic: state.getBalance(address).toString(), nonce: state.getNonce(address).toString() })) };
    } else if (message.command === 'submit') result = node.submitTransfer(Buffer.from(message.base64, 'base64'));
    else if (message.command === 'wait') result = await node.waitForSequence(BigInt(message.sequence), 15000).then(() => true);
    else if (message.command === 'close') { await close(); return; }
    else throw Error('UNKNOWN_COMMAND');
    if (process.connected) process.send({ id: message.id, result });
  } catch (error) { if (process.connected) process.send({ id: message.id, error: error.code || error.message }); }
});
