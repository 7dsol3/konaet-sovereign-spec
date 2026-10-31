import assert from 'node:assert/strict';
import fs from 'node:fs';
import { createRequire } from 'node:module';
import { execFileSync } from 'node:child_process';
import test from 'node:test';
import crypto from 'node:crypto';
import { ROOT } from '../tools/files.mjs';
import * as browser from '../docs/program-auth.mjs';
import { verifySession } from '../tools/verify-program-session.mjs';
const require = createRequire(import.meta.url);
const node = require('../chain/ko-program/auth');
const runtime = require('../chain/ko-program/runtime');
const { encodeAddress } = require('../chain/vlock7sin-js/src/crypto');
const source = fs.readFileSync(new URL('../chain/ko-program/examples/Counter.ko', import.meta.url), 'utf8');
const artifact = runtime.compileContract(source), options = { networkId: '77', salt: '0', gasLimit: 10000 };
test('browser interpreter and Node compiler produce identical artifacts and SHA-256 commitments', () => {
  execFileSync(process.execPath, ['tools/build-program-browser.mjs', '--check'], { cwd: ROOT });
  assert.deepEqual(browser.compileContract(source), artifact);
  for (const file of ['Counter', 'RegistryToken']) {
    const source = fs.readFileSync(new URL('../chain/ko-program/examples/' + file + '.ko', import.meta.url), 'utf8');
    assert.deepEqual(browser.compileContract(source), runtime.compileContract(source));
  }
});
test('WebCrypto calls verify and replay in Node with identical addresses, receipts and state', async () => {
  const identity = await browser.generateIdentity();
  assert.equal(identity.privateKey.extractable, false);
  assert.equal(identity.address, encodeAddress(Buffer.from(identity.publicKey, 'hex')));
  const deployment = await browser.signDeployment(artifact, options, identity);
  const receipt = await browser.deploySignedContract(artifact, deployment);
  assert.deepEqual(receipt, node.deploySignedContract(artifact, deployment));
  const packet = await browser.signCall(artifact, receipt.state, { method: 'increment', args: ['7'], gasLimit: 10000 }, identity);
  const result = await browser.callSignedContract(artifact, receipt.state, packet);
  assert.deepEqual(result, node.callSignedContract(artifact, receipt.state, packet));
  assert.equal(result.result, '14');
  const session = { schema: 'konaet.ko-studio-session.v1', execution: 'browser-session', artifact,
    deployment, calls: [{ envelope: packet, receipt: result }], state: result.state };
  assert.equal(verifySession(session).stateRoot, result.state.stateRoot);
  const corrupted = structuredClone(session); corrupted.calls[0].receipt.result = '99';
  assert.throws(() => verifySession(corrupted), /SESSION_RECEIPT_MISMATCH/);
  await assert.rejects(() => browser.callSignedContract(artifact, result.state, packet), { code: 'KO_STALE_STATE' });
  const forged = structuredClone(packet); forged.payload.args[0] = '8';
  await assert.rejects(() => browser.callSignedContract(artifact, receipt.state, forged), { code: 'KO_SIGNATURE_INVALID' });
});
test('Node signed calls verify in WebCrypto without key conversion or a server', async () => {
  const key = crypto.generateKeyPairSync('ed25519').privateKey;
  const deployment = node.signDeployment(artifact, options, key), state = node.deploySignedContract(artifact, deployment).state;
  assert.deepEqual(await browser.deploySignedContract(artifact, deployment), node.deploySignedContract(artifact, deployment));
  const packet = node.signCall(artifact, state, { method: 'increment', args: ['3'], gasLimit: 10000 }, key);
  assert.deepEqual(await browser.callSignedContract(artifact, state, packet), node.callSignedContract(artifact, state, packet));
});
