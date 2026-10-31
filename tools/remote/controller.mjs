import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { context, keyAt, check, readJson, writeJson, verified, signed, REPORT_DOMAIN, CONTROL_DOMAIN, NETWORK_DOMAIN,
  canonicalBytes, endpoint, pause, jsonRequest, require } from './common.mjs';
const { UNIT, createTransfer, decodeEvent, VlockLedger, PermissionedQuorum } = require('../../chain/vlock7sin-js/src');
const { decodeRecord } = require('../../chain/vlock7sin-js/src/persistence');
const { stateFromGenesis, RoundChangeQuorum } = require('../../chain/network/sovereign');
const { ContractEvent } = require('../../chain/vlock7sin-js/src/contractEvent');
const { runtime, auth } = require('../../chain/vlock7sin-js/src/koProgramRuntime');
const { verifyContractReceipt } = require('../verify-contract-receipt.cjs');
const fields = ['networkId', 'protocolVersion', 'sequence', 'constellationId', 'previousRoot', 'nextRoot', 'transitionTrace', 'pcc'];
export async function runController(ctx) {
  const control = keyAt(path.join(ctx.privateDir, 'control.seed'));
  const networkPacket = readJson(path.join(ctx.publicDir, 'network.json'));
  const network = verified(NETWORK_DOMAIN, networkPacket, control.publicBytes().toString('hex'));
  const alice = keyAt(path.join(ctx.privateDir, 'alice.seed')), bob = keyAt(path.join(ctx.privateDir, 'bob.seed'));
  const genesis = network.genesis, quorum = new PermissionedQuorum({ networkId: genesis.networkId,
    protocolVersion: genesis.protocolVersion, threshold: genesis.threshold, validators: genesis.validators });
  const roundChanges = new RoundChangeQuorum({ networkId: genesis.networkId, protocolVersion: genesis.protocolVersion,
    genesisId: genesis.genesisId, threshold: genesis.threshold, validators: genesis.validators });
  const mirror = new VlockLedger({ state: stateFromGenesis(genesis), protocolVersion: genesis.protocolVersion,
    nativePolicy: genesis.nativePolicy, quorum, requireCertificate: true, maxActs: genesis.parameters.maxActs, maxBytes: genesis.parameters.maxBytes });
  let controlSeq = 0, offset = 8, latestBundle, transfers = 0, calls = 0, startedAt, stoppedAt, crashRestarted = false, lastSubmissionAt = 0;
  const durations = [], faults = []; let lastStates = [], crashed = false;
  const active = new Set([0, 1, 2, 3]);
  async function status(index) {
    const response = await jsonRequest(endpoint(network.nodes[index].body.endpoint) + '/status', {}, 8000);
    check(response.status === 200, 'REMOTE_STATUS_HTTP_' + response.status);
    const state = verified(REPORT_DOMAIN, response.body, genesis.validators[index].publicKey);
    check(state.runId === ctx.key && state.commit === ctx.commit && state.index === index
      && state.hostHash === network.nodes[index].body.hostHash && Math.abs(Date.now() - state.observedAt) <= 30000, 'REMOTE_STATUS_CONTEXT_INVALID');
    check(state.unexpectedExits === 0, 'UNEXPECTED_VALIDATOR_EXIT_' + index);
    return state;
  }
  async function command(index, action, payload = {}) {
    const body = { schema: 'konaet.remote-control.v1', runId: ctx.key, seq: ++controlSeq, issuedAt: Date.now(), action, payload };
    const response = await jsonRequest(endpoint(network.nodes[index].body.endpoint) + '/control', {
      method: 'POST', body: JSON.stringify(signed(CONTROL_DOMAIN, body, control.privateKeyObject())) }, 25000);
    check(response.status === 200 && response.body.accepted === true, 'REMOTE_CONTROL_FAILED_' + action + '_' + index);
  }
  async function until(fn, label, max = 120000) {
    const deadline = Date.now() + max; let last = 'pending';
    while (Date.now() < deadline) { try { if (await fn()) return; } catch (error) { last = error.message; } await pause(700); }
    throw Error(label + ':' + last);
  }
  async function synchronized(sequence, participants = [...active]) {
    await until(async () => {
      lastStates = await Promise.all(participants.map(status));
      return lastStates.every(state => state.online && state.genesisId === genesis.genesisId && BigInt(state.sequence) >= sequence)
        && new Set(lastStates.map(state => state.root)).size === 1;
    }, 'REMOTE_CONVERGENCE_TIMEOUT');
  }
  function replay() {
    const file = path.join(ctx.privateDir, 'operator/data/ledger.v7wal'), fd = fs.openSync(file, 'r');
    try {
      const size = fs.fstatSync(fd).size;
      const magic = Buffer.alloc(8); check(fs.readSync(fd, magic, 0, 8, 0) === 8 && magic.equals(Buffer.from('V7WAL1\r\n')), 'WAL_HEADER_INVALID');
      while (offset < size) {
        const header = Buffer.alloc(36); check(fs.readSync(fd, header, 0, 36, offset) === 36, 'WAL_HEADER_INCOMPLETE');
        const length = header.readUInt32BE(0); check(length <= 8 * 1024 * 1024 && offset + 36 + length <= size, 'WAL_FRAME_LIMIT');
        const bytes = Buffer.alloc(length); check(fs.readSync(fd, bytes, 0, length, offset + 36) === length, 'WAL_FRAME_INCOMPLETE');
        const hash = crypto.createHash('sha3-256').update(Buffer.from('VLOCK7SIN/WAL-FRAME/v1\0')).update(header.subarray(0, 4)).update(bytes).digest();
        check(hash.equals(header.subarray(4)), 'WAL_FRAME_CHECKSUM');
        const record = decodeRecord(bytes), beforeState = mirror.getState().snapshot();
        check(record.kind === 'VLOCK7SIN_CLOSURE_COMMIT', 'WAL_RECORD_KIND');
        mirror.submitActs(record.events.map(decodeEvent), { hybridTransferAuthorizations: record.hybridTransferAuthorizations ?? [] });
        const proposal = mirror.prepareConstellation();
        const expected = Object.fromEntries(fields.map(key => [key, proposal[key]]));
        check(canonicalBytes(expected).equals(canonicalBytes(Object.fromEntries(fields.map(key => [key, record[key]])))), 'REMOTE_TRANSITION_RECOMPUTE_FAILED');
        const round = Number(record.round ?? 0);
        if (round > 0) roundChanges.verifyCertificate(record.roundChangeCertificate, { networkId: proposal.networkId,
          protocolVersion: proposal.protocolVersion, sequence: proposal.sequence, previousRoot: proposal.previousRoot, proposalHash: quorum.statementHash(proposal) }, round);
        mirror.commitPrepared(proposal, { certificate: record.certificate, round, roundChangeCertificate: record.roundChangeCertificate ?? null });
        latestBundle = { schema: 'konaet.ko-consensus-receipt.v1', genesis, beforeState, events: record.events.map(value => Buffer.from(value).toString('base64')),
          proposal: expected, certificate: record.certificate, afterState: mirror.getState().snapshot() };
        verifyContractReceipt(latestBundle, { expectedGenesisId: genesis.genesisId, expectedPreviousRoot: proposal.previousRoot });
        offset += 36 + length;
      }
    } finally { fs.closeSync(fd); }
    check(lastStates.every(state => state.root === mirror.root), 'CLIENT_MIRROR_ROOT_MISMATCH');
    check(mirror.getState().entries().reduce((sum, row) => sum + row.balance, 0n) === UNIT.initialSupplyAtomic, 'SUPPLY_CHANGED');
  }
  function eventFor(envelope, source, signer) {
    const state = mirror.getState();
    return new ContractEvent({ source, envelope, sequence: String(state.sequence + 1n), nonce: String(state.getNonce(signer.address()) + 1n),
      previousRoot: mirror.root, signature: '' }).sign(signer);
  }
  function transfer() {
    const sender = transfers % 2 ? bob : alice, receiver = transfers % 2 ? alice : bob, state = mirror.getState();
    return createTransfer({ networkId: Number(genesis.networkId), sequence: state.sequence + 1n,
      nonce: state.getNonce(sender.address()) + 1n, timestampMs: BigInt(Date.now()), previousRoot: Buffer.from(mirror.root, 'hex'),
      amountAtomic: 1n, senderPublicKey: sender.publicBytes(), receiverAddress: receiver.address(), memo: '' }, sender);
  }
  async function submit(event, wait = true) {
    // Exercise the production runner's 10/minute admission limit unchanged.
    const remaining = lastSubmissionAt + 6500 - Date.now(); if (remaining > 0) await pause(remaining);
    lastSubmissionAt = Date.now();
    const start = performance.now(), token = fs.readFileSync(path.join(ctx.privateDir, 'operator/submit.token'), 'utf8').trim();
    const response = await jsonRequest('http://127.0.0.1:58401/submit', { method: 'POST', headers: { 'Content-Type': 'application/octet-stream', Authorization: 'Bearer ' + token }, body: event.canonicalBytes() });
    check(response.status === 202 && response.body.accepted === true && response.body.finalized === false, 'NATIVE_SUBMISSION_REJECTED');
    if (wait) { await synchronized(mirror.sequence + 1n); replay(); durations.push(performance.now() - start); }
  }
  try {
    await synchronized(0n);
    const source = fs.readFileSync(new URL('../../chain/ko-program/examples/Counter.ko', import.meta.url), 'utf8'), artifact = runtime.compileContract(source);
    const deployment = eventFor(auth.signDeployment(artifact, { networkId: genesis.networkId, salt: '0', gasLimit: 10000 }, alice.privateKeyObject()), source, alice);
    await submit(deployment);
    startedAt = Date.now(); let lossTested = false, crashedAt = 0, nextProgress = startedAt + 60000;
    while (Date.now() - startedAt < ctx.seconds * 1000) {
      const elapsed = Date.now() - startedAt;
      if (!lossTested && elapsed >= ctx.seconds * 1000 / 3) {
        await command(2, 'stop'); await command(3, 'stop'); active.delete(2); active.delete(3);
        await until(async () => (await status(0)).peers.length <= 1, 'QUORUM_LOSS_NOT_OBSERVED');
        const sequence = mirror.sequence; await submit(transfer(), false); await pause(12000);
        const state = await status(0); check(BigInt(state.sequence) === sequence, 'FINALIZED_WITHOUT_QUORUM');
        await command(2, 'start'); await command(3, 'start'); active.add(2); active.add(3);
        await synchronized(sequence + 1n); replay(); transfers++;
        faults.push({ kind: 'quorum-loss-and-pending-recovery', passed: true, sequenceBefore: String(sequence), sequenceAfter: String(mirror.sequence) }); lossTested = true;
      }
      if (!crashed && elapsed >= ctx.seconds * 2000 / 3) {
        await command(3, 'kill'); active.delete(3); crashed = true; crashedAt = Date.now();
        faults.push({ kind: 'validator-3-sigkill', at: crashedAt });
      }
      if (crashed && !crashRestarted && Date.now() - crashedAt > 20000) {
        await command(3, 'start'); active.add(3); await synchronized(mirror.sequence); crashRestarted = true;
        faults.push({ kind: 'validator-3-restored-and-synchronized', passed: true, sequence: String(mirror.sequence) });
      }
      await submit(transfer()); transfers++;
      if (transfers % 3 === 0) {
        const record = mirror.getState().contract(deployment.contractId);
        const call = eventFor(auth.signCall(record.artifact, record.state, { method: 'increment', args: ['1'], gasLimit: 10000 }, alice.privateKeyObject()), null, alice);
        await submit(call); calls++;
      }
      if (Date.now() >= nextProgress) {
        console.log(JSON.stringify({ phase: 'remote-running', elapsedSeconds: Math.round((Date.now() - startedAt) / 1000), transfers, calls, sequence: String(mirror.sequence), active: [...active] }));
        nextProgress += 60000;
      }
    }
    check(lossTested && crashRestarted, 'FAULT_EXERCISES_INCOMPLETE'); await synchronized(mirror.sequence); replay();
    check(mirror.getState().contract(deployment.contractId).state.storage.total === String(calls * 2), 'CONTRACT_TOTAL_MISMATCH');
    stoppedAt = Date.now();
    const sorted = [...durations].sort((a, b) => a - b), percentile = percent => sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * percent))];
    const body = { schema: 'konaet.remote-controller-result.v1', runId: ctx.key, commit: ctx.commit, passed: true,
      requestedSeconds: ctx.seconds, startedAt, stoppedAt, elapsedMs: stoppedAt - startedAt,
      infrastructure: 'four-github-hosted-vms-via-temporary-ciphertext-relays', independentAdministrators: false,
      network: networkPacket, transferCount: transfers, contractCallCount: calls, finalSequence: String(mirror.sequence), finalRoot: mirror.root,
      supplyPreserved: true, finalContractValue: String(calls * 2), faults, finalStates: lastStates, lastReceipt: latestBundle,
      timing: { definition: 'submission-through-all-active-node-root-convergence-plus-controller-polling', samples: sorted.length,
        p50Ms: percentile(0.5), p95Ms: percentile(0.95), p99Ms: percentile(0.99) } };
    await Promise.all([0, 1, 2, 3].map(index => command(index, 'finish', { root: mirror.root, sequence: String(mirror.sequence) })));
    writeJson(path.join(ctx.publicDir, 'controller.json'), signed(REPORT_DOMAIN, body, control.privateKeyObject()));
    console.log(JSON.stringify({ phase: 'remote-complete', elapsedMs: body.elapsedMs, transfers, calls, sequence: body.finalSequence, root: body.finalRoot }));
  } catch (error) {
    writeJson(path.join(ctx.publicDir, 'controller.json'), signed(REPORT_DOMAIN, { schema: 'konaet.remote-controller-result.v1', passed: false,
      runId: ctx.key, commit: ctx.commit, network: networkPacket, error: error.message, startedAt: startedAt ?? null, stoppedAt: Date.now(), transfers, calls, faults }, control.privateKeyObject()));
    await Promise.allSettled([0, 1, 2, 3].map(index => command(index, 'abort'))); throw error;
  }
}
