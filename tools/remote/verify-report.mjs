import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { check, verified, NETWORK_DOMAIN, REPORT_DOMAIN, writeJson, require } from './common.mjs';
const { validateGenesis } = require('../../chain/network/sovereign');
const { verifyContractReceipt } = require('../verify-contract-receipt.cjs');
const { KoGlobalState } = require('../../chain/vlock7sin-js/src/koState');
const { UNIT } = require('../../chain/vlock7sin-js/src');
export function verifyRemoteResults(controllerPacket, packets, expectedCommit, expectedRun) {
  check(controllerPacket?.body?.network, 'REMOTE_CONTROLLER_REPORT_REQUIRED');
  const networkPacket = controllerPacket.body.network, controlPublicKey = networkPacket.body.controlPublicKey;
  const network = verified(NETWORK_DOMAIN, networkPacket, controlPublicKey);
  const body = verified(REPORT_DOMAIN, controllerPacket, controlPublicKey);
  check(body.schema === 'konaet.remote-controller-result.v1' && body.passed === true && body.commit === expectedCommit
    && body.runId === expectedRun && network.runId === expectedRun && network.commit === expectedCommit, 'REMOTE_REPORT_CONTEXT_INVALID');
  const genesis = validateGenesis(network.genesis);
  check(Number.isSafeInteger(body.requestedSeconds) && body.requestedSeconds >= 180 && Number.isSafeInteger(body.startedAt)
    && Number.isSafeInteger(body.stoppedAt) && body.elapsedMs === body.stoppedAt - body.startedAt && body.elapsedMs >= body.requestedSeconds * 1000,
    'REMOTE_DURATION_INCOMPLETE');
  check(packets.length === 4 && network.nodes.length === 4, 'FOUR_REMOTE_NODES_REQUIRED');
  const indexes = new Set(), hosts = new Set();
  for (const packet of packets) {
    const index = packet?.body?.index; check(Number.isInteger(index) && index >= 0 && index < 4 && !indexes.has(index), 'REMOTE_NODE_SET_INVALID');
    const node = verified(REPORT_DOMAIN, packet, genesis.validators[index].publicKey);
    const bootstrap = verified(REPORT_DOMAIN, network.nodes[index], genesis.validators[index].publicKey);
    check(node.passed && node.stoppedCleanly && node.runId === expectedRun && node.commit === expectedCommit
      && node.state.root === body.finalRoot && node.state.sequence === body.finalSequence && node.state.unexpectedExits === 0
      && node.hostHash === bootstrap.hostHash, 'REMOTE_NODE_RESULT_INVALID');
    indexes.add(index); hosts.add(node.hostHash);
  }
  check(hosts.size === 4, 'DISTINCT_OS_INSTANCES_REQUIRED');
  check(body.supplyPreserved === true && body.transferCount > 0 && body.contractCallCount > 0
    && body.faults.some(fault => fault.kind === 'quorum-loss-and-pending-recovery' && fault.passed)
    && body.faults.some(fault => fault.kind === 'validator-3-restored-and-synchronized' && fault.passed), 'REMOTE_ACCEPTANCE_CRITERIA_FAILED');
  const receipt = verifyContractReceipt(body.lastReceipt, { expectedGenesisId: genesis.genesisId, expectedPreviousRoot: body.lastReceipt.proposal.previousRoot });
  check(receipt.stateRoot === body.finalRoot, 'REMOTE_FINAL_CERTIFICATE_MISMATCH');
  const finalState = KoGlobalState.fromSnapshot(body.lastReceipt.afterState);
  check(finalState.entries().reduce((sum, row) => sum + row.balance, 0n) === UNIT.initialSupplyAtomic, 'REMOTE_FINAL_SUPPLY_MISMATCH');
  const counter = finalState.contracts().filter(record => record.artifact.program.contract === 'Counter');
  check(counter.length === 1 && counter[0].state.storage.total === String(body.contractCallCount * 2)
    && body.finalContractValue === counter[0].state.storage.total, 'REMOTE_FINAL_CONTRACT_VALUE_MISMATCH');
  return { passed: true, commit: expectedCommit, runId: expectedRun, hostCount: hosts.size, independentAdministrators: false,
    requestedSeconds: body.requestedSeconds, observedMs: body.elapsedMs, transfers: body.transferCount, calls: body.contractCallCount,
    sequence: body.finalSequence, stateRoot: body.finalRoot, signers: receipt.signers, timing: body.timing,
    operationalScope: 'four-ephemeral-github-hosted-vms-with-end-to-end-mtls', permanentHostingValidated: false };
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const directory = process.argv[2]; check(directory && fs.statSync(directory).isDirectory(), 'REMOTE_RESULTS_DIRECTORY_REQUIRED');
    const read = name => JSON.parse(fs.readFileSync(path.join(directory, name), 'utf8'));
    const result = verifyRemoteResults(read('controller.json'), [0, 1, 2, 3].map(index => read(`result-${index}.json`)),
      process.env.GITHUB_SHA, `${process.env.GITHUB_RUN_ID}-${process.env.GITHUB_RUN_ATTEMPT}`);
    writeJson(path.join(directory, 'verified-summary.json'), result); console.log(JSON.stringify(result, null, 2));
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
