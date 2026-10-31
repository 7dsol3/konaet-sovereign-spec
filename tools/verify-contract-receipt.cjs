'use strict';
const fs = require('node:fs');
const { PermissionedQuorum, decodeEvent, VlockLedger } = require('../chain/vlock7sin-js/src');
const { canonicalBytes } = require('../chain/vlock7sin-js/src/causalGraph');
const { validateGenesis } = require('../chain/network/sovereign');
const { KoGlobalState } = require('../chain/vlock7sin-js/src/koState');
const { PROTOCOL, AUTHORIZED_PROTOCOL } = require('../chain/vlock7sin-js/src/koConsensusProfile');
function requireTrue(value, message) { if (!value) throw Error(message); }
function verificationTrust(input = {}) {
  requireTrue(input && typeof input === 'object' && !Array.isArray(input)
    && Object.keys(input).every(key => ['expectedGenesisId', 'expectedPreviousRoot'].includes(key)), 'RECEIPT_TRUST_OPTIONS_INVALID');
  for (const value of Object.values(input)) requireTrue(typeof value === 'string' && /^[0-9a-f]{64}$/.test(value), 'RECEIPT_TRUST_ANCHOR_INVALID');
  return input;
}
function parseTrustArguments(args) {
  requireTrue(args.length % 2 === 0, 'RECEIPT_TRUST_ARGUMENTS_INVALID');
  const options = {};
  const names = new Map([['--genesis-id', 'expectedGenesisId'], ['--previous-root', 'expectedPreviousRoot']]);
  for (let index = 0; index < args.length; index += 2) {
    const name = names.get(args[index]);
    requireTrue(name && !Object.hasOwn(options, name), 'RECEIPT_TRUST_ARGUMENTS_INVALID');
    options[name] = args[index + 1];
  }
  return verificationTrust(options);
}
function verifyContractReceipt(bundle, options = {}) {
  const trust = verificationTrust(options);
  requireTrue(bundle && bundle.schema === 'konaet.ko-consensus-receipt.v1', 'RECEIPT_FORMAT_INVALID');
  const genesis = validateGenesis(bundle.genesis); requireTrue([PROTOCOL, AUTHORIZED_PROTOCOL].includes(genesis.protocolVersion), 'CONTRACT_GENESIS_REQUIRED');
  if (trust.expectedGenesisId !== undefined) requireTrue(genesis.genesisId === trust.expectedGenesisId, 'RECEIPT_UNEXPECTED_GENESIS');
  requireTrue(Array.isArray(bundle.events) && bundle.events.length > 0 && bundle.events.length <= genesis.parameters.maxActs, 'RECEIPT_EVENT_LIMIT');
  const previous = KoGlobalState.fromSnapshot(bundle.beforeState);
  requireTrue(canonicalBytes(previous.deploymentPolicy).equals(canonicalBytes(genesis.deploymentPolicy ?? null)), 'RECEIPT_DEPLOYMENT_POLICY_MISMATCH');
  if (trust.expectedPreviousRoot !== undefined) requireTrue(previous.root().toString('hex') === trust.expectedPreviousRoot, 'RECEIPT_UNEXPECTED_PREVIOUS_ROOT');
  requireTrue(previous.networkId === Number(genesis.networkId) && previous.parametersRoot.toString('hex') === genesis.parametersRoot
    && previous.identitiesRoot.toString('hex') === genesis.identitiesRoot, 'RECEIPT_GENESIS_MISMATCH');
  const events = bundle.events.map(base64 => {
    requireTrue(typeof base64 === 'string' && base64.length <= 87384 && /^[A-Za-z0-9+/]*={0,2}$/.test(base64), 'RECEIPT_EVENT_ENCODING');
    const bytes = Buffer.from(base64, 'base64'); requireTrue(bytes.toString('base64') === base64, 'RECEIPT_EVENT_ENCODING'); return decodeEvent(bytes);
  });
  const quorum = new PermissionedQuorum({ networkId: genesis.networkId, protocolVersion: genesis.protocolVersion, threshold: genesis.threshold, validators: genesis.validators });
  const ledger = new VlockLedger({ state: previous, protocolVersion: genesis.protocolVersion, nativePolicy: genesis.nativePolicy,
    quorum, requireCertificate: true, maxActs: genesis.parameters.maxActs, maxBytes: genesis.parameters.maxBytes });
  ledger.submitActs(events); const prepared = ledger.prepareConstellation();
  const expected = Object.fromEntries(['networkId', 'protocolVersion', 'sequence', 'constellationId', 'previousRoot', 'nextRoot', 'transitionTrace', 'pcc'].map(key => [key, prepared[key]]));
  requireTrue(canonicalBytes(expected).equals(canonicalBytes(bundle.proposal)), 'RECEIPT_PROPOSAL_MISMATCH');
  ledger.commitPrepared(prepared, { certificate: bundle.certificate }); const state = ledger.getState();
  requireTrue(canonicalBytes(state.snapshot()).equals(canonicalBytes(bundle.afterState)), 'RECEIPT_STATE_MISMATCH');
  return { verified: true, scope: 'permissioned-k-of-n', independentAdministratorsProven: false, genesisId: genesis.genesisId,
    genesisPinned: trust.expectedGenesisId !== undefined, previousStatePinned: trust.expectedPreviousRoot !== undefined,
    sequence: expected.sequence, stateRoot: expected.nextRoot, signers: bundle.certificate.signatures.map(row => row.signerId),
    contractsRoot: state.contractsRoot().toString('hex'), receiptsRoot: state.receiptsRoot().toString('hex'), receipts: state.receipts() };
}
if (require.main === module) {
  try {
    if (process.argv.length < 3) throw Error('USAGE: node tools/verify-contract-receipt.cjs RECEIPT.json [--genesis-id HASH] [--previous-root HASH]');
    const trust = parseTrustArguments(process.argv.slice(3));
    const stat = fs.statSync(process.argv[2]); requireTrue(stat.isFile() && stat.size <= 16777216, 'RECEIPT_SIZE_LIMIT');
    const bytes = fs.readFileSync(process.argv[2]); requireTrue(bytes.length <= 16777216, 'RECEIPT_SIZE_LIMIT');
    console.log(JSON.stringify(verifyContractReceipt(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)), trust), null, 2));
  } catch (error) { console.error(JSON.stringify({ verified: false, code: error.code || error.message })); process.exitCode = 1; }
}
module.exports = Object.freeze({ verifyContractReceipt, parseTrustArguments });
