'use strict';
const fs = require('node:fs');
const { PermissionedQuorum, decodeEvent, VlockLedger } = require('../chain/vlock7sin-js/src');
const { canonicalBytes } = require('../chain/vlock7sin-js/src/causalGraph');
const { validateGenesis } = require('../chain/network/sovereign');
const { KoGlobalState } = require('../chain/vlock7sin-js/src/koState');
const { PROTOCOL } = require('../chain/vlock7sin-js/src/koConsensusProfile');
function requireTrue(value, message) { if (!value) throw Error(message); }
function verifyContractReceipt(bundle) {
  requireTrue(bundle && bundle.schema === 'konaet.ko-consensus-receipt.v1', 'RECEIPT_FORMAT_INVALID');
  const genesis = validateGenesis(bundle.genesis); requireTrue(genesis.protocolVersion === PROTOCOL, 'CONTRACT_GENESIS_REQUIRED');
  requireTrue(Array.isArray(bundle.events) && bundle.events.length > 0 && bundle.events.length <= genesis.parameters.maxActs, 'RECEIPT_EVENT_LIMIT');
  const previous = KoGlobalState.fromSnapshot(bundle.beforeState);
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
    sequence: expected.sequence, stateRoot: expected.nextRoot, signers: bundle.certificate.signatures.map(row => row.signerId),
    contractsRoot: state.contractsRoot().toString('hex'), receiptsRoot: state.receiptsRoot().toString('hex'), receipts: state.receipts() };
}
if (require.main === module) {
  try {
    if (process.argv.length !== 3) throw Error('USAGE: node tools/verify-contract-receipt.cjs RECEIPT.json');
    const stat = fs.statSync(process.argv[2]); requireTrue(stat.isFile() && stat.size <= 16777216, 'RECEIPT_SIZE_LIMIT');
    const bytes = fs.readFileSync(process.argv[2]); requireTrue(bytes.length <= 16777216, 'RECEIPT_SIZE_LIMIT');
    console.log(JSON.stringify(verifyContractReceipt(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))), null, 2));
  } catch (error) { console.error(JSON.stringify({ verified: false, code: error.code || error.message })); process.exitCode = 1; }
}
module.exports = Object.freeze({ verifyContractReceipt });
