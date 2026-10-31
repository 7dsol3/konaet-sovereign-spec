'use strict';
const { verifySocialReceipt } = require('../tools/social-receipt.cjs');
function verifyPolyglotReport(report) {
  if (report?.schema !== 'konaet.polyglot-conformance.v1'
    || !['c', 'cpp', 'csharp', 'python', 'rust', 'perl', 'go', 'shell', 'node'].includes(report.language)
    || report.vectorCases !== 12 || report.validAndMismatchChecks !== 37 || report.malformedFramesRejected !== 20
    || report.realFourProcessFinality !== true) throw Error('POLYGLOT_REPORT_INVALID');
  const expected = require('./vectors.json').cases[0].commitment;
  if (report.finalityVerification.commitment !== expected) throw Error('POLYGLOT_VECTOR_MISMATCH');
  const result = verifySocialReceipt(report.receiptBundle, { expectedGenesisId: report.finalityVerification.genesisId,
    expectedContractId: report.finalityVerification.contractId, expectedCommitment: expected });
  if (JSON.stringify(result) !== JSON.stringify(report.finalityVerification)) throw Error('POLYGLOT_FINALITY_MISMATCH');
  return { language: report.language, platform: report.platform, vectorCases: 12,
    malformedFramesRejected: 20, finalityVerified: true, genesisId: result.genesisId, stateRoot: result.stateRoot };
}
module.exports = { verifyPolyglotReport };
