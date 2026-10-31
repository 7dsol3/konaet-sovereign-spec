'use strict';
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const DOMAIN = Buffer.from('KONAET/SOCIAL-RECEIPT/v1\0', 'utf8');
const OPENING = 'konaet.social-receipt-opening.v1';
const COMMITMENT = 'konaet.social-receipt-commitment.v1';
function need(value, code) { if (!value) throw Error(code); }
function digest(value) { need(typeof value === 'string' && /^[a-f0-9]{64}$/.test(value), 'SOCIAL_DIGEST_INVALID'); return value; }
function normalized(value, budget = { nodes: 0 }, depth = 0) {
  need(++budget.nodes <= 1024 && depth <= 8, 'SOCIAL_DOCUMENT_LIMIT');
  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'string') { need(value.length <= 8192, 'SOCIAL_DOCUMENT_LIMIT'); return value; }
  if (typeof value === 'number') { need(Number.isSafeInteger(value), 'SOCIAL_DOCUMENT_INVALID'); return value; }
  need(value && typeof value === 'object' && (Array.isArray(value) || Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null), 'SOCIAL_DOCUMENT_INVALID');
  need(Object.getOwnPropertySymbols(value).length === 0, 'SOCIAL_DOCUMENT_INVALID');
  const descriptors = Object.getOwnPropertyDescriptors(value), keys = Object.keys(descriptors).filter(k => !(Array.isArray(value) && k === 'length'));
  need(keys.length <= 64, 'SOCIAL_DOCUMENT_LIMIT');
  if (Array.isArray(value)) need(keys.length === value.length, 'SOCIAL_DOCUMENT_INVALID');
  const result = Array.isArray(value) ? [] : Object.create(null);
  for (const key of keys.sort()) {
    const property = descriptors[key];
    need(property.enumerable && Object.hasOwn(property, 'value') && !['__proto__', 'constructor', 'prototype'].includes(key), 'SOCIAL_DOCUMENT_INVALID');
    if (Array.isArray(value)) need(/^(0|[1-9][0-9]*)$/.test(key) && Number(key) < value.length, 'SOCIAL_DOCUMENT_INVALID');
    result[key] = normalized(property.value, budget, depth + 1);
  }
  return result;
}
function documentBytes(document) {
  need(document && typeof document === 'object' && !Array.isArray(document), 'SOCIAL_DOCUMENT_INVALID');
  const bytes = Buffer.from(JSON.stringify(normalized(document)), 'utf8');
  need(bytes.length <= 16384, 'SOCIAL_DOCUMENT_LIMIT'); return bytes;
}
function createSocialOpening(document) {
  return { schema: OPENING, document: JSON.parse(documentBytes(document)), salt: crypto.randomBytes(32).toString('hex') };
}
function createSocialCommitment(opening) {
  need(opening && typeof opening === 'object' && !Array.isArray(opening)
    && Object.keys(opening).sort().join(',') === 'document,salt,schema' && opening.schema === OPENING, 'SOCIAL_OPENING_INVALID');
  const salt = Buffer.from(digest(opening.salt), 'hex');
  const commitment = crypto.createHash('sha256').update(DOMAIN).update(salt).update(documentBytes(opening.document)).digest('hex');
  return Object.freeze({ schema: COMMITMENT, algorithm: 'SHA-256', commitment,
    args: Object.freeze([BigInt('0x' + commitment.slice(0, 32)).toString(), BigInt('0x' + commitment.slice(32)).toString()]) });
}
function verifySocialOpening(opening, expectedCommitment) {
  const expected = Buffer.from(digest(expectedCommitment), 'hex');
  return crypto.timingSafeEqual(Buffer.from(createSocialCommitment(opening).commitment, 'hex'), expected);
}
function encodeSocialCommitmentFrame(opening, { verify = true } = {}) {
  need(typeof verify === 'boolean', 'SOCIAL_FRAME_OPTIONS_INVALID');
  const commitment = createSocialCommitment(opening);
  return opening.salt + '\n' + documentBytes(opening.document).toString('hex') + '\n'
    + (verify ? commitment.commitment : '-') + '\n';
}
function verifySocialReceipt(bundle, { expectedGenesisId, expectedContractId, expectedCommitment } = {}) {
  digest(expectedGenesisId); digest(expectedContractId); digest(expectedCommitment);
  const { verifyContractReceipt } = require('./verify-contract-receipt.cjs');
  const verified = verifyContractReceipt(bundle, { expectedGenesisId });
  const contract = bundle.afterState.contracts.find(row => row.state.contractId === expectedContractId);
  const source = fs.readFileSync(path.join(__dirname, '../chain/ko-program/examples/SocialReceiptRegistry.ko'));
  need(contract && contract.artifact.sourceSha256 === crypto.createHash('sha256').update(source).digest('hex'), 'SOCIAL_REGISTRY_SOURCE_MISMATCH');
  const args = [BigInt('0x' + expectedCommitment.slice(0, 32)).toString(), BigInt('0x' + expectedCommitment.slice(32)).toString()];
  const matches = verified.receipts.filter(row => row.contractId === expectedContractId && row.method === 'record'
    && row.events.some(event => event.name === 'Recorded' && event.values.length === 3
      && event.values[1] === args[0] && event.values[2] === args[1] && event.values[0] === row.result));
  need(matches.length === 1, 'SOCIAL_COMMITMENT_NOT_FINALIZED');
  return { schema: 'konaet.social-finality-verification.v1', verified: true, commitment: expectedCommitment,
    genesisId: verified.genesisId, contractId: expectedContractId, eventId: matches[0].eventId, index: matches[0].result,
    sequence: verified.sequence, stateRoot: verified.stateRoot, signers: verified.signers,
    proves: 'commitment-inclusion-and-permissioned-finality', contentTruthVerified: false, plaintextDocumentIncluded: false };
}
module.exports = Object.freeze({ createSocialOpening, createSocialCommitment, verifySocialOpening, verifySocialReceipt, encodeSocialCommitmentFrame });
