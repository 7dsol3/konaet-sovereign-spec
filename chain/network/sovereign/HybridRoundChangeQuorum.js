'use strict';

const { createHash } = require('node:crypto');
const { canonicalBytes, compareUtf8 } = require('../../vlock7sin-js/src/causalGraph');
const { HYBRID_POLICY, normalizePublicIdentity, verifyHybridSignature } = require('../../vlock7sin-js/src/hybridCrypto');

const POLICY = 'KONAET_HYBRID_SIGNED_ROUND_CHANGE_K_OF_N_V1';
const DOMAIN_STATEMENT = Buffer.from('KONAET/SOVEREIGN/HYBRID-ROUND-CHANGE-STATEMENT/v1\0', 'ascii');
const DOMAIN_VOTE = Buffer.from('KONAET/SOVEREIGN/HYBRID-ROUND-CHANGE-VOTE/v1\0', 'ascii');
const DOMAIN_CERTIFICATE = Buffer.from('KONAET/SOVEREIGN/HYBRID-ROUND-CHANGE-CERTIFICATE/v1\0', 'ascii');

class HybridRoundChangeQuorumError extends Error {
  constructor(code, message, details = undefined) {
    super(message);
    this.name = 'HybridRoundChangeQuorumError';
    this.code = code;
    if (details !== undefined) this.details = details;
  }
}

function digest(domain, value) {
  return createHash('sha3-256').update(domain).update(canonicalBytes(value)).digest('hex');
}

function safeId(value, label) {
  const text = String(value ?? '').normalize('NFC');
  if (!/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(text)) {
    throw new HybridRoundChangeQuorumError('INVALID_FIELD', `${label} is invalid.`);
  }
  return text;
}

function exactHex(value, bytes, label) {
  const text = String(value ?? '');
  if (!new RegExp(`^[0-9a-f]{${bytes * 2}}$`).test(text)) {
    throw new HybridRoundChangeQuorumError('INVALID_FIELD', `${label} must be canonical lowercase hex.`);
  }
  return text;
}

function u64(value, label) {
  try {
    const number = BigInt(value);
    if (number < 1n || number > 0xffffffffffffffffn) throw new Error('outside u64');
    return number.toString(10);
  } catch {
    throw new HybridRoundChangeQuorumError('INVALID_FIELD', `${label} must be a positive u64.`);
  }
}

function roundNumber(value, validatorCount, label) {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < 1 || number >= validatorCount) {
    throw new HybridRoundChangeQuorumError('INVALID_ROUND', `${label} must be 1..${validatorCount - 1}.`);
  }
  return number;
}

function exactFields(value, expected, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new HybridRoundChangeQuorumError('INVALID_FIELD', `${label} must be an object.`);
  }
  const actual = Object.keys(value).sort(compareUtf8);
  const wanted = [...expected].sort(compareUtf8);
  if (actual.length !== wanted.length || actual.some((field, index) => field !== wanted[index])) {
    throw new HybridRoundChangeQuorumError('INVALID_FIELD', `${label} has missing or unexpected fields.`);
  }
}

function normalizeValidators(validators) {
  if (!Array.isArray(validators) || validators.length < 4) {
    throw new HybridRoundChangeQuorumError('INVALID_VALIDATORS', 'At least four hybrid validators are required.');
  }
  const normalized = validators.map((validator) => {
    if (!validator || typeof validator !== 'object' || Object.keys(validator).sort().join('\0')
      !== ['id', 'publicIdentity', 'publicKey'].sort().join('\0')) {
      throw new HybridRoundChangeQuorumError('INVALID_VALIDATOR', 'Hybrid validator fields are invalid.');
    }
    let identity;
    try { identity = normalizePublicIdentity(validator.publicIdentity); }
    catch (error) {
      throw new HybridRoundChangeQuorumError('INVALID_VALIDATOR_IDENTITY', 'Hybrid validator identity is invalid.', {
        cause: error.message,
      });
    }
    return Object.freeze({ id: safeId(validator.id, 'validator id'), publicIdentity: identity.identity,
      fingerprint: identity.fingerprint });
  }).sort((left, right) => compareUtf8(left.id, right.id));
  if (new Set(normalized.map(({ id }) => id)).size !== normalized.length
    || new Set(normalized.map(({ fingerprint }) => fingerprint)).size !== normalized.length) {
    throw new HybridRoundChangeQuorumError('DUPLICATE_VALIDATOR', 'Hybrid validator identities must be unique.');
  }
  return Object.freeze(normalized);
}

class HybridRoundChangeQuorum {
  constructor(options = {}) {
    this.networkId = String(options.networkId ?? '');
    this.protocolVersion = safeId(options.protocolVersion, 'protocolVersion');
    this.genesisId = exactHex(options.genesisId, 32, 'genesisId');
    this.validators = normalizeValidators(options.validators);
    this.validatorCount = this.validators.length;
    this.threshold = Number(options.threshold);
    const minimumThreshold = Math.floor((2 * this.validatorCount) / 3) + 1;
    if (!Number.isSafeInteger(this.threshold) || this.threshold < minimumThreshold || this.threshold > this.validatorCount) {
      throw new HybridRoundChangeQuorumError('INVALID_THRESHOLD', 'Hybrid round-change threshold must exceed two thirds.');
    }
    this.byId = new Map(this.validators.map((validator) => [validator.id, validator]));
    this.allowlistRoot = digest(DOMAIN_STATEMENT, {
      policy: POLICY,
      signaturePolicy: HYBRID_POLICY,
      networkId: this.networkId,
      protocolVersion: this.protocolVersion,
      genesisId: this.genesisId,
      threshold: this.threshold,
      validators: this.validators.map(({ id, publicIdentity }) => ({ id, publicIdentity })),
    });
  }

  statement(proposal, round) {
    const toRound = roundNumber(round, this.validatorCount, 'toRound');
    const statement = Object.freeze({
      networkId: String(proposal?.networkId ?? ''),
      protocolVersion: String(proposal?.protocolVersion ?? ''),
      genesisId: this.genesisId,
      sequence: u64(proposal?.sequence, 'sequence'),
      fromRound: toRound - 1,
      toRound,
      previousRoot: exactHex(proposal?.previousRoot, 32, 'previousRoot'),
      proposalHash: exactHex(proposal?.proposalHash, 32, 'proposalHash'),
    });
    if (statement.networkId !== this.networkId || statement.protocolVersion !== this.protocolVersion) {
      throw new HybridRoundChangeQuorumError('WRONG_NETWORK', 'Round change belongs to another network or protocol.');
    }
    return statement;
  }

  statementHash(proposal, round) { return digest(DOMAIN_STATEMENT, this.statement(proposal, round)); }

  message(statementLike, round) {
    const statement = this.statement(statementLike, round ?? statementLike?.toRound);
    return Buffer.concat([DOMAIN_VOTE, canonicalBytes({
      policy: POLICY,
      signaturePolicy: HYBRID_POLICY,
      threshold: this.threshold,
      validatorCount: this.validatorCount,
      allowlistRoot: this.allowlistRoot,
      statement,
    })]);
  }

  createVote(proposal, round, signerId, hybridIdentity) {
    const statement = this.statement(proposal, round);
    const id = safeId(signerId, 'signerId');
    const validator = this.byId.get(id);
    if (!validator) throw new HybridRoundChangeQuorumError('SIGNER_NOT_ALLOWED', `${id} is not a validator.`);
    if (!hybridIdentity || typeof hybridIdentity.publicIdentity !== 'function' || typeof hybridIdentity.sign !== 'function') {
      throw new HybridRoundChangeQuorumError('INVALID_SIGNER', 'Hybrid identity is required to sign round changes.');
    }
    const signer = normalizePublicIdentity(hybridIdentity.publicIdentity());
    if (signer.fingerprint !== validator.fingerprint) {
      throw new HybridRoundChangeQuorumError('KEY_MISMATCH', `Hybrid identity does not belong to ${id}.`);
    }
    const message = this.message(statement, statement.toRound);
    return Object.freeze({
      version: 1,
      policy: POLICY,
      signaturePolicy: HYBRID_POLICY,
      signerId: id,
      allowlistRoot: this.allowlistRoot,
      statementHash: digest(DOMAIN_STATEMENT, statement),
      signature: hybridIdentity.sign(message),
    });
  }

  verifyVote(proposal, round, vote) {
    exactFields(vote, ['version', 'policy', 'signaturePolicy', 'signerId', 'allowlistRoot', 'statementHash', 'signature'], 'hybrid round-change vote');
    if (vote.version !== 1 || vote.policy !== POLICY || vote.signaturePolicy !== HYBRID_POLICY) {
      throw new HybridRoundChangeQuorumError('INVALID_VOTE', 'Hybrid round-change vote profile is unsupported.');
    }
    const signerId = safeId(vote.signerId, 'signerId');
    const validator = this.byId.get(signerId);
    if (!validator) throw new HybridRoundChangeQuorumError('SIGNER_NOT_ALLOWED', `${signerId} is not a validator.`);
    if (exactHex(vote.allowlistRoot, 32, 'allowlistRoot') !== this.allowlistRoot) {
      throw new HybridRoundChangeQuorumError('ALLOWLIST_MISMATCH', 'Vote belongs to another hybrid validator allowlist.');
    }
    const statement = this.statement(proposal, round);
    const statementHash = digest(DOMAIN_STATEMENT, statement);
    if (exactHex(vote.statementHash, 32, 'statementHash') !== statementHash) {
      throw new HybridRoundChangeQuorumError('STATEMENT_MISMATCH', 'Vote signs another round-change statement.');
    }
    if (!verifyHybridSignature(validator.publicIdentity, this.message(statement, statement.toRound), vote.signature)) {
      throw new HybridRoundChangeQuorumError('INVALID_SIGNATURE', `Invalid Ed25519+ML-DSA-65 round-change vote from ${signerId}.`);
    }
    return true;
  }

  assembleCertificate(proposal, round, votes) {
    if (!Array.isArray(votes)) throw new HybridRoundChangeQuorumError('INVALID_VOTES', 'Votes must be an array.');
    const statement = this.statement(proposal, round);
    const unique = new Map();
    for (const vote of votes) {
      this.verifyVote(statement, statement.toRound, vote);
      if (unique.has(vote.signerId)) throw new HybridRoundChangeQuorumError('DUPLICATE_SIGNER', `${vote.signerId} appears twice.`);
      unique.set(vote.signerId, Object.freeze({ signerId: vote.signerId, signature: vote.signature }));
    }
    if (unique.size < this.threshold) {
      throw new HybridRoundChangeQuorumError('THRESHOLD_NOT_MET', `Round change needs ${this.threshold} hybrid signatures.`);
    }
    const certificate = {
      version: 1,
      policy: POLICY,
      signaturePolicy: HYBRID_POLICY,
      scope: 'hybrid-signed-round-change-k-of-n',
      threshold: this.threshold,
      validatorCount: this.validatorCount,
      allowlistRoot: this.allowlistRoot,
      statement,
      statementHash: digest(DOMAIN_STATEMENT, statement),
      signatures: Object.freeze([...unique.values()].sort((left, right) => compareUtf8(left.signerId, right.signerId))),
    };
    certificate.id = digest(DOMAIN_CERTIFICATE, certificate);
    return Object.freeze(certificate);
  }

  verifyCertificate(certificate, proposal, round) {
    exactFields(certificate, ['version', 'policy', 'signaturePolicy', 'scope', 'threshold', 'validatorCount',
      'allowlistRoot', 'statement', 'statementHash', 'signatures', 'id'], 'hybrid round-change certificate');
    if (certificate.version !== 1 || certificate.policy !== POLICY || certificate.signaturePolicy !== HYBRID_POLICY
      || certificate.scope !== 'hybrid-signed-round-change-k-of-n' || certificate.threshold !== this.threshold
      || certificate.validatorCount !== this.validatorCount || certificate.allowlistRoot !== this.allowlistRoot) {
      throw new HybridRoundChangeQuorumError('INVALID_CERTIFICATE', 'Hybrid round-change policy differs from local genesis.');
    }
    const statement = this.statement(proposal ?? certificate.statement, round ?? certificate.statement?.toRound);
    if (!canonicalBytes(statement).equals(canonicalBytes(certificate.statement))) {
      throw new HybridRoundChangeQuorumError('STATEMENT_MISMATCH', 'Round-change certificate statement differs from expected proposal.');
    }
    const expectedHash = digest(DOMAIN_STATEMENT, statement);
    if (certificate.statementHash !== expectedHash || !Array.isArray(certificate.signatures)) {
      throw new HybridRoundChangeQuorumError('STATEMENT_MISMATCH', 'Round-change certificate statement hash is invalid.');
    }
    let previousSigner = null;
    const seen = new Set();
    for (const entry of certificate.signatures) {
      exactFields(entry, ['signerId', 'signature'], 'hybrid round-change signature');
      const signerId = safeId(entry.signerId, 'signerId');
      if (previousSigner !== null && compareUtf8(previousSigner, signerId) >= 0) {
        throw new HybridRoundChangeQuorumError('NON_CANONICAL_SIGNER_ORDER', 'Round-change signers must be sorted.');
      }
      previousSigner = signerId;
      if (seen.has(signerId)) throw new HybridRoundChangeQuorumError('DUPLICATE_SIGNER', `${signerId} appears twice.`);
      seen.add(signerId);
      this.verifyVote(statement, statement.toRound, {
        version: 1,
        policy: POLICY,
        signaturePolicy: HYBRID_POLICY,
        signerId,
        allowlistRoot: this.allowlistRoot,
        statementHash: expectedHash,
        signature: entry.signature,
      });
    }
    if (seen.size < this.threshold || seen.size > this.validatorCount) {
      throw new HybridRoundChangeQuorumError('THRESHOLD_NOT_MET', `Certificate has ${seen.size}/${this.threshold} signatures.`);
    }
    const unsigned = { ...certificate };
    delete unsigned.id;
    if (certificate.id !== digest(DOMAIN_CERTIFICATE, unsigned)) {
      throw new HybridRoundChangeQuorumError('CERTIFICATE_ID_MISMATCH', 'Hybrid round-change certificate id is invalid.');
    }
    return true;
  }
}

module.exports = Object.freeze({ HybridRoundChangeQuorum, HybridRoundChangeQuorumError });
