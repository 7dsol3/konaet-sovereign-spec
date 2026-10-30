'use strict';

const { createHash } = require('node:crypto');
const { canonicalBytes, compareUtf8 } = require('./causalGraph');
const { normalizeStatement } = require('./quorum');
const {
  HYBRID_POLICY,
  normalizePublicIdentity,
  verifyHybridSignature,
} = require('./hybridCrypto');

const POLICY = 'HYBRID_PERMISSIONED_K_OF_N_V1';
const DOMAIN_ALLOWLIST = Buffer.from('VLOCK7SIN/HYBRID-ALLOWLIST/v1\0', 'ascii');
const DOMAIN_STATEMENT = Buffer.from('VLOCK7SIN/HYBRID-CLOSURE-STATEMENT/v1\0', 'ascii');
const DOMAIN_VOTE = Buffer.from('VLOCK7SIN/HYBRID-PERMISSIONED-VOTE/v1\0', 'ascii');
const DOMAIN_CERTIFICATE = Buffer.from('VLOCK7SIN/HYBRID-PERMISSIONED-CERTIFICATE/v1\0', 'ascii');

class HybridQuorumError extends Error {
  constructor(code, message, details = undefined) {
    super(message);
    this.name = 'HybridQuorumError';
    this.code = code;
    if (details !== undefined) this.details = details;
  }
}

function digest(domain, value) {
  return createHash('sha3-256').update(domain).update(canonicalBytes(value)).digest('hex');
}

function exactFields(value, expected, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new HybridQuorumError('INVALID_RECORD', `${label} must be an object`);
  }
  const actual = Object.keys(value).sort(compareUtf8);
  const wanted = [...expected].sort(compareUtf8);
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw new HybridQuorumError('INVALID_RECORD', `${label} has missing or unexpected fields`);
  }
}

function validatorId(value) {
  const id = String(value ?? '').normalize('NFC');
  if (!/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(id)) {
    throw new HybridQuorumError('INVALID_VALIDATOR_ID', 'validator id must be safe ASCII');
  }
  return id;
}

function canonicalHash(value, label) {
  const text = String(value ?? '');
  if (!/^[0-9a-f]{64}$/.test(text)) throw new HybridQuorumError('INVALID_HASH', `${label} must be canonical 32-byte hex`);
  return text;
}

function normalizedValidators(validators) {
  if (!Array.isArray(validators) || validators.length === 0) {
    throw new HybridQuorumError('INVALID_ALLOWLIST', 'hybrid validators must be a non-empty array');
  }
  const normalized = validators.map((entry) => {
    if (!entry || typeof entry !== 'object') throw new HybridQuorumError('INVALID_VALIDATOR', 'validator entry must be an object');
    const id = validatorId(entry.id);
    const identity = normalizePublicIdentity(entry.publicIdentity);
    const publicIdentity = identity.identity;
    const signingKey = (key) => key.export({ format: 'der', type: 'spki' }).toString('hex');
    return Object.freeze({ id, publicIdentity, fingerprint: publicIdentity.fingerprint,
      ed25519SigningKey: signingKey(identity.keys.ed25519),
      mlDsaSigningKey: signingKey(identity.keys.mlDsa) });
  }).sort((left, right) => compareUtf8(left.id, right.id));
  if (new Set(normalized.map((item) => item.id)).size !== normalized.length) {
    throw new HybridQuorumError('DUPLICATE_VALIDATOR', 'validator ids must be unique');
  }
  if (new Set(normalized.map((item) => item.fingerprint)).size !== normalized.length) {
    throw new HybridQuorumError('DUPLICATE_KEY', 'one hybrid identity cannot count as multiple validators');
  }
  for (const field of ['ed25519SigningKey', 'mlDsaSigningKey']) {
    if (new Set(normalized.map((item) => item[field])).size !== normalized.length) {
      throw new HybridQuorumError('DUPLICATE_SIGNING_KEY', 'a signing key cannot belong to multiple hybrid validators');
    }
  }
  return normalized;
}

class HybridPermissionedQuorum {
  #threshold;

  #networkId;

  #protocolVersion;

  #validators;

  #allowlist;

  #allowlistRoot;

  constructor({ validators, threshold, networkId = '', protocolVersion = '1' }) {
    const normalized = normalizedValidators(validators);
    if (!Number.isSafeInteger(threshold) || threshold < 1 || threshold > normalized.length) {
      throw new HybridQuorumError('INVALID_THRESHOLD', 'threshold must be 1..validator count');
    }
    this.#threshold = threshold;
    this.#networkId = String(networkId);
    this.#protocolVersion = String(protocolVersion);
    this.#validators = new Map(normalized.map((entry) => [entry.id, entry]));
    this.#allowlist = Object.freeze(normalized.map(({ id, publicIdentity }) => Object.freeze({ id, publicIdentity })));
    this.#allowlistRoot = digest(DOMAIN_ALLOWLIST, {
      policy: POLICY,
      signaturePolicy: HYBRID_POLICY,
      networkId: this.#networkId,
      protocolVersion: this.#protocolVersion,
      threshold,
      validators: this.#allowlist,
    });
  }

  get threshold() { return this.#threshold; }

  get validatorCount() { return this.#validators.size; }

  get allowlist() { return this.#allowlist; }

  get allowlistRoot() { return this.#allowlistRoot; }

  statement(proposal) {
    let statement;
    try {
      statement = normalizeStatement({
        ...proposal,
        networkId: proposal.networkId ?? this.#networkId,
        protocolVersion: proposal.protocolVersion ?? this.#protocolVersion,
      });
    } catch (cause) {
      throw new HybridQuorumError('INVALID_STATEMENT', 'closure statement is invalid', { cause: cause.message });
    }
    if (statement.networkId !== this.#networkId || statement.protocolVersion !== this.#protocolVersion) {
      throw new HybridQuorumError('WRONG_NETWORK', 'statement belongs to another network or protocol');
    }
    return statement;
  }

  statementHash(proposal) { return digest(DOMAIN_STATEMENT, this.statement(proposal)); }

  message(proposal) {
    const statement = this.statement(proposal);
    return Buffer.concat([DOMAIN_VOTE, canonicalBytes({
      policy: POLICY,
      signaturePolicy: HYBRID_POLICY,
      threshold: this.#threshold,
      validatorCount: this.#validators.size,
      allowlistRoot: this.#allowlistRoot,
      statement,
    })]);
  }

  createVote(proposal, signerId, hybridIdentity) {
    const id = validatorId(signerId);
    const validator = this.#validators.get(id);
    if (!validator) throw new HybridQuorumError('SIGNER_NOT_ALLOWLISTED', `validator ${id} is not allowlisted`);
    if (!hybridIdentity || typeof hybridIdentity.publicIdentity !== 'function' || typeof hybridIdentity.sign !== 'function') {
      throw new HybridQuorumError('INVALID_SIGNER', 'hybrid signer is required');
    }
    const signer = normalizePublicIdentity(hybridIdentity.publicIdentity()).identity;
    if (signer.fingerprint !== validator.fingerprint) {
      throw new HybridQuorumError('KEY_MISMATCH', `hybrid identity does not belong to validator ${id}`);
    }
    const statement = this.statement(proposal);
    return Object.freeze({
      version: 1,
      policy: POLICY,
      signaturePolicy: HYBRID_POLICY,
      signerId: id,
      allowlistRoot: this.#allowlistRoot,
      statementHash: digest(DOMAIN_STATEMENT, statement),
      signature: hybridIdentity.sign(this.message(statement)),
    });
  }

  verifyVote(proposal, vote) {
    exactFields(vote, [
      'version', 'policy', 'signaturePolicy', 'signerId', 'allowlistRoot', 'statementHash', 'signature',
    ], 'hybrid vote');
    if (vote.version !== 1 || vote.policy !== POLICY || vote.signaturePolicy !== HYBRID_POLICY) {
      throw new HybridQuorumError('INVALID_VOTE', 'hybrid vote profile is unsupported');
    }
    const id = validatorId(vote.signerId);
    const validator = this.#validators.get(id);
    if (!validator) throw new HybridQuorumError('SIGNER_NOT_ALLOWLISTED', `validator ${id} is not allowlisted`);
    if (canonicalHash(vote.allowlistRoot, 'allowlist root') !== this.#allowlistRoot) {
      throw new HybridQuorumError('ALLOWLIST_MISMATCH', 'vote belongs to another validator set');
    }
    const statement = this.statement(proposal);
    const expectedStatementHash = digest(DOMAIN_STATEMENT, statement);
    if (canonicalHash(vote.statementHash, 'statement hash') !== expectedStatementHash) {
      throw new HybridQuorumError('STATEMENT_MISMATCH', 'vote signs another statement');
    }
    if (!verifyHybridSignature(validator.publicIdentity, this.message(statement), vote.signature)) {
      throw new HybridQuorumError('INVALID_SIGNATURE', `invalid Ed25519+ML-DSA-65 vote from ${id}`);
    }
    return true;
  }

  assembleCertificate(proposal, votes) {
    if (!Array.isArray(votes)) throw new HybridQuorumError('INVALID_VOTES', 'votes must be an array');
    const statement = this.statement(proposal);
    const unique = new Map();
    for (const vote of votes) {
      this.verifyVote(statement, vote);
      if (unique.has(vote.signerId)) throw new HybridQuorumError('DUPLICATE_SIGNER', `validator ${vote.signerId} voted twice`);
      unique.set(vote.signerId, Object.freeze({ signerId: vote.signerId, signature: vote.signature }));
    }
    if (unique.size < this.#threshold) {
      throw new HybridQuorumError('THRESHOLD_NOT_MET', `certificate needs ${this.#threshold} unique hybrid votes`);
    }
    const certificate = {
      version: 1,
      policy: POLICY,
      signaturePolicy: HYBRID_POLICY,
      scope: 'hybrid-permissioned-k-of-n',
      threshold: this.#threshold,
      validatorCount: this.#validators.size,
      allowlistRoot: this.#allowlistRoot,
      statement,
      statementHash: digest(DOMAIN_STATEMENT, statement),
      signatures: Object.freeze([...unique.values()].sort((left, right) => compareUtf8(left.signerId, right.signerId))),
    };
    certificate.id = digest(DOMAIN_CERTIFICATE, certificate);
    return Object.freeze(certificate);
  }

  verifyCertificate(certificate, proposal = undefined) {
    exactFields(certificate, [
      'version', 'policy', 'signaturePolicy', 'scope', 'threshold', 'validatorCount',
      'allowlistRoot', 'statement', 'statementHash', 'signatures', 'id',
    ], 'hybrid certificate');
    if (certificate.version !== 1 || certificate.policy !== POLICY || certificate.signaturePolicy !== HYBRID_POLICY
      || certificate.scope !== 'hybrid-permissioned-k-of-n' || certificate.threshold !== this.#threshold
      || certificate.validatorCount !== this.#validators.size
      || canonicalHash(certificate.allowlistRoot, 'allowlist root') !== this.#allowlistRoot) {
      throw new HybridQuorumError('POLICY_MISMATCH', 'hybrid certificate policy is invalid');
    }
    const statement = this.statement(proposal ?? certificate.statement);
    if (!canonicalBytes(statement).equals(canonicalBytes(certificate.statement))) {
      throw new HybridQuorumError('STATEMENT_MISMATCH', 'certificate statement differs from proposal');
    }
    const expectedStatementHash = digest(DOMAIN_STATEMENT, statement);
    if (canonicalHash(certificate.statementHash, 'statement hash') !== expectedStatementHash
      || !Array.isArray(certificate.signatures)) {
      throw new HybridQuorumError('STATEMENT_MISMATCH', 'certificate statement hash is invalid');
    }
    let previousSigner = null;
    const seen = new Set();
    for (const entry of certificate.signatures) {
      exactFields(entry, ['signerId', 'signature'], 'hybrid certificate signature');
      const id = validatorId(entry.signerId);
      if (previousSigner !== null && compareUtf8(previousSigner, id) >= 0) {
        throw new HybridQuorumError('NON_CANONICAL_SIGNER_ORDER', 'certificate signers must be strictly sorted');
      }
      previousSigner = id;
      if (seen.has(id)) throw new HybridQuorumError('DUPLICATE_SIGNER', `duplicate signer ${id}`);
      seen.add(id);
      this.verifyVote(statement, {
        version: 1,
        policy: POLICY,
        signaturePolicy: HYBRID_POLICY,
        signerId: id,
        allowlistRoot: this.#allowlistRoot,
        statementHash: expectedStatementHash,
        signature: entry.signature,
      });
    }
    if (seen.size < this.#threshold || seen.size > this.#validators.size) {
      throw new HybridQuorumError('THRESHOLD_NOT_MET', `certificate has ${seen.size}/${this.#threshold} required votes`);
    }
    const unsigned = { ...certificate };
    delete unsigned.id;
    if (canonicalHash(certificate.id, 'certificate id') !== digest(DOMAIN_CERTIFICATE, unsigned)) {
      throw new HybridQuorumError('CERTIFICATE_ID_MISMATCH', 'hybrid certificate id is invalid');
    }
    return true;
  }
}

module.exports = Object.freeze({
  POLICY,
  HybridQuorumError,
  HybridPermissionedQuorum,
});
