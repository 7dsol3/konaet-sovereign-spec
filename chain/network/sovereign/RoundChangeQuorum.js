'use strict';

const { createHash } = require('node:crypto');
const { crypto: vlockCrypto } = require('../../vlock7sin-js/src');
const { canonicalBytes, compareUtf8 } = require('../../vlock7sin-js/src/causalGraph');

const POLICY = 'KONAET_SIGNED_ROUND_CHANGE_K_OF_N_V1';
const DOMAIN_STATEMENT = Buffer.from('KONAET/SOVEREIGN/ROUND-CHANGE-STATEMENT/v1\0', 'ascii');
const DOMAIN_VOTE = Buffer.from('KONAET/SOVEREIGN/ROUND-CHANGE-VOTE/v1\0', 'ascii');
const DOMAIN_CERTIFICATE = Buffer.from('KONAET/SOVEREIGN/ROUND-CHANGE-CERTIFICATE/v1\0', 'ascii');

class RoundChangeQuorumError extends Error {
  constructor(code, message, details = undefined) {
    super(message);
    this.name = 'RoundChangeQuorumError';
    this.code = code;
    if (details !== undefined) this.details = details;
  }
}

function digest(domain, value) {
  return createHash('sha3-256').update(domain).update(canonicalBytes(value)).digest();
}

function safeId(value, label) {
  const text = String(value ?? '').normalize('NFC');
  if (!/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(text)) {
    throw new RoundChangeQuorumError('INVALID_FIELD', `${label} is invalid.`);
  }
  return text;
}

function exactHex(value, bytes, label) {
  const text = String(value ?? '');
  if (!new RegExp(`^[0-9a-f]{${bytes * 2}}$`).test(text)) {
    throw new RoundChangeQuorumError('INVALID_FIELD', `${label} must be canonical lowercase hex.`);
  }
  return text;
}

function u64(value, label) {
  try {
    const number = BigInt(value);
    if (number < 1n || number > 0xffffffffffffffffn) throw new Error('outside u64');
    return number.toString(10);
  } catch {
    throw new RoundChangeQuorumError('INVALID_FIELD', `${label} must be a positive u64.`);
  }
}

function roundNumber(value, validatorCount, label) {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < 1 || number >= validatorCount) {
    throw new RoundChangeQuorumError('INVALID_ROUND', `${label} must be 1..${validatorCount - 1}.`);
  }
  return number;
}

function assertExactFields(value, expected, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new RoundChangeQuorumError('INVALID_FIELD', `${label} must be an object.`);
  }
  const actual = Object.keys(value).sort(compareUtf8);
  const wanted = [...expected].sort(compareUtf8);
  if (actual.length !== wanted.length || actual.some((field, index) => field !== wanted[index])) {
    throw new RoundChangeQuorumError('INVALID_FIELD', `${label} has missing or unexpected fields.`);
  }
}

function normalizeValidators(validators) {
  if (!Array.isArray(validators) || !validators.length) {
    throw new RoundChangeQuorumError('INVALID_VALIDATORS', 'Validator allowlist is required.');
  }
  const normalized = validators.map((validator) => Object.freeze({
    id: safeId(validator?.id, 'validator id'),
    publicKey: exactHex(validator?.publicKey, 32, 'validator publicKey'),
  })).sort((left, right) => compareUtf8(left.id, right.id));
  if (new Set(normalized.map(({ id }) => id)).size !== normalized.length) {
    throw new RoundChangeQuorumError('DUPLICATE_VALIDATOR', 'Validator ids must be unique.');
  }
  if (new Set(normalized.map(({ publicKey }) => publicKey)).size !== normalized.length) {
    throw new RoundChangeQuorumError('DUPLICATE_KEY', 'Validator keys must be unique.');
  }
  return Object.freeze(normalized);
}

class RoundChangeQuorum {
  constructor(options = {}) {
    this.networkId = String(options.networkId ?? '');
    this.protocolVersion = safeId(options.protocolVersion, 'protocolVersion');
    this.genesisId = exactHex(options.genesisId, 32, 'genesisId');
    this.validators = normalizeValidators(options.validators);
    this.validatorCount = this.validators.length;
    this.threshold = Number(options.threshold);
    if (!Number.isSafeInteger(this.threshold) || this.threshold < 1 || this.threshold > this.validatorCount) {
      throw new RoundChangeQuorumError('INVALID_THRESHOLD', 'Round-change threshold is invalid.');
    }
    this.byId = new Map(this.validators.map((validator) => [validator.id, validator]));
    this.allowlistRoot = digest(DOMAIN_STATEMENT, {
      policy: POLICY,
      networkId: this.networkId,
      protocolVersion: this.protocolVersion,
      genesisId: this.genesisId,
      threshold: this.threshold,
      validators: this.validators,
    }).toString('hex');
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
      throw new RoundChangeQuorumError('WRONG_NETWORK', 'Round change belongs to another network or protocol.');
    }
    return statement;
  }

  statementHash(proposal, round) {
    return digest(DOMAIN_STATEMENT, this.statement(proposal, round)).toString('hex');
  }

  message(statementLike, round) {
    const statement = this.statement(statementLike, round ?? statementLike?.toRound);
    return Buffer.concat([DOMAIN_VOTE, canonicalBytes({
      policy: POLICY,
      threshold: this.threshold,
      validatorCount: this.validatorCount,
      allowlistRoot: this.allowlistRoot,
      statement,
    })]);
  }

  createVote(proposal, round, signerId, privateKey) {
    const statement = this.statement(proposal, round);
    const id = safeId(signerId, 'signerId');
    const validator = this.byId.get(id);
    if (!validator) throw new RoundChangeQuorumError('SIGNER_NOT_ALLOWED', `${id} is not a validator.`);
    const message = this.message(statement, statement.toRound);
    const signature = vlockCrypto.sign(privateKey, message);
    if (!vlockCrypto.verify(Buffer.from(validator.publicKey, 'hex'), message, signature)) {
      throw new RoundChangeQuorumError('KEY_MISMATCH', `Private key does not belong to ${id}.`);
    }
    return Object.freeze({
      version: 1,
      policy: POLICY,
      signerId: id,
      allowlistRoot: this.allowlistRoot,
      statementHash: digest(DOMAIN_STATEMENT, statement).toString('hex'),
      signature: signature.toString('hex'),
    });
  }

  verifyVote(proposal, round, vote) {
    assertExactFields(vote, ['version', 'policy', 'signerId', 'allowlistRoot', 'statementHash', 'signature'], 'round-change vote');
    if (vote.version !== 1 || vote.policy !== POLICY) {
      throw new RoundChangeQuorumError('INVALID_VOTE', 'Unsupported round-change vote.');
    }
    const signerId = safeId(vote.signerId, 'signerId');
    const validator = this.byId.get(signerId);
    if (!validator) throw new RoundChangeQuorumError('SIGNER_NOT_ALLOWED', `${signerId} is not a validator.`);
    if (exactHex(vote.allowlistRoot, 32, 'allowlistRoot') !== this.allowlistRoot) {
      throw new RoundChangeQuorumError('ALLOWLIST_MISMATCH', 'Vote belongs to another validator allowlist.');
    }
    const statement = this.statement(proposal, round);
    const statementHash = digest(DOMAIN_STATEMENT, statement).toString('hex');
    if (exactHex(vote.statementHash, 32, 'statementHash') !== statementHash) {
      throw new RoundChangeQuorumError('STATEMENT_MISMATCH', 'Vote signs another round-change statement.');
    }
    const signature = Buffer.from(exactHex(vote.signature, 64, 'signature'), 'hex');
    if (!vlockCrypto.verify(Buffer.from(validator.publicKey, 'hex'), this.message(statement, statement.toRound), signature)) {
      throw new RoundChangeQuorumError('INVALID_SIGNATURE', `Invalid round-change signature from ${signerId}.`);
    }
    return true;
  }

  assembleCertificate(proposal, round, votes) {
    if (!Array.isArray(votes)) throw new RoundChangeQuorumError('INVALID_VOTES', 'Votes must be an array.');
    const statement = this.statement(proposal, round);
    const unique = new Map();
    for (const vote of votes) {
      this.verifyVote(statement, statement.toRound, vote);
      if (unique.has(vote.signerId)) {
        throw new RoundChangeQuorumError('DUPLICATE_SIGNER', `${vote.signerId} appears twice.`);
      }
      unique.set(vote.signerId, Object.freeze({ signerId: vote.signerId, signature: vote.signature }));
    }
    if (unique.size < this.threshold) {
      throw new RoundChangeQuorumError('THRESHOLD_NOT_MET', `Round change needs ${this.threshold} signatures.`);
    }
    const certificate = {
      version: 1,
      policy: POLICY,
      scope: 'signed-round-change-k-of-n',
      threshold: this.threshold,
      validatorCount: this.validatorCount,
      allowlistRoot: this.allowlistRoot,
      statement,
      statementHash: digest(DOMAIN_STATEMENT, statement).toString('hex'),
      signatures: Object.freeze([...unique.values()].sort((left, right) => compareUtf8(left.signerId, right.signerId))),
    };
    certificate.id = digest(DOMAIN_CERTIFICATE, certificate).toString('hex');
    return Object.freeze(certificate);
  }

  verifyCertificate(certificate, proposal, round) {
    assertExactFields(certificate, [
      'version', 'policy', 'scope', 'threshold', 'validatorCount', 'allowlistRoot',
      'statement', 'statementHash', 'signatures', 'id',
    ], 'round-change certificate');
    if (certificate.version !== 1 || certificate.policy !== POLICY || certificate.scope !== 'signed-round-change-k-of-n') {
      throw new RoundChangeQuorumError('INVALID_CERTIFICATE', 'Unsupported round-change certificate.');
    }
    if (certificate.threshold !== this.threshold || certificate.validatorCount !== this.validatorCount) {
      throw new RoundChangeQuorumError('POLICY_MISMATCH', 'Certificate threshold differs from genesis.');
    }
    if (exactHex(certificate.allowlistRoot, 32, 'allowlistRoot') !== this.allowlistRoot) {
      throw new RoundChangeQuorumError('ALLOWLIST_MISMATCH', 'Certificate belongs to another validator allowlist.');
    }
    const statement = this.statement(proposal, round);
    assertExactFields(certificate.statement, [
      'networkId', 'protocolVersion', 'genesisId', 'sequence', 'fromRound', 'toRound',
      'previousRoot', 'proposalHash',
    ], 'round-change statement');
    if (!canonicalBytes(statement).equals(canonicalBytes(certificate.statement))) {
      throw new RoundChangeQuorumError('STATEMENT_MISMATCH', 'Certificate authorizes another proposal or round.');
    }
    const statementHash = digest(DOMAIN_STATEMENT, statement).toString('hex');
    if (exactHex(certificate.statementHash, 32, 'statementHash') !== statementHash) {
      throw new RoundChangeQuorumError('STATEMENT_MISMATCH', 'Certificate statement hash is invalid.');
    }
    if (!Array.isArray(certificate.signatures)) {
      throw new RoundChangeQuorumError('INVALID_CERTIFICATE', 'Certificate signatures must be an array.');
    }
    let previous = null;
    const seen = new Set();
    for (const signature of certificate.signatures) {
      assertExactFields(signature, ['signerId', 'signature'], 'round-change certificate signature');
      const signerId = safeId(signature.signerId, 'signerId');
      if (previous !== null && compareUtf8(previous, signerId) >= 0) {
        throw new RoundChangeQuorumError('NON_CANONICAL_SIGNER_ORDER', 'Certificate signers are not canonical.');
      }
      previous = signerId;
      if (seen.has(signerId)) throw new RoundChangeQuorumError('DUPLICATE_SIGNER', `${signerId} appears twice.`);
      seen.add(signerId);
      this.verifyVote(statement, statement.toRound, {
        version: 1,
        policy: POLICY,
        signerId,
        allowlistRoot: this.allowlistRoot,
        statementHash,
        signature: signature.signature,
      });
    }
    if (seen.size < this.threshold || seen.size > this.validatorCount) {
      throw new RoundChangeQuorumError('THRESHOLD_NOT_MET', 'Certificate does not meet the round-change threshold.');
    }
    const unsigned = { ...certificate };
    delete unsigned.id;
    if (exactHex(certificate.id, 32, 'certificate id') !== digest(DOMAIN_CERTIFICATE, unsigned).toString('hex')) {
      throw new RoundChangeQuorumError('CERTIFICATE_ID_MISMATCH', 'Certificate id is invalid.');
    }
    return true;
  }
}

module.exports = Object.freeze({ POLICY, RoundChangeQuorum, RoundChangeQuorumError });
