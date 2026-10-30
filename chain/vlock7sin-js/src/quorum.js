'use strict';

const {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign: edSign,
  verify: edVerify,
  KeyObject,
} = require('node:crypto');
const { canonicalBytes, compareUtf8, normalizeId } = require('./causalGraph');

const DOMAIN_ALLOWLIST = Buffer.from('VLOCK7SIN/PERMISSIONED-ALLOWLIST/v1\0', 'ascii');
const DOMAIN_STATEMENT = Buffer.from('VLOCK7SIN/CLOSURE-STATEMENT/v1\0', 'ascii');
const DOMAIN_VOTE = Buffer.from('VLOCK7SIN/PERMISSIONED-VOTE/v1\0', 'ascii');
const DOMAIN_CERTIFICATE = Buffer.from('VLOCK7SIN/PERMISSIONED-CERTIFICATE/v1\0', 'ascii');
const POLICY = 'PERMISSIONED_K_OF_N_V1';

class PermissionedQuorumError extends Error {
  constructor(code, message, details = undefined) {
    super(message);
    this.name = 'PermissionedQuorumError';
    this.code = code;
    if (details !== undefined) this.details = details;
  }
}

function digest(domain, value) {
  return createHash('sha3-256').update(domain).update(canonicalBytes(value)).digest();
}

function rawEd25519PublicKey(bytes) {
  if (bytes.length !== 32) return null;
  return Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), bytes]);
}

function rawEd25519PrivateSeed(bytes) {
  if (bytes.length !== 32) return null;
  return Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), bytes]);
}

function publicKeyObject(value) {
  try {
    if (value instanceof KeyObject) return value.type === 'public' ? value : createPublicKey(value);
    if (typeof value === 'string' && /^[0-9a-fA-F]{64}$/.test(value)) {
      return createPublicKey({ key: rawEd25519PublicKey(Buffer.from(value, 'hex')), format: 'der', type: 'spki' });
    }
    if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
      const bytes = Buffer.from(value);
      const der = rawEd25519PublicKey(bytes) ?? bytes;
      return createPublicKey({ key: der, format: 'der', type: 'spki' });
    }
    return createPublicKey(value);
  } catch (error) {
    throw new PermissionedQuorumError('INVALID_PUBLIC_KEY', 'validator public key is invalid', { cause: error.message });
  }
}

function privateKeyObject(value) {
  try {
    if (value instanceof KeyObject) {
      if (value.type !== 'private') throw new Error('expected a private key');
      return value;
    }
    if (typeof value === 'string' && /^[0-9a-fA-F]{64}$/.test(value)) {
      return createPrivateKey({ key: rawEd25519PrivateSeed(Buffer.from(value, 'hex')), format: 'der', type: 'pkcs8' });
    }
    if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
      const bytes = Buffer.from(value);
      const der = rawEd25519PrivateSeed(bytes) ?? bytes;
      return createPrivateKey({ key: der, format: 'der', type: 'pkcs8' });
    }
    return createPrivateKey(value);
  } catch (error) {
    throw new PermissionedQuorumError('INVALID_PRIVATE_KEY', 'validator private key is invalid', { cause: error.message });
  }
}

function publicDer(key) {
  const object = publicKeyObject(key);
  if (object.asymmetricKeyType !== 'ed25519') {
    throw new PermissionedQuorumError('WRONG_KEY_TYPE', 'validator keys must be Ed25519');
  }
  return object.export({ format: 'der', type: 'spki' });
}

function validatorId(value) {
  const id = String(value ?? '').normalize('NFC');
  if (!/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(id)) {
    throw new PermissionedQuorumError('INVALID_VALIDATOR_ID', 'validator id must be 1..128 safe ASCII characters');
  }
  return id;
}

function exactHex(value, bytes, label) {
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    const buffer = Buffer.from(value);
    if (buffer.length !== bytes) throw new PermissionedQuorumError('INVALID_FIELD', `${label} must be ${bytes} bytes`);
    return buffer.toString('hex');
  }
  const result = String(value ?? '').toLowerCase().replace(/^0x/, '');
  if (!new RegExp(`^[0-9a-f]{${bytes * 2}}$`).test(result)) {
    throw new PermissionedQuorumError('INVALID_FIELD', `${label} must be ${bytes * 2} hexadecimal characters`);
  }
  return result;
}

function u64String(value, label = 'sequence') {
  let number;
  try { number = BigInt(value); } catch {
    throw new PermissionedQuorumError('INVALID_FIELD', `${label} must be an unsigned integer`);
  }
  if (number < 0n || number > 0xffffffffffffffffn) {
    throw new PermissionedQuorumError('INVALID_FIELD', `${label} must fit u64`);
  }
  return number.toString(10);
}

function assertExactFields(value, expected, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new PermissionedQuorumError('INVALID_FIELD', `${label} must be an object`);
  }
  const actual = Object.keys(value).sort(compareUtf8);
  const wanted = [...expected].sort(compareUtf8);
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw new PermissionedQuorumError('INVALID_FIELD', `${label} has missing or unexpected fields`);
  }
}

function lowerHex(value, bytes, label) {
  const text = String(value ?? '');
  if (!new RegExp(`^[0-9a-f]{${bytes * 2}}$`).test(text)) {
    throw new PermissionedQuorumError('INVALID_FIELD', `${label} must be canonical lowercase hex`);
  }
  return text;
}

function normalizeStatement(proposal) {
  if (!proposal || typeof proposal !== 'object') {
    throw new PermissionedQuorumError('INVALID_STATEMENT', 'closure proposal must be an object');
  }
  const constellationId = proposal.constellationId ?? proposal.constellation?.id;
  return Object.freeze({
    networkId: String(proposal.networkId ?? ''),
    protocolVersion: String(proposal.protocolVersion ?? proposal.version ?? '1'),
    sequence: u64String(proposal.sequence),
    constellationId: normalizeId(constellationId, 'constellation id'),
    previousRoot: exactHex(proposal.previousRoot, 32, 'previousRoot'),
    nextRoot: exactHex(proposal.nextRoot, 32, 'nextRoot'),
    transitionTrace: exactHex(proposal.transitionTrace, 32, 'transitionTrace'),
    pcc: exactHex(proposal.pcc, 32, 'pcc'),
  });
}

function normalizeValidators(validators) {
  let entries;
  if (Array.isArray(validators)) entries = validators.map((item) => [item.id, item.publicKey]);
  else if (validators && typeof validators === 'object') entries = Object.entries(validators);
  else throw new PermissionedQuorumError('INVALID_ALLOWLIST', 'validators must be an array or id-to-key object');

  const normalized = entries.map(([rawId, key]) => {
    const id = validatorId(rawId);
    const keyObject = publicKeyObject(key);
    const der = publicDer(keyObject);
    return { id, keyObject, publicKeyDer: der, fingerprint: digest(DOMAIN_ALLOWLIST, der).toString('hex') };
  }).sort((a, b) => compareUtf8(a.id, b.id));

  if (!normalized.length) throw new PermissionedQuorumError('INVALID_ALLOWLIST', 'allowlist cannot be empty');
  if (new Set(normalized.map((item) => item.id)).size !== normalized.length) {
    throw new PermissionedQuorumError('DUPLICATE_VALIDATOR', 'validator ids must be unique');
  }
  if (new Set(normalized.map((item) => item.fingerprint)).size !== normalized.length) {
    throw new PermissionedQuorumError('DUPLICATE_KEY', 'one Ed25519 key cannot count as multiple validators');
  }
  return normalized;
}

class PermissionedQuorum {
  #threshold;

  #networkId;

  #protocolVersion;

  #validators;

  #allowlist;

  #allowlistRoot;

  constructor({ validators, threshold, networkId = '', protocolVersion = '1' }) {
    const normalized = normalizeValidators(validators);
    if (!Number.isSafeInteger(threshold) || threshold < 1 || threshold > normalized.length) {
      throw new PermissionedQuorumError('INVALID_THRESHOLD', 'threshold must be an integer from 1 through validator count');
    }
    this.#threshold = threshold;
    this.#networkId = String(networkId);
    this.#protocolVersion = String(protocolVersion);
    this.#validators = new Map(normalized.map((item) => [item.id, item]));
    this.#allowlist = Object.freeze(normalized.map((item) => Object.freeze({
      id: item.id,
      publicKey: item.publicKeyDer.toString('hex'),
    })));
    this.#allowlistRoot = digest(DOMAIN_ALLOWLIST, {
      policy: POLICY,
      networkId: this.#networkId,
      protocolVersion: this.#protocolVersion,
      threshold,
      validators: this.#allowlist,
    }).toString('hex');
  }

  get threshold() { return this.#threshold; }

  get networkId() { return this.#networkId; }

  get protocolVersion() { return this.#protocolVersion; }

  get validatorCount() { return this.#validators.size; }

  get allowlist() { return this.#allowlist; }

  get allowlistRoot() { return this.#allowlistRoot; }

  statement(proposal) {
    const statement = normalizeStatement({
      ...proposal,
      networkId: proposal.networkId ?? this.#networkId,
      protocolVersion: proposal.protocolVersion ?? this.#protocolVersion,
    });
    if (statement.networkId !== this.#networkId || statement.protocolVersion !== this.#protocolVersion) {
      throw new PermissionedQuorumError('WRONG_NETWORK', 'proposal network/version does not match this permissioned set');
    }
    return statement;
  }

  statementHash(proposal) { return digest(DOMAIN_STATEMENT, this.statement(proposal)).toString('hex'); }

  message(proposal) {
    const statement = this.statement(proposal);
    return Buffer.concat([DOMAIN_VOTE, canonicalBytes({
      policy: POLICY,
      threshold: this.#threshold,
      validatorCount: this.#validators.size,
      allowlistRoot: this.#allowlistRoot,
      statement,
    })]);
  }

  createVote(proposal, signerId, privateKey) {
    const id = validatorId(signerId);
    const validator = this.#validators.get(id);
    if (!validator) throw new PermissionedQuorumError('SIGNER_NOT_ALLOWLISTED', `validator ${id} is not allowlisted`);
    const privateObject = privateKeyObject(privateKey);
    if (privateObject.asymmetricKeyType !== 'ed25519') {
      throw new PermissionedQuorumError('WRONG_KEY_TYPE', 'validator private key must be Ed25519');
    }
    const derived = publicDer(createPublicKey(privateObject));
    if (!derived.equals(validator.publicKeyDer)) {
      throw new PermissionedQuorumError('KEY_MISMATCH', `private key does not belong to validator ${id}`);
    }
    const statement = this.statement(proposal);
    return Object.freeze({
      version: 1,
      policy: POLICY,
      signerId: id,
      allowlistRoot: this.#allowlistRoot,
      statementHash: digest(DOMAIN_STATEMENT, statement).toString('hex'),
      signature: edSign(null, this.message(statement), privateObject).toString('hex'),
    });
  }

  verifyVote(proposal, vote) {
    assertExactFields(vote, ['version', 'policy', 'signerId', 'allowlistRoot', 'statementHash', 'signature'], 'vote');
    if (!vote || vote.version !== 1 || vote.policy !== POLICY) {
      throw new PermissionedQuorumError('INVALID_VOTE', 'unsupported permissioned vote');
    }
    const id = validatorId(vote.signerId);
    const validator = this.#validators.get(id);
    if (!validator) throw new PermissionedQuorumError('SIGNER_NOT_ALLOWLISTED', `validator ${id} is not allowlisted`);
    if (lowerHex(vote.allowlistRoot, 32, 'vote allowlistRoot') !== this.#allowlistRoot) {
      throw new PermissionedQuorumError('ALLOWLIST_MISMATCH', 'vote belongs to another permissioned validator set');
    }
    const statement = this.statement(proposal);
    const expectedHash = digest(DOMAIN_STATEMENT, statement).toString('hex');
    if (lowerHex(vote.statementHash, 32, 'vote statementHash') !== expectedHash) {
      throw new PermissionedQuorumError('STATEMENT_MISMATCH', 'vote signs another closure statement');
    }
    const signature = Buffer.from(lowerHex(vote.signature, 64, 'vote signature'), 'hex');
    if (!edVerify(null, this.message(statement), validator.keyObject, signature)) {
      throw new PermissionedQuorumError('INVALID_SIGNATURE', `invalid Ed25519 vote from ${id}`);
    }
    return true;
  }

  assembleCertificate(proposal, votes) {
    if (!Array.isArray(votes)) throw new PermissionedQuorumError('INVALID_VOTES', 'votes must be an array');
    const statement = this.statement(proposal);
    const unique = new Map();
    for (const vote of votes) {
      this.verifyVote(statement, vote);
      if (unique.has(vote.signerId)) {
        throw new PermissionedQuorumError('DUPLICATE_SIGNER', `validator ${vote.signerId} voted more than once`);
      }
      unique.set(vote.signerId, Object.freeze({ signerId: vote.signerId, signature: vote.signature }));
    }
    if (unique.size < this.#threshold) {
      throw new PermissionedQuorumError('THRESHOLD_NOT_MET', `certificate needs ${this.#threshold} unique valid signatures`, {
        valid: unique.size,
        required: this.#threshold,
      });
    }
    const certificate = {
      version: 1,
      policy: POLICY,
      scope: 'permissioned-k-of-n',
      threshold: this.#threshold,
      validatorCount: this.#validators.size,
      allowlistRoot: this.#allowlistRoot,
      statement,
      statementHash: digest(DOMAIN_STATEMENT, statement).toString('hex'),
      signatures: Object.freeze([...unique.values()]
        .sort((a, b) => compareUtf8(a.signerId, b.signerId))
        .map((item) => Object.freeze(item))),
    };
    certificate.id = digest(DOMAIN_CERTIFICATE, certificate).toString('hex');
    return Object.freeze(certificate);
  }

  verifyCertificate(certificate, proposal = undefined) {
    assertExactFields(certificate, [
      'version', 'policy', 'scope', 'threshold', 'validatorCount', 'allowlistRoot',
      'statement', 'statementHash', 'signatures', 'id',
    ], 'certificate');
    if (!certificate || certificate.version !== 1 || certificate.policy !== POLICY || certificate.scope !== 'permissioned-k-of-n') {
      throw new PermissionedQuorumError('INVALID_CERTIFICATE', 'unsupported permissioned certificate');
    }
    if (certificate.threshold !== this.#threshold || certificate.validatorCount !== this.#validators.size) {
      throw new PermissionedQuorumError('POLICY_MISMATCH', 'certificate k-of-n policy differs from local policy');
    }
    if (lowerHex(certificate.allowlistRoot, 32, 'certificate allowlistRoot') !== this.#allowlistRoot) {
      throw new PermissionedQuorumError('ALLOWLIST_MISMATCH', 'certificate belongs to another validator allowlist');
    }
    const statement = this.statement(proposal ?? certificate.statement);
    assertExactFields(certificate.statement, [
      'networkId', 'protocolVersion', 'sequence', 'constellationId', 'previousRoot',
      'nextRoot', 'transitionTrace', 'pcc',
    ], 'certificate statement');
    if (!canonicalBytes(statement).equals(canonicalBytes(certificate.statement))) {
      throw new PermissionedQuorumError('STATEMENT_MISMATCH', 'certificate statement differs from expected proposal');
    }
    const expectedStatementHash = digest(DOMAIN_STATEMENT, statement).toString('hex');
    if (lowerHex(certificate.statementHash, 32, 'certificate statementHash') !== expectedStatementHash) {
      throw new PermissionedQuorumError('STATEMENT_MISMATCH', 'certificate statement hash is invalid');
    }
    if (!Array.isArray(certificate.signatures)) {
      throw new PermissionedQuorumError('INVALID_CERTIFICATE', 'certificate signatures must be an array');
    }
    const seen = new Set();
    let valid = 0;
    let previousSigner = null;
    for (const item of certificate.signatures) {
      assertExactFields(item, ['signerId', 'signature'], 'certificate signature');
      const id = validatorId(item.signerId);
      if (previousSigner !== null && compareUtf8(previousSigner, id) >= 0) {
        throw new PermissionedQuorumError('NON_CANONICAL_SIGNER_ORDER', 'certificate signers must be strictly bytewise sorted');
      }
      previousSigner = id;
      if (seen.has(id)) throw new PermissionedQuorumError('DUPLICATE_SIGNER', `duplicate certificate signer ${id}`);
      seen.add(id);
      const vote = {
        version: 1,
        policy: POLICY,
        signerId: id,
        allowlistRoot: this.#allowlistRoot,
        statementHash: expectedStatementHash,
        signature: item.signature,
      };
      this.verifyVote(statement, vote);
      valid += 1;
    }
    if (valid < this.#threshold || valid > this.#validators.size) {
      throw new PermissionedQuorumError('THRESHOLD_NOT_MET', `certificate has ${valid}/${this.#threshold} required signatures`);
    }
    const unsigned = { ...certificate };
    delete unsigned.id;
    const expectedId = digest(DOMAIN_CERTIFICATE, unsigned).toString('hex');
    if (lowerHex(certificate.id, 32, 'certificate id') !== expectedId) {
      throw new PermissionedQuorumError('CERTIFICATE_ID_MISMATCH', 'certificate id is invalid');
    }
    return true;
  }
}

module.exports = {
  POLICY,
  PermissionedQuorum,
  PermissionedQuorumError,
  normalizeStatement,
  publicKeyObject,
  privateKeyObject,
};
