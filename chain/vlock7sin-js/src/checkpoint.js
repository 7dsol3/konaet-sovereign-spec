'use strict';

const { createHash } = require('node:crypto');
const { canonicalBytes, compareUtf8, normalizeId } = require('./causalGraph');
const { assertPublicLedgerSafe } = require('./privacy');
const { verifyHybridSignature } = require('./hybridCrypto');

const CHECKPOINT_SCHEMA = 'vlock7sin-causal-checkpoint-v1';
const SIGNED_CHECKPOINT_SCHEMA = 'vlock7sin-signed-causal-checkpoint-v1';
const ANCHOR_INTENT_SCHEMA = 'vlock7sin-external-anchor-intent-v1';
const DOMAIN_EVENT_LEAF = Buffer.from('VLOCK7SIN/CHECKPOINT-EVENT-LEAF/v1\0', 'ascii');
const DOMAIN_EVENT_NODE = Buffer.from('VLOCK7SIN/CHECKPOINT-EVENT-NODE/v1\0', 'ascii');
const DOMAIN_EVENT_EMPTY = Buffer.from('VLOCK7SIN/CHECKPOINT-EVENT-EMPTY/v1\0', 'ascii');
const DOMAIN_CHECKPOINT = Buffer.from('VLOCK7SIN/CAUSAL-CHECKPOINT/v1\0', 'ascii');
const DOMAIN_MANIFEST = Buffer.from('VLOCK7SIN/CHECKPOINT-MANIFEST/v1\0', 'ascii');
const DOMAIN_ANCHOR_INTENT = Buffer.from('VLOCK7SIN/ANCHOR-INTENT/v1\0', 'ascii');
const ZERO_HASH = '00'.repeat(32);
const BITCOIN_MAGIC = Buffer.from('V7CP', 'ascii');
const EVM_ANCHOR_CHECKPOINT_SELECTOR = Buffer.from('641fa644', 'hex');

class CheckpointError extends Error {
  constructor(code, message, details = undefined) {
    super(message);
    this.name = 'CheckpointError';
    this.code = code;
    if (details !== undefined) this.details = details;
  }
}

function exactFields(value, expected, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new CheckpointError('INVALID_RECORD', `${label} must be an object`);
  }
  const actual = Object.keys(value).sort(compareUtf8);
  const wanted = [...expected].sort(compareUtf8);
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw new CheckpointError('INVALID_RECORD', `${label} has missing or unexpected fields`);
  }
}

function hex(value, bytes, label, { allowZero = true } = {}) {
  const normalized = Buffer.isBuffer(value) || value instanceof Uint8Array
    ? Buffer.from(value).toString('hex')
    : String(value ?? '').toLowerCase().replace(/^0x/, '');
  if (!new RegExp(`^[0-9a-f]{${bytes * 2}}$`).test(normalized)
    || (!allowZero && /^0+$/.test(normalized))) {
    throw new CheckpointError('INVALID_HASH', `${label} must be ${bytes}-byte canonical lowercase hex`);
  }
  return normalized;
}

function uintString(value, label, maximum = 0xffffffffffffffffn) {
  let number;
  try { number = BigInt(value); } catch {
    throw new CheckpointError('INVALID_INTEGER', `${label} must be an unsigned integer`);
  }
  if (number < 0n || number > maximum) throw new CheckpointError('INVALID_INTEGER', `${label} is outside its range`);
  return number.toString(10);
}

function safeIdentifier(value, label, maximum = 128) {
  const text = String(value ?? '').normalize('NFC');
  if (text.length < 1 || text.length > maximum || !/^[A-Za-z0-9][A-Za-z0-9_.:-]*$/.test(text)) {
    throw new CheckpointError('INVALID_IDENTIFIER', `${label} must be safe ASCII`);
  }
  return text;
}

function eventLeaf(eventId) {
  return createHash('sha3-256').update(DOMAIN_EVENT_LEAF).update(Buffer.from(normalizeId(eventId), 'hex')).digest();
}

function eventLevels(eventIds) {
  if (!Array.isArray(eventIds)) throw new CheckpointError('INVALID_EVENTS', 'eventIds must be an array');
  if (eventIds.length > 1_000_000) throw new CheckpointError('TOO_MANY_EVENTS', 'checkpoint event count exceeds 1000000');
  const normalized = eventIds.map((id) => normalizeId(id, 'checkpoint event id'));
  if (new Set(normalized).size !== normalized.length) throw new CheckpointError('DUPLICATE_EVENT', 'checkpoint event ids must be unique');
  const levels = normalized.length ? [normalized.map(eventLeaf)] : [];
  while (levels.length && levels[levels.length - 1].length > 1) {
    const current = levels[levels.length - 1];
    const next = [];
    for (let index = 0; index < current.length; index += 2) {
      if (index + 1 >= current.length) next.push(current[index]);
      else next.push(createHash('sha3-256').update(DOMAIN_EVENT_NODE).update(current[index]).update(current[index + 1]).digest());
    }
    levels.push(next);
  }
  return { normalized, levels };
}

function computeEventRoot(eventIds) {
  const { levels } = eventLevels(eventIds);
  return levels.length
    ? levels[levels.length - 1][0].toString('hex')
    : createHash('sha3-256').update(DOMAIN_EVENT_EMPTY).digest('hex');
}

function createEventProof(eventIds, eventIndex) {
  const { normalized, levels } = eventLevels(eventIds);
  if (!Number.isSafeInteger(eventIndex) || eventIndex < 0 || eventIndex >= normalized.length) {
    throw new CheckpointError('INVALID_EVENT_INDEX', 'event proof index is invalid');
  }
  const siblings = [];
  let index = eventIndex;
  for (let levelIndex = 0; levelIndex < levels.length - 1; levelIndex += 1) {
    const level = levels[levelIndex];
    const siblingIndex = index % 2 === 0 ? index + 1 : index - 1;
    if (siblingIndex < level.length) {
      siblings.push(Object.freeze({
        side: index % 2 === 0 ? 'right' : 'left',
        hash: level[siblingIndex].toString('hex'),
      }));
    }
    index = Math.floor(index / 2);
  }
  return Object.freeze({
    schema: 'vlock7sin-checkpoint-event-proof-v1',
    version: 1,
    eventId: normalized[eventIndex],
    eventIndex,
    eventCount: normalized.length,
    siblings: Object.freeze(siblings),
    eventRoot: levels[levels.length - 1][0].toString('hex'),
  });
}

function verifyEventProof(proof, expectedRoot = undefined) {
  try {
    exactFields(proof, ['schema', 'version', 'eventId', 'eventIndex', 'eventCount', 'siblings', 'eventRoot'], 'event proof');
    if (proof.schema !== 'vlock7sin-checkpoint-event-proof-v1' || proof.version !== 1
      || !Number.isSafeInteger(proof.eventIndex) || !Number.isSafeInteger(proof.eventCount)
      || proof.eventCount < 1 || proof.eventIndex < 0 || proof.eventIndex >= proof.eventCount
      || !Array.isArray(proof.siblings)) return false;
    let current = eventLeaf(proof.eventId);
    let index = proof.eventIndex;
    let count = proof.eventCount;
    let cursor = 0;
    while (count > 1) {
      const hasSibling = index % 2 === 1 || index + 1 < count;
      if (hasSibling) {
        const sibling = proof.siblings[cursor];
        exactFields(sibling, ['side', 'hash'], 'event proof sibling');
        const expectedSide = index % 2 === 0 ? 'right' : 'left';
        if (sibling.side !== expectedSide) return false;
        const siblingHash = Buffer.from(hex(sibling.hash, 32, 'event proof sibling'), 'hex');
        current = expectedSide === 'left'
          ? createHash('sha3-256').update(DOMAIN_EVENT_NODE).update(siblingHash).update(current).digest()
          : createHash('sha3-256').update(DOMAIN_EVENT_NODE).update(current).update(siblingHash).digest();
        cursor += 1;
      }
      index = Math.floor(index / 2);
      count = Math.ceil(count / 2);
    }
    if (cursor !== proof.siblings.length) return false;
    return current.toString('hex') === hex(expectedRoot ?? proof.eventRoot, 32, 'event root');
  } catch {
    return false;
  }
}

function checkpointStatement(input) {
  const eventIds = input.eventIds.map((id) => normalizeId(id, 'checkpoint event id'));
  if (eventIds.length < 1) throw new CheckpointError('EMPTY_CHECKPOINT', 'checkpoint must commit at least one event');
  if (new Set(eventIds).size !== eventIds.length) throw new CheckpointError('DUPLICATE_EVENT', 'checkpoint event ids must be unique');
  const statement = Object.freeze({
    schema: CHECKPOINT_SCHEMA,
    version: 1,
    networkId: safeIdentifier(input.networkId, 'networkId'),
    protocolVersion: safeIdentifier(input.protocolVersion, 'protocolVersion'),
    sequence: uintString(input.sequence, 'sequence'),
    createdAtUnixMs: uintString(input.createdAtUnixMs, 'createdAtUnixMs'),
    previousCheckpointId: hex(input.previousCheckpointId ?? ZERO_HASH, 32, 'previous checkpoint id'),
    eventCount: eventIds.length,
    eventIds: Object.freeze(eventIds),
    eventRoot: computeEventRoot(eventIds),
    stateRoot: hex(input.stateRoot, 32, 'state root', { allowZero: false }),
    policyRoot: hex(input.policyRoot, 32, 'policy root', { allowZero: false }),
    privacyRoot: hex(input.privacyRoot, 32, 'privacy root'),
    closureCertificateId: hex(input.closureCertificateId, 32, 'closure certificate id', { allowZero: false }),
  });
  assertPublicLedgerSafe(statement);
  return statement;
}

function createCheckpoint(input) {
  if (!input || typeof input !== 'object' || !Array.isArray(input.eventIds)) {
    throw new CheckpointError('INVALID_CHECKPOINT', 'checkpoint input and eventIds are required');
  }
  const statement = checkpointStatement(input);
  const bytes = canonicalBytes(statement);
  return Object.freeze({
    ...statement,
    manifestSha3_512: createHash('sha3-512').update(DOMAIN_MANIFEST).update(bytes).digest('hex'),
    checkpointId: createHash('sha3-256').update(DOMAIN_CHECKPOINT).update(bytes).digest('hex'),
  });
}

function verifyCheckpoint(checkpoint) {
  try {
    exactFields(checkpoint, [
      'schema', 'version', 'networkId', 'protocolVersion', 'sequence', 'createdAtUnixMs',
      'previousCheckpointId', 'eventCount', 'eventIds', 'eventRoot', 'stateRoot', 'policyRoot',
      'privacyRoot', 'closureCertificateId', 'manifestSha3_512', 'checkpointId',
    ], 'checkpoint');
    if (!Array.isArray(checkpoint.eventIds) || checkpoint.eventCount !== checkpoint.eventIds.length) return false;
    const rebuilt = createCheckpoint(checkpoint);
    return canonicalBytes(rebuilt).equals(canonicalBytes(checkpoint));
  } catch {
    return false;
  }
}

function createCheckpointFromClosure(closure, options = {}) {
  if (!closure || !Array.isArray(closure.actIds) || !closure.certificate) {
    throw new CheckpointError('CERTIFIED_CLOSURE_REQUIRED', 'checkpoint requires a certified closure with actIds');
  }
  if (!options.quorum || typeof options.quorum.verifyCertificate !== 'function') {
    throw new CheckpointError('QUORUM_VERIFIER_REQUIRED', 'checkpoint construction requires a quorum verifier');
  }
  let certificateValid;
  try { certificateValid = options.quorum.verifyCertificate(closure.certificate, closure); } catch (cause) {
    throw new CheckpointError('INVALID_CLOSURE_CERTIFICATE', 'closure certificate verification failed', { cause: cause.message });
  }
  if (certificateValid !== true) {
    throw new CheckpointError('INVALID_CLOSURE_CERTIFICATE', 'closure certificate verifier did not positively accept certificate');
  }
  return createCheckpoint({
    networkId: closure.networkId,
    protocolVersion: closure.protocolVersion,
    sequence: closure.sequence,
    createdAtUnixMs: options.createdAtUnixMs,
    previousCheckpointId: options.previousCheckpointId,
    eventIds: closure.actIds,
    stateRoot: closure.nextRoot,
    policyRoot: options.policyRoot,
    privacyRoot: options.privacyRoot,
    closureCertificateId: closure.certificate.id,
  });
}

function signCheckpoint(checkpoint, hybridIdentity) {
  if (!verifyCheckpoint(checkpoint) || !hybridIdentity || typeof hybridIdentity.sign !== 'function'
    || typeof hybridIdentity.publicIdentity !== 'function') {
    throw new CheckpointError('INVALID_SIGNER', 'valid checkpoint and hybrid identity are required');
  }
  const record = Object.freeze({
    schema: SIGNED_CHECKPOINT_SCHEMA,
    version: 1,
    checkpoint,
    signer: hybridIdentity.publicIdentity(),
    signature: hybridIdentity.sign(canonicalBytes(checkpoint)),
  });
  assertPublicLedgerSafe(record);
  return record;
}

function verifySignedCheckpoint(record) {
  try {
    exactFields(record, ['schema', 'version', 'checkpoint', 'signer', 'signature'], 'signed checkpoint');
    return record.schema === SIGNED_CHECKPOINT_SCHEMA && record.version === 1
      && verifyCheckpoint(record.checkpoint)
      && verifyHybridSignature(record.signer, canonicalBytes(record.checkpoint), record.signature)
      && assertPublicLedgerSafe(record);
  } catch {
    return false;
  }
}

function anchorTransport(anchorType, checkpointId) {
  const commitment = Buffer.from(checkpointId, 'hex');
  if (anchorType === 'bitcoin-op-return-v1') {
    const payload = Buffer.concat([BITCOIN_MAGIC, Buffer.from([1]), commitment]);
    return Object.freeze({
      payloadEncoding: 'bitcoin-op-return-script-pubkey',
      payloadHex: Buffer.concat([Buffer.from([0x6a, payload.length]), payload]).toString('hex'),
    });
  }
  if (anchorType === 'evm-calldata-v1') {
    return Object.freeze({
      payloadEncoding: 'evm-anchorCheckpoint-bytes32-calldata',
      payloadHex: Buffer.concat([EVM_ANCHOR_CHECKPOINT_SELECTOR, commitment]).toString('hex'),
    });
  }
  if (anchorType === 'generic-content-addressed-v1') {
    return Object.freeze({ payloadEncoding: 'raw-checkpoint-id', payloadHex: commitment.toString('hex') });
  }
  throw new CheckpointError('UNSUPPORTED_ANCHOR', `unsupported anchor type ${anchorType}`);
}

function validateAnchorDestination(anchorType, destination) {
  if (anchorType === 'bitcoin-op-return-v1' && destination !== '') {
    throw new CheckpointError('INVALID_DESTINATION', 'Bitcoin OP_RETURN anchor must not declare a destination address');
  }
  if (anchorType === 'evm-calldata-v1'
    && (!/^0x[0-9a-f]{40}$/.test(destination) || /^0x0{40}$/.test(destination))) {
    throw new CheckpointError('INVALID_DESTINATION', 'EVM anchor requires a non-zero canonical lowercase address');
  }
}

function createAnchorIntent(checkpoint, options = {}) {
  if (!verifyCheckpoint(checkpoint)) throw new CheckpointError('INVALID_CHECKPOINT', 'anchor intent requires a valid checkpoint');
  const anchorType = safeIdentifier(options.anchorType, 'anchorType');
  const transport = anchorTransport(anchorType, checkpoint.checkpointId);
  const requiredConfirmations = Number(uintString(
    options.requiredConfirmations ?? 1,
    'required confirmations',
    1_000_000n,
  ));
  if (requiredConfirmations < 1) {
    throw new CheckpointError('INVALID_CONFIRMATION_POLICY', 'anchor intent requires at least one confirmation');
  }
  const statement = Object.freeze({
    schema: ANCHOR_INTENT_SCHEMA,
    version: 1,
    anchorType,
    network: safeIdentifier(options.network, 'anchor network'),
    destination: options.destination == null ? '' : String(options.destination),
    requiredConfirmations,
    checkpointId: checkpoint.checkpointId,
    manifestSha3_512: checkpoint.manifestSha3_512,
    payloadEncoding: transport.payloadEncoding,
    payloadHex: transport.payloadHex,
  });
  const destinationHasControl = [...statement.destination]
    .some((character) => character.charCodeAt(0) <= 0x1f);
  if (statement.destination.length > 256 || /\s/.test(statement.destination) || destinationHasControl) {
    throw new CheckpointError('INVALID_DESTINATION', 'anchor destination is invalid');
  }
  validateAnchorDestination(anchorType, statement.destination);
  assertPublicLedgerSafe(statement);
  return Object.freeze({
    ...statement,
    intentId: createHash('sha3-256').update(DOMAIN_ANCHOR_INTENT).update(canonicalBytes(statement)).digest('hex'),
  });
}

function verifyAnchorIntent(intent) {
  try {
    exactFields(intent, [
      'schema', 'version', 'anchorType', 'network', 'destination', 'requiredConfirmations',
      'checkpointId', 'manifestSha3_512', 'payloadEncoding', 'payloadHex', 'intentId',
    ], 'anchor intent');
    const transport = anchorTransport(intent.anchorType, hex(intent.checkpointId, 32, 'checkpoint id', { allowZero: false }));
    validateAnchorDestination(intent.anchorType, intent.destination);
    if (intent.schema !== ANCHOR_INTENT_SCHEMA || intent.version !== 1
      || !Number.isSafeInteger(intent.requiredConfirmations) || intent.requiredConfirmations < 1
      || transport.payloadEncoding !== intent.payloadEncoding || transport.payloadHex !== intent.payloadHex
      || !/^[0-9a-f]{128}$/.test(String(intent.manifestSha3_512))) return false;
    const statement = { ...intent };
    delete statement.intentId;
    const expected = createHash('sha3-256').update(DOMAIN_ANCHOR_INTENT).update(canonicalBytes(statement)).digest('hex');
    return expected === intent.intentId && assertPublicLedgerSafe(intent);
  } catch {
    return false;
  }
}

function verifyAnchorObservation(intent, observation) {
  if (!verifyAnchorIntent(intent) || !observation || typeof observation !== 'object') {
    return Object.freeze({ commitmentMatches: false, confirmationGate: false, externalTruthProven: false });
  }
  const commitmentMatches = String(observation.observedPayloadHex || '').toLowerCase() === intent.payloadHex;
  const confirmations = Number(observation.confirmations);
  const confirmationGate = commitmentMatches && Number.isSafeInteger(confirmations)
    && confirmations >= intent.requiredConfirmations;
  return Object.freeze({
    commitmentMatches,
    confirmationGate,
    externalTruthProven: false,
    statement: 'Cryptographic consistency only; an independent chain client must authenticate the external observation.',
  });
}

module.exports = Object.freeze({
  CHECKPOINT_SCHEMA,
  SIGNED_CHECKPOINT_SCHEMA,
  ANCHOR_INTENT_SCHEMA,
  CheckpointError,
  computeEventRoot,
  createEventProof,
  verifyEventProof,
  createCheckpoint,
  verifyCheckpoint,
  createCheckpointFromClosure,
  signCheckpoint,
  verifySignedCheckpoint,
  createAnchorIntent,
  verifyAnchorIntent,
  verifyAnchorObservation,
});
