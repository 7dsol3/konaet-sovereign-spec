'use strict';

const EventEmitter = require('node:events');
const { ContractEvent } = require('../../vlock7sin-js/src/contractEvent');
const { runtime: koRuntime, auth: koAuth } = require('../../vlock7sin-js/src/koProgramRuntime');
const fs = require('node:fs');
const path = require('node:path');
const {
  PermissionedQuorum,
  HybridPermissionedQuorum,
  VlockLedger,
  WalStore,
  recoverWal,
  recoverAbandonedWriterLock,
  createTransfer,
  decodeEvent,
  normalizeAct,
} = require('../../vlock7sin-js/src');
const { canonicalBytes } = require('../../vlock7sin-js/src/causalGraph');
const { validateGenesis, stateFromGenesis, HYBRID_PROFILE, HYBRID_TRANSFER_PROFILE,
  HYBRID_TRANSPORT_PROFILE, HYBRID_BINARY_TRANSPORT_PROFILE } = require('./SovereignGenesis');
const { VoteJournal } = require('./VoteJournal');
const { RoundChangeQuorum } = require('./RoundChangeQuorum');
const { HybridRoundChangeQuorum } = require('./HybridRoundChangeQuorum');
const { RoundChangeJournal } = require('./RoundChangeJournal');
const { VlockWebSocketTransport } = require('./VlockWebSocketTransport');

const CLOSURE_KIND = 'VLOCK7SIN_CLOSURE_COMMIT';
const COMMIT_ACK_KIND = 'KONAET_CLOSURE_ACK_V1';
const COMMIT_RETRY_DELAYS_MS = Object.freeze([100, 250, 500, 1000]);

class SovereignNodeError extends Error {
  constructor(code, message, details = undefined) {
    super(message);
    this.name = 'SovereignNodeError';
    this.code = code;
    if (details !== undefined) this.details = details;
  }
}

function canonicalU64(value, label, minimum = 0n) {
  try {
    const number = BigInt(value);
    if (number < minimum || number > 0xffffffffffffffffn) throw new Error('outside u64');
    return number.toString(10);
  } catch {
    throw new SovereignNodeError('INVALID_MESSAGE', `${label} must be a canonical u64.`);
  }
}

function canonicalRound(value, validatorCount) {
  const round = Number(value ?? 0);
  if (!Number.isSafeInteger(round) || round < 0 || round >= validatorCount) {
    throw new SovereignNodeError('INVALID_ROUND', `Round must be 0..${validatorCount - 1}.`);
  }
  return round;
}

function exactBuffer(value, label, maximum = 64 * 1024) {
  if (!Buffer.isBuffer(value) && !(value instanceof Uint8Array)) {
    throw new SovereignNodeError('INVALID_MESSAGE', `${label} must be binary.`);
  }
  const bytes = Buffer.from(value);
  if (!bytes.length || bytes.length > maximum) throw new SovereignNodeError('INVALID_MESSAGE', `${label} has an invalid length.`);
  return bytes;
}

function sameCanonical(left, right) {
  try { return canonicalBytes(left).equals(canonicalBytes(right)); } catch { return false; }
}

function proposalFieldsEqual(proposal, record) {
  const fields = ['networkId', 'protocolVersion', 'sequence', 'constellationId', 'previousRoot', 'nextRoot', 'transitionTrace', 'pcc'];
  return fields.every((field) => String(proposal[field]) === String(record[field]))
    && Array.isArray(record.actIds)
    && proposal.actIds.length === record.actIds.length
    && proposal.actIds.every((id, index) => id === record.actIds[index])
    && sameCanonical(proposal.hybridTransferAuthorizations ?? [], record.hybridTransferAuthorizations ?? []);
}

class SovereignNode extends EventEmitter {
  constructor(options = {}) {
    super();
    this.genesis = validateGenesis(options.genesis);
    this.validatorId = String(options.validatorId || '');
    this.identity = options.identity;
    if (!this.identity || typeof this.identity.publicBytes !== 'function' || typeof this.identity.privateKeyObject !== 'function') {
      throw new SovereignNodeError('INVALID_IDENTITY', 'Validator requires a VLOCK Ed25519 identity.');
    }
    this.validator = this.genesis.validators.find(({ id }) => id === this.validatorId);
    if (!this.validator) throw new SovereignNodeError('VALIDATOR_NOT_ALLOWED', `${this.validatorId} is not in genesis.`);
    if (this.identity.publicBytes().toString('hex') !== this.validator.publicKey) {
      throw new SovereignNodeError('VALIDATOR_KEY_MISMATCH', 'Validator private key does not match genesis.');
    }
    this.consensusIdentity = options.consensusIdentity || null;
    if (this.genesis.consensusSignatureProfile === HYBRID_PROFILE) {
      if (!this.consensusIdentity || typeof this.consensusIdentity.publicIdentity !== 'function'
        || typeof this.consensusIdentity.sign !== 'function'
        || !canonicalBytes(this.consensusIdentity.publicIdentity()).equals(canonicalBytes(this.validator.publicIdentity))) {
        throw new SovereignNodeError('CONSENSUS_IDENTITY_MISMATCH', 'Hybrid consensus identity does not match the validator identity in genesis.');
      }
    } else if (this.consensusIdentity) {
      throw new SovereignNodeError('UNEXPECTED_CONSENSUS_IDENTITY', 'Ed25519 genesis does not accept a separate hybrid consensus identity.');
    }
    this.dataDir = path.resolve(options.dataDir || '');
    if (!this.dataDir) throw new SovereignNodeError('INVALID_DATA_DIR', 'Node data directory is required.');
    fs.mkdirSync(this.dataDir, { recursive: true, mode: 0o700 });

    this.quorum = this.genesis.consensusSignatureProfile === HYBRID_PROFILE
      ? new HybridPermissionedQuorum({
        networkId: this.genesis.networkId,
        protocolVersion: this.genesis.protocolVersion,
        threshold: this.genesis.threshold,
        validators: this.genesis.validators,
      })
      : new PermissionedQuorum({
        networkId: this.genesis.networkId,
        protocolVersion: this.genesis.protocolVersion,
        threshold: this.genesis.threshold,
        validators: this.genesis.validators,
      });
    this.roundChangeQuorum = this.genesis.consensusSignatureProfile === HYBRID_PROFILE
      ? new HybridRoundChangeQuorum({
        networkId: this.genesis.networkId,
        protocolVersion: this.genesis.protocolVersion,
        genesisId: this.genesis.genesisId,
        threshold: this.genesis.threshold,
        validators: this.genesis.validators,
      })
      : new RoundChangeQuorum({
        networkId: this.genesis.networkId,
        protocolVersion: this.genesis.protocolVersion,
        genesisId: this.genesis.genesisId,
        threshold: this.genesis.threshold,
        validators: this.genesis.validators,
      });
    this.ledgerPath = path.join(this.dataDir, 'ledger.v7wal');
    try {
    this.lockRecoveries = Object.freeze(['ledger.v7wal', 'votes.v7wal', 'round-changes.v7wal']
      .map(name => recoverAbandonedWriterLock(path.join(this.dataDir, name))).filter(Boolean));
    const recovery = fs.existsSync(this.ledgerPath)
      ? recoverWal(this.ledgerPath, { decodeRecords: true })
      : null;
    if (recovery && !recovery.clean) {
      throw new SovereignNodeError('LEDGER_RECOVERY_FAILED', 'Ledger WAL is truncated or corrupt.');
    }
    if (recovery) {
      for (const { record } of recovery.frames) {
        if (record?.kind !== CLOSURE_KIND) continue;
        const round = canonicalRound(record.round ?? 0, this.genesis.validators.length);
        this.assertRoundAuthorization(record, round, record.roundChangeCertificate ?? null);
      }
    }
    this.ledgerWal = new WalStore(this.ledgerPath);
    this.ledger = new VlockLedger({
      state: stateFromGenesis(this.genesis),
      networkId: Number(this.genesis.networkId),
      protocolVersion: this.genesis.protocolVersion,
      quorum: this.quorum,
      requireCertificate: true,
      wal: this.ledgerWal,
      requireWal: true,
      requireHybridTransferAuthorization: this.genesis.transferAuthorizationProfile === HYBRID_TRANSFER_PROFILE,
      nativePolicy: this.genesis.nativePolicy ?? null,
      maxActs: this.genesis.parameters.maxActs,
      maxBytes: this.genesis.parameters.maxBytes,
    });
    if (recovery && recovery.frames.length) this.ledger.recover(recovery);
    this.closureFrames = new Map();
    for (const frame of recovery?.frames ?? []) {
      if (frame.record?.kind === CLOSURE_KIND) this.closureFrames.set(String(frame.record.sequence),
        Object.freeze({ offset: frame.offset, endOffset: frame.endOffset, length: frame.length, hash: frame.hash }));
    }
    this.voteJournal = new VoteJournal(path.join(this.dataDir, 'votes.v7wal'), { allowedRoot: this.dataDir });
    this.roundChangeJournal = new RoundChangeJournal(path.join(this.dataDir, 'round-changes.v7wal'), {
      allowedRoot: this.dataDir,
    });
    this.actBytes = new Map();
    this.prepared = new Map();
    this.rounds = new Map();
    this.pendingSince = new Map();
    this.consensusTimers = new Map();
    this.commitDeliveries = new Map();
    this.lastCommitDelivery = null;
    this.automaticConsensus = options.automaticConsensus === true;
    this.roundTimeoutMs = Number(options.roundTimeoutMs ?? 1000);
    this.proposalDelayMs = Number(options.proposalDelayMs ?? 100);
    if (!Number.isSafeInteger(this.roundTimeoutMs) || this.roundTimeoutMs < 10 || this.roundTimeoutMs > 60000
      || !Number.isSafeInteger(this.proposalDelayMs) || this.proposalDelayMs < 0 || this.proposalDelayMs > 10000) {
      throw new SovereignNodeError('INVALID_TIMEOUT_POLICY', 'Round timeout or proposal delay is outside the local safe range.');
    }
    this.started = false;
    const trustedKeys = Object.fromEntries(this.genesis.validators.map(({ id, publicKey }) => [id, publicKey]));
    const hybridTransportRequired = [HYBRID_TRANSPORT_PROFILE, HYBRID_BINARY_TRANSPORT_PROFILE]
      .includes(this.genesis.transportSignatureProfile);
    this.transport = new VlockWebSocketTransport({
      identity: this.identity,
      validatorId: this.validatorId,
      networkId: this.genesis.networkId,
      protocolVersion: this.genesis.protocolVersion,
      genesisId: this.genesis.genesisId,
      transportSignatureProfile: this.genesis.transportSignatureProfile || null,
      hybridIdentity: hybridTransportRequired ? this.consensusIdentity : null,
      trustedHybridIdentities: hybridTransportRequired
        ? Object.fromEntries(this.genesis.validators.map(({ id, publicIdentity }) => [id, publicIdentity])) : undefined,
      dataDir: this.dataDir,
      trustedKeys,
      maxConnections: this.genesis.validators.length * 2,
      rateWindowMs: this.genesis.parameters.messageRateWindowMs,
      rateLimit: this.genesis.parameters.messageRateLimit,
      tls: options.transportTls || null,
      helloProvider: () => ({ sequence: this.ledger.sequence.toString(10), root: this.ledger.root }),
    });
    this.transport.on('message', (message) => {
      Promise.resolve().then(() => this.handleMessage(message)).catch((error) => {
        this.emit('protocolError', { error, senderId: message.senderId, type: message.type });
      });
    });
    this.transport.on('denied', (event) => this.emit('transportDenied', event));
    this.transport.on('socketError', (event) => this.emit('socketError', event));
    } catch (error) {
      for (const resource of [this.roundChangeJournal, this.voteJournal, this.ledgerWal]) {
        try { resource?.close(); } catch { /* Preserve the initialization error. */ }
      }
      throw error;
    }
  }

  expectedLeader(sequence = this.ledger.sequence + 1n, round = 0) {
    const value = BigInt(sequence);
    if (value < 1n) throw new SovereignNodeError('INVALID_SEQUENCE', 'Closure sequence must be positive.');
    const canonical = canonicalRound(round, this.genesis.validators.length);
    const index = Number((value - 1n + BigInt(canonical)) % BigInt(this.genesis.validators.length));
    return this.genesis.validators[index].id;
  }

  consensusSigner() {
    return this.consensusIdentity || this.identity.privateKeyObject();
  }

  roundKey(sequence, round) {
    return `${canonicalU64(sequence, 'round sequence', 1n)}:${canonicalRound(round, this.genesis.validators.length)}`;
  }

  async start(options = {}) {
    const address = await this.transport.listen(options);
    this.started = true;
    if (this.actBytes.size) this.scheduleConsensus();
    return Object.freeze({ validatorId: this.validatorId, address, sequence: this.ledger.sequence.toString(10), root: this.ledger.root });
  }

  async connect(url, expectedPeerId) {
    if (!this.started) throw new SovereignNodeError('NODE_NOT_STARTED', 'Start node listener before connecting peers.');
    return this.transport.connect(url, { expectedPeerId });
  }

  createTransfer(options = {}) {
    const sender = options.sender;
    if (!sender || typeof sender.publicBytes !== 'function' || typeof sender.privateKeyObject !== 'function') {
      throw new SovereignNodeError('INVALID_SENDER', 'Sender VLOCK identity is required.');
    }
    const state = this.ledger.getState();
    const senderAddress = sender.address();
    return createTransfer({
      networkId: Number(this.genesis.networkId),
      sequence: this.ledger.sequence + 1n,
      nonce: state.getNonce(senderAddress) + 1n,
      timestampMs: BigInt(options.timestampMs ?? Date.now()),
      previousRoot: state.root(),
      amountAtomic: BigInt(options.amountAtomic),
      senderPublicKey: sender.publicBytes(),
      receiverAddress: options.receiverAddress,
      memo: options.memo || '',
    }, sender);
  }

  submitTransfer(eventLike, options = {}) {
    const event = normalizeAct(eventLike);
    if (event instanceof ContractEvent) throw new SovereignNodeError('INVALID_TRANSFER_TYPE', 'Use submitContract for typed contract events.');
    return this.#submitEvent(event, options);
  }

  createContractDeployment({ sender, source, salt = '0', gasLimit = 10000 }) {
    if (!this.genesis.contractRuntime || !sender?.privateKeyObject) throw new SovereignNodeError('KO_PROGRAM_NOT_ACTIVE', 'v7 genesis and a signing identity are required.');
    const artifact = koRuntime.compileContract(source), envelope = koAuth.signDeployment(artifact,
      { networkId: this.genesis.networkId, salt, gasLimit }, sender.privateKeyObject());
    return this.#contractEvent(sender, envelope, source);
  }

  createContractCall({ sender, contractId, method, args = [], gasLimit = 10000 }) {
    if (!this.genesis.contractRuntime || !sender?.privateKeyObject) throw new SovereignNodeError('KO_PROGRAM_NOT_ACTIVE', 'v7 genesis and a signing identity are required.');
    const record = this.ledger.getState().contract(contractId);
    if (!record) throw new SovereignNodeError('CONTRACT_NOT_FOUND', 'Contract is not deployed in the current ledger.');
    const envelope = koAuth.signCall(record.artifact, record.state, { method, args, gasLimit }, sender.privateKeyObject());
    return this.#contractEvent(sender, envelope, null);
  }

  #contractEvent(sender, envelope, source) {
    const state = this.ledger.getState();
    return new ContractEvent({ envelope, source, sequence: (state.sequence + 1n).toString(),
      nonce: (state.getNonce(sender.address()) + 1n).toString(), previousRoot: state.root().toString('hex'), signature: '' }).sign(sender);
  }

  submitContract(eventLike, options = {}) {
    const event = normalizeAct(eventLike);
    if (!(event instanceof ContractEvent)) throw new SovereignNodeError('INVALID_CONTRACT_TYPE', 'Typed contract event required.');
    return this.#submitEvent(event, options);
  }

  #submitEvent(event, options) {
    const bytes = event.canonicalBytes();
    const evidence = options.authorization !== undefined || options.publicIdentity !== undefined
      ? { authorization: options.authorization, publicIdentity: options.publicIdentity } : undefined;
    const id = this.ledger.submitAct(event, evidence);
    this.actBytes.set(id, bytes);
    this.notePendingAct(event.sequence);
    if (options.broadcast !== false) {
      this.transport.broadcast('ACT', Object.freeze({ kind: event instanceof ContractEvent ? event.kind : 'KONAET_TRANSFER_V1', event: bytes,
        ...(evidence ? { authorization: evidence.authorization, publicIdentity: evidence.publicIdentity } : {}) }));
    }
    this.emit('actAccepted', { id, event });
    return id;
  }

  receiveAct(bytes, evidence = undefined) {
    const event = decodeEvent(exactBuffer(bytes, 'event'));
    const id = event.id().toString('hex');
    if (this.actBytes.has(id)) return id;
    try {
      const accepted = this.ledger.submitAct(event, evidence);
      this.actBytes.set(accepted, event.canonicalBytes());
      this.notePendingAct(event.sequence);
      this.emit('actAccepted', { id: accepted, event });
      return accepted;
    } catch (error) {
      if (error.code === 'DUPLICATE_ACT') return id;
      throw error;
    }
  }

  receiveActs(events, hybridAuthorizations = []) {
    if (!Array.isArray(events) || !Array.isArray(hybridAuthorizations)) {
      throw new SovereignNodeError('INVALID_HYBRID_AUTHORIZATION', 'Transfer events and hybrid authorizations must be arrays.');
    }
    const authorizationById = new Map();
    for (const row of hybridAuthorizations) {
      if (!row || typeof row !== 'object' || typeof row.eventId !== 'string' || authorizationById.has(row.eventId)) {
        throw new SovereignNodeError('INVALID_HYBRID_AUTHORIZATION', 'Hybrid authorization event ids must be unique.');
      }
      authorizationById.set(row.eventId, row);
    }
    const ids = events.map((bytes) => {
      const event = decodeEvent(exactBuffer(bytes, 'event'));
      const id = event.id().toString('hex');
      return this.receiveAct(bytes, authorizationById.get(id));
    });
    if (authorizationById.size && ids.length === 0) {
      throw new SovereignNodeError('INVALID_HYBRID_AUTHORIZATION', 'Hybrid authorization has no matching transfer.');
    }
    const expectedIds = new Set(ids);
    if ([...authorizationById.keys()].some((id) => !expectedIds.has(id))) {
      throw new SovereignNodeError('INVALID_HYBRID_AUTHORIZATION', 'Hybrid authorization references an unknown transfer.');
    }
    return Object.freeze(ids);
  }

  eventBytesFor(proposal) {
    return Object.freeze(proposal.actIds.map((id) => {
      const bytes = this.actBytes.get(id);
      if (!bytes) throw new SovereignNodeError('ACT_BYTES_MISSING', `Missing bytes for act ${id}.`);
      return Buffer.from(bytes);
    }));
  }

  notePendingAct(sequence) {
    const canonical = canonicalU64(sequence, 'pending act sequence', 1n);
    if (!this.pendingSince.has(canonical)) this.pendingSince.set(canonical, Date.now());
    this.scheduleConsensus();
  }

  roundEligibleAt(sequence, round) {
    const canonical = canonicalU64(sequence, 'round sequence', 1n);
    const roundNumber = canonicalRound(round, this.genesis.validators.length);
    const firstSeen = this.pendingSince.get(canonical);
    if (firstSeen === undefined) {
      throw new SovereignNodeError('ROUND_TIMEOUT_NOT_OBSERVED', `No pending act was observed for sequence ${canonical}.`);
    }
    return firstSeen + (roundNumber * this.roundTimeoutMs);
  }

  assertRoundEligible(sequence, round) {
    if (round === 0) return true;
    const eligibleAt = this.roundEligibleAt(sequence, round);
    if (Date.now() < eligibleAt) {
      throw new SovereignNodeError('ROUND_TIMEOUT_NOT_ELAPSED', `Round ${round} is not locally eligible yet.`, { eligibleAt });
    }
    return true;
  }

  async waitForRoundEligibility(sequence, round) {
    if (round === 0) return true;
    const eligibleAt = this.roundEligibleAt(sequence, round);
    const remaining = eligibleAt - Date.now();
    if (remaining > 0) await new Promise((resolve) => setTimeout(resolve, remaining));
    return true;
  }

  scheduleConsensus() {
    if (!this.automaticConsensus || !this.started || !this.actBytes.size) return;
    const sequence = this.ledger.sequence + 1n;
    const sequenceText = sequence.toString(10);
    for (let round = 0; round < this.genesis.validators.length; round += 1) {
      if (this.expectedLeader(sequence, round) !== this.validatorId) continue;
      const timerKey = this.roundKey(sequence, round);
      if (this.consensusTimers.has(timerKey)) return;
      const firstSeen = this.pendingSince.get(sequenceText) ?? Date.now();
      const dueAt = firstSeen + (round * this.roundTimeoutMs) + this.proposalDelayMs;
      const timer = setTimeout(() => {
        this.consensusTimers.delete(timerKey);
        if (!this.started || this.ledger.sequence + 1n !== sequence || !this.actBytes.size) return;
        this.proposeNext({ round, timeoutMs: Math.max(15000, this.roundTimeoutMs * 4) }).catch((error) => {
          this.emit('autoConsensusError', { error, sequence: sequenceText, round });
        });
      }, Math.max(0, dueAt - Date.now()));
      timer.unref?.();
      this.consensusTimers.set(timerKey, timer);
      return;
    }
  }

  prepareRemote(proposal, events) {
    if (!proposal || typeof proposal !== 'object' || !Array.isArray(proposal.actIds)) {
      throw new SovereignNodeError('INVALID_PROPOSAL', 'Closure proposal is malformed.');
    }
    if (!Array.isArray(events) || events.length !== proposal.actIds.length) {
      throw new SovereignNodeError('DATA_UNAVAILABLE', 'Proposal must include every event byte.');
    }
    const receivedIds = this.receiveActs(events, proposal.hybridTransferAuthorizations ?? []);
    if (receivedIds.length !== proposal.actIds.length
      || receivedIds.some((id, index) => id !== proposal.actIds[index])) {
      throw new SovereignNodeError('ACT_SET_MISMATCH', 'Proposal event bytes differ from declared act ids.');
    }
    const constellation = this.ledger.proposeConstellation();
    const local = this.ledger.prepareConstellation(constellation);
    if (!sameCanonical(local, proposal)) {
      throw new SovereignNodeError('NON_DETERMINISTIC_PROPOSAL', 'Local deterministic preparation differs from leader proposal.');
    }
    this.prepared.set(local.sequence, local);
    return local;
  }

  async proposeNext(options = {}) {
    const sequence = this.ledger.sequence + 1n;
    const roundNumber = canonicalRound(options.round, this.genesis.validators.length);
    if (this.expectedLeader(sequence, roundNumber) !== this.validatorId) {
      throw new SovereignNodeError('NOT_SEQUENCE_LEADER', `${this.validatorId} is not leader for sequence ${sequence}, round ${roundNumber}.`);
    }
    this.assertRoundEligible(sequence, roundNumber);
    const constellation = this.ledger.proposeConstellation();
    const proposal = this.ledger.prepareConstellation(constellation);
    const events = this.eventBytesFor(proposal);
    const round = {
      round: roundNumber,
      proposal,
      events,
      votes: new Map(),
      roundChangeVotes: new Map(),
      roundChangeCertificate: null,
      proposed: false,
      committed: false,
    };
    this.rounds.set(this.roundKey(proposal.sequence, roundNumber), round);
    if (roundNumber === 0) {
      this.beginClosureRound(round);
    } else {
      const ownVote = this.roundChangeJournal.signOnce(
        this.roundChangeProposal(proposal),
        roundNumber,
        this.roundChangeQuorum,
        this.validatorId,
        this.consensusSigner(),
      );
      round.roundChangeVotes.set(this.validatorId, ownVote);
      this.transport.broadcast('ROOT', Object.freeze({
        kind: 'KONAET_ROUND_CHANGE_REQUEST_V1',
        round: roundNumber,
        proposal,
        events,
      }));
      if (round.roundChangeVotes.size >= this.genesis.threshold) this.authorizeRound(round);
    }
    return this.waitForSequence(BigInt(proposal.sequence), options.timeoutMs ?? 15000);
  }

  roundChangeProposal(proposal) {
    return Object.freeze({
      networkId: proposal.networkId,
      protocolVersion: proposal.protocolVersion,
      sequence: proposal.sequence,
      previousRoot: proposal.previousRoot,
      proposalHash: this.quorum.statementHash(proposal),
    });
  }

  assertRoundAuthorization(proposal, round, certificate) {
    if (round === 0) {
      if (certificate !== null && certificate !== undefined) {
        throw new SovereignNodeError('UNEXPECTED_ROUND_CHANGE', 'Round zero cannot carry a round-change certificate.');
      }
      return true;
    }
    if (!certificate) {
      throw new SovereignNodeError('ROUND_CHANGE_REQUIRED', `Round ${round} requires a signed quorum certificate.`);
    }
    this.roundChangeQuorum.verifyCertificate(
      certificate,
      this.roundChangeProposal(proposal),
      round,
    );
    return true;
  }

  beginClosureRound(round) {
    if (round.proposed) return;
    this.assertRoundAuthorization(round.proposal, round.round, round.roundChangeCertificate);
    const ownVote = this.voteJournal.signOnce(
      round.proposal,
      this.quorum,
      this.validatorId,
      this.consensusSigner(),
    );
    round.votes.set(this.validatorId, ownVote);
    round.proposed = true;
    this.transport.broadcast('ROOT', Object.freeze({
      kind: 'KONAET_CLOSURE_PROPOSAL_V1',
      round: round.round,
      proposal: round.proposal,
      events: round.events,
      roundChangeCertificate: round.roundChangeCertificate,
    }));
    if (round.votes.size >= this.genesis.threshold) this.finalizeRound(round);
  }

  authorizeRound(round) {
    if (round.roundChangeCertificate) return round.roundChangeCertificate;
    const proposal = this.roundChangeProposal(round.proposal);
    const certificate = this.roundChangeQuorum.assembleCertificate(
      proposal,
      round.round,
      [...round.roundChangeVotes.values()],
    );
    this.roundChangeJournal.recordCertificate(proposal, round.round, this.roundChangeQuorum, certificate);
    round.roundChangeCertificate = certificate;
    this.emit('roundAuthorized', Object.freeze({
      sequence: round.proposal.sequence,
      round: round.round,
      certificateId: certificate.id,
      signerCount: certificate.signatures.length,
    }));
    this.beginClosureRound(round);
    return certificate;
  }

  async handleRoundChangeRequest(senderId, payload) {
    const proposal = payload?.proposal;
    const sequence = canonicalU64(proposal?.sequence, 'round-change sequence', 1n);
    const sequenceNumber = BigInt(sequence);
    const round = canonicalRound(payload?.round, this.genesis.validators.length);
    if (round === 0) throw new SovereignNodeError('INVALID_ROUND_CHANGE', 'Round zero needs no round change.');
    if (senderId !== this.expectedLeader(sequenceNumber, round)) {
      throw new SovereignNodeError('WRONG_LEADER', `${senderId} cannot request round ${round}.`);
    }
    if (sequenceNumber <= this.ledger.sequence) {
      this.emit('staleConsensusMessageIgnored', { kind: payload?.kind, senderId, sequence, round });
      return;
    }
    if (sequenceNumber !== this.ledger.sequence + 1n) {
      throw new SovereignNodeError('FUTURE_PROPOSAL', 'Round change is ahead of the next local sequence.');
    }
    const local = this.prepareRemote(proposal, payload.events);
    await this.waitForRoundEligibility(sequence, round);
    if (sequenceNumber <= this.ledger.sequence) {
      this.emit('staleConsensusMessageIgnored', { kind: payload?.kind, senderId, sequence, round });
      return;
    }
    const roundProposal = this.roundChangeProposal(local);
    const vote = this.roundChangeJournal.signOnce(
      roundProposal,
      round,
      this.roundChangeQuorum,
      this.validatorId,
      this.consensusSigner(),
    );
    this.transport.sendTo(senderId, 'ROOT', Object.freeze({
      kind: 'KONAET_ROUND_CHANGE_VOTE_V1',
      round,
      proposal: local,
      vote,
    }));
    this.emit('roundChangeVoteSent', { sequence, round, leader: senderId });
  }

  handleRoundChangeVote(senderId, payload) {
    const proposal = payload?.proposal;
    const sequence = canonicalU64(proposal?.sequence, 'round-change vote sequence', 1n);
    if (BigInt(sequence) <= this.ledger.sequence) {
      this.emit('staleConsensusMessageIgnored', {
        kind: payload?.kind,
        senderId,
        sequence,
        round: payload?.round,
      });
      return;
    }
    const roundNumber = canonicalRound(payload?.round, this.genesis.validators.length);
    if (roundNumber === 0 || this.expectedLeader(BigInt(sequence), roundNumber) !== this.validatorId) return;
    const round = this.rounds.get(this.roundKey(sequence, roundNumber));
    if (!round || round.committed || round.roundChangeCertificate) return;
    if (!sameCanonical(round.proposal, proposal)) {
      throw new SovereignNodeError('UNKNOWN_ROUND', 'Round-change vote belongs to another proposal.');
    }
    this.roundChangeQuorum.verifyVote(this.roundChangeProposal(round.proposal), roundNumber, payload.vote);
    if (payload.vote.signerId !== senderId) {
      throw new SovereignNodeError('VOTE_SENDER_MISMATCH', 'Round-change signer differs from envelope sender.');
    }
    round.roundChangeVotes.set(senderId, payload.vote);
    if (round.roundChangeVotes.size >= this.genesis.threshold) this.authorizeRound(round);
  }

  handleProposal(senderId, payload) {
    const proposal = payload?.proposal;
    const sequence = canonicalU64(proposal?.sequence, 'proposal sequence', 1n);
    const round = canonicalRound(payload?.round, this.genesis.validators.length);
    if (senderId !== this.expectedLeader(BigInt(sequence), round)) {
      throw new SovereignNodeError('WRONG_LEADER', `${senderId} is not leader for sequence ${sequence}, round ${round}.`);
    }
    this.assertRoundAuthorization(proposal, round, payload.roundChangeCertificate);
    const sequenceNumber = BigInt(sequence);
    if (sequenceNumber <= this.ledger.sequence) {
      this.emit('staleConsensusMessageIgnored', { kind: payload?.kind, senderId, sequence, round });
      return;
    }
    if (sequenceNumber !== this.ledger.sequence + 1n) {
      throw new SovereignNodeError('FUTURE_PROPOSAL', 'Proposal is ahead of the next local sequence.');
    }
    const local = this.prepareRemote(proposal, payload.events);
    if (round > 0) {
      this.roundChangeJournal.recordCertificate(
        this.roundChangeProposal(local),
        round,
        this.roundChangeQuorum,
        payload.roundChangeCertificate,
      );
    }
    const vote = this.voteJournal.signOnce(local, this.quorum, this.validatorId, this.consensusSigner());
    this.transport.sendTo(senderId, 'ROOT', Object.freeze({ kind: 'KONAET_CLOSURE_VOTE_V1', round, proposal: local, vote }));
    this.emit('voteSent', { sequence, round, leader: senderId });
  }

  handleVote(senderId, payload) {
    const proposal = payload?.proposal;
    const sequence = canonicalU64(proposal?.sequence, 'vote proposal sequence', 1n);
    if (BigInt(sequence) <= this.ledger.sequence) return;
    const roundNumber = canonicalRound(payload?.round, this.genesis.validators.length);
    if (this.expectedLeader(BigInt(sequence), roundNumber) !== this.validatorId) return;
    const round = this.rounds.get(this.roundKey(sequence, roundNumber));
    if (round?.committed) return;
    if (!round || !sameCanonical(round.proposal, proposal)) {
      throw new SovereignNodeError('UNKNOWN_ROUND', 'Vote does not belong to the active leader round.');
    }
    this.quorum.verifyVote(round.proposal, payload.vote);
    if (payload.vote.signerId !== senderId) throw new SovereignNodeError('VOTE_SENDER_MISMATCH', 'Vote signer differs from envelope sender.');
    round.votes.set(senderId, payload.vote);
    if (round.votes.size >= this.genesis.threshold) this.finalizeRound(round);
  }

  finalizeRound(round) {
    if (round.committed) return;
    const certificate = this.quorum.assembleCertificate(round.proposal, [...round.votes.values()]);
    const closure = this.ledger.commitPrepared(round.proposal, {
      certificate,
      round: round.round,
      roundChangeCertificate: round.roundChangeCertificate,
    });
    round.committed = true;
    this.afterCommit(closure);
    const commit = Object.freeze({
      kind: 'KONAET_CLOSURE_COMMIT_V1',
      round: round.round,
      proposal: round.proposal,
      events: round.events,
      certificate,
      roundChangeCertificate: round.roundChangeCertificate,
    });
    this.beginCommitDelivery(commit);
  }

  commitDeliverySnapshot(delivery, status) {
    this.lastCommitDelivery = Object.freeze({
      sequence: delivery.sequence,
      root: delivery.root,
      certificateId: delivery.certificateId,
      acknowledgedValidatorIds: [...delivery.acknowledgements].sort(),
      requiredValidatorCount: this.genesis.validators.length,
      attempts: delivery.attempts,
      status,
    });
  }

  beginCommitDelivery(payload) {
    const sequence = canonicalU64(payload.proposal.sequence, 'commit sequence', 1n);
    const key = sequence;
    const delivery = {
      sequence,
      root: payload.proposal.nextRoot,
      certificateId: payload.certificate.id,
      payload,
      acknowledgements: new Set([this.validatorId]),
      attempts: 0,
      timer: null,
    };
    this.commitDeliveries.set(key, delivery);
    this.sendPendingCommit(key);
  }

  sendPendingCommit(key) {
    const delivery = this.commitDeliveries.get(key);
    if (!delivery) return;
    delivery.attempts += 1;
    for (const validator of this.genesis.validators) {
      if (delivery.acknowledgements.has(validator.id)) continue;
      try { this.transport.sendTo(validator.id, 'ROOT', delivery.payload); }
      catch (error) { this.emit('commitDeliverySendError', { sequence: key, peerId: validator.id, error }); }
    }
    if (delivery.acknowledgements.size === this.genesis.validators.length) {
      if (delivery.timer) clearTimeout(delivery.timer);
      this.commitDeliveries.delete(key);
      this.commitDeliverySnapshot(delivery, 'ACKNOWLEDGED');
      this.emit('commitDeliveryComplete', this.lastCommitDelivery);
      return;
    }
    const delay = COMMIT_RETRY_DELAYS_MS[delivery.attempts - 1];
    if (delay !== undefined) {
      delivery.timer = setTimeout(() => this.sendPendingCommit(key), delay);
      delivery.timer.unref?.();
      this.commitDeliverySnapshot(delivery, 'PENDING');
      return;
    }
    this.commitDeliveries.delete(key);
    this.commitDeliverySnapshot(delivery, 'INCOMPLETE');
    this.emit('commitDeliveryIncomplete', this.lastCommitDelivery);
  }

  sendCommitAcknowledgement(leaderId, proposal, certificate) {
    if (leaderId === this.validatorId) return false;
    if (!this.genesis.validators.some(({ id }) => id === leaderId)) {
      throw new SovereignNodeError('INVALID_COMMIT_LEADER', 'Commit acknowledgement leader is not in the validator set.');
    }
    this.transport.sendTo(leaderId, 'ROOT', Object.freeze({
      kind: COMMIT_ACK_KIND,
      sequence: canonicalU64(proposal.sequence, 'ack sequence', 1n),
      root: proposal.nextRoot,
      certificateId: certificate.id,
    }));
    return true;
  }

  handleCommitAcknowledgement(senderId, payload) {
    const keys = ['kind', 'sequence', 'root', 'certificateId'].sort().join('\0');
    if (!payload || Object.keys(payload).sort().join('\0') !== keys || payload.kind !== COMMIT_ACK_KIND) {
      throw new SovereignNodeError('INVALID_COMMIT_ACK', 'Commit acknowledgement has an invalid shape.');
    }
    const sequence = canonicalU64(payload.sequence, 'ack sequence', 1n);
    const root = String(payload.root ?? '');
    const certificateId = String(payload.certificateId ?? '');
    if (!/^[0-9a-f]{64}$/.test(root) || !/^[0-9a-f]{64}$/.test(certificateId)
      || !this.genesis.validators.some(({ id }) => id === senderId)) {
      throw new SovereignNodeError('INVALID_COMMIT_ACK', 'Commit acknowledgement identity or hashes are invalid.');
    }
    const delivery = this.commitDeliveries.get(sequence);
    if (!delivery) return false;
    if (delivery.root !== root || delivery.certificateId !== certificateId) {
      throw new SovereignNodeError('COMMIT_ACK_MISMATCH', 'Commit acknowledgement refers to another root or certificate.');
    }
    delivery.acknowledgements.add(senderId);
    if (delivery.acknowledgements.size === this.genesis.validators.length) {
      if (delivery.timer) clearTimeout(delivery.timer);
      this.commitDeliveries.delete(sequence);
      this.commitDeliverySnapshot(delivery, 'ACKNOWLEDGED');
      this.emit('commitDeliveryComplete', this.lastCommitDelivery);
    } else {
      this.commitDeliverySnapshot(delivery, 'PENDING');
    }
    return true;
  }

  handleCommit(senderId, payload) {
    const proposal = payload?.proposal;
    const sequence = BigInt(canonicalU64(proposal?.sequence, 'commit sequence', 1n));
    const round = canonicalRound(payload?.round, this.genesis.validators.length);
    if (senderId !== this.expectedLeader(sequence, round)) {
      throw new SovereignNodeError('WRONG_LEADER', 'Commit did not come from the sequence leader.');
    }
    this.assertRoundAuthorization(proposal, round, payload.roundChangeCertificate);
    if (sequence <= this.ledger.sequence) {
      if (sequence === this.ledger.sequence && proposal.nextRoot !== this.ledger.root) {
        throw new SovereignNodeError('COMMIT_CONFLICT', 'Committed sequence has a conflicting root.');
      }
      if (sequence === this.ledger.sequence) {
        this.quorum.verifyCertificate(payload.certificate, proposal);
        this.sendCommitAcknowledgement(senderId, proposal, payload.certificate);
      }
      return;
    }
    if (sequence !== this.ledger.sequence + 1n) {
      this.requestState(senderId);
      return;
    }
    const local = this.prepareRemote(proposal, payload.events);
    this.quorum.verifyCertificate(payload.certificate, local);
    if (round > 0) {
      this.roundChangeJournal.recordCertificate(
        this.roundChangeProposal(local),
        round,
        this.roundChangeQuorum,
        payload.roundChangeCertificate,
      );
    }
    const closure = this.ledger.commitPrepared(local, {
      certificate: payload.certificate,
      round,
      roundChangeCertificate: payload.roundChangeCertificate ?? null,
    });
    this.afterCommit(closure);
    this.sendCommitAcknowledgement(senderId, local, payload.certificate);
  }

  afterCommit(closure) {
    if (closure.walFrame) this.closureFrames.set(String(closure.sequence), closure.walFrame);
    for (const id of [...closure.actIds, ...(closure.expiredActIds ?? [])]) this.actBytes.delete(id);
    for (const [key, round] of this.rounds) if (BigInt(round.proposal.sequence) <= BigInt(closure.sequence)) this.rounds.delete(key);
    this.prepared.clear();
    this.pendingSince.delete(String(closure.sequence));
    for (const [timerKey, timer] of this.consensusTimers) {
      if (!timerKey.startsWith(`${closure.sequence}:`)) continue;
      clearTimeout(timer);
      this.consensusTimers.delete(timerKey);
    }
    this.emit('committed', Object.freeze({
      sequence: closure.sequence,
      root: closure.nextRoot,
      actCount: closure.actIds.length,
      certificateId: closure.certificate?.id || null,
      signerCount: closure.certificate?.signatures?.length || 0,
    }));
  }

  closureRecords(fromSequence, limit = this.genesis.parameters.stateSyncChunk) {
    const from = BigInt(canonicalU64(fromSequence, 'fromSequence', 1n));
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > this.genesis.parameters.stateSyncChunk) throw new SovereignNodeError('STATE_CHUNK_TOO_LARGE', 'Invalid state read limit.');
    const frames = []; let bytes = 0;
    for (let sequence = from; sequence <= this.ledger.sequence && frames.length < limit; sequence++) {
      const frame = this.closureFrames.get(String(sequence));
      if (!frame) throw new SovereignNodeError('STATE_INDEX_GAP', 'Closure index is incomplete.');
      if (bytes + frame.length + 36 > 4 * 1024 * 1024) {
        if (!frames.length) throw new SovereignNodeError('STATE_SYNC_RECORD_LIMIT', 'One closure exceeds the synchronization byte budget.');
        break;
      }
      frames.push(frame); bytes += frame.length + 36;
    }
    return this.ledgerWal.readFrames(frames, { maxBytes: 4 * 1024 * 1024 });
  }

  requestState(peerId) {
    this.transport.sendTo(peerId, 'GET_STATE', Object.freeze({
      kind: 'KONAET_STATE_REQUEST_V1',
      genesisId: this.genesis.genesisId,
      fromSequence: (this.ledger.sequence + 1n).toString(10),
    }));
  }

  handleStateRequest(senderId, payload) {
    if (payload?.kind !== 'KONAET_STATE_REQUEST_V1' || payload.genesisId !== this.genesis.genesisId) {
      throw new SovereignNodeError('INVALID_STATE_REQUEST', 'State request belongs to another protocol or genesis.');
    }
    const fromSequence = canonicalU64(payload.fromSequence, 'fromSequence', 1n);
    const records = this.closureRecords(fromSequence);
    this.transport.sendTo(senderId, 'STATE_CHUNK', Object.freeze({
      kind: 'KONAET_STATE_CHUNK_V1',
      genesisId: this.genesis.genesisId,
      fromSequence,
      tipSequence: this.ledger.sequence.toString(10),
      more: records.length > 0 && BigInt(records.at(-1).sequence) < this.ledger.sequence,
      records: Object.freeze(records),
    }));
  }

  applyClosureRecord(record) {
    if (!record || record.kind !== CLOSURE_KIND || !Array.isArray(record.events) || !record.certificate) {
      throw new SovereignNodeError('INVALID_CLOSURE_RECORD', 'State chunk contains an invalid closure record.');
    }
    const sequence = BigInt(canonicalU64(record.sequence, 'closure sequence', 1n));
    if (sequence <= this.ledger.sequence) return false;
    if (sequence !== this.ledger.sequence + 1n) {
      throw new SovereignNodeError('STATE_GAP', 'State chunk is not contiguous with the local ledger.');
    }
    const events = record.events.map((bytes) => exactBuffer(bytes, 'closure event'));
    const receivedIds = this.receiveActs(events, record.hybridTransferAuthorizations ?? []);
    if (receivedIds.some((id, index) => id !== record.actIds[index])) {
      throw new SovereignNodeError('ACT_SET_MISMATCH', 'Closure event ids differ from its record.');
    }
    const local = this.ledger.prepareConstellation(this.ledger.proposeConstellation());
    if (!proposalFieldsEqual(local, record)) {
      throw new SovereignNodeError('CLOSURE_RECOMPUTE_FAILED', 'Fetched closure differs from deterministic local execution.');
    }
    this.quorum.verifyCertificate(record.certificate, local);
    const round = canonicalRound(record.round ?? 0, this.genesis.validators.length);
    this.assertRoundAuthorization(local, round, record.roundChangeCertificate ?? null);
    const closure = this.ledger.commitPrepared(local, {
      certificate: record.certificate,
      round,
      roundChangeCertificate: record.roundChangeCertificate ?? null,
    });
    this.afterCommit(closure);
    return true;
  }

  handleStateChunk(senderId, payload) {
    if (payload?.kind !== 'KONAET_STATE_CHUNK_V1' || payload.genesisId !== this.genesis.genesisId
      || !Array.isArray(payload.records) || typeof payload.more !== 'boolean') {
      throw new SovereignNodeError('INVALID_STATE_CHUNK', 'State chunk is malformed or belongs to another genesis.');
    }
    if (payload.records.length > this.genesis.parameters.stateSyncChunk) {
      throw new SovereignNodeError('STATE_CHUNK_TOO_LARGE', 'State chunk exceeds the genesis limit.');
    }
    if (payload.more && !payload.records.length) throw new SovereignNodeError('INVALID_STATE_CHUNK', 'A continuation must advance synchronization.');
    for (const record of payload.records) this.applyClosureRecord(record);
    const tip = BigInt(canonicalU64(payload.tipSequence, 'tipSequence'));
    if (payload.more || this.ledger.sequence < tip) this.requestState(senderId);
    else this.emit('synchronized', { peerId: senderId, sequence: this.ledger.sequence.toString(10), root: this.ledger.root });
  }

  handleHello(senderId, payload) {
    if (payload?.kind !== 'KONAET_SOVEREIGN_HELLO_V1' || payload.genesisId !== this.genesis.genesisId) return;
    const peerSequence = BigInt(canonicalU64(payload.sequence, 'peer sequence'));
    if (peerSequence > this.ledger.sequence) this.requestState(senderId);
    else if (peerSequence === this.ledger.sequence && this.actBytes.size) this.scheduleConsensus();
  }

  handleMessage(message) {
    const { type, payload, senderId } = message;
    if (type === 'HELLO') return this.handleHello(senderId, payload);
    if (type === 'ACT') {
      if (!['KONAET_TRANSFER_V1', 'KONAET_KO_DEPLOY_V1', 'KONAET_KO_CALL_V1'].includes(payload?.kind)) throw new SovereignNodeError('INVALID_ACT_MESSAGE', 'ACT payload kind is invalid.');
      const event = decodeEvent(exactBuffer(payload.event, 'event'));
      if (payload.kind !== (event instanceof ContractEvent ? event.kind : 'KONAET_TRANSFER_V1')) throw new SovereignNodeError('INVALID_ACT_MESSAGE', 'ACT kind and event bytes differ.');
      const evidence = payload.authorization !== undefined || payload.publicIdentity !== undefined
        ? { authorization: payload.authorization, publicIdentity: payload.publicIdentity } : undefined;
      return this.receiveAct(payload.event, evidence);
    }
    if (type === 'ROOT') {
      if (payload?.kind === 'KONAET_CLOSURE_PROPOSAL_V1') return this.handleProposal(senderId, payload);
      if (payload?.kind === 'KONAET_CLOSURE_VOTE_V1') return this.handleVote(senderId, payload);
      if (payload?.kind === 'KONAET_CLOSURE_COMMIT_V1') return this.handleCommit(senderId, payload);
      if (payload?.kind === COMMIT_ACK_KIND) return this.handleCommitAcknowledgement(senderId, payload);
      if (payload?.kind === 'KONAET_ROUND_CHANGE_REQUEST_V1') return this.handleRoundChangeRequest(senderId, payload);
      if (payload?.kind === 'KONAET_ROUND_CHANGE_VOTE_V1') return this.handleRoundChangeVote(senderId, payload);
      throw new SovereignNodeError('INVALID_ROOT_MESSAGE', 'ROOT payload kind is invalid.');
    }
    if (type === 'GET_STATE') return this.handleStateRequest(senderId, payload);
    if (type === 'STATE_CHUNK') return this.handleStateChunk(senderId, payload);
    if (type === 'FAULT') return this.emit('peerFault', { senderId, payload });
    return undefined;
  }

  waitForSequence(sequence, timeoutMs = 10000) {
    const expected = BigInt(sequence);
    if (this.ledger.sequence >= expected) return Promise.resolve(this.status());
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        cleanup();
        reject(new SovereignNodeError('COMMIT_TIMEOUT', `Sequence ${expected} was not committed in time.`));
      }, timeoutMs);
      const onCommit = () => {
        if (this.ledger.sequence < expected) return;
        cleanup();
        resolve(this.status());
      };
      const cleanup = () => { clearTimeout(timer); this.off('committed', onCommit); };
      this.on('committed', onCommit);
    });
  }

  status() {
    const state = this.ledger.getState();
    return Object.freeze({
      schema: 'konaet-sovereign-node-status-v1',
      validatorId: this.validatorId,
      genesisId: this.genesis.genesisId,
      networkId: this.genesis.networkId,
      protocolVersion: this.genesis.protocolVersion,
      sequence: this.ledger.sequence.toString(10),
      nativePolicy: this.genesis.nativePolicy ? Object.freeze({ profile: this.genesis.nativePolicy.profile,
        sourceSha256: this.genesis.nativePolicy.sourceSha256, programSha256: this.ledger.nativePolicyHash,
        enforced: true }) : null,
      root: this.ledger.root,
      accountCount: state.accountCount,
      ...(this.genesis.contractRuntime ? { contractRuntime: Object.freeze({ ...this.genesis.contractRuntime,
        enforced: true, contracts: state.contracts().length, contractsRoot: state.contractsRoot().toString('hex'),
        receiptsRoot: state.receiptsRoot().toString('hex') }) } : {}),
      leaderForNext: this.expectedLeader(),
      fallbackLeaderForNext: this.expectedLeader(this.ledger.sequence + 1n, 1),
      peers: this.transport.status().peers,
      transport: this.transport.status(),
      voteJournal: this.voteJournal.status(),
      roundChangeJournal: this.roundChangeJournal.status(),
      commitDeliveryPending: this.commitDeliveries.size,
      lastCommitDelivery: this.lastCommitDelivery,
      automaticConsensus: Object.freeze({
        enabled: this.automaticConsensus,
        roundTimeoutMs: this.roundTimeoutMs,
        proposalDelayMs: this.proposalDelayMs,
        scheduled: this.consensusTimers.size,
      }),
    });
  }

  balance(address) {
    return this.ledger.getState().getBalance(address);
  }

  async close() {
    for (const timer of this.consensusTimers.values()) clearTimeout(timer);
    this.consensusTimers.clear();
    for (const delivery of this.commitDeliveries.values()) if (delivery.timer) clearTimeout(delivery.timer);
    this.commitDeliveries.clear();
    await this.transport.close();
    this.voteJournal.close();
    this.roundChangeJournal.close();
    this.ledgerWal.close();
    this.started = false;
  }
}

module.exports = Object.freeze({ SovereignNode, SovereignNodeError });
