'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { WalStore, recoverWal } = require('../../vlock7sin-js/src/persistence');

const VOTE_KIND = 'KONAET_SOVEREIGN_ROUND_CHANGE_VOTE_V1';
const CERTIFICATE_KIND = 'KONAET_SOVEREIGN_ROUND_CHANGE_CERTIFICATE_V1';

class RoundChangeJournalError extends Error {
  constructor(code, message, details = undefined) {
    super(message);
    this.name = 'RoundChangeJournalError';
    this.code = code;
    if (details !== undefined) this.details = details;
  }
}

function key(sequence, round) {
  try {
    const number = BigInt(sequence);
    const roundNumber = Number(round);
    if (number < 1n || number > 0xffffffffffffffffn) throw new Error('outside u64');
    if (!Number.isSafeInteger(roundNumber) || roundNumber < 1) throw new Error('invalid round');
    return `${number.toString(10)}:${roundNumber}`;
  } catch {
    throw new RoundChangeJournalError('INVALID_POSITION', 'Round-change sequence or round is invalid.');
  }
}

function exactHash(value, label) {
  const text = String(value ?? '');
  if (!/^[0-9a-f]{64}$/.test(text)) {
    throw new RoundChangeJournalError('INVALID_RECORD', `${label} must be SHA3-256 hex.`);
  }
  return text;
}

function assertRecord(record) {
  if (!record || typeof record !== 'object' || Array.isArray(record)) {
    throw new RoundChangeJournalError('INVALID_RECORD', 'Round-change record is malformed.');
  }
  const position = key(record.sequence, record.round);
  exactHash(record.statementHash, 'statementHash');
  if (record.kind === VOTE_KIND) {
    const expected = ['kind', 'sequence', 'round', 'statementHash', 'vote'].sort().join('\0');
    if (Object.keys(record).sort().join('\0') !== expected || !record.vote) {
      throw new RoundChangeJournalError('INVALID_RECORD', 'Round-change vote record is malformed.');
    }
    return { type: 'vote', position, record };
  }
  if (record.kind === CERTIFICATE_KIND) {
    const expected = ['kind', 'sequence', 'round', 'statementHash', 'certificate'].sort().join('\0');
    if (Object.keys(record).sort().join('\0') !== expected || !record.certificate) {
      throw new RoundChangeJournalError('INVALID_RECORD', 'Round-change certificate record is malformed.');
    }
    return { type: 'certificate', position, record };
  }
  throw new RoundChangeJournalError('INVALID_RECORD', 'Round-change record kind is unsupported.');
}

class RoundChangeJournal {
  constructor(filePath, options = {}) {
    if (!filePath) throw new RoundChangeJournalError('INVALID_PATH', 'Round-change journal path is required.');
    this.path = path.resolve(filePath);
    if (options.allowedRoot) {
      const root = path.resolve(options.allowedRoot);
      if (this.path !== root && !this.path.startsWith(`${root}${path.sep}`)) {
        throw new RoundChangeJournalError('INVALID_PATH', 'Journal must remain inside its node data directory.');
      }
    }
    fs.mkdirSync(path.dirname(this.path), { recursive: true, mode: 0o700 });
    this.votes = new Map();
    this.certificates = new Map();
    if (fs.existsSync(this.path)) {
      const recovery = recoverWal(this.path, { decodeRecords: true });
      if (!recovery.clean) throw new RoundChangeJournalError('UNCLEAN_JOURNAL', 'Round-change journal is corrupt.');
      for (const frame of recovery.frames) {
        const { type, position, record } = assertRecord(frame.record);
        const target = type === 'vote' ? this.votes : this.certificates;
        const existing = target.get(position);
        if (existing && existing.statementHash !== record.statementHash) {
          throw new RoundChangeJournalError('JOURNAL_EQUIVOCATION', `Conflicting ${type}s at ${position}.`);
        }
        target.set(position, Object.freeze(record));
      }
    }
    this.wal = new WalStore(this.path, options.walOptions);
  }

  signOnce(proposal, round, quorum, signerId, privateKey) {
    const statement = quorum.statement(proposal, round);
    const position = key(statement.sequence, statement.toRound);
    const statementHash = exactHash(quorum.statementHash(statement, statement.toRound), 'statementHash');
    const existing = this.votes.get(position);
    if (existing) {
      if (existing.statementHash !== statementHash) {
        throw new RoundChangeJournalError('EQUIVOCATION_REFUSED', `Another proposal was already authorized at ${position}.`);
      }
      quorum.verifyVote(statement, statement.toRound, existing.vote);
      return existing.vote;
    }
    const vote = quorum.createVote(statement, statement.toRound, signerId, privateKey);
    const record = Object.freeze({
      kind: VOTE_KIND,
      sequence: statement.sequence,
      round: statement.toRound,
      statementHash,
      vote,
    });
    this.wal.appendRecord(record);
    this.votes.set(position, record);
    return vote;
  }

  recordCertificate(proposal, round, quorum, certificate) {
    const statement = quorum.statement(proposal, round);
    quorum.verifyCertificate(certificate, statement, statement.toRound);
    const position = key(statement.sequence, statement.toRound);
    const statementHash = exactHash(quorum.statementHash(statement, statement.toRound), 'statementHash');
    const existing = this.certificates.get(position);
    if (existing) {
      if (existing.statementHash !== statementHash || existing.certificate.id !== certificate.id) {
        throw new RoundChangeJournalError('CERTIFICATE_CONFLICT', `Another certificate is already durable at ${position}.`);
      }
      return existing.certificate;
    }
    const record = Object.freeze({
      kind: CERTIFICATE_KIND,
      sequence: statement.sequence,
      round: statement.toRound,
      statementHash,
      certificate,
    });
    this.wal.appendRecord(record);
    this.certificates.set(position, record);
    return certificate;
  }

  status() {
    return Object.freeze({
      path: this.path,
      votes: this.votes.size,
      certificates: this.certificates.size,
      clean: true,
    });
  }

  close() {
    if (this.wal) {
      this.wal.close();
      this.wal = null;
    }
  }
}

module.exports = Object.freeze({ RoundChangeJournal, RoundChangeJournalError });
