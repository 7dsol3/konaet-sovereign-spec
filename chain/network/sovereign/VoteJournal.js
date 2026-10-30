'use strict';

const fs = require('node:fs');
const path = require('node:path');
const {
  WalStore,
  recoverWal,
} = require('../../vlock7sin-js/src/persistence');

const RECORD_KIND = 'KONAET_SOVEREIGN_VOTE_V1';

class VoteJournalError extends Error {
  constructor(code, message, details = undefined) {
    super(message);
    this.name = 'VoteJournalError';
    this.code = code;
    if (details !== undefined) this.details = details;
  }
}

function canonicalSequence(value) {
  try {
    const number = BigInt(value);
    if (number < 1n || number > 0xffffffffffffffffn) throw new Error('outside u64');
    return number.toString(10);
  } catch {
    throw new VoteJournalError('INVALID_SEQUENCE', 'Vote sequence must be a positive u64.');
  }
}

function exactHash(value, label) {
  const text = String(value || '');
  if (!/^[0-9a-f]{64}$/.test(text)) throw new VoteJournalError('INVALID_RECORD', `${label} must be SHA3-256 hex.`);
  return text;
}

function assertRecord(record) {
  const expected = ['kind', 'sequence', 'statementHash', 'vote'];
  if (!record || typeof record !== 'object' || Array.isArray(record)
    || Object.keys(record).sort().join('\0') !== expected.sort().join('\0')) {
    throw new VoteJournalError('INVALID_RECORD', 'Vote journal record is malformed.');
  }
  if (record.kind !== RECORD_KIND) throw new VoteJournalError('INVALID_RECORD', 'Vote journal record kind is unsupported.');
  canonicalSequence(record.sequence);
  exactHash(record.statementHash, 'statementHash');
  return record;
}

class VoteJournal {
  constructor(filePath, options = {}) {
    if (!filePath) throw new VoteJournalError('INVALID_PATH', 'Vote journal path is required.');
    this.path = path.resolve(filePath);
    if (options.allowedRoot) {
      const root = path.resolve(options.allowedRoot);
      if (this.path !== root && !this.path.startsWith(`${root}${path.sep}`)) {
        throw new VoteJournalError('INVALID_PATH', 'Vote journal must remain inside its node data directory.');
      }
    }
    fs.mkdirSync(path.dirname(this.path), { recursive: true, mode: 0o700 });
    this.records = new Map();
    if (fs.existsSync(this.path)) {
      const report = recoverWal(this.path, { decodeRecords: true });
      if (!report.clean) throw new VoteJournalError('UNCLEAN_JOURNAL', 'Vote journal is truncated or corrupt.');
      for (const frame of report.frames) {
        const record = assertRecord(frame.record);
        const existing = this.records.get(record.sequence);
        if (existing && existing.statementHash !== record.statementHash) {
          throw new VoteJournalError('JOURNAL_EQUIVOCATION', `Journal contains conflicting votes for sequence ${record.sequence}.`);
        }
        this.records.set(record.sequence, Object.freeze(record));
      }
    }
    this.wal = new WalStore(this.path, options.walOptions);
  }

  signOnce(proposal, quorum, signerId, privateKey) {
    if (!quorum || typeof quorum.statementHash !== 'function' || typeof quorum.createVote !== 'function') {
      throw new VoteJournalError('INVALID_QUORUM', 'Permissioned quorum service is required.');
    }
    const statement = quorum.statement(proposal);
    const sequence = canonicalSequence(statement.sequence);
    const statementHash = exactHash(quorum.statementHash(statement), 'statementHash');
    const existing = this.records.get(sequence);
    if (existing) {
      if (existing.statementHash !== statementHash) {
        throw new VoteJournalError(
          'EQUIVOCATION_REFUSED',
          `Validator already signed another statement for sequence ${sequence}.`,
          { sequence, existingStatementHash: existing.statementHash, rejectedStatementHash: statementHash },
        );
      }
      quorum.verifyVote(statement, existing.vote);
      return existing.vote;
    }
    const vote = quorum.createVote(statement, signerId, privateKey);
    const record = Object.freeze({ kind: RECORD_KIND, sequence, statementHash, vote });
    this.wal.appendRecord(record);
    this.records.set(sequence, record);
    return vote;
  }

  status() {
    return Object.freeze({ path: this.path, votes: this.records.size, clean: true });
  }

  close() {
    if (this.wal) {
      this.wal.close();
      this.wal = null;
    }
  }
}

module.exports = Object.freeze({ VoteJournal, VoteJournalError });
