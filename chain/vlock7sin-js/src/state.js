'use strict';

const {
  DOMAINS,
  LEGACY_DOMAINS,
  FORMAT_VERSION,
  NETWORK_ID,
  STATE_SUITE,
  LENGTHS,
  LIMITS,
  MAX_U32,
  MAX_U64,
  MAX_U128,
} = require('./constants');
const {
  asBigInt,
  asBuffer,
  asNumber,
  encodeU64,
  encodeU128,
  encodeAscii,
  parseHex,
  BinaryWriter,
} = require('./codec');
const { sha3, domainHash, validateAddress } = require('./crypto');
const { StateError, TransitionError } = require('./errors');

const STATE_PROOF_FORMAT = 'vlock7sin-state-proof-js-v1';

function checkedHash(value, label) {
  if (typeof value === 'string') return parseHex(value, { length: LENGTHS.HASH, label });
  return asBuffer(value, label, { exactLength: LENGTHS.HASH });
}

function emptyComponentRoot(domain) {
  return domainHash(domain);
}

function normalizeEntries(entries, label) {
  if (entries === undefined || entries === null) return [];
  if (entries instanceof Map) return [...entries.entries()];
  if (Array.isArray(entries)) return entries.map((entry) => {
    if (!Array.isArray(entry) || entry.length !== 2) {
      throw new StateError(`${label} entries must be [address, value] pairs`);
    }
    return entry;
  });
  if (typeof entries === 'object' && Object.getPrototypeOf(entries) === Object.prototype) {
    return Object.entries(entries);
  }
  throw new StateError(`${label} must be a Map, object, or pair array`);
}

function normalizeMap(entries, label, maximum) {
  const result = new Map();
  for (const [addressValue, amountValue] of normalizeEntries(entries, label, maximum)) {
    const address = validateAddress(addressValue);
    if (result.has(address)) throw new StateError(`duplicate ${label} entry for ${address}`);
    const amount = asBigInt(amountValue, `${label}.${address}`, maximum);
    if (amount !== 0n) result.set(address, amount);
  }
  if (result.size > LIMITS.STATE_ACCOUNTS) {
    throw new StateError(`${label} exceeds ${LIMITS.STATE_ACCOUNTS} entries`);
  }
  return result;
}

function sortedAccountEntries(balances, nonces) {
  const addresses = new Set([...balances.keys(), ...nonces.keys()]);
  return [...addresses]
    .sort((left, right) => Buffer.compare(Buffer.from(left, 'ascii'), Buffer.from(right, 'ascii')))
    .map((address) => Object.freeze({
      address,
      balance: balances.get(address) || 0n,
      nonce: nonces.get(address) || 0n,
    }));
}

function accountLeafHash(entry) {
  const address = validateAddress(entry.address);
  const balance = asBigInt(entry.balance, 'account balance', MAX_U128);
  const nonce = asBigInt(entry.nonce, 'account nonce', MAX_U64);
  if (balance === 0n && nonce === 0n) {
    throw new StateError('zero-only accounts are not canonical leaves');
  }
  return domainHash(
    DOMAINS.STATE_LEAF,
    encodeAscii(address, { maxLength: LIMITS.ADDRESS_BYTES, label: 'account address', allowEmpty: false }),
    encodeU128(balance),
    encodeU64(nonce),
  );
}

function emptyLeafHash() {
  return domainHash(DOMAINS.STATE_EMPTY_LEAF);
}

function parentHash(left, right) {
  return domainHash(
    DOMAINS.STATE_NODE,
    asBuffer(left, 'left Merkle child', { exactLength: LENGTHS.HASH }),
    asBuffer(right, 'right Merkle child', { exactLength: LENGTHS.HASH }),
  );
}

function nextPowerOfTwo(value) {
  if (!Number.isSafeInteger(value) || value < 0) throw new StateError('invalid Merkle leaf count');
  let power = 1;
  while (power < Math.max(1, value)) power *= 2;
  return power;
}

function merkleLayers(entries) {
  if (!Array.isArray(entries) || entries.length > LIMITS.STATE_ACCOUNTS) {
    throw new StateError('invalid account entries for Merkle tree');
  }
  const width = nextPowerOfTwo(entries.length);
  const leaves = entries.map(accountLeafHash);
  while (leaves.length < width) leaves.push(emptyLeafHash());
  const layers = [leaves];
  while (layers[layers.length - 1].length > 1) {
    const current = layers[layers.length - 1];
    const next = [];
    for (let index = 0; index < current.length; index += 2) {
      next.push(parentHash(current[index], current[index + 1]));
    }
    layers.push(next);
  }
  return layers;
}

function accountTreeRoot(entries) {
  if (entries.length === 0) return emptyLeafHash();
  const layers = merkleLayers(entries);
  return Buffer.from(layers[layers.length - 1][0]);
}

function stateCommitmentBytes({
  networkId,
  suite,
  sequence,
  accountCount,
  accountRoot,
  parametersRoot,
  identitiesRoot,
  replayRoot,
}) {
  const writer = new BinaryWriter(256);
  writer.write(Buffer.from(DOMAINS.STATE, 'ascii'), 'state domain');
  writer.write(Buffer.from('V7ST', 'ascii'), 'state magic');
  writer.u8(FORMAT_VERSION.major).u8(FORMAT_VERSION.minor).u8(FORMAT_VERSION.patch);
  writer.u32(asNumber(networkId, 'networkId', Number(MAX_U32)));
  writer.u16(asNumber(suite, 'state suite', Number(MAX_U16)));
  writer.u64(asBigInt(sequence, 'state sequence', MAX_U64));
  writer.u32(asNumber(accountCount, 'account count', LIMITS.STATE_ACCOUNTS));
  writer.write(checkedHash(accountRoot, 'account root'));
  writer.write(checkedHash(parametersRoot, 'parameters root'));
  writer.write(checkedHash(identitiesRoot, 'identities root'));
  writer.write(checkedHash(replayRoot, 'replay root'));
  return writer.finish();
}

// Local constant avoids expanding the public constants surface just for this bound.
const MAX_U16 = 0xffffn;

function stateRootFromMetadata(metadata) {
  return sha3(stateCommitmentBytes(metadata));
}

function proofMetadata(state, entries, accountRoot, root) {
  return Object.freeze({
    format: STATE_PROOF_FORMAT,
    networkId: state.networkId,
    suite: state.suite,
    sequence: state.sequence.toString(),
    accountCount: entries.length,
    accountRoot: accountRoot.toString('hex'),
    parametersRoot: state.parametersRoot.toString('hex'),
    identitiesRoot: state.identitiesRoot.toString('hex'),
    replayRoot: state.replayRoot.toString('hex'),
    stateRoot: root.toString('hex'),
  });
}

function expectedProofHeight(accountCount) {
  let width = nextPowerOfTwo(accountCount);
  let height = 0;
  while (width > 1) {
    height += 1;
    width /= 2;
  }
  return height;
}

function recomputeProofStateRoot(proof) {
  if (!proof || typeof proof !== 'object' || proof.type !== 'inclusion'
    || proof.format !== STATE_PROOF_FORMAT) {
    throw new StateError('invalid inclusion proof format');
  }
  const networkId = asNumber(proof.networkId, 'proof networkId', Number(MAX_U32));
  const suite = asNumber(proof.suite, 'proof state suite', Number(MAX_U16));
  const sequence = asBigInt(proof.sequence, 'proof sequence', MAX_U64);
  const accountCount = asNumber(proof.accountCount, 'proof account count', LIMITS.STATE_ACCOUNTS);
  const index = asNumber(proof.index, 'proof leaf index', Math.max(0, accountCount - 1));
  if (accountCount === 0 || index >= accountCount) throw new StateError('proof leaf index is out of range');
  if (!proof.leaf || typeof proof.leaf !== 'object') throw new StateError('proof leaf is missing');
  const leaf = {
    address: validateAddress(proof.leaf.address),
    balance: asBigInt(proof.leaf.balance, 'proof balance', MAX_U128),
    nonce: asBigInt(proof.leaf.nonce, 'proof nonce', MAX_U64),
  };
  if (!Array.isArray(proof.siblings)
    || proof.siblings.length !== expectedProofHeight(accountCount)
    || proof.siblings.length > LIMITS.PROOF_SIBLINGS) {
    throw new StateError('proof has an invalid sibling path length');
  }
  let current = accountLeafHash(leaf);
  let cursor = index;
  for (const [level, siblingHex] of proof.siblings.entries()) {
    const sibling = parseHex(siblingHex, { length: LENGTHS.HASH, label: `sibling ${level}` });
    current = cursor % 2 === 0 ? parentHash(current, sibling) : parentHash(sibling, current);
    cursor = Math.floor(cursor / 2);
  }
  const claimedAccountRoot = parseHex(proof.accountRoot, {
    length: LENGTHS.HASH,
    label: 'proof account root',
  });
  if (!current.equals(claimedAccountRoot)) throw new StateError('Merkle account root mismatch');
  return stateRootFromMetadata({
    networkId,
    suite,
    sequence,
    accountCount,
    accountRoot: current,
    parametersRoot: parseHex(proof.parametersRoot, { length: LENGTHS.HASH, label: 'parameters root' }),
    identitiesRoot: parseHex(proof.identitiesRoot, { length: LENGTHS.HASH, label: 'identities root' }),
    replayRoot: parseHex(proof.replayRoot, { length: LENGTHS.HASH, label: 'replay root' }),
  });
}

function verifyInclusionProof(proof, expectedRoot = proof?.stateRoot) {
  try {
    const root = recomputeProofStateRoot(proof);
    return root.equals(checkedHash(expectedRoot, 'expected state root'))
      && root.equals(parseHex(proof.stateRoot, { length: LENGTHS.HASH, label: 'proof state root' }));
  } catch {
    return false;
  }
}

function verifyAbsenceProof(proof, expectedRoot = proof?.stateRoot) {
  try {
    if (!proof || proof.type !== 'absence' || proof.format !== STATE_PROOF_FORMAT) return false;
    const target = validateAddress(proof.target);
    const accountCount = asNumber(proof.accountCount, 'proof account count', LIMITS.STATE_ACCOUNTS);
    const expected = checkedHash(expectedRoot, 'expected state root');
    if (!expected.equals(parseHex(proof.stateRoot, { length: LENGTHS.HASH, label: 'proof state root' }))) {
      return false;
    }
    if (accountCount === 0) {
      if (proof.left !== null || proof.right !== null) return false;
      const computed = stateRootFromMetadata({
        networkId: proof.networkId,
        suite: proof.suite,
        sequence: proof.sequence,
        accountCount: 0,
        accountRoot: emptyLeafHash(),
        parametersRoot: parseHex(proof.parametersRoot, { length: LENGTHS.HASH, label: 'parameters root' }),
        identitiesRoot: parseHex(proof.identitiesRoot, { length: LENGTHS.HASH, label: 'identities root' }),
        replayRoot: parseHex(proof.replayRoot, { length: LENGTHS.HASH, label: 'replay root' }),
      });
      return computed.equals(expected);
    }
    const neighbors = [proof.left, proof.right].filter(Boolean);
    if (neighbors.length === 0) return false;
    for (const neighbor of neighbors) {
      if (!verifyInclusionProof(neighbor, expected)) return false;
      if (neighbor.accountCount !== accountCount
        || neighbor.networkId !== proof.networkId
        || neighbor.sequence !== proof.sequence
        || neighbor.suite !== proof.suite
        || neighbor.accountRoot !== proof.accountRoot
        || neighbor.parametersRoot !== proof.parametersRoot
        || neighbor.identitiesRoot !== proof.identitiesRoot
        || neighbor.replayRoot !== proof.replayRoot
        || neighbor.stateRoot !== proof.stateRoot) return false;
    }
    if (proof.left) {
      if (Buffer.compare(Buffer.from(proof.left.leaf.address, 'ascii'), Buffer.from(target, 'ascii')) >= 0) return false;
    }
    if (proof.right) {
      if (Buffer.compare(Buffer.from(target, 'ascii'), Buffer.from(proof.right.leaf.address, 'ascii')) >= 0) return false;
    }
    if (proof.left && proof.right) return proof.right.index === proof.left.index + 1;
    if (proof.left) return proof.left.index === accountCount - 1;
    return proof.right.index === 0;
  } catch {
    return false;
  }
}

function verifyStateProof(proof, expectedRoot) {
  return proof?.type === 'inclusion'
    ? verifyInclusionProof(proof, expectedRoot)
    : verifyAbsenceProof(proof, expectedRoot);
}

class GlobalState {
  #sequence;

  #balances;

  #nonces;

  #parametersRoot;

  #identitiesRoot;

  #replayRoot;

  #networkId;

  #suite;

  #accountCount;

  constructor({
    sequence = 0n,
    balances,
    nonces,
    parametersRoot = emptyComponentRoot(DOMAINS.PARAMETERS_EMPTY),
    identitiesRoot = emptyComponentRoot(DOMAINS.IDENTITIES_EMPTY),
    replayRoot = emptyComponentRoot(DOMAINS.REPLAY_EMPTY),
    networkId = NETWORK_ID,
    suite = STATE_SUITE.SORTED_MERKLE_V1,
  } = {}) {
    this.#sequence = asBigInt(sequence, 'state sequence', MAX_U64);
    this.#balances = normalizeMap(balances, 'balances', MAX_U128);
    this.#nonces = normalizeMap(nonces, 'nonces', MAX_U64);
    this.#accountCount = new Set([...this.#balances.keys(), ...this.#nonces.keys()]).size;
    if (this.#accountCount > LIMITS.STATE_ACCOUNTS) {
      throw new StateError(`state exceeds ${LIMITS.STATE_ACCOUNTS} accounts`);
    }
    this.#parametersRoot = checkedHash(parametersRoot, 'parameters root');
    this.#identitiesRoot = checkedHash(identitiesRoot, 'identities root');
    this.#replayRoot = checkedHash(replayRoot, 'replay root');
    this.#networkId = asNumber(networkId, 'networkId', Number(MAX_U32));
    this.#suite = asNumber(suite, 'state suite', Number(MAX_U16));
    if (this.#suite !== STATE_SUITE.SORTED_MERKLE_V1) {
      throw new StateError(`unsupported state suite ${this.#suite}`);
    }
  }

  get sequence() { return this.#sequence; }

  get networkId() { return this.#networkId; }

  get suite() { return this.#suite; }

  get parametersRoot() { return Buffer.from(this.#parametersRoot); }

  get identitiesRoot() { return Buffer.from(this.#identitiesRoot); }

  get replayRoot() { return Buffer.from(this.#replayRoot); }

  get accountCount() { return this.#accountCount; }

  getBalance(address) {
    return this.#balances.get(validateAddress(address)) || 0n;
  }

  getNonce(address) {
    return this.#nonces.get(validateAddress(address)) || 0n;
  }

  hasAccount(address) {
    const canonical = validateAddress(address);
    return this.#balances.has(canonical) || this.#nonces.has(canonical);
  }

  entries() {
    return sortedAccountEntries(this.#balances, this.#nonces).map((entry) => Object.freeze({ ...entry }));
  }

  clone() {
    return new GlobalState({
      sequence: this.#sequence,
      balances: this.#balances,
      nonces: this.#nonces,
      parametersRoot: this.#parametersRoot,
      identitiesRoot: this.#identitiesRoot,
      replayRoot: this.#replayRoot,
      networkId: this.#networkId,
      suite: this.#suite,
    });
  }

  credit(address, amount) {
    const canonical = validateAddress(address);
    const delta = asBigInt(amount, 'credit amount', MAX_U128);
    const existed = this.#balances.has(canonical) || this.#nonces.has(canonical);
    const current = this.#balances.get(canonical) || 0n;
    if (current + delta > MAX_U128) throw new StateError('u128 balance overflow');
    const next = current + delta;
    if (!existed && next !== 0n && this.#accountCount >= LIMITS.STATE_ACCOUNTS) {
      throw new StateError(`state exceeds ${LIMITS.STATE_ACCOUNTS} accounts`);
    }
    if (next === 0n) this.#balances.delete(canonical);
    else this.#balances.set(canonical, next);
    const exists = this.#balances.has(canonical) || this.#nonces.has(canonical);
    if (!existed && exists) this.#accountCount += 1;
    return this;
  }

  debit(address, amount) {
    const canonical = validateAddress(address);
    const delta = asBigInt(amount, 'debit amount', MAX_U128);
    const existed = this.#balances.has(canonical) || this.#nonces.has(canonical);
    const current = this.#balances.get(canonical) || 0n;
    if (current < delta) throw new TransitionError('insufficient balance');
    const next = current - delta;
    if (next === 0n) this.#balances.delete(canonical);
    else this.#balances.set(canonical, next);
    const exists = this.#balances.has(canonical) || this.#nonces.has(canonical);
    if (existed && !exists) this.#accountCount -= 1;
    return this;
  }

  setNonce(address, nonce) {
    const canonical = validateAddress(address);
    const next = asBigInt(nonce, 'account nonce', MAX_U64);
    const existed = this.#balances.has(canonical) || this.#nonces.has(canonical);
    if (!existed && next !== 0n && this.#accountCount >= LIMITS.STATE_ACCOUNTS) {
      throw new StateError(`state exceeds ${LIMITS.STATE_ACCOUNTS} accounts`);
    }
    if (next === 0n) this.#nonces.delete(canonical);
    else this.#nonces.set(canonical, next);
    const exists = this.#balances.has(canonical) || this.#nonces.has(canonical);
    if (!existed && exists) this.#accountCount += 1;
    if (existed && !exists) this.#accountCount -= 1;
    return this;
  }

  setComponentRoots({ parametersRoot, identitiesRoot, replayRoot } = {}) {
    if (parametersRoot !== undefined) this.#parametersRoot = checkedHash(parametersRoot, 'parameters root');
    if (identitiesRoot !== undefined) this.#identitiesRoot = checkedHash(identitiesRoot, 'identities root');
    if (replayRoot !== undefined) this.#replayRoot = checkedHash(replayRoot, 'replay root');
    return this;
  }

  accountRoot() {
    return accountTreeRoot(sortedAccountEntries(this.#balances, this.#nonces));
  }

  commitmentBytes() {
    const entries = sortedAccountEntries(this.#balances, this.#nonces);
    return stateCommitmentBytes({
      networkId: this.#networkId,
      suite: this.#suite,
      sequence: this.#sequence,
      accountCount: entries.length,
      accountRoot: accountTreeRoot(entries),
      parametersRoot: this.#parametersRoot,
      identitiesRoot: this.#identitiesRoot,
      replayRoot: this.#replayRoot,
    });
  }

  canonicalBytes() {
    const entries = sortedAccountEntries(this.#balances, this.#nonces);
    const writer = new BinaryWriter(LIMITS.STATE_SERIALIZATION_BYTES);
    writer.write(this.commitmentBytes());
    writer.u32(entries.length);
    for (const entry of entries) {
      writer.ascii(entry.address, {
        maxLength: LIMITS.ADDRESS_BYTES,
        label: 'account address',
        allowEmpty: false,
      });
      writer.u128(entry.balance).u64(entry.nonce);
    }
    return writer.finish();
  }

  root() { return sha3(this.commitmentBytes()); }

  createInclusionProof(address) {
    const canonical = validateAddress(address);
    const entries = sortedAccountEntries(this.#balances, this.#nonces);
    const index = entries.findIndex((entry) => entry.address === canonical);
    if (index < 0) throw new StateError(`account ${canonical} is absent`);
    const layers = merkleLayers(entries);
    const siblings = [];
    let cursor = index;
    for (let level = 0; level < layers.length - 1; level += 1) {
      siblings.push(layers[level][cursor ^ 1].toString('hex'));
      cursor = Math.floor(cursor / 2);
    }
    const accountRoot = layers[layers.length - 1][0];
    const root = stateRootFromMetadata({
      networkId: this.#networkId,
      suite: this.#suite,
      sequence: this.#sequence,
      accountCount: entries.length,
      accountRoot,
      parametersRoot: this.#parametersRoot,
      identitiesRoot: this.#identitiesRoot,
      replayRoot: this.#replayRoot,
    });
    const metadata = proofMetadata(this, entries, accountRoot, root);
    return Object.freeze({
      type: 'inclusion',
      ...metadata,
      index,
      leaf: Object.freeze({
        address: entries[index].address,
        balance: entries[index].balance.toString(),
        nonce: entries[index].nonce.toString(),
      }),
      siblings: Object.freeze(siblings),
    });
  }

  createAbsenceProof(address) {
    const target = validateAddress(address);
    const entries = sortedAccountEntries(this.#balances, this.#nonces);
    const insertion = entries.findIndex((entry) => Buffer.compare(
      Buffer.from(target, 'ascii'),
      Buffer.from(entry.address, 'ascii'),
    ) <= 0);
    const position = insertion < 0 ? entries.length : insertion;
    if (position < entries.length && entries[position].address === target) {
      throw new StateError(`account ${target} is present`);
    }
    const accountRoot = accountTreeRoot(entries);
    const root = this.root();
    const metadata = proofMetadata(this, entries, accountRoot, root);
    return Object.freeze({
      type: 'absence',
      ...metadata,
      target,
      left: position > 0 ? this.createInclusionProof(entries[position - 1].address) : null,
      right: position < entries.length ? this.createInclusionProof(entries[position].address) : null,
    });
  }

  applyTransfer(eventLike) {
    return this.applyConstellation([eventLike]);
  }

  applyTransferWithReceipt(eventLike) {
    return this.applyConstellationWithReceipt([eventLike]);
  }

  /**
   * Atomically closes a set of causally independent transfers.
   *
   * Every event commits to the same base root and the same closure sequence.
   * JS-v1 conservatively defines independence as disjoint touched addresses;
   * overlapping balance resources are an explicit conflict. The state sequence
   * advances once for the complete constellation, never once per event.
   */
  applyConstellation(eventLikes) {
    if (!Array.isArray(eventLikes) || eventLikes.length === 0
      || eventLikes.length > LIMITS.NEXUS_COUNT) {
      throw new TransitionError(`constellation must contain 1..${LIMITS.NEXUS_COUNT} events`);
    }
    const { normalizeAct } = require('./event'); // eslint-disable-line global-require
    const events = eventLikes.map(normalizeAct);
    const previousRoot = this.root();
    const targetSequence = this.#sequence + 1n;
    const resources = new Set();
    const ids = new Set();
    for (const event of events) {
      event.assertValid({ expectedNetworkId: this.#networkId, expectedStateSuite: this.#suite });
      if (!event.previousRoot.equals(previousRoot)) throw new TransitionError('event previous root mismatch');
      if (event.sequence !== targetSequence) throw new TransitionError('event closure sequence mismatch');
      if (event.nonce !== this.getNonce(event.senderAddress) + 1n) {
        throw new TransitionError('event sender nonce mismatch');
      }
      if (this.getBalance(event.senderAddress) < event.amountAtomic) {
        throw new TransitionError('insufficient balance');
      }
      const id = event.id().toString('hex');
      if (ids.has(id)) throw new TransitionError('duplicate event in constellation');
      ids.add(id);
      for (const address of [event.senderAddress, event.receiverAddress]) {
        if (resources.has(address)) {
          throw new TransitionError(`constellation resource conflict at ${address}`);
        }
        resources.add(address);
      }
    }
    // Canonical event-id order makes replay commitment independent of arrival order.
    events.sort((left, right) => Buffer.compare(left.id(), right.id()));
    const next = this.clone();
    for (const event of events) {
      next.debit(event.senderAddress, event.amountAtomic);
      next.credit(event.receiverAddress, event.amountAtomic);
      next.setNonce(event.senderAddress, event.nonce);
    }
    next.#sequence = targetSequence;
    const replayWriter = new BinaryWriter(LIMITS.RECORD_BYTES);
    replayWriter.write(this.#replayRoot).u16(events.length);
    for (const event of events) {
      replayWriter.write(event.id()).write(event.transitionTrace());
    }
    next.#replayRoot = domainHash(DOMAINS.REPLAY, replayWriter.finish());
    return next;
  }

  applyConstellationWithReceipt(eventLikes) {
    const { normalizeAct } = require('./event'); // eslint-disable-line global-require
    const events = eventLikes.map(normalizeAct).sort((left, right) => Buffer.compare(left.id(), right.id()));
    const previousRoot = this.root();
    const state = this.applyConstellation(events);
    const traceWriter = new BinaryWriter(LIMITS.RECORD_BYTES);
    traceWriter.u16(events.length);
    for (const event of events) traceWriter.write(event.transitionTrace());
    const transitionTrace = domainHash(DOMAINS.CONSTELLATION_TRANSITION, traceWriter.finish());
    return Object.freeze({
      state,
      sequence: state.sequence,
      previousRoot: Buffer.from(previousRoot),
      nextRoot: state.root(),
      transitionTrace,
      eventIds: Object.freeze(events.map((event) => event.id().toString('hex'))),
    });
  }

  snapshot() {
    const entries = this.entries().map((entry) => Object.freeze({
      address: entry.address,
      balance: entry.balance.toString(),
      nonce: entry.nonce.toString(),
    }));
    return Object.freeze({
      format: 'vlock7sin-state-js-v1',
      networkId: this.#networkId,
      suite: this.#suite,
      sequence: this.#sequence.toString(),
      parametersRoot: this.#parametersRoot.toString('hex'),
      identitiesRoot: this.#identitiesRoot.toString('hex'),
      replayRoot: this.#replayRoot.toString('hex'),
      root: this.root().toString('hex'),
      accounts: Object.freeze(entries),
    });
  }
}

function computeLegacyStateRoot({ sequence = 0n, balances } = {}) {
  const normalized = normalizeMap(balances, 'legacy balances', MAX_U128);
  const entries = [...normalized.entries()].sort((left, right) => Buffer.compare(
    Buffer.from(left[0], 'ascii'),
    Buffer.from(right[0], 'ascii'),
  ));
  const writer = new BinaryWriter(LIMITS.RECORD_BYTES);
  writer.write(Buffer.from(LEGACY_DOMAINS.STATE, 'ascii'));
  writer.u64(asBigInt(sequence, 'legacy sequence', MAX_U64));
  writer.u32(entries.length);
  for (const [address, amount] of entries) {
    writer.ascii(address, { maxLength: LIMITS.ADDRESS_BYTES, label: 'legacy address' });
    writer.u128(amount);
  }
  return sha3(writer.finish());
}

function normalizeState(state) {
  return state instanceof GlobalState ? state : new GlobalState(state);
}

function cloneState(state) { return normalizeState(state).clone(); }

function computeStateRoot(state) { return normalizeState(state).root(); }

function applyTransfer(state, event) { return normalizeState(state).applyTransfer(event); }

function applyConstellation(state, events) { return normalizeState(state).applyConstellation(events); }

function constellationTransitionTrace(eventLikes) {
  if (!Array.isArray(eventLikes) || eventLikes.length === 0 || eventLikes.length > LIMITS.NEXUS_COUNT) {
    throw new TransitionError(`constellation must contain 1..${LIMITS.NEXUS_COUNT} events`);
  }
  const { normalizeAct } = require('./event'); // eslint-disable-line global-require
  const events = eventLikes.map(normalizeAct).sort((left, right) => Buffer.compare(left.id(), right.id()));
  const writer = new BinaryWriter(LIMITS.RECORD_BYTES);
  writer.u16(events.length);
  for (const event of events) writer.write(event.transitionTrace());
  return domainHash(DOMAINS.CONSTELLATION_TRANSITION, writer.finish());
}

const applyAct = applyTransfer;

module.exports = Object.freeze({
  STATE_PROOF_FORMAT,
  GlobalState,
  accountLeafHash,
  accountTreeRoot,
  stateCommitmentBytes,
  stateRootFromMetadata,
  computeLegacyStateRoot,
  verifyInclusionProof,
  verifyAbsenceProof,
  verifyStateProof,
  normalizeState,
  cloneState,
  computeStateRoot,
  applyTransfer,
  applyConstellation,
  constellationTransitionTrace,
  applyAct,
  emptyComponentRoot,
});
