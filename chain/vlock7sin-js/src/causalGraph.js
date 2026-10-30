'use strict';

const { createHash } = require('node:crypto');
const { TransferEvent } = require('./event');

const DOMAIN_ACT_ID = Buffer.from('VLOCK7SIN/ACT-ID/v1\0', 'ascii');
const DOMAIN_NEXO_ID = Buffer.from('VLOCK7SIN/NEXO-ID/v1\0', 'ascii');
const ID_BYTES = 32;

class CausalGraphError extends Error {
  constructor(code, message, details = undefined) {
    super(message);
    this.name = 'CausalGraphError';
    this.code = code;
    if (details !== undefined) this.details = details;
  }
}

function sha3(...parts) {
  const hash = createHash('sha3-256');
  for (const part of parts) hash.update(part);
  return hash.digest();
}

function compareUtf8(left, right) {
  return Buffer.compare(Buffer.from(String(left), 'utf8'), Buffer.from(String(right), 'utf8'));
}

/*
 * This encoder is deliberately independent of JSON object insertion order and
 * preserves BigInt/bytes.  It is used only for runtime commitments; the wire
 * and Phase-0 record codecs remain owned by codec.js.
 */
function canonicalNode(value, seen) {
  if (value === null) return ['null'];
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    return ['bytes', Buffer.from(value).toString('hex')];
  }

  switch (typeof value) {
  case 'string': return ['string', value];
  case 'boolean': return ['boolean', value];
  case 'bigint': return ['bigint', value.toString(10)];
  case 'number':
    if (!Number.isFinite(value) || Object.is(value, -0)) {
      throw new TypeError('canonical encoding only accepts finite numbers and rejects -0');
    }
    return ['number', value.toString(10)];
  case 'undefined': return ['undefined'];
  case 'object': break;
  default: throw new TypeError(`unsupported canonical value type: ${typeof value}`);
  }

  if (seen.has(value)) throw new TypeError('canonical encoding rejects cyclic objects');
  seen.add(value);
  try {
    if (Array.isArray(value)) {
      return ['array', value.map((item) => canonicalNode(item, seen))];
    }
    if (value instanceof Map) {
      const entries = [...value.entries()].map(([key, item]) => [
        canonicalNode(key, seen),
        canonicalNode(item, seen),
      ]);
      entries.sort((a, b) => compareUtf8(JSON.stringify(a[0]), JSON.stringify(b[0])));
      for (let index = 1; index < entries.length; index += 1) {
        if (compareUtf8(JSON.stringify(entries[index - 1][0]), JSON.stringify(entries[index][0])) === 0) {
          throw new TypeError('canonical encoding rejects canonically duplicate map keys');
        }
      }
      return ['map', entries];
    }
    if (value instanceof Set) {
      const entries = [...value].map((item) => canonicalNode(item, seen));
      entries.sort((a, b) => compareUtf8(JSON.stringify(a), JSON.stringify(b)));
      for (let index = 1; index < entries.length; index += 1) {
        if (compareUtf8(JSON.stringify(entries[index - 1]), JSON.stringify(entries[index])) === 0) {
          throw new TypeError('canonical encoding rejects canonically duplicate set values');
        }
      }
      return ['set', entries];
    }
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError('canonical encoding accepts only plain objects, arrays, maps, sets and bytes');
    }
    const entries = Object.keys(value)
      .sort(compareUtf8)
      .map((key) => [key, canonicalNode(value[key], seen)]);
    return ['object', entries];
  } finally {
    seen.delete(value);
  }
}

function canonicalBytes(value) {
  return Buffer.from(JSON.stringify(canonicalNode(value, new Set())), 'utf8');
}

function normalizeId(value, label = 'id') {
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    const bytes = Buffer.from(value);
    if (bytes.length !== ID_BYTES) {
      throw new CausalGraphError('INVALID_ID', `${label} must contain ${ID_BYTES} bytes`);
    }
    return bytes.toString('hex');
  }
  if (typeof value !== 'string') {
    throw new CausalGraphError('INVALID_ID', `${label} must be a 32-byte value or hexadecimal string`);
  }
  const normalized = value.toLowerCase().replace(/^0x/, '');
  if (!/^[0-9a-f]{64}$/.test(normalized)) {
    throw new CausalGraphError('INVALID_ID', `${label} must be exactly 64 hexadecimal characters`);
  }
  return normalized;
}

function isCoreTransferEvent(value) {
  return value instanceof TransferEvent && Object.getPrototypeOf(value) === TransferEvent.prototype;
}

function cloneValue(value, seen = new Map()) {
  if (value === null || typeof value !== 'object') return value;
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) return Buffer.from(value);
  // Core records are immutable through private fields and expose canonicalBytes().
  // Keep the instance so its signature/id semantics are not flattened away.
  if (isCoreTransferEvent(value)) return value;
  const prototype = Object.getPrototypeOf(value);
  const supported = Array.isArray(value)
    || prototype === Map.prototype
    || prototype === Set.prototype
    || prototype === Object.prototype
    || prototype === null;
  if (!supported) throw new TypeError(`unsupported mutable/custom object: ${prototype?.constructor?.name ?? 'unknown'}`);
  if (seen.has(value)) throw new TypeError('acts must not contain cyclic values');
  seen.set(value, true);
  try {
    if (Array.isArray(value)) {
      const descriptors = Object.getOwnPropertyDescriptors(value);
      const allowed = new Set(['length', ...Array.from({ length: value.length }, (_, index) => String(index))]);
      if (Reflect.ownKeys(descriptors).some((key) => typeof key !== 'string' || !allowed.has(key))) {
        throw new TypeError('act arrays cannot contain holes, symbols or custom properties');
      }
      const output = [];
      for (let index = 0; index < value.length; index += 1) {
        const descriptor = descriptors[String(index)];
        if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, 'value')) {
          throw new TypeError('act arrays cannot contain holes or accessors');
        }
        output.push(cloneValue(descriptor.value, seen));
      }
      return output;
    }
    if (value instanceof Map) {
      return new Map([...value].map(([key, item]) => [cloneValue(key, seen), cloneValue(item, seen)]));
    }
    if (value instanceof Set) return new Set([...value].map((item) => cloneValue(item, seen)));
    const descriptors = Object.getOwnPropertyDescriptors(value);
    if (Reflect.ownKeys(descriptors).some((key) => typeof key !== 'string')) {
      throw new TypeError('acts cannot contain symbol properties');
    }
    const output = Object.create(prototype === null ? null : Object.prototype);
    for (const key of Object.keys(descriptors)) {
      const descriptor = descriptors[key];
      if (!Object.prototype.hasOwnProperty.call(descriptor, 'value')) {
        throw new TypeError(`act property ${key} cannot be an accessor`);
      }
      if (descriptor.enumerable) output[key] = cloneValue(descriptor.value, seen);
    }
    return output;
  } finally {
    seen.delete(value);
  }
}

function withoutDerivedIdentity(act) {
  const copy = {};
  const omitted = new Set(['id', 'actId', 'nexoIds', '_id', '_nexuses']);
  for (const key of Object.keys(act).sort(compareUtf8)) {
    if (omitted.has(key)) continue;
    if ((key === 'nexuses' || key === 'nexos') && Array.isArray(act[key])) {
      copy[key] = act[key].map((nexo) => {
        if (!nexo || typeof nexo !== 'object' || Buffer.isBuffer(nexo) || nexo instanceof Uint8Array) return nexo;
        const descriptor = { ...nexo };
        delete descriptor.id;
        delete descriptor.nexoId;
        return descriptor;
      });
    } else copy[key] = act[key];
  }
  return copy;
}

function computeActId(act, customHash = undefined) {
  if (!act || typeof act !== 'object' || Array.isArray(act)) {
    throw new CausalGraphError('INVALID_ACT', 'act must be an object');
  }
  if (isCoreTransferEvent(act)) {
    return normalizeId(TransferEvent.prototype.id.call(act), 'computed act id');
  }
  const prototype = Object.getPrototypeOf(act);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new CausalGraphError('INVALID_ACT', 'only plain objects or an exact TransferEvent are valid acts');
  }
  const payload = canonicalBytes(withoutDerivedIdentity(act));
  const digest = customHash ? customHash(DOMAIN_ACT_ID, payload) : sha3(DOMAIN_ACT_ID, payload);
  return normalizeId(digest, 'computed act id');
}

function parentDescriptor(value) {
  if (typeof value === 'string' || Buffer.isBuffer(value) || value instanceof Uint8Array) {
    return { parentId: normalizeId(value, 'parent id'), relation: 'DEPENDS_ON', suppliedId: null };
  }
  if (!value || typeof value !== 'object') {
    throw new CausalGraphError('INVALID_NEXO', 'nexo must be a parent id or object');
  }
  const parent = value.parentId ?? value.parent ?? value.actId ?? value.target;
  const relation = String(value.relation ?? value.type ?? 'DEPENDS_ON').trim().toUpperCase();
  if (!/^[A-Z][A-Z0-9_.:-]{0,63}$/.test(relation)) {
    throw new CausalGraphError('INVALID_NEXO', `invalid nexo relation: ${relation}`);
  }
  return {
    parentId: normalizeId(parent, 'nexo parent id'),
    relation,
    suppliedId: value.id == null ? null : normalizeId(value.id, 'nexo id'),
  };
}

function extractParentDescriptors(act) {
  const source = act.nexuses ?? act.nexos ?? act.parents ?? act.parentIds ?? [];
  if (!Array.isArray(source)) {
    throw new CausalGraphError('INVALID_NEXO', 'act nexuses/parents must be an array');
  }
  const byEdge = new Map();
  for (const item of source) {
    const descriptor = parentDescriptor(item);
    const key = `${descriptor.parentId}:${descriptor.relation}`;
    if (byEdge.has(key)) throw new CausalGraphError('DUPLICATE_NEXO', `duplicate nexo ${key}`);
    byEdge.set(key, descriptor);
  }
  return [...byEdge.values()].sort((a, b) => {
    const parentOrder = compareUtf8(a.parentId, b.parentId);
    return parentOrder || compareUtf8(a.relation, b.relation);
  });
}

function computeNexoId(parentId, childId, relation = 'DEPENDS_ON') {
  const descriptor = {
    parentId: normalizeId(parentId, 'nexo parent id'),
    childId: normalizeId(childId, 'nexo child id'),
    relation: String(relation).toUpperCase(),
  };
  return sha3(DOMAIN_NEXO_ID, canonicalBytes(descriptor)).toString('hex');
}

function lockResource(value) {
  if (typeof value !== 'string') throw new CausalGraphError('INVALID_LOCK', 'lock resource must be a string');
  const normalized = value.normalize('NFC');
  const size = Buffer.byteLength(normalized, 'utf8');
  const hasControl = [...normalized].some((character) => {
    const codePoint = character.codePointAt(0);
    return codePoint <= 0x1f || codePoint === 0x7f;
  });
  if (size < 1 || size > 256 || hasControl) {
    throw new CausalGraphError('INVALID_LOCK', 'lock resource must be 1..256 UTF-8 bytes without controls');
  }
  return normalized;
}

function normalizeLocks(act, requireExplicit = true) {
  const reads = new Set();
  const writes = new Set();
  let explicit = false;

  const add = (mode, resource) => {
    const key = lockResource(resource);
    if (mode === 'WRITE' || mode === 'EXCLUSIVE') writes.add(key);
    else if (mode === 'READ' || mode === 'SHARED') reads.add(key);
    else throw new CausalGraphError('INVALID_LOCK', `unknown lock mode: ${mode}`);
  };

  const list = (value, label) => {
    if (value === undefined || value === null) return [];
    if (!Array.isArray(value)) throw new CausalGraphError('INVALID_LOCK', `${label} must be an array`);
    return value;
  };

  const locks = act.locks ?? act.lockSet;
  if (Array.isArray(locks)) {
    explicit = true;
    for (const lock of locks) {
      if (!lock || typeof lock !== 'object') throw new CausalGraphError('INVALID_LOCK', 'lock entries must be objects');
      add(String(lock.mode ?? '').toUpperCase(), lock.resource ?? lock.key);
    }
  } else if (locks && typeof locks === 'object') {
    explicit = true;
    for (const resource of list(locks.read ?? locks.reads, 'locks.read')) add('READ', resource);
    for (const resource of list(locks.write ?? locks.writes, 'locks.write')) add('WRITE', resource);
  }

  for (const resource of list(act.readSet ?? act.reads, 'act read set')) {
    explicit = true;
    add('READ', resource);
  }
  for (const resource of list(act.writeSet ?? act.writes, 'act write set')) {
    explicit = true;
    add('WRITE', resource);
  }

  // Known transfer semantics have a complete, conservative implicit lock set.
  const kind = String(act.kind ?? act.type ?? '').toUpperCase();
  if (!explicit && (kind === 'TRANSFER' || kind === 'ACT_TRANSFER' || (act.senderAddress && act.receiverAddress))) {
    const body = act.body ?? act.payload ?? act;
    const from = body.from ?? body.sender ?? body.senderAddress ?? body.author ?? act.author;
    const to = body.to ?? body.recipient ?? body.receiverAddress;
    if (from && to) {
      add('WRITE', `account:${String(from)}`);
      add('WRITE', `account:${String(to)}`);
      add('WRITE', `nonce:${String(from)}`);
      explicit = true;
    }
  }

  if (!explicit && requireExplicit) {
    throw new CausalGraphError('LOCKS_REQUIRED', 'act must declare read/write locks for deterministic conflict handling');
  }

  for (const key of writes) reads.delete(key);
  return Object.freeze({
    read: Object.freeze([...reads].sort(compareUtf8)),
    write: Object.freeze([...writes].sort(compareUtf8)),
  });
}

function lockConflicts(leftLocks, rightLocks) {
  const leftReads = new Set(leftLocks.read);
  const leftWrites = new Set(leftLocks.write);
  const rightReads = new Set(rightLocks.read);
  const rightWrites = new Set(rightLocks.write);
  const resources = new Set([...leftWrites, ...rightWrites]);
  const conflicts = [];
  for (const resource of [...resources].sort(compareUtf8)) {
    let modes = null;
    if (leftWrites.has(resource) && rightWrites.has(resource)) modes = ['WRITE', 'WRITE'];
    else if (leftWrites.has(resource) && rightReads.has(resource)) modes = ['WRITE', 'READ'];
    else if (leftReads.has(resource) && rightWrites.has(resource)) modes = ['READ', 'WRITE'];
    if (modes) conflicts.push(Object.freeze({ resource, leftMode: modes[0], rightMode: modes[1] }));
  }
  return conflicts;
}

class CausalGraph {
  #nodes;

  #children;

  #closed;

  constructor(options = {}) {
    this.#nodes = new Map();
    this.#children = new Map();
    this.#closed = new Set();
    Object.defineProperties(this, {
      requireExplicitLocks: { value: options.requireExplicitLocks !== false, enumerable: true },
      hash: { value: typeof options.hash === 'function' ? options.hash : undefined },
    });
  }

  get size() { return this.#nodes.size; }

  // Compatibility snapshots: mutating these copies never mutates the graph.
  get nodes() { return new Map([...this.#nodes].map(([id]) => [id, this.getNode(id)])); }

  get children() { return new Map([...this.#children].map(([id, values]) => [id, new Set(values)])); }

  get closed() { return new Set(this.#closed); }

  has(id) { return this.#nodes.has(normalizeId(id)); }

  get(id) {
    const normalized = normalizeId(id);
    const node = this.#nodes.get(normalized);
    return node ? cloneValue(node.act) : undefined;
  }

  getNode(id) {
    const node = this.#nodes.get(normalizeId(id));
    if (!node) return undefined;
    return Object.freeze({
      id: node.id,
      act: cloneValue(node.act),
      parents: node.parents,
      nexuses: node.nexuses,
      locks: node.locks,
    });
  }

  isClosed(id) { return this.#closed.has(normalizeId(id)); }

  _normalizeAct(input) {
    let act;
    try { act = cloneValue(input); } catch (error) {
      throw new CausalGraphError('INVALID_ACT', `act cannot be snapshotted safely: ${error.message}`);
    }
    const computedId = computeActId(act, this.hash);
    const supplied = Object.prototype.hasOwnProperty.call(act, 'id') ? act.id : act.actId;
    if (supplied != null && normalizeId(supplied, 'act id') !== computedId) {
      throw new CausalGraphError('ACT_ID_MISMATCH', 'supplied act id does not match its canonical hash', {
        supplied: normalizeId(supplied),
        computed: computedId,
      });
    }
    const descriptors = extractParentDescriptors(act);
    const nexuses = descriptors.map((descriptor) => {
      const id = computeNexoId(descriptor.parentId, computedId, descriptor.relation);
      if (descriptor.suppliedId && descriptor.suppliedId !== id) {
        throw new CausalGraphError('NEXO_ID_MISMATCH', 'supplied nexo id does not match its edge hash', {
          supplied: descriptor.suppliedId,
          computed: id,
        });
      }
      return Object.freeze({ id, parentId: descriptor.parentId, childId: computedId, relation: descriptor.relation });
    });
    const locks = normalizeLocks(act, this.requireExplicitLocks);
    if (typeof act.id !== 'function') act.id = computedId;
    return Object.freeze({
      id: computedId,
      act,
      parents: Object.freeze([...new Set(nexuses.map((nexo) => nexo.parentId))].sort(compareUtf8)),
      nexuses: Object.freeze(nexuses),
      locks,
    });
  }

  addAct(act) { return this.addBatch([act])[0]; }

  addBatch(acts) {
    if (!Array.isArray(acts) || acts.length === 0) {
      throw new CausalGraphError('INVALID_BATCH', 'addBatch requires a non-empty array');
    }
    const pending = acts.map((act) => this._normalizeAct(act));
    const pendingIds = new Set();
    for (const node of pending) {
      if (this.#nodes.has(node.id) || pendingIds.has(node.id)) {
        throw new CausalGraphError('DUPLICATE_ACT', `act ${node.id} already exists`);
      }
      pendingIds.add(node.id);
    }
    for (const node of pending) {
      for (const parentId of node.parents) {
        if (parentId === node.id) throw new CausalGraphError('CAUSAL_CYCLE', `act ${node.id} references itself`);
        if (!this.#nodes.has(parentId) && !pendingIds.has(parentId)) {
          throw new CausalGraphError('PARENT_MISSING', `parent ${parentId} required by ${node.id} is missing`, {
            actId: node.id,
            parentId,
          });
        }
      }
    }

    // Existing nodes form an immutable DAG and cannot reference a new ID.
    // Any newly introduced cycle must therefore be wholly inside this batch.
    // Missing parents and duplicate/self IDs were rejected before this step.
    const pendingParents = new Map(pending.map(node => [node.id, node.parents.filter(id => pendingIds.has(id))]));
    CausalGraph._assertAcyclic(pendingParents);

    for (const node of pending) {
      this.#nodes.set(node.id, node);
      if (!this.#children.has(node.id)) this.#children.set(node.id, new Set());
      for (const parentId of node.parents) {
        if (!this.#children.has(parentId)) this.#children.set(parentId, new Set());
        this.#children.get(parentId).add(node.id);
      }
    }
    return pending.map((node) => node.id);
  }

  static _assertAcyclic(parentMap) {
    const indegree = new Map([...parentMap.keys()].map((id) => [id, 0]));
    const children = new Map([...parentMap.keys()].map((id) => [id, []]));
    for (const [childId, parents] of parentMap) {
      for (const parentId of parents) {
        if (!indegree.has(parentId)) {
          throw new CausalGraphError('PARENT_MISSING', `parent ${parentId} is missing from graph`);
        }
        indegree.set(childId, indegree.get(childId) + 1);
        children.get(parentId).push(childId);
      }
    }
    const ready = [...indegree].filter(([, degree]) => degree === 0).map(([id]) => id).sort(compareUtf8);
    let visited = 0;
    while (ready.length) {
      const id = ready.shift();
      visited += 1;
      for (const childId of children.get(id).sort(compareUtf8)) {
        const degree = indegree.get(childId) - 1;
        indegree.set(childId, degree);
        if (degree === 0) {
          ready.push(childId);
          ready.sort(compareUtf8);
        }
      }
    }
    if (visited !== parentMap.size) {
      const cycleNodes = [...indegree].filter(([, degree]) => degree > 0).map(([id]) => id).sort(compareUtf8);
      throw new CausalGraphError('CAUSAL_CYCLE', 'causal graph contains a cycle', { cycleNodes });
    }
  }

  assertValid() {
    CausalGraph._assertAcyclic(new Map([...this.#nodes].map(([id, node]) => [id, node.parents])));
    return true;
  }

  topologicalOrder(options = {}) {
    const selected = options.ids == null
      ? new Set(this.#nodes.keys())
      : new Set(options.ids.map((id) => normalizeId(id)));
    for (const id of selected) {
      if (!this.#nodes.has(id)) throw new CausalGraphError('ACT_MISSING', `act ${id} is missing`);
    }
    const indegree = new Map([...selected].map((id) => [id, 0]));
    const children = new Map([...selected].map((id) => [id, []]));
    for (const id of selected) {
      for (const parentId of this.#nodes.get(id).parents) {
        if (!selected.has(parentId)) continue;
        indegree.set(id, indegree.get(id) + 1);
        children.get(parentId).push(id);
      }
    }
    const ready = [...indegree].filter(([, degree]) => degree === 0).map(([id]) => id).sort(compareUtf8);
    const order = [];
    while (ready.length) {
      const id = ready.shift();
      order.push(id);
      for (const childId of children.get(id).sort(compareUtf8)) {
        const degree = indegree.get(childId) - 1;
        indegree.set(childId, degree);
        if (degree === 0) {
          ready.push(childId);
          ready.sort(compareUtf8);
        }
      }
    }
    if (order.length !== selected.size) throw new CausalGraphError('CAUSAL_CYCLE', 'selected graph contains a cycle');
    return order;
  }

  readyIds() {
    return this.topologicalOrder().filter((id) => {
      if (this.#closed.has(id)) return false;
      return this.#nodes.get(id).parents.every((parentId) => this.#closed.has(parentId));
    });
  }

  conflictDetails(left, right) {
    const leftNode = typeof left === 'object' && left.locks ? left : this.getNode(left);
    const rightNode = typeof right === 'object' && right.locks ? right : this.getNode(right);
    if (!leftNode || !rightNode) throw new CausalGraphError('ACT_MISSING', 'cannot compare locks for a missing act');
    return lockConflicts(leftNode.locks, rightNode.locks);
  }

  conflicts(left, right) { return this.conflictDetails(left, right).length > 0; }

  markClosed(ids) {
    const normalized = ids.map((id) => normalizeId(id));
    const closing = new Set(normalized);
    if (closing.size !== normalized.length) throw new CausalGraphError('DUPLICATE_ACT', 'close list contains duplicate act ids');
    for (const id of normalized) {
      const node = this.#nodes.get(id);
      if (!node) throw new CausalGraphError('ACT_MISSING', `cannot close missing act ${id}`);
      if (this.#closed.has(id)) throw new CausalGraphError('ALREADY_CLOSED', `act ${id} is already closed`);
      for (const parentId of node.parents) {
        if (!this.#closed.has(parentId) && !closing.has(parentId)) {
          throw new CausalGraphError('UNCLOSED_PARENT', `cannot close ${id} before parent ${parentId}`);
        }
      }
    }
    const topological = this.topologicalOrder({ ids: normalized });
    for (const id of topological) this.#closed.add(id);
    return topological;
  }

  snapshot() {
    return {
      version: 1,
      requireExplicitLocks: this.requireExplicitLocks,
      closed: [...this.#closed].sort(compareUtf8),
      acts: this.topologicalOrder().map((id) => cloneValue(this.#nodes.get(id).act)),
    };
  }

  static fromSnapshot(snapshot, options = {}) {
    if (!snapshot || snapshot.version !== 1 || !Array.isArray(snapshot.acts) || !Array.isArray(snapshot.closed)) {
      throw new CausalGraphError('INVALID_SNAPSHOT', 'invalid causal graph snapshot');
    }
    const graph = new CausalGraph({
      ...options,
      requireExplicitLocks: snapshot.requireExplicitLocks !== false,
    });
    if (snapshot.acts.length) graph.addBatch(snapshot.acts);
    if (snapshot.closed.length) graph.markClosed(snapshot.closed);
    return graph;
  }
}

module.exports = {
  CausalGraph,
  CausalGraphError,
  compareUtf8,
  canonicalBytes,
  computeActId,
  computeNexoId,
  normalizeId,
  normalizeLocks,
  lockConflicts,
};
