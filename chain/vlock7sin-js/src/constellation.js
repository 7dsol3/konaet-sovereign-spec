'use strict';

const { createHash } = require('node:crypto');
const { ContractEvent } = require('./contractEvent');
const {
  CausalGraph,
  canonicalBytes,
  compareUtf8,
  normalizeId,
  lockConflicts,
} = require('./causalGraph');

const DOMAIN_CONSTELLATION = Buffer.from('VLOCK7SIN/CONSTELLATION/v1\0', 'ascii');

class ConstellationError extends Error {
  constructor(code, message, details = undefined) {
    super(message);
    this.name = 'ConstellationError';
    this.code = code;
    if (details !== undefined) this.details = details;
  }
}

function hashConstellation(statement) {
  return createHash('sha3-256')
    .update(DOMAIN_CONSTELLATION)
    .update(canonicalBytes(statement))
    .digest('hex');
}

function rootHex(value, label = 'previousRoot') {
  if (value == null) return null;
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    const bytes = Buffer.from(value);
    if (bytes.length !== 32) throw new ConstellationError('INVALID_ROOT', `${label} must be 32 bytes`);
    return bytes.toString('hex');
  }
  const normalized = String(value).toLowerCase().replace(/^0x/, '');
  if (!/^[0-9a-f]{64}$/.test(normalized)) {
    throw new ConstellationError('INVALID_ROOT', `${label} must be 64 hexadecimal characters`);
  }
  return normalized;
}

function sequenceString(value) {
  if (value == null) return null;
  let sequence;
  try { sequence = BigInt(value); } catch {
    throw new ConstellationError('INVALID_SEQUENCE', 'constellation sequence must be an unsigned integer');
  }
  if (sequence < 0n || sequence > 0xffffffffffffffffn) {
    throw new ConstellationError('INVALID_SEQUENCE', 'constellation sequence must fit u64');
  }
  return sequence.toString(10);
}

function computeConstellationId({ networkId = null, sequence = null, previousRoot = null, actIds }) {
  if (!Array.isArray(actIds) || actIds.length === 0) {
    throw new ConstellationError('EMPTY_CONSTELLATION', 'a constellation must contain at least one act');
  }
  const normalizedIds = actIds.map((id) => normalizeId(id, 'constellation act id'));
  if (new Set(normalizedIds).size !== normalizedIds.length) {
    throw new ConstellationError('DUPLICATE_ACT', 'constellation act ids must be unique');
  }
  return hashConstellation({
    networkId: networkId == null ? null : String(networkId),
    sequence: sequenceString(sequence),
    previousRoot: rootHex(previousRoot),
    actIds: normalizedIds,
  });
}

function positiveLimit(value, fallback, label) {
  if (value == null) return fallback;
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new ConstellationError('INVALID_LIMIT', `${label} must be a positive safe integer`);
  }
  return value;
}

function selectedLockSet(graph, selectedIds) {
  const reads = new Set();
  const writes = new Set();
  for (const id of selectedIds) {
    const locks = graph.getNode(id).locks;
    for (const resource of locks.write) {
      writes.add(resource);
      reads.delete(resource);
    }
    for (const resource of locks.read) if (!writes.has(resource)) reads.add(resource);
  }
  return Object.freeze({
    read: Object.freeze([...reads].sort(compareUtf8)),
    write: Object.freeze([...writes].sort(compareUtf8)),
  });
}

class ConstellationSelector {
  constructor(options = {}) {
    Object.defineProperties(this, {
      maxActs: { value: positiveLimit(options.maxActs, Number.MAX_SAFE_INTEGER, 'maxActs'), enumerable: true },
      maxBytes: { value: positiveLimit(options.maxBytes, Number.MAX_SAFE_INTEGER, 'maxBytes'), enumerable: true },
      maxGas: { value: options.maxGas == null ? null : positiveLimit(options.maxGas, null, 'maxGas'), enumerable: true },
      networkId: { value: options.networkId == null ? null : String(options.networkId), enumerable: true },
      allowInternalDependencies: { value: options.allowInternalDependencies === true, enumerable: true },
    });
  }

  select(graph, options = {}) {
    if (!(graph instanceof CausalGraph) && (!graph || typeof graph.topologicalOrder !== 'function')) {
      throw new ConstellationError('INVALID_GRAPH', 'select requires a CausalGraph-compatible object');
    }
    graph.assertValid();

    const maxActs = positiveLimit(options.maxActs, this.maxActs, 'maxActs');
    const maxBytes = positiveLimit(options.maxBytes, this.maxBytes, 'maxBytes');
    const maxGas = options.maxGas == null ? this.maxGas : positiveLimit(options.maxGas, null, 'maxGas');
    const eligible = options.eligibleIds == null
      ? new Set(graph.topologicalOrder().filter((id) => !graph.isClosed(id)))
      : new Set(options.eligibleIds.map((id) => normalizeId(id)));

    for (const id of eligible) {
      if (!graph.has(id)) throw new ConstellationError('ACT_MISSING', `eligible act ${id} is missing`);
      if (graph.isClosed(id)) eligible.delete(id);
    }

    const candidates = graph.topologicalOrder({ ids: [...eligible] });
    const selected = [];
    const selectedSet = new Set();
    const deferred = [];
    let totalBytes = 0;
    let totalGas = 0;

    for (const id of candidates) {
      const node = graph.getNode(id);
      const allowInternalDependencies = options.allowInternalDependencies ?? this.allowInternalDependencies;
      const blockedParent = node.parents.find((parentId) => !graph.isClosed(parentId)
        && !(allowInternalDependencies && selectedSet.has(parentId)));
      if (blockedParent) {
        deferred.push(Object.freeze({
          actId: id,
          reason: 'PARENT_NOT_SELECTED',
          parentId: blockedParent,
        }));
        continue;
      }

      let blocker = null;
      let details = null;
      for (const selectedId of selected) {
        const conflicts = lockConflicts(node.locks, graph.getNode(selectedId).locks);
        if (conflicts.length) {
          blocker = selectedId;
          details = conflicts;
          break;
        }
      }
      if (blocker) {
        deferred.push(Object.freeze({
          actId: id,
          reason: 'LOCK_CONFLICT',
          conflictingWith: blocker,
          conflicts: Object.freeze(details),
        }));
        continue;
      }

      const encodedSize = typeof node.act.canonicalBytes === 'function'
        ? node.act.canonicalBytes().length
        : canonicalBytes(node.act).length;
      if (selected.length >= maxActs) {
        deferred.push(Object.freeze({ actId: id, reason: 'MAX_ACTS' }));
        continue;
      }
      if (encodedSize > maxBytes - totalBytes) {
        deferred.push(Object.freeze({ actId: id, reason: 'MAX_BYTES', encodedSize }));
        continue;
      }
      const reservedGas = node.act instanceof ContractEvent ? node.act.envelope.payload.gasLimit : 0;
      if (maxGas !== null && reservedGas > maxGas - totalGas) {
        deferred.push(Object.freeze({ actId: id, reason: 'MAX_GAS', reservedGas })); continue;
      }
      if (typeof options.canInclude === 'function' && !options.canInclude([...selected, id])) {
        deferred.push(Object.freeze({ actId: id, reason: 'STATE_CAPACITY' })); continue;
      }

      selected.push(id);
      selectedSet.add(id);
      totalBytes += encodedSize;
      totalGas += reservedGas;
    }

    if (selected.length === 0 && options.allowEmpty !== true) {
      throw new ConstellationError('EMPTY_CONSTELLATION', 'no causally ready, non-conflicting act fits this constellation', {
        deferred,
      });
    }

    const context = {
      networkId: options.networkId ?? this.networkId,
      sequence: options.sequence ?? null,
      previousRoot: options.previousRoot ?? null,
      actIds: selected,
    };
    const id = selected.length ? computeConstellationId(context) : null;
    return Object.freeze({
      version: 1,
      id,
      networkId: context.networkId == null ? null : String(context.networkId),
      sequence: sequenceString(context.sequence),
      previousRoot: rootHex(context.previousRoot),
      actIds: Object.freeze(selected),
      totalBytes,
      ...(maxGas !== null ? { totalGas } : {}),
      locks: selectedLockSet(graph, selected),
      deferred: Object.freeze(deferred),
      policy: Object.freeze({
        strategy: 'TOPOLOGICAL_LEXICOGRAPHIC_GREEDY',
        maxActs,
        maxBytes,
        ...(maxGas !== null ? { maxGas } : {}),
        allowInternalDependencies: options.allowInternalDependencies ?? this.allowInternalDependencies,
      }),
    });
  }

  verify(graph, constellation, context = {}) {
    if (!constellation || constellation.version !== 1 || !Array.isArray(constellation.actIds)) {
      throw new ConstellationError('INVALID_CONSTELLATION', 'invalid constellation object');
    }
    const rebuilt = this.select(graph, {
      eligibleIds: context.eligibleIds,
      maxActs: constellation.policy?.maxActs ?? this.maxActs,
      maxBytes: constellation.policy?.maxBytes ?? this.maxBytes,
      maxGas: constellation.policy?.maxGas ?? this.maxGas,
      allowInternalDependencies: constellation.policy?.allowInternalDependencies === true,
      networkId: constellation.networkId,
      sequence: constellation.sequence,
      previousRoot: constellation.previousRoot,
      allowEmpty: constellation.actIds.length === 0,
      canInclude: context.canInclude,
    });
    const actual = constellation.actIds.map((id) => normalizeId(id));
    if (rebuilt.actIds.length !== actual.length || rebuilt.actIds.some((id, index) => id !== actual[index])) {
      throw new ConstellationError('NON_DETERMINISTIC_SELECTION', 'constellation does not match deterministic selection', {
        expected: rebuilt.actIds,
        actual,
      });
    }
    if (rebuilt.id !== constellation.id) {
      throw new ConstellationError('CONSTELLATION_ID_MISMATCH', 'constellation id does not match its contents');
    }
    return true;
  }
}

function selectConstellation(graph, options = {}) {
  return new ConstellationSelector(options).select(graph, options);
}

module.exports = {
  ConstellationError,
  ConstellationSelector,
  computeConstellationId,
  selectConstellation,
};
