'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');
const {
  CausalGraph,
  CausalGraphError,
  computeActId,
} = require('../src/causalGraph');
const {
  ConstellationSelector,
} = require('../src/constellation');

function act(label, options = {}) {
  return {
    type: 'TEST',
    label,
    parents: options.parents || [],
    locks: options.locks || { read: [], write: [`resource:${label}`] },
    payload: options.payload || {},
  };
}

test('graph resolves batches and returns bytewise deterministic topological order', () => {
  const parent = act('parent');
  const parentId = computeActId(parent);
  const child = act('child', { parents: [parentId] });
  const independent = act('independent');
  const graph = new CausalGraph();
  graph.addBatch([child, independent, parent]);
  const sameGraph = new CausalGraph();
  sameGraph.addBatch([parent, independent, child]);

  const order = graph.topologicalOrder();
  assert.equal(order.indexOf(parentId) < order.indexOf(computeActId(child)), true);
  assert.deepEqual(order, sameGraph.topologicalOrder());
  assert.equal(graph.assertValid(), true);
});

test('missing parents and cycles fail before mutating the graph', () => {
  const graph = new CausalGraph();
  const missing = 'ab'.repeat(32);
  assert.throws(
    () => graph.addAct(act('orphan', { parents: [missing] })),
    (error) => error instanceof CausalGraphError && error.code === 'PARENT_MISSING',
  );
  assert.equal(graph.size, 0);

  const fixedId = Buffer.alloc(32, 1);
  const cyclic = new CausalGraph({ hash: () => fixedId });
  assert.throws(
    () => cyclic.addAct(act('self', { parents: [fixedId] })),
    (error) => error instanceof CausalGraphError && error.code === 'CAUSAL_CYCLE',
  );
  assert.equal(cyclic.size, 0);
});

test('constellation closes ready parents before children', () => {
  const parent = act('parent');
  const parentId = computeActId(parent);
  const child = act('child', { parents: [parentId] });
  const childId = computeActId(child);
  const graph = new CausalGraph();
  graph.addBatch([child, parent]);
  const selector = new ConstellationSelector({ maxActs: 10 });

  const first = selector.select(graph, { networkId: 0x7001, sequence: 1n, previousRoot: Buffer.alloc(32) });
  assert.deepEqual(first.actIds, [parentId]);
  graph.markClosed(first.actIds);
  const second = selector.select(graph, { networkId: 0x7001, sequence: 2n, previousRoot: Buffer.alloc(32) });
  assert.deepEqual(second.actIds, [childId]);
});

test('conflicting locks are split deterministically regardless of insertion order', () => {
  const firstAct = act('first', { locks: { write: ['account:shared'] } });
  const secondAct = act('second', { locks: { write: ['account:shared'] } });
  const expected = [computeActId(firstAct), computeActId(secondAct)].sort()[0];

  for (const input of [[firstAct, secondAct], [secondAct, firstAct]]) {
    const graph = new CausalGraph();
    graph.addBatch(input);
    const constellation = new ConstellationSelector().select(graph, {
      networkId: 0x7001,
      sequence: 1n,
      previousRoot: Buffer.alloc(32),
    });
    assert.deepEqual(constellation.actIds, [expected]);
    assert.equal(constellation.deferred.length, 1);
    assert.equal(constellation.deferred[0].reason, 'LOCK_CONFLICT');
  }
});

test('read/read locks commute while read/write locks conflict', () => {
  const graph = new CausalGraph();
  const readerA = act('reader-a', { locks: { read: ['object:x'] } });
  const readerB = act('reader-b', { locks: { read: ['object:x'] } });
  const writer = act('writer', { locks: { write: ['object:x'] } });
  graph.addBatch([readerA, readerB, writer]);
  assert.equal(graph.conflicts(computeActId(readerA), computeActId(readerB)), false);
  assert.equal(graph.conflicts(computeActId(readerA), computeActId(writer)), true);
});
