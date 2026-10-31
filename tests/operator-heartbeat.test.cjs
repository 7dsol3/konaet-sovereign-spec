'use strict';
const assert = require('node:assert/strict');
const EventEmitter = require('node:events');
const { once } = require('node:events');
const test = require('node:test');
const { setTimeout: delay } = require('node:timers/promises');
const WebSocket = require('ws');
const { startPeerHeartbeat } = require('../chain/scripts/operatorHeartbeat');

async function fixture(t, { autoPong = true, existing = true } = {}) {
  const transport = new EventEmitter(); transport.connections = new Set(); transport.byPeer = new Map();
  const server = new WebSocket.Server({ host: '127.0.0.1', port: 0 });
  await once(server, 'listening');
  const connection = once(server, 'connection');
  const client = new WebSocket(`ws://127.0.0.1:${server.address().port}/`, { autoPong });
  const opened = once(client, 'open');
  const [socket] = await connection; await opened;
  const record = { socket, hello: true, peerId: 'validator-1' };
  socket.on('close', () => { transport.connections.delete(record); transport.byPeer.delete(record.peerId); });
  if (existing) { transport.connections.add(record); transport.byPeer.set(record.peerId, record); }
  t.after(async () => { client.terminate(); socket.terminate(); await new Promise(resolve => server.close(resolve)); });
  return { transport, record, socket, client };
}

test('heartbeat terminates a real websocket without a matching pong despite unrelated traffic', { timeout: 5000 }, async t => {
  const f = await fixture(t, { autoPong: false, existing: false });
  let challenge;
  f.client.on('ping', bytes => { challenge = Buffer.from(bytes); });
  const stop = startPeerHeartbeat(f.transport, { intervalMs: 40, timeoutMs: 140 }); t.after(stop);
  f.transport.connections.add(f.record); f.transport.byPeer.set(f.record.peerId, f.record);
  const closed = once(f.socket, 'close');
  f.transport.emit('peerReady', { record: f.record });
  const noise = setInterval(() => {
    if (f.client.readyState === WebSocket.OPEN) { f.client.pong(Buffer.alloc(16)); f.client.send('still here'); }
  }, 15);
  t.after(() => clearInterval(noise));
  await closed;
  assert.equal(challenge?.length, 16);
  assert.equal(f.transport.byPeer.has('validator-1'), false);
  assert.equal(f.socket.listenerCount('pong'), 0);
});

test('heartbeat preserves a healthy websocket and cleanup removes timers and listeners', { timeout: 5000 }, async t => {
  const f = await fixture(t); let pings = 0;
  let observed;
  const threePings = new Promise(resolve => { observed = resolve; });
  f.client.on('ping', () => { if (++pings === 3) observed(); });
  const baseCloseListeners = f.socket.listenerCount('close');
  const stop = startPeerHeartbeat(f.transport, { intervalMs: 40, timeoutMs: 600 }); t.after(stop);
  await threePings; await delay(650);
  assert.ok(pings >= 3); assert.equal(f.socket.readyState, WebSocket.OPEN);
  stop(); stop(); await delay(40);
  const afterStop = pings; await delay(180);
  assert.equal(pings, afterStop); assert.equal(f.socket.readyState, WebSocket.OPEN);
  assert.equal(f.transport.listenerCount('peerReady'), 0);
  assert.equal(f.socket.listenerCount('pong'), 0);
  assert.equal(f.socket.listenerCount('close'), baseCloseListeners);
});

test('cleanup cancels an outstanding deadline and ignores later peerReady events', { timeout: 5000 }, async t => {
  const f = await fixture(t, { autoPong: false });
  const ping = once(f.client, 'ping');
  const stop = startPeerHeartbeat(f.transport, { intervalMs: 40, timeoutMs: 140 }); t.after(stop);
  await ping; stop(); f.transport.emit('peerReady', { record: f.record });
  await delay(240);
  assert.equal(f.socket.readyState, WebSocket.OPEN);
  assert.equal(f.socket.listenerCount('pong'), 0);
  assert.equal(f.transport.listenerCount('peerReady'), 0);
});

test('heartbeat rejects invalid supervision intervals', () => {
  const transport = new EventEmitter(); transport.connections = new Set();
  for (const options of [{ intervalMs: 0 }, { timeoutMs: 9 }, { intervalMs: 60001 }, { timeoutMs: NaN }]) {
    assert.throws(() => startPeerHeartbeat(transport, options), /INVALID_HEARTBEAT_INTERVAL/);
  }
});
