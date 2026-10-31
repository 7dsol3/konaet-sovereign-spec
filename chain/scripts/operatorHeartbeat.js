'use strict';

const assert = require('node:assert/strict');
const { randomBytes } = require('node:crypto');
const WebSocket = require('ws');

// Runtime supervision only: does not change the signed transport or consensus.
function startPeerHeartbeat(transport, { intervalMs = 10000, timeoutMs = 10000 } = {}) {
  for (const value of [intervalMs, timeoutMs]) {
    assert.ok(Number.isSafeInteger(value) && value >= 10 && value <= 60000, 'INVALID_HEARTBEAT_INTERVAL');
  }
  assert.ok(transport && typeof transport.on === 'function' && typeof transport.off === 'function'
    && transport.connections instanceof Set, 'INVALID_HEARTBEAT_TRANSPORT');
  const tracked = new Map();
  let stopped = false;

  function forget(record) {
    const state = tracked.get(record);
    if (!state) return;
    clearTimeout(state.deadline);
    record.socket.off('pong', state.onPong);
    record.socket.off('close', state.onClose);
    tracked.delete(record);
  }

  function terminate(record) {
    forget(record);
    try { record.socket.terminate(); } catch { /* Already closed. */ }
  }

  function probe(record) {
    const state = tracked.get(record);
    if (stopped || !state || state.challenge) return;
    if (!transport.connections.has(record) || record.socket.readyState !== WebSocket.OPEN) {
      forget(record); return;
    }
    const challenge = randomBytes(16);
    state.challenge = challenge;
    state.deadline = setTimeout(() => {
      if (!stopped && tracked.get(record) === state && state.challenge === challenge) terminate(record);
    }, timeoutMs);
    state.deadline.unref();
    try {
      record.socket.ping(challenge, error => {
        if (error && !stopped && tracked.get(record) === state) terminate(record);
      });
    } catch { terminate(record); }
  }

  function track({ record } = {}) {
    if (stopped || !record?.hello || !transport.connections.has(record) || tracked.has(record)) return;
    const state = { challenge: null, deadline: null,
      onPong: bytes => {
        if (!state.challenge || !Buffer.isBuffer(bytes) || !state.challenge.equals(bytes)) return;
        clearTimeout(state.deadline);
        state.deadline = null;
        state.challenge = null;
      },
      onClose: () => forget(record) };
    tracked.set(record, state);
    record.socket.on('pong', state.onPong);
    record.socket.on('close', state.onClose);
    probe(record);
  }

  transport.on('peerReady', track);
  for (const record of transport.connections) track({ record });
  const timer = setInterval(() => {
    for (const record of tracked.keys()) probe(record);
  }, intervalMs);
  timer.unref();
  return function stopPeerHeartbeat() {
    if (stopped) return;
    stopped = true;
    clearInterval(timer);
    transport.off('peerReady', track);
    for (const record of [...tracked.keys()]) forget(record);
  };
}

module.exports = { startPeerHeartbeat };
