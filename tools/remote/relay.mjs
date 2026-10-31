import net from 'node:net';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const WebSocket = require('ws');
export function bridge(socket, websocket) {
  const stream = WebSocket.createWebSocketStream(websocket, { highWaterMark: 65536 });
  const cleanup = () => { socket.destroy(); stream.destroy(); if (websocket.readyState !== WebSocket.CLOSED) websocket.terminate(); };
  socket.on('error', cleanup); stream.on('error', cleanup); socket.on('close', cleanup);
  stream.on('close', () => socket.destroy());
  socket.setTimeout(45000, cleanup); socket.pipe(stream).pipe(socket);
  return cleanup;
}
export async function outgoingProxy(remote, port = 0) {
  const sockets = new Set();
  const server = net.createServer(socket => {
    sockets.add(socket); socket.once('close', () => sockets.delete(socket));
    const websocket = new WebSocket(remote, { maxPayload: 65536, handshakeTimeout: 15000, perMessageDeflate: false });
    websocket.on('error', () => socket.destroy()); socket.pause();
    socket.on('error', () => websocket.terminate()); socket.once('close', () => websocket.terminate());
    websocket.once('open', () => { bridge(socket, websocket); socket.resume(); });
  });
  server.maxConnections = 16;
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, '127.0.0.1', resolve); });
  return { port: server.address().port, async close() { for (const socket of sockets) socket.destroy(); await new Promise(resolve => server.close(resolve)); } };
}
export function incomingRelay(server, targetPort) {
  const wss = new WebSocket.Server({ noServer: true, maxPayload: 65536, perMessageDeflate: false });
  server.on('upgrade', (req, socket, head) => {
    if (req.url !== '/transport' || wss.clients.size >= 16) { socket.destroy(); return; }
    wss.handleUpgrade(req, socket, head, websocket => {
      const target = net.connect(targetPort, '127.0.0.1'); bridge(target, websocket);
    });
  });
  return async () => { for (const socket of wss.clients) socket.terminate(); await new Promise(resolve => wss.close(resolve)); };
}
