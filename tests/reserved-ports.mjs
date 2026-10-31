import crypto from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
// Keep every not-yet-used fixture port bound throughout TLS/key generation.
// Choose below the dynamic client range so outbound test sockets cannot take
// a released server port while the real listener is being started.
export async function reserveFixturePorts(count) {
  let maximum = 30000;
  if (process.platform === 'linux') {
    const firstDynamic = Number(fs.readFileSync('/proc/sys/net/ipv4/ip_local_port_range', 'utf8').trim().split(/\s+/)[0]);
    if (!Number.isSafeInteger(firstDynamic) || firstDynamic <= 10001) throw Error('TEST_PORT_RANGE_UNAVAILABLE');
    maximum = Math.min(maximum, firstDynamic);
  }
  const sockets = new Map();
  async function release(port) {
    const server = sockets.get(port); if (!server) return;
    await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve())); sockets.delete(port);
  }
  async function close() { await Promise.all([...sockets.keys()].map(release)); }
  try {
    for (let attempt = 0; sockets.size < count && attempt < count * 100; attempt++) {
      const port = crypto.randomInt(10000, maximum); if (sockets.has(port)) continue;
      const server = net.createServer();
      try { await new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, '127.0.0.1', resolve); }); }
      catch (error) { if (error.code === 'EADDRINUSE' || error.code === 'EACCES') continue; throw error; }
      sockets.set(port, server);
    }
    if (sockets.size !== count) throw Error('TEST_PORT_RESERVATION_FAILED');
    return { ports: [...sockets.keys()], release, close };
  } catch (error) { await close(); throw error; }
}
