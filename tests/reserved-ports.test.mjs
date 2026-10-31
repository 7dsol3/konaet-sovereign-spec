import assert from 'node:assert/strict';
import net from 'node:net';
import test from 'node:test';
import { reserveFixturePorts } from './reserved-ports.mjs';

test('fixture server ports remain reserved until explicit handoff and unrelated occupied ports are untouched', async t => {
  const leases = await reserveFixturePorts(8); t.after(() => leases.close());
  assert.equal(new Set(leases.ports).size, 8);
  for (const port of leases.ports) {
    assert.ok(port >= 10000 && port < 30000);
    const competitor = net.createServer();
    await assert.rejects(new Promise((resolve, reject) => { competitor.once('error', reject); competitor.listen(port, '127.0.0.1', resolve); }), { code: 'EADDRINUSE' });
  }
  const selected = leases.ports[0]; await leases.release(selected);
  const listener = net.createServer(); t.after(() => new Promise(resolve => listener.close(resolve)));
  await new Promise((resolve, reject) => { listener.once('error', reject); listener.listen(selected, '127.0.0.1', resolve); });
  await leases.close(); assert.equal(listener.listening, true);
});
