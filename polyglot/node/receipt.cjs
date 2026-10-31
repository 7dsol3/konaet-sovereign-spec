'use strict';
// Copyright 2026 Adilson Oliveira / 7dsol3. ISC license.
const crypto = require('node:crypto');
function processFrame(frame) {
  if (!Buffer.isBuffer(frame) || frame.length > 32900) throw Error('INPUT_INVALID');
  const text = frame.toString('utf8'), lines = text.split('\n');
  if (lines.length !== 4 || lines[3] !== '' || !/^[a-f0-9]{64}$/.test(lines[0])
    || lines[1].length < 4 || lines[1].length > 32768 || lines[1].length % 2 || !/^[a-f0-9]+$/.test(lines[1])
    || (lines[2] !== '-' && !/^[a-f0-9]{64}$/.test(lines[2]))) throw Error('INPUT_INVALID');
  const digest = crypto.createHash('sha256').update('KONAET/SOCIAL-RECEIPT/v1\0', 'ascii')
    .update(Buffer.from(lines[0], 'hex')).update(Buffer.from(lines[1], 'hex')).digest();
  const commitment = digest.toString('hex');
  return { commitment, args: [BigInt('0x' + commitment.slice(0, 32)).toString(), BigInt('0x' + commitment.slice(32)).toString()],
    matches: lines[2] === '-' ? null : crypto.timingSafeEqual(digest, Buffer.from(lines[2], 'hex')) };
}
if (require.main === module) {
  let used = 0; const chunks = [];
  process.stdin.on('data', chunk => { used += chunk.length; if (used > 32900) { process.stderr.write('KONAET_INPUT_INVALID\n'); process.exit(2); } chunks.push(chunk); });
  process.stdin.on('error', () => process.exit(2));
  process.stdin.on('end', () => { try { const result = processFrame(Buffer.concat(chunks));
    process.stdout.write(JSON.stringify(result) + '\n'); process.exitCode = result.matches === false ? 1 : 0;
  } catch { process.stderr.write('KONAET_INPUT_INVALID\n'); process.exitCode = 2; } });
}
module.exports = { processFrame };
