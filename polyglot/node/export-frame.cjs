'use strict';
// Private opening -> bounded ASCII frame. Redirect stdout to a private file or pipe.
const fs = require('node:fs');
const { encodeSocialCommitmentFrame } = require('../../tools/social-receipt.cjs');
try {
  const file = process.argv[2];
  if (!file || process.argv.length !== 3) throw Error('USAGE');
  const stat = fs.lstatSync(file);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 65536) throw Error('INPUT');
  const document = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(fs.readFileSync(file)));
  process.stdout.write(encodeSocialCommitmentFrame(document));
} catch { process.stderr.write('Usage: node polyglot/node/export-frame.cjs PRIVATE_OPENING.json\n'); process.exitCode = 2; }
