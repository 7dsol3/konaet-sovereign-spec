import fs from 'node:fs';
import { verifyTransferVector } from '../lib/event.mjs';

try {
  const input = process.argv[2];
  if (!input || fs.statSync(input).size > 262144) throw new Error('BOUNDED_VECTOR_FILE_REQUIRED');
  const result = verifyTransferVector(JSON.parse(fs.readFileSync(input, 'utf8')));
  console.log(JSON.stringify({ profile: 'EVENT/js-v1', eventId: result.eventIdHex,
    amountAtomic: result.amountAtomic, cryptographicallyValid: result.cryptographicallyValid,
    ledgerFinalityProven: result.ledgerFinalityProven }, null, 2));
} catch (error) {
  console.error(`REJECTED ${error.message}`);
  process.exitCode = 1;
}
