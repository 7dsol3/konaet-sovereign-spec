'use strict';
const { createHash } = require('node:crypto');
const FORMAT = 'konaet-sovereign-genesis-v7-ko-program';
const PROTOCOL = '0.6.0-sovereign-ko-program.1';
const PROFILE = Object.freeze({ profile: 'KONAET_KO_PROGRAM_V1', eventFormat: 'vlock7sin-ko-event-v1',
  stateFormat: 'vlock7sin-ko-state-v1', sourceBytes: 16384, transactionBytes: 65536,
  gasPerTransaction: 100000, gasPerClosure: 1000000, actsPerClosure: 64, closureBytes: 262144, contracts: 128, stateBytes: 4194304 });
const PROFILE_HASH = createHash('sha256').update(JSON.stringify(PROFILE)).digest('hex');
module.exports = Object.freeze({ FORMAT, PROTOCOL, PROFILE, PROFILE_HASH });
