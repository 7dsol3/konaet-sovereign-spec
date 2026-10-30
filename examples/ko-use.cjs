'use strict';
// Run from the repository: node examples/ko-use.cjs
const fs = require('node:fs');
const path = require('node:path');
const { compileKoPolicy, executeKoPolicy } = require('../chain/vlock7sin-js/src/koPolicy');
const source = fs.readFileSync(path.join(__dirname, '../runtime/SindraRuntime.ko'), 'utf8');
const context = JSON.parse(fs.readFileSync(path.join(__dirname, 'ko-transfer-context.json'), 'utf8'));
const policy = compileKoPolicy(source);
executeKoPolicy(policy, 'transfer', context);
console.log(JSON.stringify({ accepted: true, phase: 'transfer', programSha256: policy.programSha256 }, null, 2));
