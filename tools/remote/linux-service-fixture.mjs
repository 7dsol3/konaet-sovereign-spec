import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const { crypto: vcrypto, UNIT } = require('../../chain/vlock7sin-js/src');
const { createGenesis } = require('../../chain/network/sovereign');
const { AUTHORIZED_PROFILE } = require('../../chain/vlock7sin-js/src/koConsensusProfile');
const { compileKoPolicy } = require('../../chain/vlock7sin-js/src/koPolicy');
if (process.env.GITHUB_ACTIONS !== 'true' || process.platform !== 'linux' || process.getuid() !== 0) throw Error('ISOLATED_ROOT_CI_REQUIRED');
const directory = '/var/lib/konaet/validator-0';
if (fs.existsSync(directory)) throw Error('NEW_SERVICE_DIRECTORY_REQUIRED');
fs.mkdirSync('/var/lib/konaet', { recursive: true, mode: 0o755 });
fs.mkdirSync(directory, { recursive: true, mode: 0o750 }); fs.mkdirSync(path.join(directory, 'data'), { mode: 0o700 });
const seed = crypto.randomBytes(32), identity = vcrypto.IdentityKeypair.fromSeed(seed);
fs.writeFileSync(path.join(directory, 'own.seed'), seed.toString('hex'), { flag: 'wx', mode: 0o640 }); seed.fill(0);
const keys = [identity, ...Array.from({ length: 3 }, () => vcrypto.IdentityKeypair.generate())];
const owner = vcrypto.IdentityKeypair.generate();
const nativePolicy = compileKoPolicy(fs.readFileSync('/opt/konaet/chain/contracts-ko/SindraRuntime.ko', 'utf8'));
const genesis = createGenesis({ contractRuntime: AUTHORIZED_PROFILE, nativePolicy, networkId: 79000001,
  createdAt: new Date().toISOString(), threshold: 3, validators: keys.map((key, index) => ({ id: 'validator-' + index, publicKey: key.publicBytes() })),
  deploymentPolicy: { schema: 'konaet.contract-deployment-policy.v1', deployers: [{ address: owner.address(), maxContracts: 64 }] },
  allocations: [{ address: owner.address(), amountAtomic: UNIT.initialSupplyAtomic }] });
const bytes = Buffer.from(JSON.stringify(genesis, null, 2) + '\n');
fs.writeFileSync(path.join(directory, 'genesis.json'), bytes, { mode: 0o640 });
const caDirectory = path.join(process.env.RUNNER_TEMP, 'konaet-service-ca'); fs.mkdirSync(caDirectory, { mode: 0o700 });
const ssl = args => execFileSync('openssl', args, { cwd: caDirectory, stdio: 'pipe' });
ssl(['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=KonaetServiceCI', '-keyout', 'ca.key', '-out', 'ca.pem', '-days', '1', '-addext', 'basicConstraints=critical,CA:TRUE']);
ssl(['req', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=validator-0', '-keyout', 'own.key', '-out', 'own.csr']);
fs.writeFileSync(path.join(caDirectory, 'extensions.cnf'), 'basicConstraints=CA:FALSE\nsubjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth,clientAuth\n');
ssl(['x509', '-req', '-in', 'own.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-set_serial', '1', '-days', '1', '-extfile', 'extensions.cnf', '-out', 'own.pem']);
for (const name of ['ca.pem', 'own.key', 'own.pem']) { fs.copyFileSync(path.join(caDirectory, name), path.join(directory, name)); fs.chmodSync(path.join(directory, name), 0o640); }
fs.writeFileSync(path.join(directory, 'submit.token'), crypto.randomBytes(32).toString('hex'), { mode: 0o640 });
fs.writeFileSync(path.join(directory, 'operator-config.json'), JSON.stringify({ schema: 'konaet.independent-validator.config.v1', scope: 'private-testnet-no-value',
  mutualTlsRequired: true, validatorId: 'validator-0', host: '127.0.0.1', port: 58600, statusPort: 58601,
  genesisFile: 'genesis.json', genesisSha256: crypto.createHash('sha256').update(bytes).digest('hex'), seedFile: 'own.seed',
  caFile: 'ca.pem', certificateFile: 'own.pem', tlsKeyFile: 'own.key', submitTokenFile: 'submit.token', dataDirectory: 'data',
  peers: [1, 2, 3].map(index => ({ validatorId: 'validator-' + index, url: `wss://127.0.0.1:${58600 + index * 2}/` })) }), { mode: 0o640 });
console.log(JSON.stringify({ prepared: true, genesisId: genesis.genesisId, privateKeysExported: false }));
