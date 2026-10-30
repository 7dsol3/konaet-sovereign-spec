import fs from 'node:fs';
import path from 'node:path';
import { ROOT, inventory, verifyFilePolicy } from './files.mjs';

const files = inventory();
verifyFilePolicy(files);
const manifest = { schema: 'konaet.spec.publication-manifest.v1', edition: '1.1.0',
  purpose: 'Integrity inventory for the documentation and public verifier; not signed provenance',
  publicNetworkDeployed: false, containsProductionKeys: false, files };
fs.writeFileSync(path.join(ROOT, 'publication-manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);
console.log(`Manifest created: ${files.length} files. No signing or network deployment performed.`);
