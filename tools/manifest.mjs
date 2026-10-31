import fs from 'node:fs';
import path from 'node:path';
import { ROOT, inventory, verifyFilePolicy } from './files.mjs';

const files = inventory();
verifyFilePolicy(files);
const manifest = { schema: 'konaet.spec.publication-manifest.v1', edition: JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8')).version,
  purpose: 'Integrity inventory for executable nodes, console, runtime and documentation',
  publicNetworkDeployed: false, containsProductionKeys: false, files };
fs.writeFileSync(path.join(ROOT, 'publication-manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);
console.log(`Manifest created: ${files.length} distribution source files.`);
