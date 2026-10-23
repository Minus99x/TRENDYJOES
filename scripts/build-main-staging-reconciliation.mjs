/** Offline only; emits a candidate to disk. Never connects to Shopify. */
import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {resolve,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {buildMainStagingReconciliation} from '../src/main-staging-reconciliation.mjs';
const root=resolve(fileURLToPath(new URL('..',import.meta.url)));
const out=resolve(root,'integrations/shopify/main-staging-reconciliation-candidate');
const check=process.argv.includes('--check');
if(process.argv.length>3||(process.argv.length===3&&!check))throw new Error('Usage: node scripts/build-main-staging-reconciliation.mjs [--check]');
const {files,manifest}=await buildMainStagingReconciliation({root});
files.set('main-night-reconciliation-manifest.json',JSON.stringify(manifest,null,2)+'\n');
for(const [name,code] of files){const p=resolve(out,name);if(check){if(await readFile(p,'utf8')!==code)throw new Error('MAIN_RECONCILIATION_INTEGRITY_MISMATCH:'+name);}else{await mkdir(dirname(p),{recursive:true});await writeFile(p,code);}}
console.log(`${check?'PASS':'WROTE'}: ${manifest.entries.length} candidate files + manifest; Shopify writes NONE; NOT INSTALLED`);
