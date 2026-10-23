/** Generates only local candidate assets. Never contacts or modifies Shopify. */
import {readFile,writeFile,mkdir} from 'node:fs/promises';
import {resolve,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {buildStagingStaticBundle} from '../src/staging-static-package.mjs';
const root=resolve(fileURLToPath(new URL('..',import.meta.url)));
const outputRoot=resolve(root,'integrations/shopify/staging-static-preview');
const {files,manifest}=await buildStagingStaticBundle({root});
files.set('staging-static-preview-bundle-manifest.json',JSON.stringify(manifest,null,2)+'\n');
const check=process.argv.includes('--check');
if(process.argv.length>3||(process.argv.length===3&&!check))throw new Error('Usage: node scripts/build-staging-static-bundle.mjs [--check]');
for(const [path,contents] of files){
 const dest=resolve(outputRoot,path);
 if(check){if(await readFile(dest,'utf8')!==contents)throw new Error('STAGING_BUNDLE_INTEGRITY_MISMATCH:'+path);}
 else{await mkdir(dirname(dest),{recursive:true});await writeFile(dest,contents);}
}
console.log(`${check?'PASS':'WROTE'}: ${manifest.entries.length} staged offline files + integrity manifest; no Shopify writes; no hosted acceptance`);
