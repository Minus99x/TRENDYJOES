/** Build/check deterministic offline inventory. Never calls Shopify or a network. */
import {readFile,writeFile} from 'node:fs/promises';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {collectPreviewAssetManifest,verifyPreviewAssetManifest} from '../src/preview-asset-manifest.mjs';
const root=resolve(fileURLToPath(new URL('..',import.meta.url)));
const output=resolve(root,'integrations/shopify/preview-asset-manifest.json');
const expected=await collectPreviewAssetManifest({root});
if(process.argv.includes('--check')){
 const actual=JSON.parse(await readFile(output,'utf8'));
 verifyPreviewAssetManifest(actual,expected);
 console.log(`PASS: ${expected.assets.length} offline browser assets match SHA256 manifest; NOT hosted-ready`);
}else if(process.argv.length===2){
 await writeFile(output,JSON.stringify(expected,null,2)+'\n',{flag:'w'});
 console.log(`WROTE: ${expected.assets.length} offline browser assets; NOT hosted-ready`);
}else throw new Error('Usage: node scripts/build-preview-asset-manifest.mjs [--check]');
