/** Offline static-client asset graph: integrity inventory, NOT a deployment tool. */
import {readFile,writeFile} from 'node:fs/promises';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {collectPreviewAssetManifest,verifyPreviewAssetManifest} from '../src/preview-asset-manifest.mjs';
const root=resolve(fileURLToPath(new URL('..',import.meta.url)));
const path=resolve(root,'integrations/shopify/static-preview-asset-manifest.json');
const graph=await collectPreviewAssetManifest({root,entryFiles:['demo/static-preview.html','demo/studio.css','demo/static-preview.css','demo/static-preview.mjs']});
const expected={...graph,schema:'TJ-STATIC-CLIENT-ASSET-INVENTORY-1',scope:'EPHEMERAL_CLIENT_ONLY',
 backendRequirement:'NONE_CLIENT_ONLY',hostedPreviewReady:false,
 blockedHostedFeatures:['PRIVATE_DRAFT_SAVE','PRIVATE_ARTWORK_UPLOAD','MODEL_UPLOAD','AUTHENTICATED_REVISIONS','CUSTOMER_STORAGE','CART_AND_CHECKOUT']};
if(process.argv.includes('--check')){
 verifyPreviewAssetManifest(JSON.parse(await readFile(path,'utf8')),expected);
 console.log(`PASS: ${expected.assets.length} static-only browser assets match SHA256; no hosted acceptance claimed`);
}else if(process.argv.length===2){
 await writeFile(path,JSON.stringify(expected,null,2)+'\n');
 console.log(`WROTE: ${expected.assets.length} static-only browser assets; no hosted acceptance claimed`);
}else throw new Error('Usage: node scripts/build-static-preview-assets.mjs [--check]');
