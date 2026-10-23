import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile,writeFile,mkdtemp,rm} from 'node:fs/promises';
import {resolve,join} from 'node:path';
import {tmpdir} from 'node:os';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {createLocalServer} from '../src/local-server.mjs';
import {collectPreviewAssetManifest,verifyPreviewAssetManifest} from '../src/preview-asset-manifest.mjs';
import {PRODUCT_MANIFESTS} from '../src/catalog.mjs';
import {STATIC_PREVIEW_CAPABILITIES,createStaticPreviewState,updateStaticPreview,reviewStaticPreview,staticPreviewProductOptions} from '../src/static-preview-contract.mjs';
const root=resolve(fileURLToPath(new URL('..',import.meta.url)));
const assetPath=join(root,'integrations/shopify/static-preview-asset-manifest.json');
const readExpected=async()=>JSON.parse(await readFile(assetPath,'utf8'));
const graph=async()=>{
 const base=await collectPreviewAssetManifest({root,entryFiles:['demo/static-preview.html','demo/studio.css','demo/static-preview.css','demo/static-preview.mjs']});
 return {...base,schema:'TJ-STATIC-CLIENT-ASSET-INVENTORY-1',scope:'EPHEMERAL_CLIENT_ONLY',backendRequirement:'NONE_CLIENT_ONLY',hostedPreviewReady:false,blockedHostedFeatures:['PRIVATE_DRAFT_SAVE','PRIVATE_ARTWORK_UPLOAD','MODEL_UPLOAD','AUTHENTICATED_REVISIONS','CUSTOMER_STORAGE','CART_AND_CHECKOUT']};
};
const add=(s,value='Make it yours')=>updateStaticPreview(s,{type:'ADD_TEXT',value});
const act=(s,type,more={})=>updateStaticPreview(s,{type,...more});
test('34H static capabilities explicitly disable all backend, storage and commerce functions',()=>{
 assert.equal(Object.isFrozen(STATIC_PREVIEW_CAPABILITIES),true);
 assert.equal(STATIC_PREVIEW_CAPABILITIES.mode,'EPHEMERAL_CLIENT_ONLY');
 for(const [key,value] of Object.entries(STATIC_PREVIEW_CAPABILITIES))if(key!=='mode')assert.equal(value,false,key);
});
test('34H strict deep links reject credentials, forged product, duplicate or encoded separators',()=>{
 for(const query of ['?product=concept-crew-tee&ownerToken=secret','?product=concept-crew-tee&product=concept-rug','?product=bad','?product=%26checkout%3D1','?product=__proto__','?variant=123']){
  const s=createStaticPreviewState(query);assert.equal(s.productManifestId,PRODUCT_MANIFESTS[0].id);assert.ok(['INVALID_LINK','UNKNOWN_PRODUCT'].includes(s.entryStatus),query);
 }
 assert.equal(createStaticPreviewState('?product=concept-rug').productManifestId,'concept-rug');
});
test('34H all eight conceptual product families can be selected and previewed',()=>{
 assert.deepEqual(staticPreviewProductOptions().map(x=>x.id),PRODUCT_MANIFESTS.map(x=>x.id));
 for(const product of PRODUCT_MANIFESTS){const state=createStaticPreviewState('?product='+product.id);const added=add(state);const review=reviewStaticPreview(added);
  assert.equal(review.productManifestId,product.id);assert.equal(review.layerCount,1);assert.equal(review.checkoutEnabled,false);
  assert.equal(review.manufacturingApproved,false);assert.equal(review.shopifyCustomerAuthenticated,false);
 }
});
test('34H text-only review is a redacted non-purchasing projection, never a saved draft',()=>{
 const review=reviewStaticPreview(add(createStaticPreviewState()));
 assert.equal(review.draftState,'UNSAVED_PREVIEW');assert.equal(review.cartLine,null);assert.equal(review.orderId,null);
 assert.equal(review.priceApproved,false);assert.equal(review.modelStatus,'CONCEPT_UNVERIFIED');
 for(const key of ['ownerToken','price','artworkId','customerId','variantGid','designReference'])assert.equal(Object.hasOwn(review,key),false);
});
test('34H unapproved or backend-dependent operations always fail closed',()=>{
 const state=createStaticPreviewState();
 for(const type of ['SAVE_DRAFT','UPLOAD_ARTWORK','IMPORT_GLB','RESTORE_SESSION','EXPORT_RECEIPT','AUTHENTICATE','CHECKOUT','CREATE_ORDER','FETCH_CATALOG','ADD_TO_CART'])assert.throws(()=>act(state,type),/STATIC_PREVIEW_FORBIDDEN_ACTION/,type);
 assert.throws(()=>updateStaticPreview(state,null),/INVALID_ACTION/);
 const withExtras=updateStaticPreview(state,{type:'ADD_TEXT',value:'x',checkout:true,ownerToken:'secret',productGid:'fake'});
 assert.equal(withExtras.layers.length,1);assert.doesNotMatch(JSON.stringify(withExtras),/secret|fake|checkout/);
});
test('34H product switching requires explicit discard confirmation for any existing layers',()=>{
 const initial=add(createStaticPreviewState());
 assert.throws(()=>act(initial,'SELECT_PRODUCT',{productManifestId:'concept-rug'}),/UNSAVED_WORK_CONFIRMATION_REQUIRED/);
 const switched=act(initial,'SELECT_PRODUCT',{productManifestId:'concept-rug',confirmed:true});
 assert.equal(switched.productManifestId,'concept-rug');assert.equal(switched.layers.length,0);
 assert.equal(switched.nextLayerSequence,1);
});
test('34H composition bounds reject impossible rotation and scale without mutating original state',()=>{
 const initial=add(createStaticPreviewState());
 assert.throws(()=>act(initial,'ROTATE_LAYER',{degrees:181}),/INVALID_ROTATION/);
 assert.throws(()=>act(initial,'SCALE_LAYER',{percent:201}),/INVALID_SCALE/);
 const turned=act(initial,'ROTATE_LAYER',{degrees:45});
 assert.throws(()=>act(turned,'SCALE_LAYER',{percent:200}),/INVALID_COMPOSITION/);
 assert.equal(initial.layers[0].width,.5);assert.equal(initial.layers[0].rotationDeg,0);
 const rotated=act(initial,'ROTATE_LAYER',{degrees:20});assert.equal(rotated.layers[0].rotationDeg,20);
 assert.equal(initial.layers[0].rotationDeg,0);
});
test('34H edits invalidate review and reset removes all ephemeral work',()=>{
 let s=add(createStaticPreviewState());
 const summary=reviewStaticPreview(s);assert.equal(summary.layerCount,1);
 s=act(s,'SET_MODE',{mode:'2d'});assert.equal(s.mode,'2d');
 s=act(s,'REMOVE_LAYER');assert.equal(s.layers.length,0);assert.throws(()=>reviewStaticPreview(s),/INVALID_LAYERS/);
 s=add(s,'New words');s=act(s,'RESET');assert.equal(s.layers.length,0);assert.equal(s.selectedLayerId,null);
});
test('34H invalid surfaces, colors, sizes, layers and text rejected',()=>{
 const s=createStaticPreviewState();
 assert.throws(()=>act(s,'SELECT_SURFACE',{surfaceId:'unknown'}),/UNAVAILABLE_SURFACES/);
 assert.throws(()=>act(s,'SELECT_COLOR',{colorId:'nonexistent'}),/Invalid concept/);
 assert.throws(()=>act(s,'SELECT_SIZE',{sizeId:'nonexistent'}),/Invalid concept/);
 assert.throws(()=>act(s,'SELECT_LAYER',{layerId:'missing'}),/UNKNOWN_LAYER/);
 for(const value of ['', ' ', 'X'.repeat(201),'Bad\u0001control'])assert.throws(()=>add(s,value),/INVALID_TEXT/);
});
test('34H cannot review injected private artwork layer or fake saved owner',()=>{
 const s=add(createStaticPreviewState());
 const injected={...s,layers:[...s.layers,{...s.layers[0],id:'art2',type:'artwork',artworkId:'secret'}]};
 assert.throws(()=>reviewStaticPreview(injected),/STATIC_PREVIEW_FORBIDDEN_LAYER/);
 const review=reviewStaticPreview({...s,saved:{ownerToken:'secret',revision:5},savedSnapshot:null});
 assert.equal(review.draftState,'UNSAVED_PREVIEW');assert.doesNotMatch(JSON.stringify(review),/secret/);
});
test('34H static asset graph has no backend/service imports or hidden external dependencies',async()=>{
 const current=await graph();const expected=await readExpected();verifyPreviewAssetManifest(expected,current);
 assert.equal(current.backendRequirement,'NONE_CLIENT_ONLY');assert.equal(current.hostedPreviewReady,false);
 assert.equal(current.checkoutEnabled,false);assert.ok(current.assets.length>=8);
 assert.ok(current.assets.some(a=>a.path==='src/viewer3d.mjs'));
 for(const item of current.assets){
  assert.doesNotMatch(item.path,/(local-server|local-store|browser-acceptance|artwork-store|shopify-bridge|node_modules)/);
  const bytes=await readFile(join(root,item.path));assert.equal(createHash('sha256').update(bytes).digest('hex'),item.sha256);
  if(item.path.endsWith('.mjs'))assert.doesNotMatch(bytes.toString('utf8'),/\b(?:fetch|XMLHttpRequest|WebSocket|sendBeacon|localStorage|sessionStorage|indexedDB)\s*\(/);
 }
});
test('34H tampered static manifest fails verification and does not imply hosted acceptance',async()=>{
 const current=await graph();assert.throws(()=>verifyPreviewAssetManifest({...current,hostedPreviewReady:true},current),/ASSET_MANIFEST_MISMATCH/);
 assert.throws(()=>verifyPreviewAssetManifest({...current,assets:current.assets.slice(1)},current),/ASSET_MANIFEST_MISMATCH/);
});
test('34H static page has restrictive CSP and no API/upload/save/checkout controls',async()=>{
 const html=await readFile(join(root,'demo/static-preview.html'),'utf8');
 assert.match(html,/connect-src 'none'/);assert.match(html,/form-action 'none'/);
 assert.match(html,/script type="module" src="\.\/static-preview\.mjs"/);
 for(const id of ['product','mode-2d','mode-3d','add-text','review-preview','preview-summary-panel'])assert.match(html,new RegExp(`id="${id}"`));
 assert.doesNotMatch(html,/(?:<input[^>]+type="file"|id="save-local"|id="review-cart"|href="\/cart|href="\/checkout)/);
 assert.match(html,/Checkout unavailable/);
});
test('34H actual loopback HTTP serves the static-only asset graph byte-for-byte',async()=>{
 const dir=await mkdtemp(join(tmpdir(),'tj34h-'));
 const app=await createLocalServer({dataDir:dir});const {port}=await app.listen(0);
 try{
  const manifest=await readExpected();
  for(const asset of manifest.assets){
   const response=await fetch(`http://127.0.0.1:${port}${asset.url}`);
   assert.equal(response.status,200,asset.url);
   assert.ok(response.headers.get('content-type')?.startsWith(asset.contentType),asset.url);
   const bytes=Buffer.from(await response.arrayBuffer());
   assert.equal(createHash('sha256').update(bytes).digest('hex'),asset.sha256,asset.url);
  }
 }finally{await new Promise(resolve=>app.server.close(resolve));await rm(dir,{recursive:true,force:true});}
});
