import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {PRODUCT_MANIFESTS} from '../src/catalog.mjs';
import {
 createStaticPreviewState,updateStaticPreview,reviewStaticPreview,
 staticPreviewReviewAvailability,staticPreviewSurfaceDraftTransition
} from '../src/static-preview-contract.mjs';
import {buildStagingStaticBundle} from '../src/staging-static-package.mjs';

const create=(product='concept-crew-tee')=>createStaticPreviewState('?product='+product);
const add=(state,value='VALID LETTERING')=>updateStaticPreview(state,{type:'ADD_TEXT',value});
const gate=state=>staticPreviewReviewAvailability(state);

for(const [name,mutate] of [
 ['stale selected lettering',s=>({...s,selectedLayerId:'static-layer-900'})],
 ['cross-surface hidden selected lettering',s=>({...s,surfaceId:'back'})],
 ['missing layer sequence',s=>({...s,nextLayerSequence:undefined})],
 ['reused layer sequence',s=>({...s,nextLayerSequence:1})],
 ['fractional layer sequence',s=>({...s,nextLayerSequence:1.5})],
 ['unsafe layer sequence',s=>({...s,nextLayerSequence:Number.MAX_SAFE_INTEGER+1})],
 ['forged lettering identity',s=>({...s,layers:[{...s.layers[0],id:'customer-private-id'}]})],
 ['unsupported checkout mode',s=>({...s,mode:'checkout'})],
 ['missing preview mode',s=>({...s,mode:undefined})],
 ['numeric selected layer',s=>({...s,selectedLayerId:123})],
 ['missing color binding',s=>({...s,previewSelection:{sizeId:s.previewSelection.sizeId}})],
 ['extra private option key',s=>({...s,previewSelection:{...s.previewSelection,owner:'PRIVATE'}})],
 ['unknown active surface',s=>({...s,surfaceId:'unknown'})],
 ['foreign product identifier',s=>({...s,productManifestId:'forged-product'})],
]){
 test(`34Z review rejects ${name} instead of presenting an authorized concept`,()=>{
  const s=mutate(add(create()));const before=structuredClone(s);
  assert.throws(()=>reviewStaticPreview(s),undefined,name);
  assert.deepEqual(gate(s),{ready:false,reason:'INVALID_PREVIEW'});
  assert.deepEqual(s,before,'review must not mutate invalid state');
  assert.equal(staticPreviewSurfaceDraftTransition(s,'','back'),'REJECTED');
 });
}

test('34Z all merchandise categories retain valid text-only review and unavailable checkout',()=>{
 for(const p of PRODUCT_MANIFESTS){
  const s=add(create(p.id));const r=reviewStaticPreview(s);
  assert.equal(r.productManifestId,p.id);assert.equal(r.layerCount,1);
  assert.equal(r.checkoutEnabled,false);assert.equal(r.shopifyCustomerAuthenticated,false);
  assert.deepEqual(gate(s),{ready:true,reason:null});
 }
});
test('34Z valid front/back lettering remains reviewable after selecting active layer',()=>{
 let s=add(create());s=updateStaticPreview(s,{type:'SELECT_SURFACE',surfaceId:'back'});
 s=add(s,'BACK LETTERING');assert.equal(reviewStaticPreview(s).layerCount,2);
 s=updateStaticPreview(s,{type:'SELECT_SURFACE',surfaceId:'front'});
 assert.equal(s.selectedLayerId,null);assert.equal(reviewStaticPreview(s).layerCount,2);
 s=updateStaticPreview(s,{type:'SELECT_LAYER',layerId:'static-layer-1'});
 assert.deepEqual(gate(s),{ready:true,reason:null});
});
test('34Z removing and re-adding lettering maintains valid monotonically increasing IDs',()=>{
 let s=add(create());s=updateStaticPreview(s,{type:'REMOVE_LAYER'});
 s=add(s,'REPLACEMENT');assert.equal(s.nextLayerSequence,3);
 assert.equal(reviewStaticPreview(s).layerCount,1);
});
test('34Z review retains explicit empty-concept guidance',()=>{
 const s=create();assert.throws(()=>reviewStaticPreview(s),/INVALID_LAYERS/);
 assert.deepEqual(gate(s),{ready:false,reason:'ADD_LETTERING'});
});
test('34Z forged private data never appears in review gate or error projection',()=>{
 const s={...add(create()),mode:'checkout',ownerToken:'PRIVATE OWNER TOKEN'};
 assert.deepEqual(gate(s),{ready:false,reason:'INVALID_PREVIEW'});
 assert.doesNotMatch(JSON.stringify(gate(s)),/PRIVATE|OWNER|TOKEN|checkout/);
});
test('34Z offline staging package contains same fail-closed review guard',async()=>{
 const {files,manifest}=await buildStagingStaticBundle({root:new URL('..',import.meta.url).pathname});
 const js=files.get('assets/tj34i-src-static-preview-contract.js');
 assert.match(js,/assertStaticPreviewIntegrity\(state,product\)/);
 assert.match(js,/export function reviewStaticPreview/);
 assert.equal(manifest.shopifyThemeInstalled,false);assert.equal(manifest.checkoutEnabled,false);
});
test('34Z review contract remains ephemeral with no auth, storage, network, cart or checkout',async()=>{
 const src=await readFile(new URL('../src/static-preview-contract.mjs',import.meta.url),'utf8');
 assert.doesNotMatch(src,/\bfetch\s*\(|\blocalStorage\b|\bsessionStorage\b|\bnew\s+(?:XMLHttpRequest|WebSocket)\b|\/cart\/add/);
});
