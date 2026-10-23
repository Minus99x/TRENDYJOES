import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {PRODUCT_MANIFESTS} from '../src/catalog.mjs';
import {createStaticPreviewState,updateStaticPreview,staticPreviewSurfaceDraftTransition} from '../src/static-preview-contract.mjs';
import {buildStagingStaticBundle} from '../src/staging-static-package.mjs';
const fresh=(id='concept-crew-tee')=>createStaticPreviewState('?product='+id);
const decide=(s,draft='',target='back')=>staticPreviewSurfaceDraftTransition(s,draft,target);
const add=(s,value='SAFE LETTERING')=>updateStaticPreview(s,{type:'ADD_TEXT',value});
const base=()=>fresh();

test('34Y valid empty and committed multi-surface designs still switch without draft loss',()=>{
 for(const product of PRODUCT_MANIFESTS){
  const s=fresh(product.id),other=product.surfaces.find(x=>x.id!==s.surfaceId);
  if(!other)continue;
  assert.equal(decide(s,'',other.id),'SAFE',product.id);
  assert.equal(decide(s,'PRIVATE DRAFT',other.id),'DISCARD_CONFIRMATION_REQUIRED',product.id);
  const withLayer=add(s);
  assert.equal(decide(withLayer,'',other.id),'SAFE',product.id);
  assert.equal(decide(withLayer,'PRIVATE DRAFT',other.id),'DISCARD_CONFIRMATION_REQUIRED',product.id);
 }
});
test('34Y current-surface selection remains a no-op for legitimate committed design',()=>{
 const s=add(base());assert.equal(decide(s,'PRIVATE','front'),'SAME_SURFACE');
});
for(const [name,mutate] of [
 ['missing option key',s=>({...s,previewSelection:{sizeId:s.previewSelection.sizeId}})],
 ['extra option owner token',s=>({...s,previewSelection:{...s.previewSelection,owner:'PRIVATE_OWNER'}})],
 ['forged checkout mode',s=>({...s,mode:'checkout'})],
 ['missing mode',s=>({...s,mode:undefined})],
 ['stale selected layer',s=>({...s,selectedLayerId:'static-layer-900'})],
 ['nonstring selected layer',s=>({...s,selectedLayerId:42})],
 ['zero next-layer sequence',s=>({...s,nextLayerSequence:0})],
 ['missing next-layer sequence',s=>({...s,nextLayerSequence:undefined})],
 ['noninteger next-layer sequence',s=>({...s,nextLayerSequence:1.5})],
 ['forged artwork layer',s=>{const a=add(s);return {...a,layers:[{...a.layers[0],type:'artwork',artworkId:'FORGED_ASSET'}]};}],
 ['bidirectional spoofed lettering',s=>{const a=add(s);return {...a,layers:[{...a.layers[0],value:'A\u202eB'}]};}],
 ['invisible-only lettering',s=>{const a=add(s);return {...a,layers:[{...a.layers[0],value:'\u200b'}]};}],
 ['foreign layer identity',s=>{const a=add(s);return {...a,layers:[{...a.layers[0],id:'FOREIGN_LAYER'}]};}],
 ['reused layer sequence',s=>{const a=add(s);return {...a,nextLayerSequence:1};}],
 ['hidden cross-surface selection',s=>{const a=add(s);return {...a,surfaceId:'back'};}],
 ['more than 25 valid text layers',s=>{const a=add(s);return {...a,layers:Array.from({length:26},(_,i)=>({...a.layers[0],id:`static-layer-${i+1}`})),nextLayerSequence:27};}]
]){
 test(`34Y rejects ${name} before surface transition`,()=>{
  const s=mutate(base()),before=structuredClone(s);
  assert.equal(decide(s,'','back'),'REJECTED');
  assert.equal(decide(s,'PRIVATE CUSTOMER DRAFT','back'),'REJECTED');
  assert.deepEqual(s,before,'decision must not mutate forged input');
 });
}
test('34Y malformed property accessor fails closed and never echoes private data',()=>{
 const s=base();Object.defineProperty(s.previewSelection,'colorId',{get(){throw Error('PRIVATE CUSTOMER TOKEN');},enumerable:true});
 const out=decide(s,'PRIVATE CUSTOMER DRAFT');
 assert.equal(out,'REJECTED');assert.doesNotMatch(out,/PRIVATE|CUSTOMER|TOKEN/);
});
test('34Y valid sequence after removal and re-add remains accepted',()=>{
 let s=add(base());s=updateStaticPreview(s,{type:'REMOVE_LAYER'});s=add(s,'SECOND');
 assert.equal(s.nextLayerSequence,3);assert.equal(decide(s),'SAFE');
});
test('34Y staging generated contract contains fail-closed guard without enabling commerce',async()=>{
 const {files,manifest}=await buildStagingStaticBundle({root:new URL('..',import.meta.url).pathname});
 const js=files.get('assets/tj34i-src-static-preview-contract.js');
 assert.match(js,/staticPreviewSurfaceDraftTransition/);
 assert.match(js,/INVALID_PREVIEW_SURFACE_STATE/);
 assert.equal(manifest.checkoutEnabled,false);assert.equal(manifest.customerStorageEnabled,false);
});
test('34Y local surface guard introduces no network, storage, identity or checkout',async()=>{
 const code=await readFile(new URL('../src/static-preview-contract.mjs',import.meta.url),'utf8');
 assert.doesNotMatch(code,/\bfetch\s*\(|\blocalStorage\b|\bsessionStorage\b|\bnew\s+(?:XMLHttpRequest|WebSocket)\b|\/cart\/add/);
});
