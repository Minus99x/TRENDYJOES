import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {PRODUCT_MANIFESTS} from '../src/catalog.mjs';
import {
 createStaticPreviewState,updateStaticPreview,staticPreviewHasPendingWork,
 staticPreviewReviewAvailability,staticPreviewAccessibilitySummary,
 staticPreviewSurfaceDraftTransition,reviewStaticPreview
} from '../src/static-preview-contract.mjs';
import {buildStagingStaticBundle} from '../src/staging-static-package.mjs';
const fresh=(id='concept-crew-tee')=>createStaticPreviewState('?product='+id);
const forged=[
 ['forged mode',s=>({...s,mode:'checkout'})],
 ['forged surface',s=>({...s,surfaceId:'FORGED_SURFACE'})],
 ['zero sequence',s=>({...s,nextLayerSequence:0})],
 ['fractional sequence',s=>({...s,nextLayerSequence:1.5})],
 ['stale selected layer',s=>({...s,selectedLayerId:'static-layer-900'})],
 ['missing color binding',s=>({...s,previewSelection:{sizeId:s.previewSelection.sizeId}})],
 ['unknown color',s=>({...s,previewSelection:{...s.previewSelection,colorId:'FORGED_COLOR'}})],
 ['extra owner property',s=>({...s,previewSelection:{...s.previewSelection,owner:'PRIVATE_CUSTOMER_ID'}})],
 ['missing layer array',s=>({...s,layers:null})],
 ['malformed layer array',s=>({...s,layers:{length:0}})],
];
for(const [name,mutate] of forged){
 test(`35B invalid empty ${name} cannot bypass discard or change product`,()=>{
  const state=mutate(fresh());
  assert.equal(staticPreviewReviewAvailability(state).ready,false);
  assert.equal(staticPreviewHasPendingWork(state,''),true,'invalid state must be considered pending');
  for(const confirmed of [undefined,true]){
   const action={type:'SELECT_PRODUCT',productManifestId:'concept-rug'};
   if(confirmed!==undefined)action.confirmed=confirmed;
   assert.throws(()=>updateStaticPreview(state,action),/INVALID_PREVIEW_SURFACE_STATE|INVALID_|UNAVAILABLE_/);
  }
 });
}
test('35B malformed empty states cannot mutate other preview controls or reset',()=>{
 const state={...fresh(),layers:{length:0},mode:'checkout'};
 for(const action of [
  {type:'SELECT_COLOR',colorId:'slate'},
  {type:'SELECT_SIZE',sizeId:'m'},
  {type:'SELECT_SURFACE',surfaceId:'back'},
  {type:'ADD_TEXT',value:'PRIVATE CUSTOMER TEXT'},
  {type:'SET_MODE',mode:'2d'},
  {type:'RESET'}
 ]) assert.throws(()=>updateStaticPreview(state,action),/INVALID_PREVIEW_SURFACE_STATE|INVALID_/);
});
test('35B invalid populated state cannot accept color, size, mode or new layer',()=>{
 const base=updateStaticPreview(fresh(),{type:'ADD_TEXT',value:'PRIVATE CUSTOMER WORDING'});
 const state={...base,selectedLayerId:'static-layer-900'};
 const before=structuredClone(state);
 for(const action of [
  {type:'SELECT_COLOR',colorId:'slate'},
  {type:'SELECT_SIZE',sizeId:'m'},
  {type:'SET_MODE',mode:'2d'},
  {type:'ADD_TEXT',value:'PRIVATE OTHER WORDING'},
  {type:'REMOVE_LAYER'},
  {type:'SELECT_PRODUCT',productManifestId:'concept-rug',confirmed:true}
 ])assert.throws(()=>updateStaticPreview(state,action),/INVALID_PREVIEW_SURFACE_STATE|INVALID_|UNKNOWN_/);
 assert.deepEqual(state,before,'rejected action must not mutate the supplied state');
});
test('35B malformed getter rejects without leaking private error or mutating input',()=>{
 const state=fresh();Object.defineProperty(state.previewSelection,'colorId',{enumerable:true,get(){throw Error('PRIVATE CUSTOMER TOKEN');}});
 assert.equal(staticPreviewHasPendingWork(state,''),true);
 for(const action of [{type:'SELECT_PRODUCT',productManifestId:'concept-rug',confirmed:true},{type:'SELECT_SURFACE',surfaceId:'back'}]){
  assert.throws(()=>updateStaticPreview(state,action),e=>!String(e.message).includes('PRIVATE CUSTOMER TOKEN'));
 }
});
test('35B all merchandise concepts retain healthy editor transitions and review',()=>{
 for(const product of PRODUCT_MANIFESTS){
  let state=fresh(product.id);
  assert.equal(staticPreviewHasPendingWork(state,''),false,product.id);
  state=updateStaticPreview(state,{type:'ADD_TEXT',value:'CUSTOM TEXT'});
  assert.equal(staticPreviewHasPendingWork(state,''),true);
  assert.equal(reviewStaticPreview(state).layerCount,1);
  state=updateStaticPreview(state,{type:'SET_MODE',mode:'2d'});
  assert.equal(staticPreviewAccessibilitySummary(state).valid,true);
  const other=product.surfaces.find(s=>s.id!==state.surfaceId);
  if(other){assert.equal(staticPreviewSurfaceDraftTransition(state,'',other.id),'SAFE');state=updateStaticPreview(state,{type:'SELECT_SURFACE',surfaceId:other.id});}
  state=updateStaticPreview(state,{type:'RESET'});
  assert.equal(staticPreviewHasPendingWork(state,''),false);
  assert.equal(staticPreviewReviewAvailability(state).ready,false);
 }
});
test('35B confirmed product change preserves legitimate behavior and rejects unconfirmed work',()=>{
 const s=updateStaticPreview(fresh(),{type:'ADD_TEXT',value:'TEXT'});
 assert.throws(()=>updateStaticPreview(s,{type:'SELECT_PRODUCT',productManifestId:'concept-rug'}),/UNSAVED_WORK_CONFIRMATION_REQUIRED/);
 const next=updateStaticPreview(s,{type:'SELECT_PRODUCT',productManifestId:'concept-rug',confirmed:true});
 assert.equal(next.productManifestId,'concept-rug');assert.equal(next.layers.length,0);
});
test('35B generated offline staging includes fail-closed mutation boundary',async()=>{
 const {files,manifest}=await buildStagingStaticBundle({root:new URL('..',import.meta.url).pathname});
 const js=files.get('assets/tj34i-src-static-preview-contract.js');
 assert.match(js,/export function updateStaticPreview/);
 assert.match(js,/assertStaticPreviewIntegrity\(state,product\)/);
 assert.equal(manifest.checkoutEnabled,false);
 assert.equal(manifest.customerStorageEnabled,false);
});
test('35B guard remains client-only without network, persistence or checkout',async()=>{
 const code=await readFile(new URL('../src/static-preview-contract.mjs',import.meta.url),'utf8');
 assert.doesNotMatch(code,/\bfetch\s*\(|\blocalStorage\b|\bsessionStorage\b|\bnew\s+(?:WebSocket|XMLHttpRequest)\b|\/cart\/add/);
});
