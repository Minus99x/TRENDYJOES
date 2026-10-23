import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {PRODUCT_MANIFESTS} from '../src/catalog.mjs';
import {
 createStaticPreviewState,updateStaticPreview,reviewStaticPreview,
 staticPreviewReviewAvailability,staticPreviewAccessibilitySummary,
 staticPreviewActionAnnouncement,staticPreviewSurfaceDraftTransition
} from '../src/static-preview-contract.mjs';
import {buildStagingStaticBundle} from '../src/staging-static-package.mjs';

const fresh=(id='concept-crew-tee')=>createStaticPreviewState('?product='+id);
const add=s=>updateStaticPreview(s,{type:'ADD_TEXT',value:'PRIVATE LETTERING'});
const invalid=[
 ['missing color binding',s=>({...s,previewSelection:{sizeId:s.previewSelection.sizeId}})],
 ['extra owner binding',s=>({...s,previewSelection:{...s.previewSelection,owner:'PRIVATE_OWNER'}})],
 ['unknown illustrative color',s=>({...s,previewSelection:{...s.previewSelection,colorId:'FORGED_COLOR'}})],
 ['missing next sequence',s=>({...s,nextLayerSequence:undefined})],
 ['zero next sequence',s=>({...s,nextLayerSequence:0})],
 ['reused next sequence',s=>({...s,nextLayerSequence:1})],
 ['fractional next sequence',s=>({...s,nextLayerSequence:1.5})],
 ['forged layer ID with no selection',s=>({...s,selectedLayerId:null,layers:[{...s.layers[0],id:'PRIVATE_LAYER'}]})],
 ['future layer ID with no selection',s=>({...s,selectedLayerId:null,layers:[{...s.layers[0],id:'static-layer-900'}]})],
 ['malformed layer sequence with no selection',s=>({...s,selectedLayerId:null,layers:[{...s.layers[0],id:'static-layer-01'}]})]
];
for(const [name,mutate] of invalid){
 test(`35A accessibility rejects ${name} already rejected by review`,()=>{
  const state=mutate(add(fresh()));const before=structuredClone(state);
  assert.deepEqual(staticPreviewReviewAvailability(state),{ready:false,reason:'INVALID_PREVIEW'});
  const view=staticPreviewAccessibilitySummary(state);
  assert.deepEqual(view,{valid:false,description:'Concept status unavailable. No changes were saved.'});
  assert.equal(staticPreviewActionAnnouncement({type:'ADD_TEXT',value:'PRIVATE'},state),'Preview change unavailable.');
  assert.equal(staticPreviewActionAnnouncement({type:'ROTATE_LAYER'},state),'Preview change unavailable.');
  assert.deepEqual(state,before,'accessibility checks must never mutate invalid state');
 });
}
test('35A all eight concept families retain approved catalog descriptions and no private wording',()=>{
 for(const product of PRODUCT_MANIFESTS){
  const state=add(fresh(product.id));const view=staticPreviewAccessibilitySummary(state);
  assert.equal(view.valid,true,product.id);
  assert.equal(view.productLabel,product.label);
  assert.equal(view.totalLayerCount,1);
  assert.doesNotMatch(JSON.stringify(view),/PRIVATE LETTERING|static-layer-1/);
  assert.equal(staticPreviewActionAnnouncement({type:'ADD_TEXT'},state).includes('Lettering added'),true);
 }
});
test('35A valid multi-surface and cleared-selection announcements remain usable',()=>{
 let state=add(fresh());state=updateStaticPreview(state,{type:'SELECT_SURFACE',surfaceId:'back'});
 assert.equal(staticPreviewAccessibilitySummary(state).valid,true);
 assert.equal(staticPreviewAccessibilitySummary(state).activeLayerCount,0);
 assert.equal(staticPreviewActionAnnouncement({type:'SELECT_SURFACE'},state),'Back surface selected. 0 lettering layers on this surface.');
 state=add(state);assert.equal(staticPreviewAccessibilitySummary(state).totalLayerCount,2);
 assert.equal(staticPreviewSurfaceDraftTransition(state,'','front'),'SAFE');
 assert.equal(reviewStaticPreview(state).layerCount,2);
});
test('35A continuous slider announcements remain silent only for valid states',()=>{
 const state=add(fresh());
 assert.equal(staticPreviewActionAnnouncement({type:'ROTATE_LAYER'},state),null);
 assert.equal(staticPreviewActionAnnouncement({type:'SCALE_LAYER'},state),null);
});
test('35A malformed state and thrown option getters never expose sensitive values',()=>{
 const state=add(fresh());
 Object.defineProperty(state.previewSelection,'colorId',{enumerable:true,get(){throw Error('PRIVATE CUSTOMER SECRET');}});
 const view=staticPreviewAccessibilitySummary(state);
 assert.equal(view.valid,false);
 assert.doesNotMatch(JSON.stringify(view),/PRIVATE|CUSTOMER|SECRET/);
 assert.equal(staticPreviewActionAnnouncement({type:'SCALE_LAYER'},state),'Preview change unavailable.');
});
test('35A offline staging static asset embeds shared integrity validation',async()=>{
 const {files,manifest}=await buildStagingStaticBundle({root:new URL('..',import.meta.url).pathname});
 const js=files.get('assets/tj34i-src-static-preview-contract.js');
 assert.match(js,/export function staticPreviewAccessibilitySummary/);
 assert.match(js,/assertStaticPreviewIntegrity\(state,product\)/);
 assert.equal(manifest.checkoutEnabled,false);
 assert.equal(manifest.customerStorageEnabled,false);
});
test('35A accessibility guard introduces no network, storage or checkout',async()=>{
 const src=await readFile(new URL('../src/static-preview-contract.mjs',import.meta.url),'utf8');
 assert.doesNotMatch(src,/\bfetch\s*\(|\blocalStorage\b|\bsessionStorage\b|\bnew\s+(?:WebSocket|XMLHttpRequest)\b|\/cart\/add/);
});
