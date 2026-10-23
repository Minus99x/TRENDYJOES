import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {PRODUCT_MANIFESTS} from '../src/catalog.mjs';
import {
 createStaticPreviewState,updateStaticPreview,reviewStaticPreview,
 staticPreviewReviewAvailability,staticPreviewAccessibilitySummary,
 staticPreviewHasPendingWork,staticPreviewSurfaceDraftTransition
} from '../src/static-preview-contract.mjs';
import {buildStagingStaticBundle} from '../src/staging-static-package.mjs';

const fresh=(id='concept-crew-tee')=>updateStaticPreview(createStaticPreviewState('?product='+id),{type:'ADD_TEXT',value:'PRIVATE LETTERING'});
const corrupt=(state,key,value)=>({...state,layers:state.layers.map((layer,index)=>index===0?{...layer,[key]:value}:layer)});
const invalid=[
 ['rotation NaN','rotationDeg',NaN],
 ['rotation null','rotationDeg',null],
 ['rotation missing','rotationDeg',undefined],
 ['rotation string','rotationDeg','90'],
 ['rotation fraction','rotationDeg',13.5],
 ['rotation above limit','rotationDeg',181],
 ['rotation below limit','rotationDeg',-181],
 ['scale NaN','scaleFactor',NaN],
 ['scale infinity','scaleFactor',Infinity],
 ['scale zero','scaleFactor',0],
 ['scale negative','scaleFactor',-1],
 ['scale below limit','scaleFactor',.29],
 ['scale above limit','scaleFactor',2.01],
 ['scale string','scaleFactor','1'],
 ['scale missing','scaleFactor',undefined],
 ['scale null','scaleFactor',null],
 ['scale/dimensions mismatch','scaleFactor',1.5],
 ['shifted position','x',.26],
 ['forged width','width',.49],
 ['forged height','height',.17]
];
for(const [name,key,value] of invalid){
 test(`35C ${name}: malformed transform cannot be reviewed or edited`,()=>{
  const state=corrupt(fresh(),key,value);
  assert.equal(staticPreviewReviewAvailability(state).ready,false);
  assert.equal(staticPreviewAccessibilitySummary(state).valid,false);
  assert.equal(staticPreviewHasPendingWork(state,''),true);
  assert.throws(()=>reviewStaticPreview(state));
  for(const action of [
   {type:'SET_MODE',mode:'2d'},
   {type:'SELECT_PRODUCT',productManifestId:'concept-rug',confirmed:true},
   {type:'ROTATE_LAYER',degrees:0},
   {type:'SCALE_LAYER',percent:100},
   {type:'RESET'}
  ])assert.throws(()=>updateStaticPreview(state,action),/INVALID_PREVIEW_SURFACE_STATE|INVALID_COMPOSITION/);
 });
}
test('35C all eight concepts reject corrupted transforms without leaking customer wording',()=>{
 for(const product of PRODUCT_MANIFESTS){
  const s=fresh(product.id);
  const invalidState=corrupt(s,'scaleFactor',-5);
  assert.equal(staticPreviewReviewAvailability(invalidState).ready,false,product.id);
  assert.equal(staticPreviewAccessibilitySummary(invalidState).description,'Concept status unavailable. No changes were saved.');
  const other=product.surfaces.find(x=>x.id!==s.surfaceId);
  if(other)assert.equal(staticPreviewSurfaceDraftTransition(invalidState,'',other.id),'REJECTED');
  assert.throws(()=>updateStaticPreview(invalidState,{type:'SELECT_COLOR',colorId:s.previewSelection.colorId}),e=>!String(e.message).includes('PRIVATE LETTERING'));
 }
});
test('35C valid edge transforms and surface switching still work across concepts',()=>{
 for(const product of PRODUCT_MANIFESTS){
  let s=fresh(product.id);
  s=updateStaticPreview(s,{type:'ROTATE_LAYER',degrees:180});
  assert.equal(reviewStaticPreview(s).layerCount,1,product.id);
  s=updateStaticPreview(s,{type:'ROTATE_LAYER',degrees:-180});
  s=updateStaticPreview(s,{type:'SCALE_LAYER',percent:30});
  assert.equal(reviewStaticPreview(s).layerCount,1,product.id);
  s=updateStaticPreview(s,{type:'SCALE_LAYER',percent:100});
  assert.equal(staticPreviewAccessibilitySummary(s).valid,true,product.id);
  const other=product.surfaces.find(x=>x.id!==s.surfaceId);
  if(other){s=updateStaticPreview(s,{type:'SELECT_SURFACE',surfaceId:other.id});assert.equal(reviewStaticPreview(s).layerCount,1);}
 }
});
test('35C canonical repeated scale changes preserve center and width/height invariants',()=>{
 let s=fresh();
 for(const percent of [50,175,65,110,30,200,100]){
  s=updateStaticPreview(s,{type:'SCALE_LAYER',percent});
  const l=s.layers[0];
  assert.ok(Math.abs(l.width-.5*l.scaleFactor)<1e-9);
  assert.ok(Math.abs(l.height-.16*l.scaleFactor)<1e-9);
  assert.ok(Math.abs(l.x+l.width/2-.5)<1e-9);
  assert.ok(Math.abs(l.y+l.height/2-.46)<1e-9);
  assert.equal(staticPreviewReviewAvailability(s).ready,true);
 }
});
test('35C bundled offline static preview inherits the same strict layer boundary',async()=>{
 const {files,manifest}=await buildStagingStaticBundle({root:new URL('..',import.meta.url).pathname});
 const bundled=files.get('assets/tj34i-src-static-preview-contract.js');
 assert.match(bundled,/INVALID_PREVIEW_SURFACE_STATE/);
 assert.match(bundled,/layer\.scaleFactor/);
 assert.match(bundled,/layer\.rotationDeg/);
 assert.equal(manifest.checkoutEnabled,false);
 assert.equal(manifest.customerStorageEnabled,false);
});
test('35C guard adds no storage, network or commerce behavior',async()=>{
 const source=await readFile(new URL('../src/static-preview-contract.mjs',import.meta.url),'utf8');
 assert.doesNotMatch(source,/\bfetch\s*\(|\blocalStorage\b|\bsessionStorage\b|\bnew\s+(?:WebSocket|XMLHttpRequest)\b|\/cart\/add/);
});
