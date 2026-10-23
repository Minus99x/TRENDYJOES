import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {resolve,join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {PRODUCT_MANIFESTS,MANIFEST_BY_ID} from '../src/catalog.mjs';
import {conceptCameraForSurface,CONCEPT_PREVIEW_CAMERA_DEFAULT,updateConceptPreviewCamera} from '../src/viewer3d.mjs';
import {createStaticPreviewState,updateStaticPreview} from '../src/static-preview-contract.mjs';
import {buildStagingStaticBundle} from '../src/staging-static-package.mjs';
const root=resolve(fileURLToPath(new URL('..',import.meta.url)));
const camera=(id,surface,options)=>conceptCameraForSurface(MANIFEST_BY_ID[id],surface,options);
const read=p=>readFile(join(root,p),'utf8');
test('34N back surface on all garment concepts faces the rear, not the front',()=>{
 for(const p of PRODUCT_MANIFESTS.filter(p=>p.geometry.kind==='garment')){
  const c=camera(p.id,'back');assert.ok(Math.cos(c.yaw)<-.03,p.id);
  assert.equal(c.pitch,CONCEPT_PREVIEW_CAMERA_DEFAULT.pitch);
 }
});
test('34N front garment surfaces face front with default camera',()=>{
 for(const p of PRODUCT_MANIFESTS.filter(p=>p.geometry.kind==='garment'))
  assert.deepEqual(camera(p.id,'front'),CONCEPT_PREVIEW_CAMERA_DEFAULT);
});
test('34N left sleeve receives a visible front-quarter angle, not the rear',()=>{
 for(const p of PRODUCT_MANIFESTS.filter(p=>p.surfaces.some(s=>s.id==='sleeve-left'))){
  const c=camera(p.id,'sleeve-left');assert.ok(c.yaw>.5 && c.yaw<Math.PI/2);
  assert.ok(Math.cos(c.yaw)>.03);
 }
});
test('34N all eight product categories and every surface have finite, bounded camera defaults',()=>{
 for(const p of PRODUCT_MANIFESTS)for(const surface of p.surfaces){
  const c=conceptCameraForSurface(p,surface.id);
  assert.ok(Object.values(c).every(Number.isFinite));
  assert.ok(c.zoom>=.6 && c.zoom<=1.8);
  assert.doesNotThrow(()=>updateConceptPreviewCamera(c,{type:'ZOOM',factor:1.1}));
 }
});
test('34N zoom is retained on a surface change and reset to default when requested',()=>{
 assert.equal(camera('concept-crew-tee','back',{zoom:1.6}).zoom,1.6);
 assert.equal(camera('concept-crew-tee','back').zoom,1);
});
test('34N rejects forged or stale product surface IDs without falling back to front',()=>{
 for(const id of ['forged','BACK','__proto__','',null,undefined])
  assert.throws(()=>camera('concept-crew-tee',id),/INVALID_CONCEPT_CAMERA_ACTION/);
});
test('34N rejects invalid zoom, malformed manifest, and missing surfaces',()=>{
 for(const zoom of [-1,0,.59,1.81,Infinity,NaN,'1',null])
  assert.throws(()=>camera('concept-crew-tee','back',{zoom}),/INVALID_CONCEPT_CAMERA_ACTION/);
 for(const bad of [null,{},[],{surfaces:[]},{surfaces:null}])
  assert.throws(()=>conceptCameraForSurface(bad,'front'),/INVALID_CONCEPT_CAMERA_ACTION/);
});
test('34N pure camera function does not mutate caller product or options',()=>{
 const p=MANIFEST_BY_ID['concept-crew-tee'];const before=JSON.stringify(p);
 const options={zoom:1.3};const c=conceptCameraForSurface(p,'back',options);
 assert.equal(JSON.stringify(p),before);assert.deepEqual(options,{zoom:1.3});
 c.zoom=.7;assert.equal(options.zoom,1.3);
});
test('34N customer multi-surface design retains both layers when camera reorients',()=>{
 let state=createStaticPreviewState('?product=concept-crew-tee');
 state=updateStaticPreview(state,{type:'ADD_TEXT',value:'Front'});
 state=updateStaticPreview(state,{type:'SELECT_SURFACE',surfaceId:'back'});
 state=updateStaticPreview(state,{type:'ADD_TEXT',value:'Back'});
 assert.deepEqual(state.layers.map(l=>l.surfaceId),['front','back']);
 assert.ok(Math.cos(conceptCameraForSurface(MANIFEST_BY_ID[state.productManifestId],state.surfaceId).yaw)<0);
});
test('34N browser editor aligns surface/product/reset and camera reset interactions',async()=>{
 const code=await read('demo/static-preview.mjs');
 assert.match(code,/\['SELECT_PRODUCT','RESET','SELECT_SURFACE'\]\.includes\(action\.type\)/);
 assert.match(code,/action\.type==='SELECT_SURFACE'\?camera\.zoom:1/);
 assert.match(code,/action\.type==='RESET'\?conceptCameraForSurface/);
 assert.match(code,/action\.type==='SELECT_SURFACE'\)cancelDrag\(\)/);
});
test('34N generated staging bundle carries surface camera routing without commerce activation',async()=>{
 const {files,manifest}=await buildStagingStaticBundle({root});
 assert.equal(manifest.sourceVersion,JSON.parse(await readFile(join(root,'package.json'),'utf8')).version);
 assert.equal(manifest.checkoutEnabled,false);assert.equal(manifest.shopifyThemeInstalled,false);
 const ui=files.get('assets/tj34i-demo-static-preview.js');
 const viewer=files.get('assets/tj34i-src-viewer3d.js');
 assert.match(ui,/conceptCameraForSurface/);assert.match(viewer,/export function conceptCameraForSurface/);
 assert.doesNotMatch(ui,/fetch\(|localStorage|sessionStorage|\/cart\/add|\/checkout/);
});
