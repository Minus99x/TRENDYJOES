import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {MANIFEST_BY_ID,PRODUCT_MANIFESTS} from '../src/catalog.mjs';
import {createCalibrationWorksheet} from '../src/calibration.mjs';
import {nudgePreviewLayer} from '../src/preview-keyboard-position.mjs';

const layer=(surfaceId)=>({id:'example',type:'text',surfaceId,x:.25,y:.32,width:.45,height:.17,rotationDeg:0,scaleFactor:1,value:'CONCEPT'});
test('35AT every product category supports isolated normalized keyboard positioning',()=>{
 const categories=new Set();
 for(const p of PRODUCT_MANIFESTS){
  categories.add(p.category);
  const current=layer(p.surfaces[0].id);
  const before=structuredClone(current);
  const result=nudgePreviewLayer({product:p,layers:[current],selectedId:current.id,surfaceId:current.surfaceId,direction:'right',step:.01});
  assert.equal(result.applied,true,p.id);
  assert.equal(result.layers[0].x,.26,p.id);
  assert.deepEqual(current,before,p.id);
  if(p.surfaces.length>1){
   const denied=nudgePreviewLayer({product:p,layers:[current],selectedId:current.id,surfaceId:p.surfaces[1].id,direction:'left'});
   assert.equal(denied.applied,false,p.id);
   assert.equal(denied.reason,'DIFFERENT_SURFACE',p.id);
  }
 }
 assert.deepEqual([...categories].sort(),['accessories','apparel','drinkware','footwear','home']);
});
test('35AT physical calibration drafts remain unapproved, product/surface scoped',()=>{
 for(const p of PRODUCT_MANIFESTS){
  const surface=p.surfaces[0];
  const draft=createCalibrationWorksheet(p,[{surfaceId:surface.id,widthMm:80,heightMm:60,blankWidthMm:120,blankHeightMm:100,processCode:surface.allowableMethods[0],fixtureReference:'SYNTHETIC TEST FIXTURE'}],{
   blankSku:'TEST-BLANK',measuredBy:'TEST ONLY',sourceDocument:'SYNTHETIC TEST EVIDENCE',measuredAt:'2026-10-22'});
  if(surface.allowableMethods.length)assert.deepEqual(draft.issues,[],p.id);
  else assert.ok(draft.issues.some(issue=>issue.code==='PROCESS'),p.id);
  assert.equal(draft.productManifestId,p.id);
  assert.equal(draft.zones[0].surfaceId,surface.id);
  assert.equal(draft.manufacturingApproved,false);
  assert.equal(draft.checkoutEnabled,false);
 }
});
test('35AT local editor guards stale calibration exports and clears cross-product fields',async()=>{
 const js=await readFile(new URL('../demo/studio.mjs',import.meta.url),'utf8');
 assert.match(js,/calibrationSignature!==calibrationFingerprint\(\)/);
 assert.match(js,/if\(state\.calibrationSignature!==calibrationFingerprint\(\)\)/);
 assert.match(js,/invalidateCalibration\('New product selected; measurements are not carried over\.',\{clearFields:true\}\)/);
 assert.match(js,/invalidateCalibration\('Design surface changed; measurements are not carried over\.',\{clearFields:true\}\)/);
 assert.match(js,/invalidateCalibration\('No calibration worksheet recovered\.',\{clearFields:true\}\)/);
 assert.match(js,/calibrationInputIds\.map\(id=>\$\(id\)\.value\)/);
 assert.match(js,/\$\('export-calibration'\)\.disabled=true/);
 assert.match(js,/state\.calibrationSignature=draft\.issues\.length\|\|!reviewed\.canEstimatePlacement\?null:calibrationFingerprint\(\)/);
});
