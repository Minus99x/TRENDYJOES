import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {PRODUCT_MANIFESTS,MANIFEST_BY_ID} from '../src/catalog.mjs';
import {duplicatePreviewLayerToSurface as copy} from '../src/preview-surface-copy.mjs';
import {validateComposition,preflight} from '../src/core.mjs';
const product=MANIFEST_BY_ID['concept-crew-tee'];
const layer={id:'art1',type:'text',surfaceId:'front',x:.12,y:.18,width:.36,height:.19,rotationDeg:20,scaleFactor:1,value:'TJDW'};
const base=(opts={})=>({product,layers:[layer],selectedId:'art1',sourceSurfaceId:'front',targetSurfaceId:'back',newId:'copy-35aq',...opts});
test('35AQ center is an explicit, geometry-valid, non-mutating target placement',()=>{
 const layers=[layer];const snapshot=structuredClone(layers);const r=copy(base({layers,placement:'center'}));
 assert.equal(r.applied,true);assert.equal(r.placement,'center');assert.equal(r.layers[1].x,.32);assert.equal(r.layers[1].y,.405);
 assert.deepEqual(layers,snapshot);assert.equal(r.layers[0],layer);assert.deepEqual(validateComposition(product,{layers:r.layers}),[]);
});
test('35AQ preserve remains backward-compatible default with no silent repositioning',()=>{
 const implicit=copy(base()),explicit=copy(base({placement:'preserve'}));
 assert.equal(implicit.applied,true);assert.deepEqual(implicit.layers,explicit.layers);
 assert.equal(implicit.layers[1].x,layer.x);assert.equal(implicit.layers[1].y,layer.y);
});
for(const placement of [null,undefined,'CENTER','stretch','fit','center;checkout',{},[],0]){
 test(`35AQ rejects invalid placement ${String(placement)} with no mutation`,()=>{
  const layers=[layer];const r=copy(base({layers,placement}));
  if(placement===undefined){assert.equal(r.applied,true);return;}
  assert.equal(r.applied,false);assert.equal(r.reason,'INVALID_ACTION');assert.equal(r.layers,layers);
 });
}
test('35AQ refuses invalid rotated target geometry, no clamp or shrink',()=>{
 const source={...layer,width:.95,height:.95,rotationDeg:0,x:.025,y:.025};
 const r=copy(base({layers:[source],placement:'center'}));assert.equal(r.applied,true);
 const rotate={...source,rotationDeg:45};
 const denied=copy(base({layers:[rotate],placement:'center'}));
 assert.equal(denied.applied,false);assert.equal(denied.reason,'INVALID_COMPOSITION');
});
test('35AQ all multiple-surface concept products support explicit centered copy',()=>{
 for(const p of PRODUCT_MANIFESTS){if(p.surfaces.length<2)continue;
  const l={...layer,surfaceId:p.surfaces[0].id};const r=copy(base({product:p,layers:[l],sourceSurfaceId:p.surfaces[0].id,targetSurfaceId:p.surfaces[1].id,placement:'center'}));
  assert.equal(r.applied,true,p.id);assert.deepEqual(validateComposition(p,{layers:r.layers}),[],p.id);
 }
});
test('35AQ center cannot duplicate private authority or grant production readiness',()=>{
 const secret={...layer,ownerToken:'never-copy',authorization:'no',artworkGrant:'secret'};
 const r=copy(base({layers:[secret],placement:'center'}));assert.equal(r.applied,true);
 assert.equal(JSON.stringify(r.layers[1]).includes('secret'),false);
 assert.equal(preflight(product,{layers:r.layers}).productionReady,false);
});
test('35AQ browser UI presents accessible explicit placement choice',async()=>{
 const html=await readFile(new URL('../demo/index.html',import.meta.url),'utf8');
 const js=await readFile(new URL('../demo/studio.mjs',import.meta.url),'utf8');
 assert.match(html,/<label for="copy-placement">Position on target surface<\/label>/);
 assert.match(html,/<select id="copy-placement" disabled>/);
 assert.match(html,/<option value="preserve">Keep relative placement<\/option>/);
 assert.match(html,/<option value="center">Center element in target zone<\/option>/);
 assert.match(js,/placement=\$\('copy-placement'\)\.value/);
 assert.match(js,/\$\('copy-placement'\)\.disabled=targetSelect\.disabled/);
 assert.match(html,/disabled class="disabled-checkout"/);
});
