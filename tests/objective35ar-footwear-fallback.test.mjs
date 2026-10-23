import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {MANIFEST_BY_ID,PRODUCT_MANIFESTS,FOOTWEAR_CONCEPT_SURFACES,getFootwearConceptView} from '../src/catalog.mjs';
import {createConceptMesh,sampleConceptSurface} from '../src/geometry3d.mjs';
import {validateManifest,validateComposition,preflight} from '../src/core.mjs';
import {createStaticPreviewState,updateStaticPreview,reviewStaticPreview} from '../src/static-preview-contract.mjs';
import {duplicatePreviewLayerToSurface} from '../src/preview-surface-copy.mjs';
const shoe=MANIFEST_BY_ID['concept-sneaker'];
const layer={id:'letter',type:'text',value:'TJ',surfaceId:'outer-side',x:.20,y:.30,width:.36,height:.18,rotationDeg:0,scaleFactor:1};
test('35AR eight product concepts include exactly one 2D-only footwear manifest',()=>{
 assert.equal(PRODUCT_MANIFESTS.length,8);assert.deepEqual(validateManifest(shoe),[]);
 assert.equal(shoe.category,'footwear');assert.equal(shoe.geometry.subtype,'low-top-sneaker');
 assert.equal(createConceptMesh(shoe),null);assert.equal(sampleConceptSurface(shoe,'outer-side',.5,.5),null);
 assert.equal(shoe.manufacturing.approvedMethods.length,0);assert.equal(shoe.commerce.pricingVerified,false);
 assert.equal(shoe.lifecycle,'CONCEPT');
});
test('35AR three explicit footwear views have unique fixed geometry and normalized zones',()=>{
 assert.deepEqual(shoe.surfaces.map(s=>s.id),['outer-side','inner-side','tongue']);
 const shapes=FOOTWEAR_CONCEPT_SURFACES.map(s=>getFootwearConceptView(shoe,s.id)?.shapeMarkup);
 assert.equal(shapes.length,3);assert.equal(new Set(shapes).size,3);
 for(const s of shoe.surfaces){
  const v=getFootwearConceptView(shoe,s.id);assert.equal(v.previewRect.x,s.previewRect.x);
  assert.ok(s.previewRect.width>0&&s.previewRect.height>0);
  assert.equal(s.calibrated,false);assert.equal(s.printableWidthMm,null);assert.equal(s.allowableMethods.length,0);
 }
});
test('35AR missing, forged, mutated, inherited or foreign surface cannot silently render as another shoe view',()=>{
 for(const id of ['heel','sole','__proto__',null,{},'outer-side\0'])assert.equal(getFootwearConceptView(shoe,id),null);
 assert.equal(getFootwearConceptView(MANIFEST_BY_ID['concept-rug'],'outer-side'),null);
 const mutated=structuredClone(shoe);mutated.surfaces[0].previewRect.x=.01;
 assert.equal(getFootwearConceptView(mutated,'outer-side'),null);
 assert.equal(getFootwearConceptView({...shoe,geometry:{...shoe.geometry,subtype:'approved-supplier'}},'outer-side'),null);
});
test('35AR cross-surface footwear duplication remains immutable and production-blocked',()=>{
 const layers=[layer];const before=structuredClone(layers);
 const r=duplicatePreviewLayerToSurface({product:shoe,layers,selectedId:'letter',sourceSurfaceId:'outer-side',targetSurfaceId:'tongue',newId:'copy-shoe1',placement:'center'});
 assert.equal(r.applied,true);assert.deepEqual(layers,before);assert.equal(r.layers[1].surfaceId,'tongue');
 assert.deepEqual(validateComposition(shoe,{layers:r.layers}),[]);
 assert.equal(preflight(shoe,{layers:r.layers}).productionReady,false);
 assert.ok(preflight(shoe,{layers:r.layers}).blockers.some(x=>x.code==='SURFACE_UNCALIBRATED'));
});
test('35AR ephemeral footwear state defaults to 2D, rejects unsupported 3D, retains valid design review',()=>{
 let state=createStaticPreviewState('?product=concept-sneaker');assert.equal(state.mode,'2d');
 assert.throws(()=>updateStaticPreview(state,{type:'SET_MODE',mode:'3d'}),/INVALID_MODE/);
 assert.throws(()=>reviewStaticPreview({...state,mode:'3d'}),/INVALID_PREVIEW_SURFACE_STATE/);
 state=updateStaticPreview(state,{type:'ADD_TEXT',value:'Oxblood'});
 assert.equal(reviewStaticPreview(state).layerCount,1);assert.equal(reviewStaticPreview(state).checkoutEnabled,false);
 const switched=updateStaticPreview(createStaticPreviewState(),{type:'SELECT_PRODUCT',productManifestId:'concept-sneaker'});
 assert.equal(switched.mode,'2d');
});
test('35AR offline editors expose 2D fallback without granting commerce',async()=>{
 const [html,staticHtml,interactive,ephemeral]=await Promise.all([
  readFile(new URL('../demo/index.html',import.meta.url),'utf8'),
  readFile(new URL('../demo/static-preview.html',import.meta.url),'utf8'),
  readFile(new URL('../demo/studio.mjs',import.meta.url),'utf8'),
  readFile(new URL('../demo/static-preview.mjs',import.meta.url),'utf8')]);
 assert.match(interactive,/getFootwearConceptView/);assert.match(ephemeral,/getFootwearConceptView/);
 assert.match(interactive,/mode-3d'\)\.disabled/);assert.match(ephemeral,/mode-3d'\)\.disabled/);
 assert.match(html,/disabled class="disabled-checkout"/);assert.match(staticHtml,/Checkout unavailable/i);
});
