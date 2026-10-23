import test from 'node:test';import assert from 'node:assert/strict';
import {buildConceptUvReport} from '../src/preview-uv-report.mjs';
import {checkPreviewArtworkUvFootprint} from '../src/preview-uv-footprint.mjs';
import {PRODUCT_MANIFESTS} from '../src/catalog.mjs';
const p=PRODUCT_MANIFESTS[0],sha='a'.repeat(64);
const layer={id:'x',type:'text',value:'OK',surfaceId:'front',x:.2,y:.2,width:.2,height:.2,rotationDeg:0,scaleFactor:1};
const model=()=>({sha256:sha,mappedSurfaces:['front'],asset:{triangles:[{surfaceId:'front',uv:[[0,0],[1,0],[0,1]]}]}});
test('35BE bounded valid concept report never authorizes production',()=>{const r=buildConceptUvReport({product:p,layers:[layer],inspection:model()});assert.equal(r.previewChecked,true);assert.equal(r.productionApproved,false);assert.equal(r.checkoutEnabled,false);});
for(const [name,mutation,expected] of [['missing map',r=>delete r.mappedSurfaces,'INVALID_COMPOSITION_OR_MODEL'],['duplicate map',r=>r.mappedSurfaces.push('front'),'INVALID_MODEL_SURFACE_MAP'],['unexpected map',r=>r.mappedSurfaces.push('phantom'),'INVALID_MODEL_SURFACE_MAP'],['missing triangles',r=>delete r.asset.triangles,'INVALID_COMPOSITION_OR_MODEL'],['oversized geometry',r=>r.asset.triangles=Array(45001).fill(null),'INVALID_COMPOSITION_OR_MODEL'],['wrong digest',r=>r.sha256='invalid','INVALID_COMPOSITION_OR_MODEL']])test(`35BE ${name} denied`,()=>{const r=model();mutation(r);const out=buildConceptUvReport({product:p,layers:[layer],inspection:r});assert.equal(out.previewChecked,false);assert.deepEqual(out.issues,[expected]);});
test('35BE invalid mapped UV cannot silently disappear from diagnostic',()=>{const m=model();m.asset.triangles[0].uv[1]=[NaN,1];assert.equal(checkPreviewArtworkUvFootprint(layer,m).reason,'INVALID_MAPPED_UV');assert(buildConceptUvReport({product:p,layers:[layer],inspection:m}).issues.includes('front:INVALID_MAPPED_UV'));});
test('35BE hostile malformed product fails closed without uncaught error',()=>{const out=buildConceptUvReport({product:{surfaces:[null]},layers:[layer],inspection:model()});assert.equal(out.previewChecked,false);});

test('35BE excessive mapped UV triangles are bounded before expensive sampling',()=>{
 const m=model();m.asset.triangles=Array.from({length:5001},()=>({surfaceId:'front',uv:[[0,0],[1,0],[0,1]]}));
 const o=checkPreviewArtworkUvFootprint(layer,m);assert.equal(o.covered,false);assert.equal(o.reason,'UV_PREVIEW_COMPLEXITY_LIMIT');
});
