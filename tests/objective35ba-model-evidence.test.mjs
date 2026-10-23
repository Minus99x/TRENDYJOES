import test from 'node:test';import assert from 'node:assert/strict';
import {buildPrivateConceptDesignEvidence as evidence} from '../src/preview-private-design-evidence.mjs';
import {fingerprintConceptEvidence as fingerprint} from '../src/preview-design-fingerprint.mjs';
import {PRODUCT_MANIFESTS} from '../src/catalog.mjs';
const product=PRODUCT_MANIFESTS[0],front=product.surfaces[0].id;
const sha='e'.repeat(64);
const triangle=()=>({a:[-1,0,0],b:[1,0,0],c:[0,1,0],material:'fabric',side:'asset',surfaceId:front,uv:[[0,0],[1,0],[0,1]]});
const inspection=()=>({sha256:sha,byteLength:2048,nodeCount:1,vertexCount:3,triangleCount:1,mappedSurfaces:[front],missingSurfaces:product.surfaces.slice(1).map(s=>s.id),approval:'UNVERIFIED_LOCAL_PREVIEW_ONLY',assetBoundsMeters:{min:[0,0,0],max:[1,1,0],extent:[1,1,0]},asset:{status:'IMPORTED_UNVERIFIED',sha256:sha,modelId:`imported-${sha.slice(0,14)}`,surfaceIds:[front],triangles:[triangle()]}});
const data=()=>({product,surfaceId:front,previewSelection:{colorId:null,sizeId:null},layers:[{id:'txt',type:'text',surfaceId:front,x:.2,y:.2,width:.3,height:.2,rotationDeg:0,scaleFactor:1,value:'PRIVATE CUSTOMER NAME'}]});
test('model identity is included without geometry, private text or forged checkout approval',async()=>{
 const a=evidence({...data(),inspection:inspection()});const raw=JSON.stringify(a);
 assert.equal(a.modelInspection.sha256,sha);assert.equal(a.modelInspection.triangleCount,1);
 assert.deepEqual(a.modelInspection.mappedSurfaces,[front]);
 assert(!raw.includes('PRIVATE CUSTOMER NAME'));assert(!raw.includes('assetBoundsMeters'));assert(raw.includes('triangleCount')); 
 assert(!raw.includes('"uv"'));assert(!raw.includes('"modelId"'));
 assert.equal(a.modelInspection.manufacturingApproved,false);assert.equal(a.checkoutEnabled,false);
 const d=await fingerprint(a);assert.match(d.digestSha256,/^[a-f0-9]{64}$/);
});
test('draft without imported model retains explicit no-model state',()=>{
 assert.equal(evidence(data()).modelInspection,null);
});
test('forged model result is rejected before serialization',()=>{
 for(const mutation of [r=>r.asset.sha256='f'.repeat(64),r=>r.asset.triangles[0].a[0]=Infinity,
 r=>r.approval='APPROVED',r=>r.asset.surfaceIds.push('other'),r=>r.asset.triangles[0].uv[1]=[2,0]]){
  const m=inspection();mutation(m);assert.throws(()=>evidence({...data(),inspection:m}),/MODEL_/);
 }
});
