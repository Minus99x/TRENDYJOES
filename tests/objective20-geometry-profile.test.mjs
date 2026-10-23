import test from 'node:test';
import assert from 'node:assert/strict';
import {createHmac,randomBytes} from 'node:crypto';
import {PRODUCT_MANIFESTS} from '../src/catalog.mjs';
import {createCalibrationWorksheet} from '../src/calibration.mjs';
import {inspectGlb} from '../src/model-assets.mjs';
import {reviewManufacturingProfile} from '../src/manufacturing-review.mjs';
import {reviewManufacturingGeometryProfile,uvRectangleCovered} from '../src/manufacturing-geometry-profile.mjs';

const shop='gucgmp-bc.myshopify.com',productGid='gid://shopify/Product/123',variantGid='gid://shopify/ProductVariant/456';
const now=Date.parse('2026-10-15T17:00:00Z');
const baseKey=randomBytes(32),modelKey=randomBytes(32);
const sign=(record,key)=>createHmac('sha256',key).update(JSON.stringify(Object.fromEntries(Object.entries(record).filter(([k])=>k!=='signature')))).digest('hex');
const verifyBase=async r=>r.signature===sign(r,baseKey);
const verifyModel=async r=>r.signature===sign(r,modelKey);
const layer={id:'design-1',type:'text',surfaceId:'front',x:.2,y:.2,width:.3,height:.3,rotationDeg:0,value:'Synthetic'};
const manifest=PRODUCT_MANIFESTS[0];
function glb({surface='front',gap=0,triangles=2,scale=1,degenerate=false,corrupt=false}={}){
 const points=degenerate?[0,0,0,1,0,0,2,0,0,0,0,0]:[0,0,0,1,0,0,1,1,0,0,1,0];
 const uvs=[0,0,.5-gap/2,0,.5-gap/2,1,0,1];
 // Two halves leave a real seam if gap>0. With gap=0 both triangles span only half;
 // use full-square coordinates for normal tests.
 const tex=gap?uvs:[0,0,1,0,1,1,0,1];
 const idx=triangles===1?[0,1,3]:[0,1,2,0,2,3];
 const bin=Buffer.alloc(48+32+idx.length*2+((4-idx.length*2%4)%4));
 const v=new DataView(bin.buffer,bin.byteOffset,bin.byteLength);
 points.forEach((x,i)=>v.setFloat32(i*4,x,true));tex.forEach((x,i)=>v.setFloat32(48+i*4,x,true));idx.forEach((x,i)=>v.setUint16(80+i*2,x,true));
 const doc={asset:{version:'2.0'},buffers:[{byteLength:bin.length}],bufferViews:[{buffer:0,byteOffset:0,byteLength:48},{buffer:0,byteOffset:48,byteLength:32},{buffer:0,byteOffset:80,byteLength:idx.length*2}],accessors:[{bufferView:0,componentType:5126,count:4,type:'VEC3'},{bufferView:1,componentType:5126,count:4,type:'VEC2'},{bufferView:2,componentType:5123,count:idx.length,type:'SCALAR'}],meshes:[{primitives:[{attributes:{POSITION:0,TEXCOORD_0:1},indices:2}]}],nodes:[{mesh:0,scale:[scale,scale,scale],extras:{tjSurfaceId:surface}}],scenes:[{nodes:[0]}],scene:0};
 let json=Buffer.from(JSON.stringify(doc));json=Buffer.concat([json,Buffer.alloc((4-json.length%4)%4,32)]);
 const bytes=Buffer.alloc(12+8+json.length+8+bin.length);bytes.writeUInt32LE(0x46546c67,0);bytes.writeUInt32LE(2,4);bytes.writeUInt32LE(bytes.length,8);bytes.writeUInt32LE(json.length,12);bytes.writeUInt32LE(0x4e4f534a,16);json.copy(bytes,20);const off=20+json.length;bytes.writeUInt32LE(bin.length,off);bytes.writeUInt32LE(0x004e4942,off+4);bin.copy(bytes,off+8);if(corrupt)bytes[0]=0;return bytes;
}
async function setup({bytes=glb(),layers=[layer],selectedManifest=manifest,zones=[{surfaceId:'front',widthMm:240,heightMm:300,blankWidthMm:300,blankHeightMm:400,processCode:'DTF-TEXTILE',fixtureReference:'Synthetic fixture',safetyInsetMm:5}]}={}){
 const inspected=await inspectGlb(bytes,selectedManifest);
 const worksheet=createCalibrationWorksheet(selectedManifest,zones,{blankSku:'TEST-BLANK',measuredBy:'Test technician',sourceDocument:'Synthetic measurement',measuredAt:'2026-10-14',modelSha256:inspected.sha256});
 const base={shop,productGid,variantGid,manifest:selectedManifest,worksheet,design:{layers},glbBytes:bytes,now,verifyApproval:verifyBase};
 const pre=await reviewManufacturingProfile(base);
 const approvalRecord={schema:'TJ-MANUFACTURING-REVIEW-1',reviewId:'base-review',revision:1,issuedAtMs:now-1000,expiresAtMs:now+3600000,reviewerId:'synthetic-base-reviewer',shop,productGid,variantGid,manifestId:selectedManifest.id,blankSku:worksheet.blankSku,modelSha256:inspected.sha256,profileSha256:pre.profileSha256,signature:''};approvalRecord.signature=sign(approvalRecord,baseKey);
 const geometryProfile={schema:'TJ-GLB-GEOMETRY-CALIBRATION-1',shop,productGid,variantGid,manifestId:selectedManifest.id,blankSku:worksheet.blankSku,modelSha256:inspected.sha256,mmPerModelUnit:400,physicalBoundsMm:[400,400,0],toleranceMm:.5,measuredBy:'Synthetic test operator',measuredAt:'2026-10-14',evidenceReference:'synthetic measurement evidence',status:'DRAFT_REQUIRES_INDEPENDENT_APPROVAL'};
 const input={...base,approvalRecord,geometryProfile,verifyModelApproval:verifyModel};
 const preliminary=await reviewManufacturingGeometryProfile(input);
 const modelApprovalRecord={schema:'TJ-GLB-GEOMETRY-REVIEW-1',reviewId:'model-review',revision:1,issuedAtMs:now-1000,expiresAtMs:now+3600000,reviewerId:'synthetic-model-reviewer',shop,productGid,variantGid,manifestId:selectedManifest.id,blankSku:worksheet.blankSku,modelSha256:inspected.sha256,geometryProfileSha256:preliminary.geometryProfileSha256,signature:''};modelApprovalRecord.signature=sign(modelApprovalRecord,modelKey);
 return {...input,modelApprovalRecord};
}
const run=(f,overrides={})=>reviewManufacturingGeometryProfile({...f,...overrides});
const codes=r=>r.issues.map(x=>x.code);
const denied=r=>{assert.equal(r.geometryEvidenceReady,false);assert.equal(r.productionApproved,false);assert.equal(r.checkoutEnabled,false);assert.equal(r.machineOutput,null);};

test('synthetic independently reviewed model and calibrated zone are evidence only, never production',async()=>{
 const f=await setup(),r=await run(f);assert.equal(r.geometryEvidenceReady,true);assert.match(r.geometryProfileSha256,/^[0-9a-f]{64}$/);assert.equal(r.issues.length,0);assert.equal(r.productionApproved,false);assert.equal(r.checkoutEnabled,false);assert.equal(r.machineOutput,null);
});
test('unapproved model and missing model verifier both fail closed',async()=>{
 const f=await setup();denied(await run(f,{modelApprovalRecord:undefined}));assert.ok(codes(await run(f,{verifyModelApproval:undefined})).includes('MODEL_VERIFIER_REQUIRED'));
});
test('forged model signature and verifier outages reject',async()=>{
 const f=await setup();assert.ok(codes(await run(f,{modelApprovalRecord:{...f.modelApprovalRecord,signature:'forged'}})).includes('MODEL_APPROVAL_REJECTED'));
 assert.ok(codes(await run(f,{verifyModelApproval:()=>{throw Error('offline');}})).includes('MODEL_APPROVAL_REJECTED'));
});
test('revoked model record rejected by external verifier',async()=>{const f=await setup();assert.ok(codes(await run(f,{verifyModelApproval:()=>false})).includes('MODEL_APPROVAL_REJECTED'));});
test('cross-tenant, product and variant substitution rejects model identity',async()=>{
 const f=await setup();for(const o of [{shop:'other.myshopify.com'},{productGid:'gid://shopify/Product/999'},{variantGid:'gid://shopify/ProductVariant/999'}])denied(await run(f,o));
});
test('calibration profile cannot silently switch tenant, product, variant, blank or manifest',async()=>{
 const f=await setup();for(const change of [{shop:'other.myshopify.com'},{productGid:'gid://shopify/Product/999'},{variantGid:'gid://shopify/ProductVariant/999'},{blankSku:'OTHER'},{manifestId:'OTHER'}]){
  const r=await run(f,{geometryProfile:{...f.geometryProfile,...change}});denied(r);assert.ok(codes(r).includes('GEOMETRY_IDENTITY'));
 }
});
test('GLB digest must bind exact inspected bytes',async()=>{
 const f=await setup();const r=await run(f,{geometryProfile:{...f.geometryProfile,modelSha256:'f'.repeat(64)}});denied(r);assert.ok(codes(r).includes('GEOMETRY_IDENTITY'));
});
test('missing, corrupted or surface-swapped GLB cannot pass',async()=>{
 const f=await setup();for(const bytes of [undefined,glb({corrupt:true}),glb({surface:'back'})])denied(await run(f,{glbBytes:bytes}));
});
test('scaled GLB requires independently matching physical bounds',async()=>{
 const f=await setup();const r=await run(f,{glbBytes:glb({scale:1.5})});denied(r);
 const changed=await setup({bytes:glb({scale:1.5})});const mismatch=await run(changed);denied(mismatch);assert.ok(codes(mismatch).includes('MODEL_SCALE_MISMATCH'));
});
test('physical measurement mismatch and unit factor substitution rejected',async()=>{
 const f=await setup();for(const change of [{physicalBoundsMm:[405,400,0]},{mmPerModelUnit:1000}]){
  const r=await run(f,{geometryProfile:{...f.geometryProfile,...change}});denied(r);assert.ok(codes(r).includes('MODEL_SCALE_MISMATCH'));
 }
});
test('model geometry bounds reject print zones larger than physical model',async()=>{
 const f=await setup();const r=await run(f,{geometryProfile:{...f.geometryProfile,mmPerModelUnit:200,physicalBoundsMm:[200,200,0]}});denied(r);assert.ok(codes(r).includes('MODEL_ZONE_FIT'));
});
test('model calibration changes invalidate the prior model review even if plausible',async()=>{
 const f=await setup();const r=await run(f,{geometryProfile:{...f.geometryProfile,toleranceMm:.6}});denied(r);assert.ok(codes(r).includes('MODEL_APPROVAL_BINDING'));
});
test('model review cannot be replayed across different blank or reviewer scope',async()=>{
 const f=await setup();for(const change of [{blankSku:'OTHER'},{variantGid:'gid://shopify/ProductVariant/789'},{geometryProfileSha256:'0'.repeat(64)}]){
  const r=await run(f,{modelApprovalRecord:{...f.modelApprovalRecord,...change}});denied(r);assert.ok(codes(r).includes('MODEL_APPROVAL_BINDING'));
 }
});
test('model review must be current and limited to thirty days',async()=>{
 const f=await setup();for(const change of [{issuedAtMs:now+1},{expiresAtMs:now},{expiresAtMs:now+31*86400000}]){
  const r=await run(f,{modelApprovalRecord:{...f.modelApprovalRecord,...change}});denied(r);assert.ok(codes(r).includes('MODEL_APPROVAL_EXPIRY'));
 }
});
test('unexpected model profile or approval fields reject',async()=>{
 const f=await setup();assert.ok(codes(await run(f,{geometryProfile:{...f.geometryProfile,manufacturingApproved:true}})).includes('GEOMETRY_PROFILE_SCHEMA'));
 assert.ok(codes(await run(f,{modelApprovalRecord:{...f.modelApprovalRecord,checkoutEnabled:true}})).includes('MODEL_APPROVAL_SCHEMA'));
});
test('future measurements, absent source and self-approved status reject',async()=>{
 const f=await setup();for(const change of [{measuredAt:'2026-10-16'},{evidenceReference:''},{status:'APPROVED'}]){
  const r=await run(f,{geometryProfile:{...f.geometryProfile,...change}});denied(r);assert.ok(codes(r).includes('GEOMETRY_PROVENANCE'));
 }
});
test('invalid scales, impossible dimensions, tolerances and nonfinite values reject',async()=>{
 const f=await setup();for(const change of [{mmPerModelUnit:0},{mmPerModelUnit:Infinity},{physicalBoundsMm:[NaN,400,0]},{physicalBoundsMm:[400,400,6000]},{toleranceMm:10},{toleranceMm:-1}]){
  const r=await run(f,{geometryProfile:{...f.geometryProfile,...change}});denied(r);assert.ok(codes(r).includes('GEOMETRY_UNITS'));
 }
});
test('UV full-square pair of triangles covers rotated artwork conservatively',async()=>{
 const f=await setup({layers:[{...layer,rotationDeg:30}]});const r=await run(f);assert.equal(r.geometryEvidenceReady,true);
});
test('UV half-triangle cannot cover artwork in missing half',async()=>{
 const f=await setup({bytes:glb({triangles:1}),layers:[{...layer,x:.68,y:.68,width:.15,height:.15}]});const r=await run(f);denied(r);assert.ok(codes(r).includes('UV_ARTWORK_GAP'));
});
test('UV coverage is polygonal rather than just testing four corners',()=>{
 const b={left:0,top:0,right:1,bottom:1};const triangles=[[[0,0],[1,0],[0,1]],[[1,0],[1,1],[0,1]]];
 assert.equal(uvRectangleCovered(b,triangles),true);
 assert.equal(uvRectangleCovered(b,triangles.slice(0,1)),false);
});
test('narrow UV seam not masked by sparse sampling',()=>{
 const b={left:0,top:0,right:1,bottom:1};
 const tris=[[[0,0],[.499,0],[.499,1]],[[0,0],[.499,1],[0,1]],[[.501,0],[1,0],[1,1]],[[.501,0],[1,1],[.501,1]]];
 assert.equal(uvRectangleCovered(b,tris),false);
});
test('degenerate and nonfinite UV triangles cannot count as coverage',()=>{
 const b={left:0,top:0,right:1,bottom:1};
 assert.equal(uvRectangleCovered(b,[[[0,0],[0,0],[0,0]]]),false);
 assert.equal(uvRectangleCovered(b,[[[0,0],[Infinity,0],[0,1]]]),false);
});
test('UV triangle count and malformed bounds are bounded fail-closed',()=>{
 const tri=[[0,0],[1,0],[0,1]];assert.equal(uvRectangleCovered({left:0,top:0,right:1,bottom:1},Array(4097).fill(tri)),false);
 assert.equal(uvRectangleCovered({left:0,top:0,right:0,bottom:1},[tri]),false);
});
test('degenerate printable model triangles reject even when UVs are valid',async()=>{
 const f=await setup({bytes:glb({degenerate:true})});const r=await run(f);denied(r);assert.ok(codes(r).some(x=>['MODEL_TRIANGLE_DEGENERATE','MODEL_SCALE_MISMATCH'].includes(x)));
});
test('base manufacturing approval remains independent and required',async()=>{
 const f=await setup();const r=await run(f,{verifyApproval:()=>false});denied(r);assert.ok(codes(r).includes('REVIEW_NOT_VERIFIED'));
});
test('artwork layers without independent artwork evidence still reject',async()=>{
 const f=await setup({layers:[{...layer,type:'artwork',artworkId:'client-artwork',sourceWidthPx:8000}]});const r=await run(f);denied(r);assert.ok(codes(r).includes('ARTWORK_EVIDENCE_REQUIRED'));
});

test('cylindrical wrap rejects a planar GLB masquerading as a physical cylinder',async()=>{
 const selectedManifest=PRODUCT_MANIFESTS.find(p=>p.id==='concept-tumbler');
 const f=await setup({selectedManifest,bytes:glb({surface:'wrap'}),layers:[{...layer,surfaceId:'wrap'}],zones:[{surfaceId:'wrap',widthMm:240,heightMm:300,blankWidthMm:300,blankHeightMm:400,processCode:'UV-ROTARY',fixtureReference:'Synthetic rotary',safetyInsetMm:5,curveCircumferenceMm:300}]});
 const r=await run(f);denied(r);assert.ok(codes(r).includes('MODEL_ZONE_FIT'));
});
test('flat merchandise accepts synthetic UV evidence with a declared physical flat route, not production',async()=>{
 const selectedManifest=structuredClone(PRODUCT_MANIFESTS.find(p=>p.id==='concept-rug'));
 selectedManifest.surfaces[0].allowableMethods=['UV-FLAT'];selectedManifest.manufacturing.candidateMethods=['UV-FLAT'];
 const f=await setup({selectedManifest,bytes:glb({surface:'top'}),layers:[{...layer,surfaceId:'top'}],zones:[{surfaceId:'top',widthMm:240,heightMm:300,blankWidthMm:300,blankHeightMm:400,processCode:'UV-FLAT',fixtureReference:'Synthetic flat fixture',safetyInsetMm:5}]});
 const r=await run(f);assert.equal(r.geometryEvidenceReady,true);assert.equal(r.productionApproved,false);
});
test('accessories use the same explicit surface and manufacturing-method contracts',async()=>{
 const selectedManifest=structuredClone(PRODUCT_MANIFESTS.find(p=>p.id==='concept-backpack'));
 selectedManifest.surfaces[0].allowableMethods=['UV-FLAT'];selectedManifest.manufacturing.candidateMethods=['UV-FLAT'];
 const f=await setup({selectedManifest,bytes:glb({surface:'front-panel'}),layers:[{...layer,surfaceId:'front-panel'}],zones:[{surfaceId:'front-panel',widthMm:240,heightMm:300,blankWidthMm:300,blankHeightMm:400,processCode:'UV-FLAT',fixtureReference:'Synthetic accessory fixture',safetyInsetMm:5}]});
 const r=await run(f);assert.equal(r.geometryEvidenceReady,true);assert.equal(r.machineOutput,null);
});
test('method substitution is rejected by the base route gate before model approval',async()=>{
 const f=await setup();const w=structuredClone(f.worksheet);w.zones[0].processCode='UV-ROTARY';
 const r=await run(f,{worksheet:w});denied(r);assert.ok(codes(r).some(x=>['MANUFACTURING_ROUTE','ZONE_ROUTE'].includes(x)));
});
