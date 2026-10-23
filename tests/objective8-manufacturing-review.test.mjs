import test from 'node:test';
import assert from 'node:assert/strict';
import {createHmac,randomBytes} from 'node:crypto';
import {PRODUCT_MANIFESTS} from '../src/catalog.mjs';
import {createCalibrationWorksheet} from '../src/calibration.mjs';
import {inspectGlb} from '../src/model-assets.mjs';
import {reviewManufacturingProfile} from '../src/manufacturing-review.mjs';

const shop='gucgmp-bc.myshopify.com',productGid='gid://shopify/Product/123',variantGid='gid://shopify/ProductVariant/456';
const now=Date.parse('2026-10-14T22:00:00Z');
const secret=randomBytes(32),revoked=new Set();
const sign=record=>createHmac('sha256',secret).update(JSON.stringify(Object.fromEntries(Object.entries(record).filter(([k])=>k!=='signature')))).digest('hex');
// The test verifier below proves the injected interface wiring only; it is NOT a hosted signer or production PKI.
const verifier=async(record)=>!revoked.has(record.reviewId)&&sign(record)===record.signature;
const layer={id:'l1',type:'text',surfaceId:'front',x:.2,y:.2,width:.4,height:.3,rotationDeg:0,value:'Test'};
function glb({surface='front',uv=[0,0,1,0,0,1],corrupt=false}={}){
 const bin=Buffer.alloc(68),v=new DataView(bin.buffer,bin.byteOffset,bin.byteLength);
 [-.5,0,0,.5,0,0,0,1,0].forEach((x,i)=>v.setFloat32(i*4,x,true));
 uv.forEach((x,i)=>v.setFloat32(36+i*4,x,true));[0,1,2].forEach((x,i)=>v.setUint16(60+i*2,x,true));
 const doc={asset:{version:'2.0'},buffers:[{byteLength:68}],bufferViews:[{buffer:0,byteOffset:0,byteLength:36},{buffer:0,byteOffset:36,byteLength:24},{buffer:0,byteOffset:60,byteLength:6}],accessors:[{bufferView:0,componentType:5126,count:3,type:'VEC3'},{bufferView:1,componentType:5126,count:3,type:'VEC2'},{bufferView:2,componentType:5123,count:3,type:'SCALAR'}],meshes:[{primitives:[{attributes:{POSITION:0,TEXCOORD_0:1},indices:2}]}],nodes:[{mesh:0,extras:{tjSurfaceId:surface}}],scenes:[{nodes:[0]}],scene:0};
 let js=Buffer.from(JSON.stringify(doc));js=Buffer.concat([js,Buffer.alloc((4-js.length%4)%4,32)]);
 const b=Buffer.alloc(12+8+js.length+8+bin.length);b.writeUInt32LE(0x46546c67,0);b.writeUInt32LE(2,4);b.writeUInt32LE(b.length,8);b.writeUInt32LE(js.length,12);b.writeUInt32LE(0x4e4f534a,16);js.copy(b,20);const off=20+js.length;b.writeUInt32LE(bin.length,off);b.writeUInt32LE(0x004e4942,off+4);bin.copy(b,off+8);if(corrupt)b[0]=0;return b;
}
const meta={blankSku:'BENCH-TEST-ONLY',measuredBy:'QA mock',sourceDocument:'Synthetic fixture - no real measurements',measuredAt:'2026-10-14'};
const zone={surfaceId:'front',widthMm:240,heightMm:300,blankWidthMm:300,blankHeightMm:400,processCode:'DTF-TEXTILE',fixtureReference:'Synthetic jig',safetyInsetMm:5};
async function setup({manifest=PRODUCT_MANIFESTS[0],model=glb(),zones=[zone],layers=[layer],metadata=meta}={}){
 const inspection=model?await inspectGlb(model,manifest):null;
 const worksheet=createCalibrationWorksheet(manifest,zones,{...metadata,modelSha256:inspection?.sha256});
 const input={shop,productGid,variantGid,manifest,worksheet,design:{layers},...(model?{glbBytes:model}:{}) ,now};
 const preliminary=await reviewManufacturingProfile(input);
 const record={schema:'TJ-MANUFACTURING-REVIEW-1',reviewId:'mock-review-001',revision:1,issuedAtMs:now-1000,expiresAtMs:now+3600000,reviewerId:'test-only-reviewer',shop,productGid,variantGid,manifestId:manifest.id,blankSku:worksheet.blankSku,modelSha256:inspection?.sha256??null,profileSha256:preliminary.profileSha256,signature:''};
 record.signature=sign(record);
 return {input,record,inspection};
}
const codes=r=>r.issues.map(i=>i.code);
const run=({input,record},overrides={},recordOverrides={})=>reviewManufacturingProfile({...input,approvalRecord:{...record,...recordOverrides},verifyApproval:verifier,...overrides});

test('reviewed GLB+measured zone+external verifier passes evidence but NEVER enables production or checkout',async()=>{
 const f=await setup();const r=await run(f);
 assert.equal(r.reviewReady,true);assert.equal(r.evidenceVerified,true);assert.equal(r.productionApproved,false);assert.equal(r.checkoutEnabled,false);assert.equal(r.machineOutput,null);
 assert.match(r.profileSha256,/^[a-f0-9]{64}$/);assert.equal(r.modelSha256,f.inspection.sha256);assert.equal(r.placements[0].ok,true);
});
test('missing independent verifier refuses valid-looking signed review',async()=>{
 const f=await setup(),r=await run(f,{verifyApproval:undefined});assert.equal(r.reviewReady,false);assert.ok(codes(r).includes('TRUSTED_REVIEW_VERIFIER_REQUIRED'));
});
test('self-asserted approval flag on draft worksheet fails closed',async()=>{
 const f=await setup(),r=await run(f,{worksheet:{...f.input.worksheet,manufacturingApproved:true}});
 assert.equal(r.reviewReady,false);assert.ok(codes(r).includes('WORKSHEET_DRAFT_ONLY'));
});
test('forged verified flag and extra signature metadata cannot bypass exact schema',async()=>{
 const f=await setup();const r=await run(f,{}, {verified:true});assert.equal(r.reviewReady,false);assert.ok(codes(r).includes('APPROVAL_SCHEMA'));
});
test('cross-tenant, product and variant substitution fail record binding',async()=>{
 const f=await setup();for(const override of [{shop:'other.myshopify.com'},{productGid:'gid://shopify/Product/999'},{variantGid:'gid://shopify/ProductVariant/999'}]){
  const r=await run(f,override);assert.equal(r.reviewReady,false);assert.ok(codes(r).includes('PROFILE_BINDING'));
 }
});
test('blank substitution and manifest model digest substitution fail closed',async()=>{
 const f=await setup();
 const w=structuredClone(f.input.worksheet);w.blankSku='SWAPPED-BLANK';
 assert.ok(codes(await run(f,{worksheet:w})).includes('PROFILE_BINDING'));
 const m=structuredClone(f.input.manifest);m.geometry.modelAsset={sha256:'f'.repeat(64)};
 assert.ok(codes(await run(f,{manifest:m})).includes('MODEL_MANIFEST_BINDING'));
});
test('plausible measurement tampering is detected by immutable profile hash',async()=>{
 const f=await setup();const w=structuredClone(f.input.worksheet);w.zones[0].printableWidthMm=235;
 const r=await run(f,{worksheet:w});assert.equal(r.reviewReady,false);assert.ok(codes(r).includes('PROFILE_BINDING'));
});
test('unsupported process and missing fixture evidence reject even with old signature',async()=>{
 const f=await setup();const w=structuredClone(f.input.worksheet);w.zones[0].processCode='UV-ROTARY';
 assert.ok(codes(await run(f,{worksheet:w})).includes('ZONE_ROUTE'));
 const x=structuredClone(f.input.worksheet);x.zones[0].fixtureReference='';
 assert.ok(codes(await run(f,{worksheet:x})).includes('FIXTURE_EVIDENCE'));
});
test('expired, future-issued, and overly long review windows reject',async()=>{
 const f=await setup();for(const change of [{expiresAtMs:now},{issuedAtMs:now+1},{expiresAtMs:now+91*86400000}]){
  const record={...f.record,...change};record.signature=sign(record);
  const r=await run(f,{},record);assert.equal(r.reviewReady,false);assert.ok(codes(r).includes('REVIEW_EXPIRY'));
 }
});
test('missing GLB bytes reject a garment even with valid old record',async()=>{
 const f=await setup();const r=await run(f,{glbBytes:undefined});assert.equal(r.reviewReady,false);assert.ok(codes(r).includes('GLB_REQUIRED'));
});
test('corrupt GLB bytes reject, no model promotion',async()=>{
 const f=await setup();const r=await run(f,{glbBytes:glb({corrupt:true})});assert.equal(r.reviewReady,false);assert.ok(codes(r).includes('GLB_REJECTED'));
});
test('GLB must map exact printed surface, not just some valid surface',async()=>{
 const f=await setup({model:glb({surface:'back'})});const r=await run(f);
 assert.equal(r.reviewReady,false);assert.ok(codes(r).includes('MODEL_SURFACE_UNMAPPED'));
});
test('zero-area printable UV triangles fail despite a parseable GLB',async()=>{
 const f=await setup({model:glb({uv:[0,0,0,0,0,0]})});const r=await run(f);
 assert.equal(r.reviewReady,false);assert.ok(codes(r).includes('MODEL_UV_DEGENERATE'));
});
test('unsafe rotated placement is rejected despite signed unchanged profile',async()=>{
 const f=await setup();const design={layers:[{...layer,x:.84,width:.25,rotationDeg:35}]};
 const r=await run(f,{design});assert.equal(r.reviewReady,false);assert.ok(codes(r).some(x=>['OUTSIDE_SAFE_ZONE','OUTSIDE_PRINT_ZONE'].includes(x)));
});
test('cylinder wrap requires real measured circumference even when worksheet omitted it',async()=>{
 const tumbler=PRODUCT_MANIFESTS.find(p=>p.id==='concept-tumbler');
 const tZone={surfaceId:'wrap',widthMm:100,heightMm:90,blankWidthMm:150,blankHeightMm:150,processCode:'UV-ROTARY',fixtureReference:'Synthetic rotary',safetyInsetMm:3};
 const f=await setup({manifest:tumbler,model:glb({surface:'wrap'}),zones:[tZone],layers:[{...layer,surfaceId:'wrap'}]});
 const r=await run(f);assert.equal(r.reviewReady,false);assert.ok(codes(r).includes('WRAP_MEASUREMENT_MISSING'));
});
test('measurement provenance, unexpected worksheet fields and unknown review keys fail closed',async()=>{
 const f=await setup();const w=structuredClone(f.input.worksheet);w.sourceDocument='';
 assert.ok(codes(await run(f,{worksheet:w})).includes('MEASUREMENT_PROVENANCE'));
 assert.ok(codes(await run(f,{worksheet:{...f.input.worksheet,unreviewed:true}})).includes('WORKSHEET_SCHEMA'));
 assert.ok(codes(await run(f,{}, {extra:'foo'})).includes('APPROVAL_SCHEMA'));
});
test('artwork cannot use client-supplied pixel dimensions as production evidence',async()=>{
 const f=await setup({layers:[{...layer,type:'artwork',artworkId:'local-only',sourceWidthPx:5000,sourceHeightPx:5000}]});
 const r=await run(f);assert.equal(r.reviewReady,false);assert.ok(codes(r).includes('ARTWORK_EVIDENCE_REQUIRED'));
});
test('flat 2D measured profile can be reviewed without GLB, still cannot manufacture',async()=>{
 const manifest=PRODUCT_MANIFESTS.find(p=>p.id==='concept-rug');
 const m=structuredClone(manifest);m.surfaces[0].allowableMethods=['UV-FLAT'];m.manufacturing.candidateMethods=['UV-FLAT'];
 const z={surfaceId:'top',widthMm:100,heightMm:150,blankWidthMm:150,blankHeightMm:200,processCode:'UV-FLAT',fixtureReference:'Synthetic flat jig',safetyInsetMm:2};
 const f=await setup({manifest:m,model:null,zones:[z],layers:[{...layer,surfaceId:'top'}]});const r=await run(f);
 assert.equal(r.reviewReady,true);assert.equal(r.modelSha256,null);assert.equal(r.productionApproved,false);
});
test('review signature mismatch, revocation and verifier exceptions all reject',async()=>{
 const f=await setup();
 assert.ok(codes(await run(f,{}, {signature:'forged'})).includes('REVIEW_NOT_VERIFIED'));
 revoked.add(f.record.reviewId);try{assert.ok(codes(await run(f)).includes('REVIEW_NOT_VERIFIED'));}finally{revoked.clear();}
 assert.ok(codes(await run(f,{verifyApproval:()=>{throw Error('service offline');}})).includes('REVIEW_NOT_VERIFIED'));
});
test('hostile missing objects and malformed zone arrays reject without enabling manufacturing',async()=>{
 const f=await setup();for(const overrides of [{manifest:null},{worksheet:null},{design:null},{worksheet:{...f.input.worksheet,zones:{}}},{worksheet:{...f.input.worksheet,zones:[null]}}]){
  const r=await run(f,overrides);assert.equal(r.reviewReady,false);assert.equal(r.productionApproved,false);assert.equal(r.checkoutEnabled,false);
 }
});

test('measured zones missing from GLB UV mappings cannot enter reviewed profile',async()=>{
 const f=await setup();const w=structuredClone(f.input.worksheet);w.zones.push({...w.zones[0],surfaceId:'back'});
 const r=await run(f,{worksheet:w});assert.equal(r.reviewReady,false);assert.ok(codes(r).includes('MODEL_ZONE_UNMAPPED'));
});
test('future-dated measurement source cannot be reviewed',async()=>{
 const f=await setup();const w=structuredClone(f.input.worksheet);w.measuredAt='2026-10-16';
 const r=await run(f,{worksheet:w});assert.equal(r.reviewReady,false);assert.ok(codes(r).includes('MEASUREMENT_PROVENANCE'));
});
test('bleed plus safety inset must fit inside measured geometry',async()=>{
 const f=await setup();const w=structuredClone(f.input.worksheet);w.zones[0].bleedMm=30;
 const r=await run(f,{worksheet:w,design:{layers:[{...layer,x:.13,y:.15}]}});
 assert.equal(r.reviewReady,false);assert.ok(codes(r).includes('BLEED_SAFE_ZONE'));
});
