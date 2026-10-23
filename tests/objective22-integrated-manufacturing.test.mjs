import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,createHmac,randomBytes} from 'node:crypto';
import {deflateSync} from 'node:zlib';
import {PRODUCT_MANIFESTS} from '../src/catalog.mjs';
import {createCalibrationWorksheet} from '../src/calibration.mjs';
import {inspectGlb} from '../src/model-assets.mjs';
import {computeArtworkDesignSha256,reviewManufacturingArtworkEvidence} from '../src/manufacturing-artwork-evidence.mjs';
import {reviewManufacturingProfile} from '../src/manufacturing-review.mjs';
import {reviewManufacturingGeometryProfile} from '../src/manufacturing-geometry-profile.mjs';
import {reviewIntegratedManufacturingEvidence} from '../src/manufacturing-integrated-review.mjs';

const shop='gucgmp-bc.myshopify.com',productGid='gid://shopify/Product/123',variantGid='gid://shopify/ProductVariant/456';
const ownerId='owner-1',designId='design-1',revision=7,now=Date.parse('2026-10-15T18:00:00Z');
const keys=Array.from({length:4},()=>randomBytes(32));
const hash=x=>createHash('sha256').update(typeof x==='string'||Buffer.isBuffer(x)?x:JSON.stringify(x)).digest('hex');
const sorted=x=>Array.isArray(x)?x.map(sorted):x&&typeof x==='object'&&!Buffer.isBuffer(x)?Object.fromEntries(Object.entries(x).sort(([a],[b])=>a.localeCompare(b)).map(([k,v])=>[k,sorted(v)])):x;
const sign=(r,k)=>createHmac('sha256',k).update(JSON.stringify(sorted(Object.fromEntries(Object.entries(r).filter(([field])=>field!=='signature'))))).digest('hex');
const verify=k=>async r=>r.signature===sign(r,k);
const codes=r=>r.issues.map(i=>i.code);
const denied=r=>{assert.equal(r.integratedEvidenceReady,false);assert.equal(r.productionApproved,false);assert.equal(r.checkoutEnabled,false);assert.equal(r.machineOutput,null);};
const layer={id:'art-layer',type:'artwork',artworkId:'asset-1',surfaceId:'front',x:.2,y:.2,width:.3,height:.3,rotationDeg:0,sourceWidthPx:9000,sourceHeightPx:9000};
function glb(){
 const points=[0,0,0,1,0,0,1,1,0,0,1,0],tex=[0,0,1,0,1,1,0,1],idx=[0,1,2,0,2,3];
 const bin=Buffer.alloc(92);const v=new DataView(bin.buffer,bin.byteOffset,bin.byteLength);
 points.forEach((x,i)=>v.setFloat32(i*4,x,true));tex.forEach((x,i)=>v.setFloat32(48+i*4,x,true));idx.forEach((x,i)=>v.setUint16(80+i*2,x,true));
 const doc={asset:{version:'2.0'},buffers:[{byteLength:bin.length}],bufferViews:[{buffer:0,byteOffset:0,byteLength:48},{buffer:0,byteOffset:48,byteLength:32},{buffer:0,byteOffset:80,byteLength:12}],accessors:[{bufferView:0,componentType:5126,count:4,type:'VEC3'},{bufferView:1,componentType:5126,count:4,type:'VEC2'},{bufferView:2,componentType:5123,count:6,type:'SCALAR'}],meshes:[{primitives:[{attributes:{POSITION:0,TEXCOORD_0:1},indices:2}]}],nodes:[{mesh:0,extras:{tjSurfaceId:'front'}}],scenes:[{nodes:[0]}],scene:0};
 let json=Buffer.from(JSON.stringify(doc));json=Buffer.concat([json,Buffer.alloc((4-json.length%4)%4,32)]);
 const bytes=Buffer.alloc(12+8+json.length+8+bin.length);bytes.writeUInt32LE(0x46546c67,0);bytes.writeUInt32LE(2,4);bytes.writeUInt32LE(bytes.length,8);bytes.writeUInt32LE(json.length,12);bytes.writeUInt32LE(0x4e4f534a,16);json.copy(bytes,20);const off=20+json.length;bytes.writeUInt32LE(bin.length,off);bytes.writeUInt32LE(0x004e4942,off+4);bin.copy(bytes,off+8);return bytes;
}
function crc32(bytes){let c=0xffffffff;for(const b of bytes){c^=b;for(let i=0;i<8;i++)c=(c>>>1)^(0xedb88320&-(c&1));}return (c^0xffffffff)>>>0;}
function chunk(type,data){const buf=Buffer.alloc(12+data.length);buf.writeUInt32BE(data.length,0);buf.write(type,4);data.copy(buf,8);buf.writeUInt32BE(crc32(buf.subarray(4,8+data.length)),8+data.length);return buf;}
function png(w=600,h=750){const ihdr=Buffer.alloc(13);ihdr.writeUInt32BE(w,0);ihdr.writeUInt32BE(h,4);ihdr[8]=8;ihdr[9]=6;const raw=Buffer.alloc(h*(w*4+1));return Buffer.concat([Buffer.from([137,80,78,71,13,10,26,10]),chunk('IHDR',ihdr),chunk('IDAT',deflateSync(raw)),chunk('IEND',Buffer.alloc(0))]);}
async function fixture({artworkLayer=layer,artworkBytes=png()}={}){
 const manifest=structuredClone(PRODUCT_MANIFESTS[0]),glbBytes=glb(),inspected=await inspectGlb(glbBytes,manifest);
 const worksheet=createCalibrationWorksheet(manifest,[{surfaceId:'front',widthMm:240,heightMm:300,blankWidthMm:300,blankHeightMm:400,processCode:'DTF-TEXTILE',fixtureReference:'Synthetic fixture',safetyInsetMm:5,bleedMm:3}],{blankSku:'TEST-BLANK',measuredBy:'Synthetic technician',sourceDocument:'Synthetic measurement',measuredAt:'2026-10-14',modelSha256:inspected.sha256});
 const design={layers:[artworkLayer]},designSha256=computeArtworkDesignSha256(design);
 const current={schema:'TJ-CURRENT-IMMUTABLE-DESIGN-1',shop,productGid,variantGid,manifestId:manifest.id,ownerId,designId,revision,designSha256,status:'CURRENT_IMMUTABLE',design};
 const storageRecord={schema:'TJ-PRIVATE-ARTWORK-ATTESTATION-1',shop,productGid,variantGid,ownerId,designId,revision,designSha256,manifestId:manifest.id,blankSku:worksheet.blankSku,surfaceId:'front',processCode:'DTF-TEXTILE',layerId:artworkLayer.id,artworkId:artworkLayer.artworkId,storageKey:'OpaquePrivateKey012345',sha256:hash(artworkBytes),mediaType:'image/png',byteLength:artworkBytes.length,issuedAtMs:now-1000,expiresAtMs:now+60000,signature:''};storageRecord.signature=sign(storageRecord,keys[2]);
 const policy={schema:'TJ-ARTWORK-PROCESS-POLICY-1',shop,productGid,variantGid,blankSku:worksheet.blankSku,surfaceId:'front',processCode:'DTF-TEXTILE',minDpi:200,minBleedMm:2,maxBleedMm:5,maxBytes:8*1024*1024,allowedMediaTypes:['image/png'],issuedAtMs:now-1000,expiresAtMs:now+60000,policyId:'synthetic-policy',signature:''};policy.signature=sign(policy,keys[3]);
 const args={shop,productGid,variantGid,ownerId,designId,revision,manifest,worksheet,glbBytes,now,
  loadCurrentRevision:async()=>structuredClone(current),verifyApproval:verify(keys[0]),verifyModelApproval:verify(keys[1]),
  storageRecords:[storageRecord],processPolicies:[policy],readPrivateArtwork:async()=>artworkBytes,
  verifyStorageAttestation:verify(keys[2]),verifyProcessPolicy:verify(keys[3]),verifyIntegratedApproval:verify(keys[0])};
 const artworkEvidenceInput={ownerId,designId,revision,storageRecords:args.storageRecords,processPolicies:args.processPolicies,
  readPrivateArtwork:args.readPrivateArtwork,verifyStorageAttestation:args.verifyStorageAttestation,verifyProcessPolicy:args.verifyProcessPolicy};
 const initial=await reviewManufacturingProfile({...args,design,artworkEvidenceInput});
 assert.match(initial.profileSha256,/^[a-f0-9]{64}$/);
 const approvalRecord={schema:'TJ-MANUFACTURING-REVIEW-1',reviewId:'base',revision:1,issuedAtMs:now-1000,expiresAtMs:now+60000,reviewerId:'base-reviewer',shop,productGid,variantGid,manifestId:manifest.id,blankSku:worksheet.blankSku,modelSha256:inspected.sha256,profileSha256:initial.profileSha256,signature:''};approvalRecord.signature=sign(approvalRecord,keys[0]);
 const geometryProfile={schema:'TJ-GLB-GEOMETRY-CALIBRATION-1',shop,productGid,variantGid,manifestId:manifest.id,blankSku:worksheet.blankSku,modelSha256:inspected.sha256,mmPerModelUnit:400,physicalBoundsMm:[400,400,0],toleranceMm:.5,measuredBy:'Synthetic operator',measuredAt:'2026-10-14',evidenceReference:'synthetic GLB bounds',status:'DRAFT_REQUIRES_INDEPENDENT_APPROVAL'};
 const before=await reviewManufacturingGeometryProfile({...args,design,approvalRecord,geometryProfile,artworkEvidenceInput});
 assert.match(before.geometryProfileSha256,/^[a-f0-9]{64}$/);
 const modelApprovalRecord={schema:'TJ-GLB-GEOMETRY-REVIEW-1',reviewId:'model',revision:1,issuedAtMs:now-1000,expiresAtMs:now+60000,reviewerId:'model-reviewer',shop,productGid,variantGid,manifestId:manifest.id,blankSku:worksheet.blankSku,modelSha256:inspected.sha256,geometryProfileSha256:before.geometryProfileSha256,signature:''};modelApprovalRecord.signature=sign(modelApprovalRecord,keys[1]);
 Object.assign(args,{approvalRecord,geometryProfile,modelApprovalRecord});
 const geometry=await reviewManufacturingGeometryProfile({...args,design,artworkEvidenceInput});assert.equal(geometry.geometryEvidenceReady,true);
 const artwork=await reviewManufacturingArtworkEvidence({...args,design});assert.equal(artwork.artworkEvidenceReady,true);
 const subject={schema:'TJ-INTEGRATED-MANUFACTURING-SUBJECT-1',shop,productGid,variantGid,ownerId,designId,revision,designSha256,manifestId:manifest.id,blankSku:worksheet.blankSku,manufacturingProfileSha256:geometry.profileSha256,geometryProfileSha256:geometry.geometryProfileSha256,modelSha256:geometry.modelSha256,artworks:artwork.artworks.map(a=>Object.fromEntries(Object.entries(a).sort(([a],[b])=>a.localeCompare(b)))).sort((a,b)=>a.layerId.localeCompare(b.layerId)),storageRecordsSha256:hash(sorted(args.storageRecords)),processPoliciesSha256:hash(sorted(args.processPolicies))};
 const integratedApprovalRecord={schema:'TJ-INTEGRATED-MANUFACTURING-REVIEW-1',reviewId:'integrated',revision:1,reviewerId:'synthetic-integrator',issuedAtMs:now-1000,expiresAtMs:now+60000,shop,productGid,variantGid,ownerId,designId,designRevision:revision,subjectSha256:hash(subject),signature:''};integratedApprovalRecord.signature=sign(integratedApprovalRecord,keys[0]);
 return {...args,integratedApprovalRecord,current,design,artworkEvidenceInput};
}
const run=(f,changes={})=>{const {design,artworkEvidenceInput,current,...safe}=f;return reviewIntegratedManufacturingEvidence({...safe,...changes});};
const reSign=(r,k)=>{const v={...r,signature:''};v.signature=sign(v,k);return v;};

test('independent immutable revision, artwork bytes, geometry, and integrated signature yield evidence only',async()=>{const f=await fixture(),r=await run(f);assert.equal(r.integratedEvidenceReady,true);assert.equal(r.artworkCount,1);assert.equal(r.designSha256,f.current.designSha256);assert.match(r.subjectSha256,/^[a-f0-9]{64}$/);assert.equal(r.productionApproved,false);assert.equal(r.checkoutEnabled,false);assert.equal(r.machineOutput,null);});
test('old manufacturing entrypoint retains artwork hold without raw evidence',async()=>{const f=await fixture(),r=await reviewManufacturingProfile({...f,design:f.design,artworkEvidenceInput:undefined});assert.ok(codes(r).includes('ARTWORK_EVIDENCE_REQUIRED'));});
test('old geometry entrypoint retains artwork hold without raw evidence',async()=>{const f=await fixture(),r=await reviewManufacturingGeometryProfile({...f,design:f.design,artworkEvidenceInput:undefined});assert.ok(codes(r).includes('ARTWORK_EVIDENCE_REQUIRED'));});
test('old geometry entrypoint cannot bypass artwork hold using verified boolean',async()=>{const f=await fixture(),r=await reviewManufacturingGeometryProfile({...f,design:f.design,artworkEvidenceInput:undefined,artworkEvidenceReady:true});assert.equal(r.geometryEvidenceReady,false);});
test('base manufacturing rejects forged evidence-ready flags instead of trust callbacks',async()=>{const f=await fixture(),r=await reviewManufacturingProfile({...f,design:f.design,artworkEvidenceInput:{artworkEvidenceReady:true}});assert.ok(codes(r).includes('ARTWORK_EVIDENCE_REQUIRED'));});
test('new integrated review rejects caller-provided design even when it equals stored revision',async()=>{const f=await fixture(),r=await run(f,{design:f.design});denied(r);assert.ok(codes(r).includes('CALLER_EVIDENCE_FORBIDDEN'));});
test('new integrated review rejects caller-provided approval and verified flags',async()=>{const f=await fixture();for(const change of [{verified:true},{geometryEvidenceReady:true},{artworkEvidenceReady:true}]){const r=await run(f,change);denied(r);}});
test('missing trusted revision loader fails before any other trust gate',async()=>{const f=await fixture(),r=await run(f,{loadCurrentRevision:undefined});denied(r);assert.ok(codes(r).includes('INTEGRATED_TRUST'));});
test('missing current revision is rejected',async()=>{const f=await fixture(),r=await run(f,{loadCurrentRevision:async()=>null});denied(r);assert.ok(codes(r).includes('REVISION_NOT_CURRENT'));});
test('stale immutable revision status is rejected',async()=>{const f=await fixture(),r=await run(f,{loadCurrentRevision:async()=>({...f.current,status:'SUPERSEDED'})});denied(r);});
test('server-owned revision substitution of owner, product, variant, shop, design or manifest fails',async()=>{const f=await fixture();for(const change of [{ownerId:'intruder'},{productGid:'gid://shopify/Product/999'},{variantGid:'gid://shopify/ProductVariant/999'},{shop:'other.myshopify.com'},{designId:'other'},{manifestId:'other'}]){const r=await run(f,{loadCurrentRevision:async()=>({...f.current,...change})});denied(r);assert.ok(codes(r).includes('REVISION_NOT_CURRENT'));}});
test('server-owned revision with forged composition digest rejects',async()=>{const f=await fixture(),r=await run(f,{loadCurrentRevision:async()=>({...f.current,designSha256:'a'.repeat(64)})});denied(r);});
test('server-owned composition changed without digest update rejects',async()=>{const f=await fixture(),r=await run(f,{loadCurrentRevision:async()=>({...f.current,design:{layers:[{...layer,x:.3}]}})});denied(r);});
test('server-owned revision with extra self-verified field rejects',async()=>{const f=await fixture(),r=await run(f,{loadCurrentRevision:async()=>({...f.current,verified:true})});denied(r);});
test('registry exception fails closed',async()=>{const f=await fixture(),r=await run(f,{loadCurrentRevision:async()=>{throw Error('offline');}});denied(r);});
test('revision changes between first and final registry read rejects',async()=>{const f=await fixture();let count=0;const r=await run(f,{loadCurrentRevision:async()=>++count===1?f.current:{...f.current,revision:8}});denied(r);assert.ok(codes(r).includes('REVISION_CHANGED_DURING_REVIEW'));});
test('registry outage during final check fails closed',async()=>{const f=await fixture();let count=0;const r=await run(f,{loadCurrentRevision:async()=>{if(++count>1)throw Error('offline');return f.current;}});denied(r);});
test('cross-gate artwork byte substitution rejects despite valid model approval',async()=>{const f=await fixture(),r=await run(f,{readPrivateArtwork:async()=>png(601,750)});denied(r);assert.ok(codes(r).includes('ARTWORK_DIGEST'));});
test('cross-gate storage attestation tampering rejects before geometry approval',async()=>{const f=await fixture(),r=await run(f,{storageRecords:[{...f.storageRecords[0],ownerId:'other'}]});denied(r);});
test('cross-gate process policy tampering rejects without re-signing',async()=>{const f=await fixture(),r=await run(f,{processPolicies:[{...f.processPolicies[0],minDpi:1}]});denied(r);});
test('cross-gate signed stricter policy still invalidates integrated approval',async()=>{const f=await fixture();const p=reSign({...f.processPolicies[0],minDpi:210},keys[3]);const r=await run(f,{processPolicies:[p]});denied(r);assert.ok(codes(r).includes('INTEGRATED_APPROVAL_BINDING'));});
test('cross-gate newly signed storage attestation still invalidates integrated approval',async()=>{const f=await fixture();const s=reSign({...f.storageRecords[0],storageKey:'AnotherOpaquePrivateKey12'},keys[2]);const r=await run(f,{storageRecords:[s]});denied(r);assert.ok(codes(r).includes('INTEGRATED_APPROVAL_BINDING'));});
test('cross-gate GLB substitution rejects before integrated approval',async()=>{const f=await fixture(),bytes=Buffer.from(f.glbBytes);bytes[0]^=1;const r=await run(f,{glbBytes:bytes});denied(r);});
test('cross-gate geometry measurement tampering rejects',async()=>{const f=await fixture(),r=await run(f,{geometryProfile:{...f.geometryProfile,toleranceMm:.6}});denied(r);});
test('cross-gate base reviewer signature failure rejects',async()=>{const f=await fixture(),r=await run(f,{approvalRecord:{...f.approvalRecord,signature:'forged'}});denied(r);});
test('cross-gate model reviewer revocation rejects',async()=>{const f=await fixture(),r=await run(f,{verifyModelApproval:async()=>false});denied(r);});
test('integrated reviewer signature failure rejects',async()=>{const f=await fixture(),r=await run(f,{integratedApprovalRecord:{...f.integratedApprovalRecord,signature:'forged'}});denied(r);assert.ok(codes(r).includes('INTEGRATED_APPROVAL_REJECTED'));});
test('integrated reviewer revocation rejects',async()=>{const f=await fixture(),r=await run(f,{verifyIntegratedApproval:async()=>false});denied(r);});
test('integrated reviewer outage rejects',async()=>{const f=await fixture(),r=await run(f,{verifyIntegratedApproval:async()=>{throw Error('offline');}});denied(r);});
test('integrated reviewer missing rejects',async()=>{const f=await fixture(),r=await run(f,{verifyIntegratedApproval:undefined});denied(r);});
test('integrated approval cannot be reused on another owner, design or revision',async()=>{const f=await fixture();for(const change of [{ownerId:'other'},{designId:'other'},{designRevision:8}]){const r=await run(f,{integratedApprovalRecord:{...f.integratedApprovalRecord,...change}});denied(r);assert.ok(codes(r).includes('INTEGRATED_APPROVAL_BINDING'));}});
test('integrated approval cannot be reused on another product, variant or tenant',async()=>{const f=await fixture();for(const change of [{productGid:'gid://shopify/Product/999'},{variantGid:'gid://shopify/ProductVariant/999'},{shop:'other.myshopify.com'}]){const r=await run(f,{integratedApprovalRecord:{...f.integratedApprovalRecord,...change}});denied(r);}});
test('integrated approval expiry, future issue and overlong validity reject',async()=>{const f=await fixture();for(const change of [{expiresAtMs:now},{issuedAtMs:now+1},{expiresAtMs:now+8*86400000}]){const r=await run(f,{integratedApprovalRecord:reSign({...f.integratedApprovalRecord,...change},keys[0])});denied(r);assert.ok(codes(r).includes('INTEGRATED_APPROVAL_BINDING'));}});
test('integrated approval extra productionApproved flag rejects even if signed',async()=>{const f=await fixture(),r=await run(f,{integratedApprovalRecord:reSign({...f.integratedApprovalRecord,productionApproved:true},keys[0])});denied(r);});
test('integrated approval subject checksum substitution rejects',async()=>{const f=await fixture(),r=await run(f,{integratedApprovalRecord:reSign({...f.integratedApprovalRecord,subjectSha256:'a'.repeat(64)},keys[0])});denied(r);});
test('artwork verifier outage fails closed without integration success',async()=>{const f=await fixture(),r=await run(f,{verifyStorageAttestation:async()=>{throw Error('down');}});denied(r);});
test('policy verifier outage fails closed without integration success',async()=>{const f=await fixture(),r=await run(f,{verifyProcessPolicy:async()=>{throw Error('down');}});denied(r);});
test('missing private artwork bytes fails closed',async()=>{const f=await fixture(),r=await run(f,{readPrivateArtwork:async()=>null});denied(r);});
test('immutable revision with only text layers does not borrow artwork evidence',async()=>{const f=await fixture(),design={layers:[{...layer,type:'text',value:'text'}]};const r=await run(f,{loadCurrentRevision:async()=>({...f.current,design,designSha256:computeArtworkDesignSha256(design)})});denied(r);});
test('artwork attestation cannot be silently supplied with extra approved flag',async()=>{const f=await fixture(),r=await run(f,{storageRecords:[{...f.storageRecords[0],approved:true}]});denied(r);});
test('manufacturing worksheet blank and process substitutions reject integrated evidence',async()=>{const f=await fixture();for(const change of [{blankSku:'OTHER'},{zones:[{...f.worksheet.zones[0],processCode:'UV-ROTARY'}]}]){const r=await run(f,{worksheet:{...f.worksheet,...change}});denied(r);}});
test('caller cannot mutate geometry profile through asynchronous verifier after snapshot',async()=>{const f=await fixture(),geometryProfile=structuredClone(f.geometryProfile);const r=await run(f,{geometryProfile,verifyStorageAttestation:async record=>{geometryProfile.toleranceMm=100;return verify(keys[2])(record);}});assert.equal(r.integratedEvidenceReady,true);});
test('caller cannot mutate signed policy through asynchronous verifier after snapshot',async()=>{const f=await fixture(),processPolicies=structuredClone(f.processPolicies);const r=await run(f,{processPolicies,verifyStorageAttestation:async record=>{processPolicies[0].minDpi=1;return verify(keys[2])(record);}});assert.equal(r.integratedEvidenceReady,true);});

test('reapproved geometry calibration cannot reuse an earlier integrated approval',async()=>{
 const f=await fixture(),geometryProfile={...f.geometryProfile,toleranceMm:.6};
 const first=await reviewManufacturingGeometryProfile({...f,geometryProfile,design:f.design,artworkEvidenceInput:f.artworkEvidenceInput});
 const modelApprovalRecord=reSign({...f.modelApprovalRecord,geometryProfileSha256:first.geometryProfileSha256},keys[1]);
 const r=await run(f,{geometryProfile,modelApprovalRecord});denied(r);assert.ok(codes(r).includes('INTEGRATED_APPROVAL_BINDING'));
});
test('new authenticated immutable composition cannot borrow old integrated approval',async()=>{
 const f=await fixture(),design={layers:[{...layer,x:.3}]},designSha256=computeArtworkDesignSha256(design);
 const current={...f.current,design,designSha256};
 const storageRecords=[reSign({...f.storageRecords[0],designSha256},keys[2])];
 const r=await run(f,{loadCurrentRevision:async()=>current,storageRecords});denied(r);assert.ok(codes(r).includes('INTEGRATED_APPROVAL_BINDING'));
});
test('artwork whose real pixels fall below reviewed DPI fails integrated review',async()=>{
 const f=await fixture(),bytes=png(100,100),storageRecords=[reSign({...f.storageRecords[0],sha256:hash(bytes),byteLength:bytes.length},keys[2])];const r=await run(f,{storageRecords,readPrivateArtwork:async()=>bytes});denied(r);assert.ok(codes(r).includes('ARTWORK_LOW_DPI'));
});
test('missing integrated approval record fails closed',async()=>{const f=await fixture(),r=await run(f,{integratedApprovalRecord:undefined});denied(r);});
test('missing GLB bytes fails before approval',async()=>{const f=await fixture(),r=await run(f,{glbBytes:undefined});denied(r);assert.ok(codes(r).includes('INTEGRATED_MODEL'));});
test('noninteger or invalid trusted time fails closed',async()=>{const f=await fixture();for(const value of [NaN,Infinity,1.5])denied(await run(f,{now:value}));});
test('integrated approval does not accept unexpected checkout or machine fields',async()=>{const f=await fixture(),r=await run(f,{integratedApprovalRecord:reSign({...f.integratedApprovalRecord,checkoutEnabled:true,machineOutput:'ready'},keys[0])});denied(r);});
test('integrated review rejects an additional unsigned process policy for another surface',async()=>{
 const f=await fixture(),p={...f.processPolicies[0],surfaceId:'other'};const r=await run(f,{processPolicies:[...f.processPolicies,p]});denied(r);
});
test('integrated review rejects revoked base manufacturing approval',async()=>{const f=await fixture(),r=await run(f,{verifyApproval:async()=>false});denied(r);assert.ok(codes(r).includes('REVIEW_NOT_VERIFIED'));});
test('ArrayBuffer GLB is copied before awaited verifiers can mutate caller memory',async()=>{
 const f=await fixture(),buffer=f.glbBytes.buffer.slice(f.glbBytes.byteOffset,f.glbBytes.byteOffset+f.glbBytes.byteLength);
 const r=await run(f,{glbBytes:buffer,verifyStorageAttestation:async record=>{
  new Uint8Array(buffer)[0]=0;return verify(keys[2])(record);
 }});assert.equal(r.integratedEvidenceReady,true);
});
test('caller worksheet mutation during asynchronous evidence review cannot alter signed subject',async()=>{
 const f=await fixture(),worksheet=structuredClone(f.worksheet);
 const r=await run(f,{worksheet,verifyStorageAttestation:async record=>{
  worksheet.zones[0].bleedMm=0;return verify(keys[2])(record);
 }});assert.equal(r.integratedEvidenceReady,true);
});
