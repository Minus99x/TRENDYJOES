import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,createHmac,randomBytes} from 'node:crypto';
import {deflateSync} from 'node:zlib';
import {PRODUCT_MANIFESTS} from '../src/catalog.mjs';
import {createCalibrationWorksheet} from '../src/calibration.mjs';
import {inspectVerifiedPng,reviewManufacturingArtworkEvidence,computeArtworkDesignSha256} from '../src/manufacturing-artwork-evidence.mjs';
const shop='gucgmp-bc.myshopify.com',productGid='gid://shopify/Product/123',variantGid='gid://shopify/ProductVariant/456',ownerId='test-owner',designId='test-design',revision=3,now=Date.parse('2026-10-15T18:00:00Z');
const manifest=PRODUCT_MANIFESTS[0],storageKey=randomBytes(32),policyKey=randomBytes(32);
const hash=b=>createHash('sha256').update(b).digest('hex');
const sign=(r,k)=>createHmac('sha256',k).update(JSON.stringify(Object.fromEntries(Object.entries(r).filter(([key])=>key!=='signature')))).digest('hex');
const verifyStorageAttestation=r=>r.signature===sign(r,storageKey);
const verifyProcessPolicy=r=>r.signature===sign(r,policyKey);
const layer={id:'art-layer',type:'artwork',artworkId:'private-asset-1',surfaceId:'front',x:.2,y:.2,width:.3,height:.3,rotationDeg:0,sourceWidthPx:9000,sourceHeightPx:9000};
function crc32(bytes){let c=0xffffffff;for(const b of bytes){c^=b;for(let i=0;i<8;i++)c=(c>>>1)^(0xedb88320&-(c&1));}return (c^0xffffffff)>>>0;}
function chunk(type,data){const name=Buffer.from(type),buf=Buffer.alloc(12+data.length);buf.writeUInt32BE(data.length,0);name.copy(buf,4);data.copy(buf,8);buf.writeUInt32BE(crc32(buf.subarray(4,8+data.length)),8+data.length);return buf;}
function png(w=600,h=750,{filter=0,channels=4,extraChunk=null,deflateSuffix=null}={}){
 const ihdr=Buffer.alloc(13);ihdr.writeUInt32BE(w,0);ihdr.writeUInt32BE(h,4);ihdr[8]=8;ihdr[9]=channels===4?6:2;
 const raw=Buffer.alloc(h*(w*channels+1));for(let y=0;y<h;y++)raw[y*(w*channels+1)]=filter;
 const deflated=deflateSync(raw);
 return Buffer.concat([Buffer.from([137,80,78,71,13,10,26,10]),chunk('IHDR',ihdr),...(extraChunk?[chunk(extraChunk,Buffer.from([1,2,3]))]:[]),chunk('IDAT',deflateSuffix?Buffer.concat([deflated,deflateSuffix]):deflated),chunk('IEND',Buffer.alloc(0))]);
}
function fixture({bytes=png(),bleedMm=3,safetyInsetMm=5,processCode='DTF-TEXTILE',artworkLayer=layer}={}){
 const worksheet=createCalibrationWorksheet(manifest,[{surfaceId:'front',widthMm:240,heightMm:300,blankWidthMm:300,blankHeightMm:400,processCode,fixtureReference:'Synthetic jig',safetyInsetMm,bleedMm}],{blankSku:'TEST-BLANK',measuredBy:'Synthetic QA',sourceDocument:'Synthetic only',measuredAt:'2026-10-14'});
 const storageRecord={schema:'TJ-PRIVATE-ARTWORK-ATTESTATION-1',shop,productGid,variantGid,ownerId,designId,revision,designSha256:computeArtworkDesignSha256({layers:[artworkLayer]}),manifestId:manifest.id,blankSku:worksheet.blankSku,surfaceId:artworkLayer.surfaceId,processCode,layerId:artworkLayer.id,artworkId:artworkLayer.artworkId,storageKey:'OpaqueStorageKey12345',sha256:hash(bytes),mediaType:'image/png',byteLength:bytes.length,issuedAtMs:now-1000,expiresAtMs:now+60000,signature:''};storageRecord.signature=sign(storageRecord,storageKey);
 const policy={schema:'TJ-ARTWORK-PROCESS-POLICY-1',shop,productGid,variantGid,blankSku:worksheet.blankSku,surfaceId:'front',processCode,minDpi:200,minBleedMm:2,maxBleedMm:5,maxBytes:8*1024*1024,allowedMediaTypes:['image/png'],issuedAtMs:now-1000,expiresAtMs:now+60000,policyId:'test-policy',signature:''};policy.signature=sign(policy,policyKey);
 return {shop,productGid,variantGid,ownerId,designId,revision,manifest,worksheet,design:{layers:[artworkLayer]},storageRecords:[storageRecord],processPolicies:[policy],readPrivateArtwork:async()=>bytes,verifyStorageAttestation,verifyProcessPolicy,now};
}
const run=(f,change={})=>reviewManufacturingArtworkEvidence({...f,...change});
const codes=r=>r.issues.map(i=>i.code);
const deny=r=>{assert.equal(r.artworkEvidenceReady,false);assert.equal(r.productionApproved,false);assert.equal(r.checkoutEnabled,false);assert.equal(r.machineOutput,null);assert.deepEqual(r.artworks,[]);};
const modify=(f,field,delta,key)=>{const obj={...f[field][0],...delta};if(key)obj.signature=sign(obj,key);return {[field]:[obj]};};

test('actual CRC-checked inflated PNG and two independent mock signatures produce evidence only',async()=>{const f=fixture(),r=await run(f);assert.equal(r.artworkEvidenceReady,true);assert.equal(r.productionApproved,false);assert.equal(r.checkoutEnabled,false);assert.equal(r.machineOutput,null);assert.equal(r.artworks.length,1);assert.equal(r.artworks[0].widthPx,600);assert.equal(r.artworks[0].heightPx,750);assert.ok(r.artworks[0].effectiveDpi>200);});
test('client-provided 9000px dimensions cannot overcome low resolution',async()=>{const f=fixture({bytes:png(100,100)});const r=await run(f);deny(r);assert.ok(codes(r).includes('ARTWORK_LOW_DPI'));});
test('private bytes are hashed independently of signed but false metadata',async()=>{const f=fixture();const r=await run(f,{readPrivateArtwork:async()=>png(601,750)});deny(r);assert.ok(codes(r).includes('ARTWORK_DIGEST'));});
test('corrupt PNG CRC fails even with a freshly signed hash and byte count',async()=>{const f=fixture();const b=Buffer.from(await f.readPrivateArtwork());b[b.length-7]^=1;const record=modify(f,'storageRecords',{sha256:hash(b)},storageKey);const r=await run(f,{...record,readPrivateArtwork:async()=>b});deny(r);assert.ok(codes(r).includes('ARTWORK_BYTES_INVALID'));});
test('truncated IDAT is rejected even if attestation is resigned',async()=>{const f=fixture(),b=Buffer.from(await f.readPrivateArtwork());const truncated=b.subarray(0,b.length-10);const r=await run(f,{...modify(f,'storageRecords',{sha256:hash(truncated),byteLength:truncated.length},storageKey),readPrivateArtwork:async()=>truncated});deny(r);});
test('malformed PNG filter bytes fail structural validation',()=>assert.throws(()=>inspectVerifiedPng(png(2,2,{filter:5})),/PNG_FILTER/));
test('extra bytes after valid IEND are rejected',()=>assert.throws(()=>inspectVerifiedPng(Buffer.concat([png(2,2),Buffer.from('junk')])),/PNG_IEND/));
test('unknown or animated PNG chunk is rejected',()=>assert.throws(()=>inspectVerifiedPng(png(2,2,{extraChunk:'acTL'})),/PNG_UNSUPPORTED_CHUNK/));
test('unsupported PNG bit depth rejected with valid CRC',()=>{const b=png(2,2);const copy=Buffer.from(b);copy[24]=16;copy.writeUInt32BE(crc32(copy.subarray(12,29)),29);assert.throws(()=>inspectVerifiedPng(copy),/PNG_UNSUPPORTED_FORMAT/);});
test('PNG compressed trailing garbage rejected',()=>assert.throws(()=>inspectVerifiedPng(png(2,2,{deflateSuffix:Buffer.from([9,8,7])})),/PNG_DEFLATE/));
test('JPEG, WebP, SVG and polyglot non-PNG bytes denied',async()=>{const f=fixture();for(const b of [Buffer.from([255,216,255,217]),Buffer.from('RIFF1234WEBP'),Buffer.from('<svg/>')]){const r=await run(f,{...modify(f,'storageRecords',{sha256:hash(b),byteLength:b.length},storageKey),readPrivateArtwork:async()=>b});deny(r);}});
test('untrusted missing or exception-throwing storage verifier rejects',async()=>{const f=fixture();for(const v of [undefined,()=>false,()=>{throw Error('down');}])deny(await run(f,{verifyStorageAttestation:v}));});
test('untrusted missing or exception-throwing policy verifier rejects',async()=>{const f=fixture();for(const v of [undefined,()=>false,()=>{throw Error('down');}])deny(await run(f,{verifyProcessPolicy:v}));});
test('forged storage signature rejects before private fetch',async()=>{const f=fixture();let called=false;const r=await run(f,{storageRecords:[{...f.storageRecords[0],signature:'forged'}],readPrivateArtwork:()=>{called=true;return png();}});deny(r);assert.equal(called,false);});
test('forged process signature rejects before private fetch',async()=>{const f=fixture();let called=false;const r=await run(f,{processPolicies:[{...f.processPolicies[0],signature:'forged'}],readPrivateArtwork:()=>{called=true;return png();}});deny(r);assert.equal(called,false);});
test('tenant, owner, design, revision, product and variant swaps all fail closed',async()=>{const f=fixture();for(const change of [{shop:'evil.myshopify.com'},{ownerId:'attacker'},{designId:'another'},{revision:4},{productGid:'gid://shopify/Product/999'},{variantGid:'gid://shopify/ProductVariant/999'}]){const r=await run(f,change);deny(r);assert.ok(codes(r).includes('ARTWORK_STORAGE_BINDING'));}});
test('layer ID, artwork ID and surface substitution cannot borrow attestation',async()=>{const f=fixture();for(const change of [{id:'another'},{artworkId:'other-asset'},{surfaceId:'back'}])deny(await run(f,{design:{layers:[{...layer,...change}]}}));});
test('expired, future-issued, overlong attestation rejects',async()=>{const f=fixture();for(const change of [{expiresAtMs:now},{issuedAtMs:now+1},{expiresAtMs:now+2*86400000}]){const r=await run(f,modify(f,'storageRecords',change,storageKey));deny(r);assert.ok(codes(r).includes('ARTWORK_STORAGE_BINDING'));}});
test('expired, future-issued and overlong process policy rejects',async()=>{const f=fixture();for(const change of [{expiresAtMs:now},{issuedAtMs:now+1},{expiresAtMs:now+31*86400000}]){const r=await run(f,modify(f,'processPolicies',change,policyKey));deny(r);assert.ok(codes(r).includes('ARTWORK_POLICY_BINDING'));}});
test('policy process, blank, variant and surface cannot be swapped',async()=>{const f=fixture();for(const change of [{processCode:'UV-ROTARY'},{blankSku:'OTHER'},{variantGid:'gid://shopify/ProductVariant/789'},{surfaceId:'back'}]){const r=await run(f,modify(f,'processPolicies',change,policyKey));deny(r);assert.ok(codes(r).includes('ARTWORK_POLICY_BINDING')||codes(r).includes('ARTWORK_EVIDENCE_MISSING'));}});
test('untrusted policy DPI cannot be lowered without independent signature',async()=>{const f=fixture({bytes:png(100,100)});const p={...f.processPolicies[0],minDpi:1};const r=await run(f,{processPolicies:[p]});deny(r);assert.ok(codes(r).includes('ARTWORK_POLICY_REJECTED'));});
test('authenticated stricter process DPI is enforced',async()=>{const f=fixture();const r=await run(f,modify(f,'processPolicies',{minDpi:300},policyKey));deny(r);assert.ok(codes(r).includes('ARTWORK_LOW_DPI'));});
test('minimum bleed and maximum bleed policy both enforced',async()=>{for(const bleedMm of [0,6]){const f=fixture({bleedMm});const r=await run(f);deny(r);assert.ok(codes(r).includes('ARTWORK_BLEED_POLICY'));}});
test('rotated artwork whose bleed crosses safety edge rejects',async()=>{const f=fixture({artworkLayer:{...layer,x:.02,y:.2}});const r=await run(f);deny(r);assert.ok(codes(r).includes('ARTWORK_BLEED_FIT')||codes(r).includes('ARTWORK_PLACEMENT'));});
test('policy byte limit rejects even authenticated intact PNG',async()=>{const f=fixture();const r=await run(f,modify(f,'processPolicies',{maxBytes:60},policyKey));deny(r);assert.ok(codes(r).includes('ARTWORK_DIGEST'));});
test('missing private bytes or unavailable storage fail closed',async()=>{const f=fixture();for(const readPrivateArtwork of [undefined,async()=>null,async()=>{throw Error('unavailable');}])deny(await run(f,{readPrivateArtwork}));});
test('storage path traversal and extra self-asserted verified flag reject',async()=>{const f=fixture();for(const change of [{storageKey:'../../etc/passwd'},{verified:true}])deny(await run(f,modify(f,'storageRecords',change,storageKey)));});
test('unreviewed policy extra fields and unsupported media types reject',async()=>{const f=fixture();for(const change of [{verified:true},{allowedMediaTypes:['image/jpeg']},{allowedMediaTypes:['image/png','image/jpeg']}])deny(await run(f,modify(f,'processPolicies',change,policyKey)));});
test('duplicate artwork reuse or duplicate attestation entries reject',async()=>{const f=fixture();deny(await run(f,{design:{layers:[layer,{...layer,id:'second-layer'}]}}));deny(await run(f,{storageRecords:[f.storageRecords[0],f.storageRecords[0]]}));});
test('missing second artwork attestation fails all-or-nothing',async()=>{const f=fixture();const r=await run(f,{design:{layers:[layer,{...layer,id:'other',artworkId:'asset-2'}]}});deny(r);assert.ok(codes(r).includes('ARTWORK_EVIDENCE_MISSING'));});
test('empty artwork, missing worksheet, and invalid revision fail closed',async()=>{const f=fixture();for(const change of [{design:{layers:[]}},{worksheet:null},{revision:0}])deny(await run(f,change));});
test('PNG pixel decompression limit and dimensions are bounded',()=>{assert.throws(()=>inspectVerifiedPng(png(5000,4000)),/PNG_DIMENSIONS/);});

test('authenticated composition digest rejects layer relocation even when within print zone',async()=>{const f=fixture();const r=await run(f,{design:{layers:[{...layer,x:.3}]}});deny(r);assert.ok(codes(r).includes('ARTWORK_STORAGE_BINDING'));});
test('canonical composition hash ignores property ordering but not layer content',()=>{const a={layers:[{id:'a',x:.2,y:.3}]},b={layers:[{y:.3,x:.2,id:'a'}]},c={layers:[{y:.4,x:.2,id:'a'}]};assert.equal(computeArtworkDesignSha256(a),computeArtworkDesignSha256(b));assert.notEqual(computeArtworkDesignSha256(a),computeArtworkDesignSha256(c));});
test('storage attestation cannot be replayed on a different blank, process or surface',async()=>{const f=fixture();for(const change of [{blankSku:'OTHER'},{processCode:'UV-ROTARY'},{surfaceId:'back'}]){const r=await run(f,modify(f,'storageRecords',change,storageKey));deny(r);assert.ok(codes(r).includes('ARTWORK_STORAGE_BINDING'));}});
test('two separately authenticated artwork layers pass as one evidence batch',async()=>{
 const f=fixture(),second={...layer,id:'second-layer',artworkId:'private-asset-2',x:.55,y:.2,width:.2};
 const design={layers:[layer,second]},designSha256=computeArtworkDesignSha256(design);
 const first={...f.storageRecords[0],designSha256};first.signature=sign(first,storageKey);
 const other={...first,layerId:second.id,artworkId:second.artworkId,storageKey:'AnotherOpaqueStorageKey22'};other.signature=sign(other,storageKey);
 const r=await run(f,{design,storageRecords:[first,other]});assert.equal(r.artworkEvidenceReady,true);assert.equal(r.artworks.length,2);assert.equal(r.productionApproved,false);
});
test('one corrupt private asset invalidates an otherwise valid two-artwork batch',async()=>{
 const f=fixture(),second={...layer,id:'second-layer',artworkId:'private-asset-2',x:.55,y:.2,width:.2};
 const design={layers:[layer,second]},designSha256=computeArtworkDesignSha256(design);
 const first={...f.storageRecords[0],designSha256};first.signature=sign(first,storageKey);
 const other={...first,layerId:second.id,artworkId:second.artworkId,storageKey:'AnotherOpaqueStorageKey22'};other.signature=sign(other,storageKey);
 const r=await run(f,{design,storageRecords:[first,other],readPrivateArtwork:async q=>q.artworkId===second.artworkId?png(99,99):await f.readPrivateArtwork()});deny(r);assert.ok(codes(r).includes('ARTWORK_DIGEST'));
});
test('private read receives only opaque key and exact owner/revision scope, no public URL',async()=>{
 const f=fixture();let seen;const r=await run(f,{readPrivateArtwork:async q=>{seen=q;return await f.readPrivateArtwork();}});
 assert.equal(r.artworkEvidenceReady,true);assert.deepEqual(seen,{storageKey:'OpaqueStorageKey12345',ownerId,designId,revision,artworkId:layer.artworkId});
});
test('re-signed attestation with wrong byte length fails even if hash matches',async()=>{
 const f=fixture(),r=await run(f,modify(f,'storageRecords',{byteLength:f.storageRecords[0].byteLength+1},storageKey));deny(r);assert.ok(codes(r).includes('ARTWORK_DIGEST'));
});
test('PNG inflated scanline length must match IHDR dimensions',()=>{
 const b=png(2,2),c=Buffer.from(b);c.writeUInt32BE(3,16);c.writeUInt32BE(crc32(c.subarray(12,29)),29);
 assert.throws(()=>inspectVerifiedPng(c),/PNG_SCANLINES/);
});
