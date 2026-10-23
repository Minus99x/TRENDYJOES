/**
 * Objective 21: independent, fail-closed OFFLINE artwork-byte evidence gate.
 * Only a narrow, fully checked PNG subset is accepted; JPEG/WebP and other
 * formats await a separate trusted full decoder. Nothing here approves output.
 * Caller-provided storage/policy verifiers are protected BACKEND trust seams,
 * not services provided by this package. Test verifiers prove no hosted trust.
 */
import {createHash, timingSafeEqual} from 'node:crypto';
import {inflateSync} from 'node:zlib';
import {estimateLayerPhysicalPlacement} from './calibration.mjs';

const issue=(code,message)=>({code,message});
const plain=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&[Object.prototype,null].includes(Object.getPrototypeOf(x));
const exact=(x,keys)=>plain(x)&&Object.keys(x).sort().join('|')===[...keys].sort().join('|');
const finite=x=>typeof x==='number'&&Number.isFinite(x);
const text=(x,max=200)=>typeof x==='string'&&x.length>0&&x.length<=max&&x.trim()===x;
const sha=/^[0-9a-f]{64}$/;
const sha256=x=>createHash('sha256').update(x).digest('hex');
const sameHash=(a,b)=>sha.test(a||'')&&sha.test(b||'')&&timingSafeEqual(Buffer.from(a,'hex'),Buffer.from(b,'hex'));
const storeKeys=['schema','shop','productGid','variantGid','ownerId','designId','revision','designSha256','manifestId','blankSku','surfaceId','processCode','layerId','artworkId','storageKey','sha256','mediaType','byteLength','issuedAtMs','expiresAtMs','signature'];
const policyKeys=['schema','shop','productGid','variantGid','blankSku','surfaceId','processCode','minDpi','minBleedMm','maxBleedMm','maxBytes','allowedMediaTypes','issuedAtMs','expiresAtMs','policyId','signature'];
const MAX_FILE=8*1024*1024,MAX_PIXELS=16_000_000,MAX_RAW=64*1024*1024;
/** Canonical JSON composition digest; rejects unsupported values and deep cycles. */
export function computeArtworkDesignSha256(design){
 const walk=(x,depth)=>{
  if(depth>12)throw Error('DESIGN_DEPTH');
  if(x===null||typeof x==='string'||typeof x==='boolean')return x;
  if(typeof x==='number'&&Number.isFinite(x))return x;
  if(Array.isArray(x))return x.map(v=>walk(v,depth+1));
  if(plain(x)){const out=Object.create(null);for(const k of Object.keys(x).sort())out[k]=walk(x[k],depth+1);return out;}
  throw Error('DESIGN_UNSUPPORTED');
 };
 const serialized=JSON.stringify(walk(design,0));if(serialized.length>1024*1024)throw Error('DESIGN_SIZE');
 return sha256(Buffer.from(serialized));
}
const denied=issues=>({artworkEvidenceReady:false,productionApproved:false,checkoutEnabled:false,machineOutput:null,artworks:[],issues});

function crc32(bytes){let c=0xffffffff;for(const b of bytes){c^=b;for(let i=0;i<8;i++)c=(c>>>1)^(0xedb88320&-(c&1));}return (c^0xffffffff)>>>0;}
/** Full PNG chunk/CRC/IDAT-inflation/scanline structural verification.
 * No image rendering, malware scanning, color management, or physical proof.
 * Narrow 8-bit noninterlaced RGB/RGBA subset; unknown chunks fail closed.
 */
export function inspectVerifiedPng(bytes){
 if(!(bytes instanceof Uint8Array||bytes instanceof ArrayBuffer))throw Error('PNG_BYTES_REQUIRED');
 const b=Buffer.from(bytes);if(b.length>MAX_FILE||b.length<60||!b.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10])))throw Error('PNG_SIGNATURE');
 let offset=8,seenIHDR=false,seenIDAT=false,endedIDAT=false,seenEnd=false,w=0,h=0,channels=0;
 const compressed=[];
 while(offset<b.length){
  if(offset+12>b.length)throw Error('PNG_TRUNCATED_CHUNK');
  const len=b.readUInt32BE(offset),type=b.toString('ascii',offset+4,offset+8),start=offset+8,end=start+len;
  if(len>MAX_FILE||end+4>b.length||!/^[A-Za-z]{4}$/.test(type))throw Error('PNG_CHUNK_BOUNDS');
  if(crc32(b.subarray(offset+4,end))!==b.readUInt32BE(end))throw Error('PNG_CRC');
  if(!seenIHDR&&type!=='IHDR')throw Error('PNG_IHDR_ORDER');
  if(type==='IHDR'){
   if(seenIHDR||len!==13)throw Error('PNG_IHDR');
   w=b.readUInt32BE(start);h=b.readUInt32BE(start+4);
   if(w<1||h<1||w>10000||h>10000||w*h>MAX_PIXELS)throw Error('PNG_DIMENSIONS');
   if(b[start+8]!==8||![2,6].includes(b[start+9])||b[start+10]!==0||b[start+11]!==0||b[start+12]!==0)throw Error('PNG_UNSUPPORTED_FORMAT');
   channels=b[start+9]===6?4:3;seenIHDR=true;
  }else if(type==='IDAT'){
   if(endedIDAT||seenEnd||!len)throw Error('PNG_IDAT_ORDER');
   seenIDAT=true;compressed.push(b.subarray(start,end));
  }else if(type==='IEND'){
   if(!seenIDAT||len!==0||seenEnd||end+4!==b.length)throw Error('PNG_IEND');
   seenEnd=true;
  }else throw Error('PNG_UNSUPPORTED_CHUNK');
  if(type!=='IDAT'&&seenIDAT&&type!=='IEND')endedIDAT=true;
  offset=end+4;
 }
 if(!seenEnd||!seenIDAT)throw Error('PNG_INCOMPLETE');
 const row=w*channels,expected=h*(row+1);
 if(expected>MAX_RAW)throw Error('PNG_RAW_LIMIT');
 let raw;try{const encoded=Buffer.concat(compressed),decoded=inflateSync(encoded,{maxOutputLength:expected+1,info:true});if(decoded.engine.bytesWritten!==encoded.length)throw Error('PNG_TRAILING_DEFLATE');raw=decoded.buffer;}catch{throw Error('PNG_DEFLATE');}
 if(raw.length!==expected)throw Error('PNG_SCANLINES');
 for(let y=0;y<h;y++)if(raw[y*(row+1)]>4)throw Error('PNG_FILTER');
 return {mediaType:'image/png',width:w,height:h,sha256:sha256(b),byteLength:b.length};
}

/**
 * Inspect every artwork layer against actual private bytes and independently
 * authenticated storage + process policy records. No self-attested pixel size,
 * public URL, client-supplied grant, or synthetic policy defaults accepted.
 */
export async function reviewManufacturingArtworkEvidence({shop,productGid,variantGid,ownerId,designId,revision,manifest,worksheet,design,storageRecords,processPolicies,readPrivateArtwork,verifyStorageAttestation,verifyProcessPolicy,now=Date.now()}={}){
 const issues=[];
 if(!text(shop)||!/^gid:\/\/shopify\/Product\/[1-9]\d*$/.test(productGid||'')||!/^gid:\/\/shopify\/ProductVariant\/[1-9]\d*$/.test(variantGid||'')||!text(ownerId)||!text(designId)||!Number.isSafeInteger(revision)||revision<1||!Number.isSafeInteger(now))issues.push(issue('ARTWORK_IDENTITY','Trusted tenant, owner, design, revision, product and variant required'));
 if(!Array.isArray(design?.layers)||design.layers.length>100||!Array.isArray(storageRecords)||!Array.isArray(processPolicies)||!Array.isArray(worksheet?.zones)||!text(worksheet?.blankSku)||worksheet?.status!=='DRAFT_REQUIRES_PHYSICAL_VERIFICATION'||worksheet?.issues?.length||worksheet?.productManifestId!==manifest?.id)issues.push(issue('ARTWORK_INPUT','Complete measured draft, layer set, storage evidence and policies required'));
 if(typeof readPrivateArtwork!=='function'||typeof verifyStorageAttestation!=='function'||typeof verifyProcessPolicy!=='function')issues.push(issue('ARTWORK_TRUST','Three independent protected storage, attestation and policy seams required'));
 if(issues.length)return denied(issues);
 let designSha256;try{designSha256=computeArtworkDesignSha256(design);}catch{issues.push(issue('ARTWORK_DESIGN_DIGEST','Exact JSON composition required'));return denied(issues);}
 const layers=design.layers.filter(l=>l?.type==='artwork');
 if(!layers.length){issues.push(issue('ARTWORK_REQUIRED','At least one raster artwork layer required'));return denied(issues);}
 const ids=new Set(),recordIds=new Set(),policyIds=new Set(),verified=[];
 for(const r of storageRecords){if(!exact(r,storeKeys)||!text(r.artworkId)||recordIds.has(r.artworkId)){issues.push(issue('STORAGE_RECORD_SET','Storage records must be exact and unique'));return denied(issues);}recordIds.add(r.artworkId);}
 for(const p of processPolicies){if(!exact(p,policyKeys)||!text(p.surfaceId)||policyIds.has(p.surfaceId)){issues.push(issue('POLICY_RECORD_SET','Policy records must be exact and unique'));return denied(issues);}policyIds.add(p.surfaceId);}
 for(const l of layers){
  if(!text(l.id)||!text(l.artworkId)||ids.has(l.id)){issues.push(issue('ARTWORK_LAYER','Unique layer and artwork identity required'));continue;}ids.add(l.id);
  const zone=worksheet.zones.find(z=>z?.surfaceId===l.surfaceId);
  const surface=manifest?.surfaces?.find(s=>s.id===l.surfaceId);
  if(!zone||!surface||!surface.allowableMethods?.includes(zone.processCode)||!manifest?.manufacturing?.candidateMethods?.includes(zone.processCode)){issues.push(issue('ARTWORK_ROUTE','Measured print zone and approved candidate process must match manifest'));continue;}
  const r=storageRecords.find(r=>r.artworkId===l.artworkId),p=processPolicies.find(p=>p.surfaceId===l.surfaceId);
  if(!r||!p){issues.push(issue('ARTWORK_EVIDENCE_MISSING','Exact private-storage and process policy records required'));continue;}
  if(r.schema!=='TJ-PRIVATE-ARTWORK-ATTESTATION-1'||r.shop!==shop||r.productGid!==productGid||r.variantGid!==variantGid||r.ownerId!==ownerId||r.designId!==designId||r.revision!==revision||r.designSha256!==designSha256||r.manifestId!==manifest.id||r.blankSku!==worksheet.blankSku||r.surfaceId!==l.surfaceId||r.processCode!==zone.processCode||r.layerId!==l.id||r.artworkId!==l.artworkId||!/^[-A-Za-z0-9_]{8,160}$/.test(r.storageKey||'')||!sha.test(r.sha256||'')||r.mediaType!=='image/png'||!Number.isSafeInteger(r.byteLength)||r.byteLength<60||r.byteLength>MAX_FILE||!text(r.signature,4096)||!Number.isSafeInteger(r.issuedAtMs)||!Number.isSafeInteger(r.expiresAtMs)||r.issuedAtMs>now||r.expiresAtMs<=now||r.expiresAtMs-r.issuedAtMs>86400000){issues.push(issue('ARTWORK_STORAGE_BINDING','Storage attestation identity, content, scope or lifetime invalid'));continue;}
  if(p.schema!=='TJ-ARTWORK-PROCESS-POLICY-1'||p.shop!==shop||p.productGid!==productGid||p.variantGid!==variantGid||p.blankSku!==worksheet.blankSku||p.surfaceId!==l.surfaceId||p.processCode!==zone.processCode||!text(p.policyId)||!text(p.signature,4096)||!finite(p.minDpi)||p.minDpi<1||p.minDpi>2400||!finite(p.minBleedMm)||p.minBleedMm<0||p.minBleedMm>30||!finite(p.maxBleedMm)||p.maxBleedMm<p.minBleedMm||p.maxBleedMm>30||!Number.isSafeInteger(p.maxBytes)||p.maxBytes<60||p.maxBytes>MAX_FILE||!Array.isArray(p.allowedMediaTypes)||p.allowedMediaTypes.length!==1||p.allowedMediaTypes[0]!=='image/png'||!Number.isSafeInteger(p.issuedAtMs)||!Number.isSafeInteger(p.expiresAtMs)||p.issuedAtMs>now||p.expiresAtMs<=now||p.expiresAtMs-p.issuedAtMs>30*86400000){issues.push(issue('ARTWORK_POLICY_BINDING','Independent process policy invalid or mismatched'));continue;}
  // No callback is allowed to authorize an invalid record; callbacks only deny or confirm.
  try{if(await verifyStorageAttestation(r,{shop,productGid,variantGid,ownerId,designId,revision,designSha256,manifestId:manifest.id,blankSku:worksheet.blankSku,surfaceId:l.surfaceId,processCode:zone.processCode,layerId:l.id,artworkId:l.artworkId})!==true){issues.push(issue('ARTWORK_ATTESTATION_REJECTED','Private-storage attestation rejected'));continue;}}catch{issues.push(issue('ARTWORK_ATTESTATION_REJECTED','Private-storage attestation unavailable'));continue;}
  try{if(await verifyProcessPolicy(p,{shop,productGid,variantGid,blankSku:worksheet.blankSku,surfaceId:l.surfaceId,processCode:zone.processCode})!==true){issues.push(issue('ARTWORK_POLICY_REJECTED','Independent process policy rejected'));continue;}}catch{issues.push(issue('ARTWORK_POLICY_REJECTED','Independent process policy unavailable'));continue;}
  let bytes,inspected;
  try{
   // Backend must use owner-scoped private storage, never a caller-supplied URL.
   bytes=await readPrivateArtwork({storageKey:r.storageKey,ownerId,designId,revision,artworkId:l.artworkId});
   inspected=inspectVerifiedPng(bytes);
  }catch{issues.push(issue('ARTWORK_BYTES_INVALID','Private artwork missing, malformed, truncated or unsupported'));continue;}
  if(!sameHash(inspected.sha256,r.sha256)||inspected.byteLength!==r.byteLength||inspected.mediaType!==r.mediaType||inspected.byteLength>p.maxBytes){issues.push(issue('ARTWORK_DIGEST','Private bytes disagree with attested digest, size or policy'));continue;}
  const placement=estimateLayerPhysicalPlacement(worksheet,l,{sourceWidthPx:inspected.width,sourceHeightPx:inspected.height});
  if(!placement.ok||!finite(placement.dpi)){issues.push(issue('ARTWORK_PLACEMENT','Measured placement is invalid'));continue;}
  if(placement.dpi<p.minDpi){issues.push(issue('ARTWORK_LOW_DPI','Effective source resolution below independently reviewed process policy'));continue;}
  if(!finite(zone.bleedMm)||zone.bleedMm<p.minBleedMm||zone.bleedMm>p.maxBleedMm||!finite(zone.safetyInsetMm)||zone.safetyInsetMm<0){issues.push(issue('ARTWORK_BLEED_POLICY','Measured bleed violates independently reviewed process policy'));continue;}
  const b=placement.rotatedBoundsMm,m=zone.safetyInsetMm+zone.bleedMm;
  if(!b||![b.left,b.top,b.right,b.bottom].every(finite)||b.left<m||b.top<m||b.right>zone.printableWidthMm-m||b.bottom>zone.printableHeightMm-m){issues.push(issue('ARTWORK_BLEED_FIT','Rotated artwork and bleed do not fit the measured zone'));continue;}
  verified.push({layerId:l.id,artworkId:l.artworkId,sha256:inspected.sha256,widthPx:inspected.width,heightPx:inspected.height,effectiveDpi:placement.dpi,processCode:zone.processCode,surfaceId:l.surfaceId});
 }
 if(storageRecords.length!==layers.length||new Set(layers.map(l=>l.artworkId)).size!==layers.length)issues.push(issue('ARTWORK_RECORD_COVERAGE','Each artwork must have a distinct exact storage attestation'));
 if(issues.length)return denied(issues);
 return {artworkEvidenceReady:true,productionApproved:false,checkoutEnabled:false,machineOutput:null,artworks:verified,issues:[]};
}
