/**
 * Objective 22: offline integration of immutable design, inspected artwork bytes,
 * measured manufacturing profile, and GLB UV/physical geometry reviews.
 * No Shopify operations, machine files, sale, checkout or production approval.
 * Every injected verifier/registry is a BACKEND TRUST SEAM, not an implementation.
 */
import {createHash,timingSafeEqual} from 'node:crypto';
import {computeArtworkDesignSha256,reviewManufacturingArtworkEvidence} from './manufacturing-artwork-evidence.mjs';
import {reviewManufacturingGeometryProfile} from './manufacturing-geometry-profile.mjs';

const issue=(code,message)=>({code,message});
const plain=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&[Object.prototype,null].includes(Object.getPrototypeOf(x));
const exact=(x,keys)=>plain(x)&&Object.keys(x).sort().join('|')===[...keys].sort().join('|');
const text=(x,max=200)=>typeof x==='string'&&x.length>0&&x.length<=max&&x.trim()===x;
const sha=/^[a-f0-9]{64}$/;
const hash=x=>createHash('sha256').update(JSON.stringify(x)).digest('hex');
const canonical=x=>{
 const visit=(v,depth)=>{
  if(depth>20)throw Error('DEPTH');
  if(v===null||typeof v==='string'||typeof v==='boolean')return v;
  if(typeof v==='number'&&Number.isFinite(v))return v;
  if(Array.isArray(v))return v.map(y=>visit(y,depth+1));
  if(!plain(v))throw Error('NONPLAIN');
  const out=Object.create(null);for(const k of Object.keys(v).sort())out[k]=visit(v[k],depth+1);return out;
 };
 return visit(x,0);
};
const freeze=x=>{if(x&&typeof x==='object'){for(const v of Object.values(x))freeze(v);Object.freeze(x);}return x;};
const snapshotKeys=['schema','shop','productGid','variantGid','manifestId','ownerId','designId','revision','designSha256','status','design'];
const approvalKeys=['schema','reviewId','revision','reviewerId','issuedAtMs','expiresAtMs','shop','productGid','variantGid','ownerId','designId','designRevision','subjectSha256','signature'];
const denied=(issues,extra={})=>({integratedEvidenceReady:false,productionApproved:false,checkoutEnabled:false,machineOutput:null,subjectSha256:null,issues,...extra});
function checkedSnapshot(raw,identity,manifestId){
 if(!exact(raw,snapshotKeys))throw Error('REVISION_SCHEMA');
 const r=freeze(canonical(raw));
 if(r.schema!=='TJ-CURRENT-IMMUTABLE-DESIGN-1'||r.status!=='CURRENT_IMMUTABLE'||
    r.shop!==identity.shop||r.productGid!==identity.productGid||r.variantGid!==identity.variantGid||
    r.ownerId!==identity.ownerId||r.designId!==identity.designId||r.revision!==identity.revision||
    r.manifestId!==manifestId||!sha.test(r.designSha256)||!Array.isArray(r.design?.layers)||
    !r.design.layers.length||r.design.layers.length>100||computeArtworkDesignSha256(r.design)!==r.designSha256)
  throw Error('REVISION_BINDING');
 return r;
}
const eqHash=(a,b)=>sha.test(a||'')&&sha.test(b||'')&&timingSafeEqual(Buffer.from(a,'hex'),Buffer.from(b,'hex'));
/**
 * loadCurrentRevision must query an independently protected CURRENT immutable
 * revision registry, never a caller-owned draft or a self-attested `verified`.
 * A second registry read catches changes during asynchronous verification, but
 * is NOT a substitute for production transactional locking or authorization.
 */
export async function reviewIntegratedManufacturingEvidence(options={}){
 const issues=[];
 const {shop,productGid,variantGid,ownerId,designId,revision,manifest,worksheet,glbBytes,
  approvalRecord,verifyApproval,geometryProfile,modelApprovalRecord,verifyModelApproval,
  storageRecords,processPolicies,readPrivateArtwork,verifyStorageAttestation,verifyProcessPolicy,
  loadCurrentRevision,integratedApprovalRecord,verifyIntegratedApproval,now=Date.now()}=options||{};
 if(Object.hasOwn(options||{},'design')||Object.hasOwn(options||{},'artworkEvidenceReady')||Object.hasOwn(options||{},'geometryEvidenceReady')||Object.hasOwn(options||{},'verified'))
  return denied([issue('CALLER_EVIDENCE_FORBIDDEN','Caller-supplied design or evidence flags cannot authorize integrated review')]);
 if(!text(shop)||!/^gid:\/\/shopify\/Product\/[1-9]\d*$/.test(productGid||'')||!/^gid:\/\/shopify\/ProductVariant\/[1-9]\d*$/.test(variantGid||'')||!text(ownerId)||!text(designId)||!Number.isSafeInteger(revision)||revision<1||!Number.isSafeInteger(now)||!text(manifest?.id))
  return denied([issue('INTEGRATED_IDENTITY','Trusted identity and manifest required')]);
 if(typeof loadCurrentRevision!=='function'||typeof verifyIntegratedApproval!=='function')
  return denied([issue('INTEGRATED_TRUST','Protected current-revision registry and independent integrated approval verifier required')]);
 const identity=Object.freeze({shop,productGid,variantGid,ownerId,designId,revision});
 let current;
 try{current=checkedSnapshot(await loadCurrentRevision(identity),identity,manifest.id);}
 catch{return denied([issue('REVISION_NOT_CURRENT','Missing, stale, mutable, malformed or mismatched server-owned revision')]);}
 let safe;
 try{
  // Clone all untrusted records and binary bytes before awaiting callbacks;
  // callbacks cannot change the subject after an earlier gate has passed.
  safe={manifest:freeze(canonical(manifest)),worksheet:freeze(canonical(worksheet)),
   geometryProfile:freeze(canonical(geometryProfile)),approvalRecord:freeze(canonical(approvalRecord)),
   modelApprovalRecord:freeze(canonical(modelApprovalRecord)),
   storageRecords:freeze(canonical(storageRecords)),processPolicies:freeze(canonical(processPolicies)),
   integratedApprovalRecord:freeze(canonical(integratedApprovalRecord)),
   glbBytes:glbBytes instanceof ArrayBuffer?Buffer.from(new Uint8Array(glbBytes)):
    glbBytes instanceof Uint8Array?Buffer.from(glbBytes):null};
 }catch{return denied([issue('INTEGRATED_INPUT','Untrusted manufacturing or evidence records are malformed')]);}
 if(!safe.glbBytes)return denied([issue('INTEGRATED_MODEL','Inspected GLB bytes required')]);
 const design=current.design;
 const artworkEvidenceInput={ownerId,designId,revision,storageRecords:safe.storageRecords,processPolicies:safe.processPolicies,
  readPrivateArtwork,verifyStorageAttestation,verifyProcessPolicy};
 let geometry;
 try{geometry=await reviewManufacturingGeometryProfile({shop,productGid,variantGid,manifest:safe.manifest,
  worksheet:safe.worksheet,design,glbBytes:safe.glbBytes,approvalRecord:safe.approvalRecord,verifyApproval,
  geometryProfile:safe.geometryProfile,modelApprovalRecord:safe.modelApprovalRecord,verifyModelApproval,
  artworkEvidenceInput,now});}
 catch{return denied([issue('GEOMETRY_REVIEW_FAILED','Integrated geometry and base manufacturing review failed closed')]);}
 if(!geometry.geometryEvidenceReady)return denied(geometry.issues.length?geometry.issues:[issue('GEOMETRY_REJECTED','Geometry evidence incomplete')]);
 let artwork;
 try{artwork=await reviewManufacturingArtworkEvidence({shop,productGid,variantGid,ownerId,designId,revision,
  manifest:safe.manifest,worksheet:safe.worksheet,design,storageRecords:safe.storageRecords,
  processPolicies:safe.processPolicies,readPrivateArtwork,verifyStorageAttestation,verifyProcessPolicy,now});}
 catch{return denied([issue('ARTWORK_REVIEW_FAILED','Artwork evidence failed closed')]);}
 if(!artwork.artworkEvidenceReady)return denied(artwork.issues.length?artwork.issues:[issue('ARTWORK_REJECTED','Artwork evidence incomplete')]);
 // Bind all independently checked gates to one review subject; a policy,
 // signed storage attestation, GLB, worksheet or composition change invalidates it.
 const subject={schema:'TJ-INTEGRATED-MANUFACTURING-SUBJECT-1',shop,productGid,variantGid,ownerId,designId,
  revision,designSha256:current.designSha256,manifestId:safe.manifest.id,blankSku:safe.worksheet.blankSku,
  manufacturingProfileSha256:geometry.profileSha256,geometryProfileSha256:geometry.geometryProfileSha256,
  modelSha256:geometry.modelSha256,
  artworks:artwork.artworks.map(a=>canonical(a)).sort((a,b)=>a.layerId.localeCompare(b.layerId)),
  storageRecordsSha256:hash(safe.storageRecords),processPoliciesSha256:hash(safe.processPolicies)};
 const subjectSha256=hash(subject),r=safe.integratedApprovalRecord;
 if(!exact(r,approvalKeys)||r.schema!=='TJ-INTEGRATED-MANUFACTURING-REVIEW-1'||!text(r.reviewId)||
    !Number.isSafeInteger(r.revision)||r.revision<1||!text(r.reviewerId)||!text(r.signature,4096)||
    !Number.isSafeInteger(r.issuedAtMs)||!Number.isSafeInteger(r.expiresAtMs)||r.issuedAtMs>now||
    r.expiresAtMs<=now||r.expiresAtMs-r.issuedAtMs>7*86400000||
    r.shop!==shop||r.productGid!==productGid||r.variantGid!==variantGid||r.ownerId!==ownerId||
    r.designId!==designId||r.designRevision!==revision||!eqHash(r.subjectSha256,subjectSha256))
  return denied([issue('INTEGRATED_APPROVAL_BINDING','Signed integrated approval must bind all exact evidence and remain current')]);
 try{if(await verifyIntegratedApproval(r,subject)!==true)return denied([issue('INTEGRATED_APPROVAL_REJECTED','Independent integrated reviewer rejected record')]);}
 catch{return denied([issue('INTEGRATED_APPROVAL_REJECTED','Independent integrated verifier unavailable')]);}
 // Recheck after all awaited verifiers: an earlier revision must not be accepted
 // when a new current revision has appeared mid-review.
 try{
  const latest=checkedSnapshot(await loadCurrentRevision(identity),identity,safe.manifest.id);
  if(hash(latest)!==hash(current))throw Error('REVISION_CHANGED');
 }catch{return denied([issue('REVISION_CHANGED_DURING_REVIEW','Current immutable revision changed during evidence review')]);}
 return {integratedEvidenceReady:true,productionApproved:false,checkoutEnabled:false,machineOutput:null,
  subjectSha256,designSha256:current.designSha256,manufacturingProfileSha256:geometry.profileSha256,
  geometryProfileSha256:geometry.geometryProfileSha256,artworkCount:artwork.artworks.length,issues:[]};
}
