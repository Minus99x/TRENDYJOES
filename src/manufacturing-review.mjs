/**
 * Server-side OFFLINE manufacturing evidence contract. A review of a profile is
 * not authorization to print, sell, charge, ship, or enable checkout.
 *
 * An injected verifyApproval function is a TRUST BOUNDARY: in production it
 * must verify an independently signed, tenant-scoped reviewer attestation and
 * revocation in a protected registry. This module does not ship that service.
 */
import {createHash} from 'node:crypto';
import {reviewManufacturingGeometry} from './integration-security.mjs';
import {estimateLayerPhysicalPlacement} from './calibration.mjs';
import {inspectGlb} from './model-assets.mjs';
import {reviewManufacturingArtworkEvidence} from './manufacturing-artwork-evidence.mjs';

const issue=(code,message)=>({code,message});
const shaPattern=/^[a-f0-9]{64}$/;
const productPattern=/^gid:\/\/shopify\/Product\/[1-9]\d*$/;
const variantPattern=/^gid:\/\/shopify\/ProductVariant\/[1-9]\d*$/;
const shopPattern=/^[a-z0-9][a-z0-9-]*\.myshopify\.com$/;
const validText=(s,max=300)=>typeof s==='string'&&s.trim().length>0&&s.length<=max;
const finite=n=>typeof n==='number'&&Number.isFinite(n);
const positive=n=>finite(n)&&n>0;
const plain=v=>v!==null&&typeof v==='object'&&!Array.isArray(v)&&[Object.prototype,null].includes(Object.getPrototypeOf(v));
const exactKeys=(v,keys)=>plain(v)&&Object.keys(v).sort().join('|')===[...keys].sort().join('|');
const dateOk=s=>typeof s==='string'&&/^\d{4}-\d\d-\d\d$/.test(s)&&!Number.isNaN(Date.parse(s+'T00:00:00Z'))&&new Date(s+'T00:00:00Z').toISOString().slice(0,10)===s;
const keys=['schema','reviewId','revision','issuedAtMs','expiresAtMs','reviewerId','shop','productGid','variantGid','manifestId','blankSku','modelSha256','profileSha256','signature'];
const zoneKeys=['surfaceId','printableWidthMm','printableHeightMm','blankWidthMm','blankHeightMm','bleedMm','safetyInsetMm','processCode','fixtureReference','curveCircumferenceMm'];
const artworkInputKeys=['ownerId','designId','revision','storageRecords','processPolicies','readPrivateArtwork','verifyStorageAttestation','verifyProcessPolicy'];
const worksheetKeys=['schema','productManifestId','blankSku','measuredBy','sourceDocument','measuredAt','modelSha256','zones','issues','status','manufacturingApproved','checkoutEnabled'];
const hexHash=v=>createHash('sha256').update(JSON.stringify(v)).digest('hex');
const unique=a=>new Set(a).size===a.length;

/** Check a measured draft's complete provenance and geometry; it remains DRAFT. */
function validateWorksheet(worksheet,manifest,issues,now){
 if(!exactKeys(worksheet,worksheetKeys)){issues.push(issue('WORKSHEET_SCHEMA','Unexpected or missing measurement fields'));return false;}
 if(worksheet.schema!=='TJ-CALIBRATION-DRAFT-1'||worksheet.productManifestId!==manifest?.id||worksheet.status!=='DRAFT_REQUIRES_PHYSICAL_VERIFICATION'||worksheet.manufacturingApproved!==false||worksheet.checkoutEnabled!==false||!Array.isArray(worksheet.issues)||worksheet.issues.length){issues.push(issue('WORKSHEET_DRAFT_ONLY','A complete unapproved worksheet is required'));return false;}
 if(!validText(worksheet.blankSku,80)||!validText(worksheet.measuredBy,160)||!validText(worksheet.sourceDocument,400)||!dateOk(worksheet.measuredAt)||Date.parse(worksheet.measuredAt+'T00:00:00Z')>now){issues.push(issue('MEASUREMENT_PROVENANCE','Measurement source, blank, author and nonfuture date required'));return false;}
 if(worksheet.modelSha256!==null&&!shaPattern.test(worksheet.modelSha256)){issues.push(issue('MODEL_DIGEST','Model digest must be SHA-256 or null'));return false;}
 if(!Array.isArray(worksheet.zones)||!worksheet.zones.length||worksheet.zones.length>100){issues.push(issue('ZONE_SET','At least one measured zone is required'));return false;}
 const declared=new Map((manifest?.surfaces||[]).map(s=>[s.id,s]));
 const ids=[];
 for(const z of worksheet.zones){
  if(!exactKeys(z,zoneKeys)){issues.push(issue('ZONE_SCHEMA','Unexpected or missing zone fields'));continue;}
  ids.push(z.surfaceId);
  const surface=declared.get(z.surfaceId);
  if(!surface||!surface.allowableMethods?.includes(z.processCode)||!manifest?.manufacturing?.candidateMethods?.includes(z.processCode))issues.push(issue('ZONE_ROUTE','Zone and manufacturing method must match selected product'));
  if(![z.printableWidthMm,z.printableHeightMm,z.blankWidthMm,z.blankHeightMm].every(positive)||z.blankWidthMm>5000||z.blankHeightMm>5000||z.printableWidthMm>z.blankWidthMm||z.printableHeightMm>z.blankHeightMm)issues.push(issue('ZONE_DIMENSIONS','Measured printable dimensions must fit the physical blank'));
  if(!finite(z.bleedMm)||z.bleedMm<0||z.bleedMm>30||!finite(z.safetyInsetMm)||z.safetyInsetMm<0||2*(z.safetyInsetMm+z.bleedMm)>=Math.min(z.printableWidthMm,z.printableHeightMm))issues.push(issue('ZONE_TOLERANCE','Combined bleed and safe inset invalid'));
  if(!validText(z.fixtureReference,200))issues.push(issue('FIXTURE_EVIDENCE','Fixture traceability required'));
  if(z.curveCircumferenceMm!==null&&(!positive(z.curveCircumferenceMm)||z.curveCircumferenceMm>5000||z.printableWidthMm>z.curveCircumferenceMm))issues.push(issue('WRAP_GEOMETRY','Measured wrap exceeds physical circumference'));
  if(manifest?.geometry?.kind==='cylinder'&&z.curveCircumferenceMm===null)issues.push(issue('WRAP_MEASUREMENT_MISSING','Curved wrap requires measured circumference'));
 }
 if(!unique(ids))issues.push(issue('ZONE_DUPLICATE','Measured surface IDs must be unique'));
 return issues.length===0;
}

/** Return a profile hash for an immutable review subject, not a signature. */
function subjectFor({shop,productGid,variantGid,manifest,worksheet,modelSha256,mappedSurfaces}){
 return {schema:'TJ-MANUFACTURING-SUBJECT-1',shop,productGid,variantGid,manifestId:manifest.id,
  geometry:{kind:manifest.geometry.kind,subtype:manifest.geometry.subtype},
  surfaceMethods:manifest.surfaces.map(s=>({id:s.id,methods:[...s.allowableMethods].sort()})).sort((a,b)=>a.id.localeCompare(b.id)),
  blankSku:worksheet.blankSku,measuredBy:worksheet.measuredBy,sourceDocument:worksheet.sourceDocument,measuredAt:worksheet.measuredAt,
  modelSha256, mappedSurfaces:[...mappedSurfaces].sort(),
  zones:worksheet.zones.map(z=>Object.fromEntries(zoneKeys.map(k=>[k,z[k]]))).sort((a,b)=>a.surfaceId.localeCompare(b.surfaceId))};
}
function recordValid(record,subject,hash,now,issues){
 if(!exactKeys(record,keys)){issues.push(issue('APPROVAL_SCHEMA','Exact external review record required'));return false;}
 if(record.schema!=='TJ-MANUFACTURING-REVIEW-1'||!validText(record.reviewId,100)||!Number.isSafeInteger(record.revision)||record.revision<1||!validText(record.reviewerId,160)||!validText(record.signature,4096))issues.push(issue('REVIEW_IDENTITY','Reviewer, revision and signed record required'));
 if(!Number.isSafeInteger(now)||!Number.isSafeInteger(record.issuedAtMs)||!Number.isSafeInteger(record.expiresAtMs)||record.issuedAtMs>now||record.expiresAtMs<=now||record.expiresAtMs<=record.issuedAtMs||record.expiresAtMs-record.issuedAtMs>90*86400000)issues.push(issue('REVIEW_EXPIRY','Review record must be current and bounded to 90 days'));
 if(record.shop!==subject.shop||record.productGid!==subject.productGid||record.variantGid!==subject.variantGid||record.manifestId!==subject.manifestId||record.blankSku!==subject.blankSku||record.modelSha256!==subject.modelSha256||record.profileSha256!==hash)issues.push(issue('PROFILE_BINDING','Signed record does not match exact tenant, variant, blank, model and measurements'));
 return issues.length===0;
}
/**
 * Offline evidence verification. Even with a trusted verifier, the result is
 * NEVER a production/checkout grant. Missing approvals, actual GLB bytes,
 * UV mapping, physical evidence or reviewer trust all fail closed.
 */
export async function reviewManufacturingProfile({shop,productGid,variantGid,manifest,worksheet,design,glbBytes,approvalRecord,verifyApproval,artworkEvidenceInput,now=Date.now()}={}){
 const issues=[];
 if(!shopPattern.test(shop||'')||!productPattern.test(productGid||'')||!variantPattern.test(variantGid||''))issues.push(issue('SHOPIFY_IDENTITY','Exact shop/product/variant identity required'));
 if(Array.isArray(design?.layers)&&design.layers.length>100)issues.push(issue('LAYER_LIMIT','Manufacturing review limited to 100 layers'));
 try{const base=reviewManufacturingGeometry({manifest,worksheet,design});issues.push(...base.issues);}catch{issues.push(issue('GEOMETRY_INVALID','Untrusted geometry review input rejected'));}
 const worksheetValid=validateWorksheet(worksheet,manifest,issues,now);
 let modelSha256=null,mappedSurfaces=[];
 const requiresGlb=manifest?.geometry?.kind!=='flat';
 if(glbBytes!==undefined&&glbBytes!==null){
  try{
   if(!(glbBytes instanceof Uint8Array||glbBytes instanceof ArrayBuffer))throw Error('GLB_BYTES_REQUIRED');
   const inspected=await inspectGlb(glbBytes,manifest);
   modelSha256=inspected.sha256;mappedSurfaces=inspected.mappedSurfaces;
   if(inspected.triangleCount<1||!inspected.asset?.triangles?.length)issues.push(issue('MODEL_EMPTY','No geometry to inspect'));
   const used=new Set((design?.layers||[]).map(l=>l?.surfaceId));
   for(const id of used){if(!mappedSurfaces.includes(id))issues.push(issue('MODEL_SURFACE_UNMAPPED',`No GLB UV mapping for ${id}`));}
   for(const z of (Array.isArray(worksheet?.zones)?worksheet.zones:[])){if(z?.surfaceId&&!mappedSurfaces.includes(z.surfaceId))issues.push(issue('MODEL_ZONE_UNMAPPED',`Measured zone ${z.surfaceId} lacks GLB UV mapping`));}
   for(const tri of inspected.asset.triangles){
    if(!tri.surfaceId)continue;
    const [a,b,c]=tri.uv||[];
    if(!a||!b||!c||Math.abs((b[0]-a[0])*(c[1]-a[1])-(b[1]-a[1])*(c[0]-a[0]))<1e-9)issues.push(issue('MODEL_UV_DEGENERATE','Zero-area printable UV triangle'));
   }
  }catch(e){issues.push(issue('GLB_REJECTED',`GLB cannot be reviewed: ${e.code||'INVALID_ASSET'}`));}
 }else if(requiresGlb||worksheet?.modelSha256!==null){issues.push(issue('GLB_REQUIRED','Actual inspected model bytes required for this profile'));}
 if(worksheetValid&&worksheet.modelSha256!==modelSha256)issues.push(issue('MODEL_WORKSHEET_BINDING','Measured worksheet must bind exact GLB checksum'));
 if(manifest?.geometry?.modelAsset?.sha256&&manifest.geometry.modelAsset.sha256!==modelSha256)issues.push(issue('MODEL_MANIFEST_BINDING','Selected product model differs from inspected GLB'));
 // No caller-supplied boolean/approval flag can bypass the old artwork hold.
 // The ONLY opt-in path reruns independent private-byte and signed-policy review.
 const artworkLayers=(Array.isArray(design?.layers)?design.layers:[]).filter(l=>l?.type==='artwork');
 if(artworkLayers.length){
  if(!exactKeys(artworkEvidenceInput,artworkInputKeys))issues.push(issue('ARTWORK_EVIDENCE_REQUIRED','Exact private-byte review integration is required'));
  else {
   try{
    const evidence=await reviewManufacturingArtworkEvidence({
     shop,productGid,variantGid,manifest,worksheet,design,now,
     ownerId:artworkEvidenceInput.ownerId,designId:artworkEvidenceInput.designId,revision:artworkEvidenceInput.revision,
     storageRecords:artworkEvidenceInput.storageRecords,processPolicies:artworkEvidenceInput.processPolicies,
     readPrivateArtwork:artworkEvidenceInput.readPrivateArtwork,verifyStorageAttestation:artworkEvidenceInput.verifyStorageAttestation,verifyProcessPolicy:artworkEvidenceInput.verifyProcessPolicy});
    if(!evidence.artworkEvidenceReady)issues.push(...evidence.issues);
   }catch{issues.push(issue('ARTWORK_EVIDENCE_FAILED','Private-byte evidence review failed closed'));}
  }
 }else if(artworkEvidenceInput!==undefined)issues.push(issue('ARTWORK_EVIDENCE_UNEXPECTED','Cannot attach artwork approval to a design without artwork'));
 for(const layer of (Array.isArray(design?.layers)?design.layers:[])){
  if(layer&&worksheet?.zones){const z=Array.isArray(worksheet.zones)?worksheet.zones.find(z=>z?.surfaceId===layer.surfaceId):null;
   if(z&&finite(z.bleedMm)&&z.bleedMm>0){const placement=estimateLayerPhysicalPlacement(worksheet,layer);const b=placement.rotatedBoundsMm;const m=z.safetyInsetMm+z.bleedMm;
    if(!b||b.left<m||b.top<m||b.right>z.printableWidthMm-m||b.bottom>z.printableHeightMm-m)issues.push(issue('BLEED_SAFE_ZONE','Artwork and its required bleed must fit inside measured print zone'));
   }}
 }
 if(issues.length){return {reviewReady:false,evidenceVerified:false,productionApproved:false,checkoutEnabled:false,machineOutput:null,profileSha256:null,modelSha256,issues};}
 const subject=subjectFor({shop,productGid,variantGid,manifest,worksheet,modelSha256,mappedSurfaces});
 const profileSha256=hexHash(subject);
 recordValid(approvalRecord,subject,profileSha256,now,issues);
 if(typeof verifyApproval!=='function')issues.push(issue('TRUSTED_REVIEW_VERIFIER_REQUIRED','External reviewer signature and revocation verifier required'));
 if(!issues.length){
  try{
   // Verifier MUST independently authenticate signature, trusted signer,
   // tenant, exact payload, revocation and reviewId/revision. A test stub is
   // NOT an implementation of that requirement.
   if(await verifyApproval(approvalRecord,subject)!==true)issues.push(issue('REVIEW_NOT_VERIFIED','External reviewer rejected evidence'));
  }catch{issues.push(issue('REVIEW_NOT_VERIFIED','External reviewer failed closed'));}
 }
 return {reviewReady:issues.length===0,evidenceVerified:issues.length===0,
  productionApproved:false,checkoutEnabled:false,machineOutput:null,profileSha256,modelSha256,
  placements:(design.layers||[]).map(l=>({layerId:l.id,...estimateLayerPhysicalPlacement(worksheet,l)})),issues};
}
