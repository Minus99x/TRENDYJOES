/**
 * Objective 20: strict OFFLINE manufacturing geometry evidence boundary.
 * Imported GLBs are previews, never approved models. No physical dimensions are
 * invented; a separately reviewed calibration and model approval are required.
 * This module never produces print files, authorizes sales, or enables checkout.
 */
import {createHash} from 'node:crypto';
import {reviewManufacturingProfile} from './manufacturing-review.mjs';
import {inspectGlb} from './model-assets.mjs';
import {rotatedBounds} from './core.mjs';

const issue=(code,message)=>({code,message});
const isPlain=v=>v!==null&&typeof v==='object'&&!Array.isArray(v)&&[Object.prototype,null].includes(Object.getPrototypeOf(v));
const exact=(v,keys)=>isPlain(v)&&Object.keys(v).sort().join('|')===[...keys].sort().join('|');
const finite=n=>typeof n==='number'&&Number.isFinite(n);
const positive=n=>finite(n)&&n>0;
const text=v=>typeof v==='string'&&v.trim().length>0&&v.length<=300;
const sha=/^[0-9a-f]{64}$/;
const profileKeys=['schema','shop','productGid','variantGid','manifestId','blankSku','modelSha256','mmPerModelUnit','physicalBoundsMm','toleranceMm','measuredBy','measuredAt','evidenceReference','status'];
const approvalKeys=['schema','reviewId','revision','issuedAtMs','expiresAtMs','reviewerId','shop','productGid','variantGid','manifestId','blankSku','modelSha256','geometryProfileSha256','signature'];
const dateValid=(s,now)=>typeof s==='string'&&/^\d{4}-\d\d-\d\d$/.test(s)&&!Number.isNaN(Date.parse(s+'T00:00:00Z'))&&new Date(s+'T00:00:00Z').toISOString().slice(0,10)===s&&Date.parse(s+'T00:00:00Z')<=now;
const hash=v=>createHash('sha256').update(JSON.stringify(v)).digest('hex');
const area=poly=>Math.abs(poly.reduce((s,p,i)=>{const q=poly[(i+1)%poly.length];return s+p[0]*q[1]-q[0]*p[1];},0))/2;
const EPS=1e-11;
function split(poly,a,b,sign){
 const inner=[],outer=[];
 if(poly.length<3)return [inner,outer];
 const signed=p=>sign*((b[0]-a[0])*(p[1]-a[1])-(b[1]-a[1])*(p[0]-a[0]));
 for(let i=0;i<poly.length;i++){
  const p=poly[i],q=poly[(i+1)%poly.length],dp=signed(p),dq=signed(q);
  if(dp>=-EPS)inner.push(p);
  if(dp<=EPS)outer.push(p);
  if((dp>EPS&&dq<-EPS)||(dp<-EPS&&dq>EPS)){
   const t=dp/(dp-dq),cross=[p[0]+(q[0]-p[0])*t,p[1]+(q[1]-p[1])*t];
   inner.push(cross);outer.push(cross);
  }
 }
 return [inner,outer];
}
/** Exact polygon subtraction (subject to float precision): rectangle minus UV triangles.
 * Unlike point sampling, this detects narrow UV gaps and uncovered strips.
 * Conservative axis-aligned bounds include all rotated artwork pixels.
 */
export function uvRectangleCovered(bounds,triangles){
 if(!bounds||![bounds.left,bounds.top,bounds.right,bounds.bottom].every(finite)||bounds.right<=bounds.left||bounds.bottom<=bounds.top||!Array.isArray(triangles)||triangles.length>4096)return false;
 let remaining=[[[bounds.left,bounds.top],[bounds.right,bounds.top],[bounds.right,bounds.bottom],[bounds.left,bounds.bottom]]];
 for(const tri of triangles){
  if(!Array.isArray(tri)||tri.length!==3||tri.some(p=>!Array.isArray(p)||p.length!==2||p.some(x=>!finite(x)||x<0||x>1)))return false;
  const cross=(tri[1][0]-tri[0][0])*(tri[2][1]-tri[0][1])-(tri[1][1]-tri[0][1])*(tri[2][0]-tri[0][0]);
  if(Math.abs(cross)<EPS)return false;
  const sign=Math.sign(cross),next=[];
  for(const poly of remaining){
   let inside=poly;
   for(let k=0;k<3;k++){
    const [i,o]=split(inside,tri[k],tri[(k+1)%3],sign);
    if(o.length>=3&&area(o)>EPS)next.push(o);
    inside=i;
    if(inside.length<3||area(inside)<=EPS)break;
   }
  }
  remaining=next;
  if(remaining.length>4096)return false;
  if(!remaining.length)return true;
 }
 return remaining.every(p=>area(p)<=EPS);
}
const denied=(issues,base=null,geometryProfileSha256=null)=>({geometryEvidenceReady:false,productionApproved:false,checkoutEnabled:false,machineOutput:null,profileSha256:base?.profileSha256??null,geometryProfileSha256,issues});

/** Requires two independent review seams: the v0.8 manufacturing profile and
 * a distinct GLB calibration approval. Both are caller-supplied trust boundaries.
 * A mock verifier is only meaningful for offline contract tests.
 */
export async function reviewManufacturingGeometryProfile({shop,productGid,variantGid,manifest,worksheet,design,glbBytes,approvalRecord,verifyApproval,geometryProfile,modelApprovalRecord,verifyModelApproval,artworkEvidenceInput,now=Date.now()}={}){
 const base=await reviewManufacturingProfile({shop,productGid,variantGid,manifest,worksheet,design,glbBytes,approvalRecord,verifyApproval,artworkEvidenceInput,now});
 const issues=[...base.issues];
 if(!base.reviewReady)return denied(issues,base);
 if(!exact(geometryProfile,profileKeys)){issues.push(issue('GEOMETRY_PROFILE_SCHEMA','Exact independent geometry calibration profile required'));return denied(issues,base);}
 const p=geometryProfile;
 if(p.schema!=='TJ-GLB-GEOMETRY-CALIBRATION-1'||p.status!=='DRAFT_REQUIRES_INDEPENDENT_APPROVAL'||!text(p.measuredBy)||!text(p.evidenceReference)||!dateValid(p.measuredAt,now))issues.push(issue('GEOMETRY_PROVENANCE','Unapproved, dated and sourced physical measurement required'));
 if(p.shop!==shop||p.productGid!==productGid||p.variantGid!==variantGid||p.manifestId!==manifest?.id||p.blankSku!==worksheet?.blankSku||p.modelSha256!==base.modelSha256||!sha.test(p.modelSha256||''))issues.push(issue('GEOMETRY_IDENTITY','Calibration must bind exact shop, product, variant, blank and GLB bytes'));
 if(!positive(p.mmPerModelUnit)||p.mmPerModelUnit>1e6||!Array.isArray(p.physicalBoundsMm)||p.physicalBoundsMm.length!==3||p.physicalBoundsMm.some(n=>!finite(n)||n<0||n>5000)||!finite(p.toleranceMm)||p.toleranceMm<0||p.toleranceMm>2)issues.push(issue('GEOMETRY_UNITS','Bounded, explicit physical unit conversion and measurements required'));
 let inspection=null;
 if(glbBytes===undefined||glbBytes===null)issues.push(issue('MODEL_REQUIRED','Actual GLB required even for a flat geometry profile'));
 else try{inspection=await inspectGlb(glbBytes,manifest);}catch{issues.push(issue('MODEL_INVALID','Actual model inspection failed'));}
 if(inspection&&positive(p.mmPerModelUnit)&&Array.isArray(p.physicalBoundsMm)&&p.physicalBoundsMm.length===3&&p.physicalBoundsMm.every(n=>finite(n)&&n>=0)&&finite(p.toleranceMm)&&p.toleranceMm>=0){
  const predicted=inspection.assetBoundsMeters.extent.map(x=>x*p.mmPerModelUnit);
  if(predicted.some((x,i)=>!finite(x)||x>5000||Math.abs(x-p.physicalBoundsMm[i])>Math.min(p.toleranceMm,Math.max(.01,p.physicalBoundsMm[i]*.02))))issues.push(issue('MODEL_SCALE_MISMATCH','GLB transformed bounds disagree with independently measured physical bounds'));
  const dims=p.physicalBoundsMm;
  for(const zone of worksheet.zones){
   if(!zone)continue;
   const kind=manifest.geometry.kind;
   if(kind==='cylinder'){
    const diameter=Math.max(dims[0],dims[2]);
    if(!positive(dims[0])||!positive(dims[2])||!positive(diameter)||!positive(dims[1])||zone.printableHeightMm>dims[1]+p.toleranceMm||!positive(zone.curveCircumferenceMm)||zone.curveCircumferenceMm>Math.PI*diameter+p.toleranceMm)issues.push(issue('MODEL_ZONE_FIT','Curved measured print area exceeds modeled physical envelope'));
   }else if(kind==='flat'){
    const planar=[...dims].sort((a,b)=>b-a);
    if(zone.printableWidthMm>planar[0]+p.toleranceMm||zone.printableHeightMm>planar[1]+p.toleranceMm)issues.push(issue('MODEL_ZONE_FIT','Measured flat print area exceeds modeled physical envelope'));
   }else if(zone.printableWidthMm>dims[0]+p.toleranceMm||zone.printableHeightMm>dims[1]+p.toleranceMm)issues.push(issue('MODEL_ZONE_FIT','Measured print area exceeds modeled physical envelope'));
  }
  const surfaceTriangles=new Map();
  for(const tri of inspection.asset.triangles){
   if(!tri.surfaceId)continue;
   if(!tri.uv||tri.uv.length!==3){issues.push(issue('UV_INVALID','Missing printable UV coordinates'));continue;}
   const a=tri.a,b=tri.b,c=tri.c;
   const ab=b.map((x,i)=>x-a[i]),ac=c.map((x,i)=>x-a[i]);
   const cross=[ab[1]*ac[2]-ab[2]*ac[1],ab[2]*ac[0]-ab[0]*ac[2],ab[0]*ac[1]-ab[1]*ac[0]];
   if(Math.hypot(...cross)<1e-10)issues.push(issue('MODEL_TRIANGLE_DEGENERATE','Printable triangle has no geometric area'));
   if(!surfaceTriangles.has(tri.surfaceId))surfaceTriangles.set(tri.surfaceId,[]);
   surfaceTriangles.get(tri.surfaceId).push(tri.uv);
  }
  for(const layer of design.layers){
   const bounds=rotatedBounds(layer);
   if(!uvRectangleCovered(bounds,surfaceTriangles.get(layer.surfaceId)||[]))issues.push(issue('UV_ARTWORK_GAP',`Artwork ${layer.id} crosses an unmapped UV region`));
  }
 }
 if(issues.length)return denied(issues,base);
 const subject={schema:'TJ-GLB-GEOMETRY-SUBJECT-1',manufacturingProfileSha256:base.profileSha256,
  shop,productGid,variantGid,manifestId:manifest.id,blankSku:worksheet.blankSku,modelSha256:inspection.sha256,
  calibration:Object.fromEntries(profileKeys.map(k=>[k,p[k]]))};
 const geometryProfileSha256=hash(subject);
 const r=modelApprovalRecord;
 if(!exact(r,approvalKeys))issues.push(issue('MODEL_APPROVAL_SCHEMA','Exact independently signed model approval record required'));
 else{
  if(r.schema!=='TJ-GLB-GEOMETRY-REVIEW-1'||!text(r.reviewId)||!text(r.reviewerId)||!text(r.signature)||!Number.isSafeInteger(r.revision)||r.revision<1)issues.push(issue('MODEL_APPROVAL_IDENTITY','Reviewer identity, revision and signature required'));
  if(!Number.isSafeInteger(now)||!Number.isSafeInteger(r.issuedAtMs)||!Number.isSafeInteger(r.expiresAtMs)||r.issuedAtMs>now||r.expiresAtMs<=now||r.expiresAtMs-r.issuedAtMs>30*86400000)issues.push(issue('MODEL_APPROVAL_EXPIRY','Current, bounded review required'));
  if(r.shop!==shop||r.productGid!==productGid||r.variantGid!==variantGid||r.manifestId!==manifest.id||r.blankSku!==worksheet.blankSku||r.modelSha256!==inspection.sha256||r.geometryProfileSha256!==geometryProfileSha256)issues.push(issue('MODEL_APPROVAL_BINDING','Review must bind exact model, measurement, variant and tenant'));
 }
 if(typeof verifyModelApproval!=='function')issues.push(issue('MODEL_VERIFIER_REQUIRED','Independent signed model approval verifier required'));
 if(!issues.length){try{if(await verifyModelApproval(r,subject)!==true)issues.push(issue('MODEL_APPROVAL_REJECTED','Model reviewer rejected signature, role or revocation'));}catch{issues.push(issue('MODEL_APPROVAL_REJECTED','Model reviewer failed closed'));}}
 if(issues.length)return denied(issues,base,geometryProfileSha256);
 return {geometryEvidenceReady:true,productionApproved:false,checkoutEnabled:false,machineOutput:null,
  profileSha256:base.profileSha256,geometryProfileSha256,modelSha256:inspection.sha256,issues:[]};
}
