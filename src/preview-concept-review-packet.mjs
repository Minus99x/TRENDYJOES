/** Redacted, local-only quality review. Never a manufacturing certificate or cart token. */
import {buildPrivateConceptDesignEvidence} from './preview-private-design-evidence.mjs';
import {fingerprintConceptEvidence} from './preview-design-fingerprint.mjs';
import {reviewConceptCalibration} from './preview-calibration-review.mjs';
import {estimateLayerPhysicalPlacement} from './calibration.mjs';
import {buildConceptUvReport} from './preview-uv-report.mjs';
export async function buildConceptReviewPacket({product,surfaceId,previewSelection,layers,availableArtworkIds=[],inspection=null,worksheet=null}={}){
 const evidence=buildPrivateConceptDesignEvidence({product,surfaceId,previewSelection,layers,availableArtworkIds,inspection});
 const digest=await fingerprintConceptEvidence(evidence);
 const calibration=worksheet?reviewConceptCalibration({worksheet,product,surfaceId,modelSha256:inspection?.sha256??null}):null;
 const uv=inspection?buildConceptUvReport({product,layers,inspection}):null;
 const issues=[];
 if(!inspection)issues.push('SUPPLIER_MODEL_UNVERIFIED');
 if(!worksheet)issues.push('NO_MEASUREMENT_WORKSHEET');
 else if(!calibration.canEstimatePlacement)issues.push(...calibration.issues);
 if(!uv)issues.push('NO_UV_PREVIEW_REPORT');
 else if(!uv.allSamplePointsCovered)issues.push('UV_PREVIEW_GAPS_OR_UNMAPPED_SURFACES');
 const fit=calibration?.canEstimatePlacement?layers.filter(l=>l.surfaceId===surfaceId).map((l,index)=>{
  const r=estimateLayerPhysicalPlacement(worksheet,l);
  if(!r.ok)issues.push('ARTWORK_OUTSIDE_MEASURED_SAFE_ZONE');
  return {layerOrdinal:index+1,withinMeasuredDraftZone:r.ok===true};
 }):[];
 // Deliberately no operator name, fixture, source documentation, blank SKU,
 // artwork bytes/IDs, price, customer text, or authorization tokens.
 return Object.freeze({schema:'TJ-CONCEPT-REVIEW-PACKET-35BG-1',productManifestId:product.id,
  activeSurfaceId:surfaceId,designSha256:digest.digestSha256,
  modelSha256:inspection?.sha256??null,modelStatus:inspection?'UNVERIFIED_LOCAL_PREVIEW':'NOT_PROVIDED',
  draftCalibrationStatus:calibration?.canEstimatePlacement?'DRAFT_CONTEXT_MATCHED':'NOT_VERIFIED',
  uvSampledCoverage:uv?.allSamplePointsCovered===true,
  layoutFitsDraftZone:fit.length>0&&fit.every(x=>x.withinMeasuredDraftZone),
  layerFit:fit,issues:[...new Set(issues)].sort(),
  privateContentIncluded:false,physicalVerificationRequired:true,
  customerAuthenticated:false,manufacturingApproved:false,checkoutEnabled:false,
  pricingVerified:false,cartLine:null,orderId:null});
}
