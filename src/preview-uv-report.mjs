/** Allowlisted concept-only UV diagnostic. Reject partial/malicious inspection data. */
import {checkPreviewArtworkUvFootprint} from './preview-uv-footprint.mjs';
import {validateComposition} from './core.mjs';
const denied=(code)=>({schema:'TJ-CONCEPT-UV-REPORT-1',previewChecked:false,
 issues:[code],productionApproved:false,checkoutEnabled:false});
export function buildConceptUvReport({product,layers,inspection}={}){
 if(!product||!Array.isArray(product.surfaces)||product.surfaces.length>100||
  !Array.isArray(layers)||layers.length>100||!inspection||
  !Array.isArray(inspection.mappedSurfaces)||!Array.isArray(inspection.asset?.triangles)||
  inspection.asset.triangles.length>45000||typeof inspection.sha256!=='string'||
  !/^[a-f0-9]{64}$/.test(inspection.sha256))return denied('INVALID_COMPOSITION_OR_MODEL');
 try{if(validateComposition(product,{layers}).length)return denied('INVALID_COMPOSITION_OR_MODEL');}
 catch{return denied('INVALID_COMPOSITION_OR_MODEL');}
 const ids=product.surfaces.map(s=>s?.id);
 if(ids.some(id=>typeof id!=='string'||!id)||new Set(ids).size!==ids.length||
  inspection.mappedSurfaces.some(id=>!ids.includes(id))||
  new Set(inspection.mappedSurfaces).size!==inspection.mappedSurfaces.length)
  return denied('INVALID_MODEL_SURFACE_MAP');
 if(inspection.asset.triangles.some(t=>!t||typeof t!=='object'||
  (t.surfaceId!==null&&(!ids.includes(t.surfaceId)||!inspection.mappedSurfaces.includes(t.surfaceId)))))
  return denied('INVALID_TRIANGLE_SURFACE');
 if(inspection.mappedSurfaces.some(id=>!inspection.asset.triangles.some(t=>t.surfaceId===id)))
  return denied('MAPPED_SURFACE_WITHOUT_UV_GEOMETRY');
 const details=layers.map(l=>({id:l.id,surfaceId:l.surfaceId,...checkPreviewArtworkUvFootprint(l,inspection)}));
 const issues=[];
 for(const d of details)if(!d.covered)issues.push(`${d.surfaceId}:${d.reason}`);
 for(const id of ids)if(!inspection.mappedSurfaces.includes(id))issues.push(`MISSING_MODEL_MAPPING:${id}`);
 return {schema:'TJ-CONCEPT-UV-REPORT-1',previewChecked:true,
  allSamplePointsCovered:issues.length===0,
  details:details.map(d=>({layerId:d.id,surfaceId:d.surfaceId,covered:d.covered,reason:d.reason,
   sampleCount:d.sampleCount,missingCount:d.missingSamples.length})),issues,
  inspectionSha256:inspection.sha256,productionApproved:false,checkoutEnabled:false};
}
