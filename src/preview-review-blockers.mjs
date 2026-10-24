/** Deterministic preview warnings. Never convert preview assessments into commerce authority. */
const CODE = Object.freeze({
  raster:'LOW_RASTER_DPI',safeArea:'DESIGN_OUTSIDE_SAFE_AREA',contrast:'LOW_SCREEN_CONTRAST',text:'TEXT_PREVIEW_TRUNCATED',
  model:'IMPORTED_MODEL_UNVERIFIED'
});
export function collectPreviewReviewBlockers({raster=null,safeArea=null,contrast=null,text=null,importedModelPresent=false}={}){
 const warnings=[];
 if(raster!==null){if(raster?.schema!=='TJ-PREVIEW-RASTER-RESOLUTION-1'||raster.manufacturingApproved!==false)throw new TypeError('INVALID_RASTER_REVIEW');if(!raster.meetsPreviewTarget)warnings.push(CODE.raster);}
 if(safeArea!==null){if(safeArea?.schema!=='TJ-PREVIEW-SAFE-AREA-1'||safeArea.manufacturingApproved!==false)throw new TypeError('INVALID_SAFE_AREA_REVIEW');if(!safeArea.fitsSafeArea)warnings.push(CODE.safeArea);}
 if(contrast!==null){if(contrast?.schema!=='TJ-PREVIEW-CONTRAST-1'||contrast.manufacturingApproved!==false)throw new TypeError('INVALID_CONTRAST_REVIEW');if(!contrast.passesAA)warnings.push(CODE.contrast);}
 if(text!==null){if(text?.schema!=='TJ-PREVIEW-TEXT-WRAP-1'||text.manufacturingApproved!==false)throw new TypeError('INVALID_TEXT_REVIEW');if(text.truncated)warnings.push(CODE.text);}
 if(typeof importedModelPresent!=='boolean')throw new TypeError('INVALID_MODEL_REVIEW');
 if(importedModelPresent)warnings.push(CODE.model);
 return Object.freeze({schema:'TJ-PREVIEW-REVIEW-BLOCKERS-1',warnings:Object.freeze(warnings),
  manufacturingApproved:false,priceApproved:false,checkoutEnabled:false,localOnly:true});
}
