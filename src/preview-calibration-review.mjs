/** Non-authorizing calibration worksheet review against exact editor/model context. */
const text=(s,n=400)=>typeof s==='string'&&s.trim().length>0&&s.length<=n;
const finite=x=>typeof x==='number'&&Number.isFinite(x);
const gregorianDate=s=>typeof s==='string'&&/^(?:19|20)\d{2}-\d{2}-\d{2}$/.test(s)&&!Number.isNaN(Date.parse(`${s}T00:00:00Z`))&&new Date(Date.parse(`${s}T00:00:00Z`)).toISOString().slice(0,10)===s;
export function reviewConceptCalibration({worksheet,product,surfaceId,modelSha256=null}={}){
 const issues=[];
 if(!worksheet||worksheet.schema!=='TJ-CALIBRATION-DRAFT-1'||!product?.id||
  worksheet.productManifestId!==product.id||worksheet.manufacturingApproved!==false||
  worksheet.checkoutEnabled!==false||worksheet.status!=='DRAFT_REQUIRES_PHYSICAL_VERIFICATION'||
  !Array.isArray(worksheet.issues)||worksheet.issues.length||
  !text(worksheet.blankSku,80)||!text(worksheet.measuredBy,160)||
  !text(worksheet.sourceDocument)||!gregorianDate(worksheet.measuredAt))
  issues.push('CALIBRATION_DRAFT_INVALID');
 const surfaces=Array.isArray(product?.surfaces)?product.surfaces:[];
 const zones=Array.isArray(worksheet?.zones)?worksheet.zones:[];
 const zoneKeys=new Set(['surfaceId','printableWidthMm','printableHeightMm','blankWidthMm','blankHeightMm','bleedMm','safetyInsetMm','processCode','fixtureReference','curveCircumferenceMm']);
 if(zones.some(z=>!z||typeof z!=='object'||Array.isArray(z)||Object.keys(z).some(k=>!zoneKeys.has(k))))issues.push('CALIBRATION_ZONE_UNKNOWN_FIELDS');
 if(!surfaces.some(s=>s?.id===surfaceId)||!zones.length||zones.length>100||
  !zones.some(z=>z?.surfaceId===surfaceId)||
  new Set(zones.map(z=>z?.surfaceId)).size!==zones.length||
  zones.some(z=>!surfaces.some(s=>s?.id===z?.surfaceId)))issues.push('CALIBRATION_SURFACE_MISMATCH');
 if(modelSha256!==null&&(!/^[a-f0-9]{64}$/.test(modelSha256)||worksheet?.modelSha256!==modelSha256))
  issues.push('CALIBRATION_MODEL_MISMATCH');
 if(zones.some(z=>!z||!finite(z.printableWidthMm)||!finite(z.printableHeightMm)||
  !finite(z.blankWidthMm)||!finite(z.blankHeightMm)||
  z.printableWidthMm<0.01||z.printableHeightMm<0.01||
  z.blankWidthMm<z.printableWidthMm||z.blankHeightMm<z.printableHeightMm||
  z.printableWidthMm>4000||z.printableHeightMm>4000||z.blankWidthMm>5000||z.blankHeightMm>5000||
  !finite(z.safetyInsetMm)||z.safetyInsetMm<0||
  !finite(z.bleedMm)||z.bleedMm<0||
  2*(z.bleedMm+z.safetyInsetMm)>=Math.min(z.printableWidthMm,z.printableHeightMm)||
  !text(z.fixtureReference,200)||
  (z.curveCircumferenceMm!==null&&z.curveCircumferenceMm!==undefined&&(!finite(z.curveCircumferenceMm)||z.curveCircumferenceMm<0.01||z.curveCircumferenceMm>5000||z.curveCircumferenceMm<z.printableWidthMm))||
  !surfaces.some(s=>s?.id===z.surfaceId&&Array.isArray(s.allowableMethods)&&s.allowableMethods.includes(z.processCode))))
  issues.push('CALIBRATION_ZONE_UNSAFE');
 return Object.freeze({schema:'TJ-CONCEPT-CALIBRATION-REVIEW-35BF-1',previewOnly:true,
  canEstimatePlacement:issues.length===0,issues:Object.freeze([...issues]),
  physicalVerificationRequired:true,manufacturingApproved:false,checkoutEnabled:false});
}
