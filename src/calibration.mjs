/** Physical print calibration WORKSHEET. No numerical defaults. No approval pathway. */
import {artworkDpi,rotatedBounds} from './core.mjs';
const isPositive=n=>typeof n==='number'&&Number.isFinite(n)&&n>0;
const normalize=n=>Math.round(n*100)/100;
const safeText=(s,max=160)=>typeof s==='string'&&s.trim()&&s.length<=max;
const stop=(code,msg)=>({code,message:msg});
/**
 * Records measurable facts supplied by a technician; never mutates manifests.
 * width/height are actual measured, flat artwork dimensions for the selected
 * surface (even if its underlying mesh is curved). Provide source, date, blank.
 */
export function createCalibrationWorksheet(manifest,entries,{blankSku,measuredBy,sourceDocument,measuredAt,modelSha256}={}){
 const issues=[];const byId=new Map((manifest?.surfaces||[]).map(s=>[s.id,s]));
 if(!manifest?.id||!byId.size||byId.size!==manifest.surfaces.length)issues.push(stop('PRODUCT','Unknown or duplicate product surfaces'));
 if(!safeText(blankSku,80))issues.push(stop('BLANK','Exact physical blank SKU required'));
 if(!safeText(measuredBy))issues.push(stop('TECHNICIAN','Measurement author required'));
 if(!safeText(sourceDocument,400))issues.push(stop('SOURCE','Measurement evidence reference required'));
 if(!/^\d{4}-\d\d-\d\d$/.test(measuredAt||'')||!Number.isFinite(Date.parse(measuredAt+'T00:00:00Z'))||new Date(Date.parse(measuredAt+'T00:00:00Z')).toISOString().slice(0,10)!==measuredAt)issues.push(stop('DATE','Valid measurement date required'));
 if(modelSha256!==undefined&&!/^[a-f0-9]{64}$/.test(modelSha256))issues.push(stop('HASH','Model checksum must be SHA-256'));
 if(!Array.isArray(entries)||!entries.length)issues.push(stop('ZONES','At least one measured zone required'));
 const zones=[],used=new Set();
 for(const z of (Array.isArray(entries)?entries:[])){
  if(!z||!byId.has(z.surfaceId)||used.has(z.surfaceId)){issues.push(stop('SURFACE','Unknown or repeated surface'));continue;}
  used.add(z.surfaceId);
  if(!isPositive(z.widthMm)||!isPositive(z.heightMm)||z.widthMm<0.01||z.heightMm<0.01||z.widthMm>4000||z.heightMm>4000){issues.push(stop('SIZE',`Missing or implausible print dimensions for ${z.surfaceId}`));continue;}
  if(!isPositive(z.blankWidthMm)||!isPositive(z.blankHeightMm)||z.blankWidthMm>5000||z.blankHeightMm>5000||z.widthMm>z.blankWidthMm||z.heightMm>z.blankHeightMm)issues.push(stop('BLANK_FIT',`Printable zone must fit measured blank dimensions for ${z.surfaceId}`));
  if(z.bleedMm!==undefined&&(!Number.isFinite(z.bleedMm)||z.bleedMm<0||z.bleedMm>30))issues.push(stop('BLEED','Invalid bleed value'));
  if(z.safetyInsetMm!==undefined&&(!Number.isFinite(z.safetyInsetMm)||z.safetyInsetMm<0||z.safetyInsetMm*2>=Math.min(z.widthMm,z.heightMm)))issues.push(stop('INSET','Invalid safety inset'));
  if(isPositive(z.widthMm)&&isPositive(z.heightMm)&&
   (z.bleedMm??0)+(z.safetyInsetMm??0)>=Math.min(z.widthMm,z.heightMm)/2)
   issues.push(stop('MARGIN_FIT',`Bleed plus safe inset consumes ${z.surfaceId} print zone`));
  const route=z.processCode;
  if(typeof route!=='string'||!byId.get(z.surfaceId).allowableMethods.includes(route))issues.push(stop('PROCESS',`Unapproved/unknown manufacturing method for ${z.surfaceId}`));
  if(!safeText(z.fixtureReference,200))issues.push(stop('FIXTURE',`Equipment/fixture evidence needed for ${z.surfaceId}`));
  if(z.curveCircumferenceMm!==undefined){if(!isPositive(z.curveCircumferenceMm)||z.curveCircumferenceMm>5000||z.widthMm>z.curveCircumferenceMm)issues.push(stop('CURVATURE','Wrap exceeds measured circumference'));}
  zones.push({surfaceId:z.surfaceId,printableWidthMm:normalize(z.widthMm),printableHeightMm:normalize(z.heightMm),blankWidthMm:normalize(z.blankWidthMm||0),blankHeightMm:normalize(z.blankHeightMm||0),bleedMm:normalize(z.bleedMm??0),safetyInsetMm:normalize(z.safetyInsetMm??0),processCode:z.processCode,fixtureReference:z.fixtureReference,curveCircumferenceMm:z.curveCircumferenceMm??null});
 }
 return {schema:'TJ-CALIBRATION-DRAFT-1',productManifestId:manifest?.id??null,blankSku,measuredBy,sourceDocument,measuredAt,modelSha256:modelSha256??null,zones,issues,status:issues.length?'INCOMPLETE':'DRAFT_REQUIRES_PHYSICAL_VERIFICATION',manufacturingApproved:false,checkoutEnabled:false};
}
/** Measurement math for positioning and DPI; not a machine-ready print file. */
export function estimateLayerPhysicalPlacement(worksheet,layer,{sourceWidthPx,sourceHeightPx}={}){
 if(!worksheet||worksheet.schema!=='TJ-CALIBRATION-DRAFT-1'||!Array.isArray(worksheet.zones)||
  !Array.isArray(worksheet.issues)||worksheet.issues.length||
  worksheet.manufacturingApproved!==false||worksheet.checkoutEnabled!==false||
  worksheet.status!=='DRAFT_REQUIRES_PHYSICAL_VERIFICATION')return {ok:false,issues:[stop('CALIBRATION','Worksheet incomplete or not draft')]};
 const zone=worksheet.zones.find(z=>z.surfaceId===layer?.surfaceId);
 if(!zone)return {ok:false,issues:[stop('SURFACE','Layer surface not measured')]};
 if(!Number.isFinite(zone.printableWidthMm)||!Number.isFinite(zone.printableHeightMm)||
  zone.printableWidthMm<0.01||zone.printableHeightMm<0.01||zone.printableWidthMm>4000||zone.printableHeightMm>4000||
  !Number.isFinite(zone.safetyInsetMm)||zone.safetyInsetMm<0||
  zone.safetyInsetMm*2>=Math.min(zone.printableWidthMm,zone.printableHeightMm)||
  [sourceWidthPx,sourceHeightPx].some(p=>p!==undefined&&(!Number.isSafeInteger(p)||p<1||p>100000000)))
  return {ok:false,issues:[stop('MEASUREMENTS','Invalid print geometry or source pixel measurements')]};
 if(![layer.x,layer.y,layer.width,layer.height,layer.rotationDeg??0].every(Number.isFinite)||layer.width<=0||layer.height<=0)return {ok:false,issues:[stop('TRANSFORM','Invalid layer dimensions')]};
 const b=rotatedBounds(layer),insetX=zone.safetyInsetMm/zone.printableWidthMm,insetY=zone.safetyInsetMm/zone.printableHeightMm;
 const within=b.left>=insetX&&b.top>=insetY&&b.right<=1-insetX&&b.bottom<=1-insetY;
 const width=layer.width*zone.printableWidthMm,height=layer.height*zone.printableHeightMm;
 const dpiX=isPositive(sourceWidthPx)?artworkDpi({sourcePixels:sourceWidthPx,printedMm:width}):null;
 const dpiY=isPositive(sourceHeightPx)?artworkDpi({sourcePixels:sourceHeightPx,printedMm:height}):null;
 return {ok:within,previewOnly:true,printableWidthMm:width,printableHeightMm:height,
  originMm:{x:layer.x*zone.printableWidthMm,y:layer.y*zone.printableHeightMm},
  rotatedBoundsMm:{left:b.left*zone.printableWidthMm,top:b.top*zone.printableHeightMm,right:b.right*zone.printableWidthMm,bottom:b.bottom*zone.printableHeightMm},
  dpi: dpiX&&dpiY?Math.min(dpiX,dpiY):null,issues:within?[]:[stop('OUTSIDE_SAFE_ZONE','Rotated artwork intersects the measured safe margin')]};
}
