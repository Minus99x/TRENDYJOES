/** Pure, dependency-free prototype validation. Do not use client validation as a production security gate. */
const KINDS=new Set(['garment','cylinder','irregular','flat','other']);
const PROCESS_CODES=new Set(['UV-DTF','UV-FLAT','UV-ROTARY','DTF-TEXTILE','DTG-TEXTILE','FDM-3D']);
const okNum=n=>typeof n==='number'&&Number.isFinite(n);
const isRect=r=>r&&['x','y','width','height'].every(k=>okNum(r[k]))&&r.x>=0&&r.y>=0&&r.width>0&&r.height>0&&r.x+r.width<=1+1e-8&&r.y+r.height<=1+1e-8;
const fail=(code,message)=>({code,message});
export function validateManifest(p){
 const errors=[];
 if(!p||typeof p!=='object')return [fail('BAD_MANIFEST','Manifest must be an object')];
 if(p.schemaVersion!=='1.0')errors.push(fail('BAD_VERSION','Unsupported manifest version'));
 if(typeof p.id!=='string'||!p.id.trim())errors.push(fail('MISSING_ID','Manifest needs an ID'));
 if(!p.geometry||!KINDS.has(p.geometry.kind)||!p.geometry.subtype)errors.push(fail('BAD_GEOMETRY','Product-specific geometry kind and subtype required'));
 if(!Array.isArray(p.surfaces)||!p.surfaces.length)errors.push(fail('NO_SURFACES','At least one surface is needed'));
 const seen=new Set();
 for(const s of p.surfaces||[]){
  if(typeof s.id!=='string'||!s.id||seen.has(s.id))errors.push(fail('DUPLICATE_SURFACE','Surface IDs must be distinct and nonempty'));
  seen.add(s.id);
  if(!isRect(s.previewRect))errors.push(fail('BAD_SURFACE','Preview surface coordinates must be normalized rectangles'));
  if(!Array.isArray(s.allowableMethods)||s.allowableMethods.some(m=>!PROCESS_CODES.has(m)))errors.push(fail('BAD_PROCESS','Manufacturing method is invalid'));
  if(s.calibrated && !(okNum(s.printableWidthMm)&&s.printableWidthMm>0&&okNum(s.printableHeightMm)&&s.printableHeightMm>0))errors.push(fail('CALIBRATION_INCOMPLETE','Calibrated zones need verified millimeter dimensions'));
 }
 if(!p.manufacturing||!Array.isArray(p.manufacturing.approvedMethods))errors.push(fail('BAD_MANUFACTURING','Manufacturing approval status required'));
 if(!p.commerce||!Array.isArray(p.commerce.variantIds))errors.push(fail('BAD_COMMERCE','Commerce verification fields required'));
 return errors;
}
/** layer positions/sizes are normalized INSIDE one chosen printable surface. */
export function rotatedBounds(layer){
 const {x,y,width,height}=layer;
 const angle=(layer.rotationDeg||0)*Math.PI/180;
 const w=Math.abs(width*Math.cos(angle))+Math.abs(height*Math.sin(angle));
 const h=Math.abs(width*Math.sin(angle))+Math.abs(height*Math.cos(angle));
 return {left:x+width/2-w/2,right:x+width/2+w/2,top:y+height/2-h/2,bottom:y+height/2+h/2};
}
export function validateComposition(product,design){
 const errors=validateManifest(product);
 if(!design||!Array.isArray(design.layers))return [...errors,fail('BAD_DESIGN','Design needs a layers array')];
 const ids=new Set();
 for(const layer of design.layers){
  if(!layer||!['text','artwork'].includes(layer.type)) {errors.push(fail('BAD_LAYER_TYPE','Unsupported design layer'));continue;}
  if(typeof layer.id!=='string'||!layer.id||ids.has(layer.id))errors.push(fail('DUPLICATE_LAYER','Layer IDs must be unique and nonempty'));
  ids.add(layer.id);
  if(!product?.surfaces?.find(s=>s.id===layer.surfaceId))errors.push(fail('INVALID_SURFACE','Layer references an unavailable surface'));
  if(![layer.x,layer.y,layer.width,layer.height].every(okNum)||layer.width<=0||layer.height<=0||!okNum(layer.rotationDeg||0)){
   errors.push(fail('BAD_TRANSFORM','Layer transform must be finite and positive'));continue;
  }
  const b=rotatedBounds(layer);
  if([b.left,b.top].some(n=>n<-.000001)||[b.right,b.bottom].some(n=>n>1.000001))errors.push(fail('OUTSIDE_PRINT_ZONE','A rotated layer extends beyond its chosen surface'));
  if(layer.type==='text' && (typeof layer.value!=='string'||!layer.value.trim()||layer.value.length>200))errors.push(fail('BAD_TEXT','Text must be 1–200 characters'));
  if(layer.type==='artwork' && (!layer.artworkId||typeof layer.artworkId!=='string'))errors.push(fail('MISSING_ARTWORK','Artwork needs a stored asset reference'));
 }
 return errors;
}
export function artworkDpi({sourcePixels,printedMm}){
 if(!okNum(sourcePixels)||!okNum(printedMm)||sourcePixels<=0||printedMm<=0) return null;
 return sourcePixels/(printedMm/25.4);
}
/** Returns separate preview and production gates; preview success is never approval to manufacture. */
export function preflight(product,design){
 const errors=validateComposition(product,design);
 const blockers=[];
 if(!design?.layers?.length)blockers.push(fail('EMPTY_DESIGN','A production design is required'));
 if(product?.lifecycle!=='PRODUCTION_APPROVED')blockers.push(fail('UNAPPROVED_PRODUCT','Product is not approved for production'));
 if(!product?.manufacturing?.materialsVerified)blockers.push(fail('UNTESTED_MATERIALS','Material and equipment acceptance remain pending'));
 if(!product?.commerce?.pricingVerified)blockers.push(fail('UNVERIFIED_PRICING','Verified cost/pricing not available'));
 const used=new Set((design?.layers||[]).map(l=>l.surfaceId));
 for(const s of product?.surfaces||[]){
  if(used.has(s.id)&&(!s.calibrated||!okNum(s.printableWidthMm)||!okNum(s.printableHeightMm)))blockers.push(fail('SURFACE_UNCALIBRATED',`Uncalibrated: ${s.id}`));
 }
 return {previewValid:errors.length===0,productionReady:errors.length===0&&blockers.length===0,errors,blockers};
}
/** This serializer MUST be invoked after authenticated server-side persistence/price checks. */
export function buildShopifyLine({variantGid,designReference,product,design,serverApprovedPrice}){
 const p=preflight(product,design);
 if(!p.productionReady)throw new Error('Production and pricing gates not passed');
 if(!/^gid:\/\/shopify\/ProductVariant\/\d+$/.test(variantGid||'')||!product.commerce.variantIds.includes(variantGid))throw new Error('Variant not verified on product');
 if(!/^TJ-[A-Z0-9-]{8,80}$/.test(designReference||''))throw new Error('Server-issued design reference required');
 if(!Number.isSafeInteger(serverApprovedPrice)||serverApprovedPrice<=0)throw new Error('Authoritative priced amount required in minor currency units');
 return {id:Number(variantGid.split('/').at(-1)),quantity:1,properties:{'Design Reference':designReference}};
}
