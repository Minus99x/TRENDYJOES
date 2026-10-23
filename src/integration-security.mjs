/** Fail-closed offline review contracts; no Shopify cart/order mutation. */
import {validateComposition,validateManifest} from './core.mjs';
import {estimateLayerPhysicalPlacement} from './calibration.mjs';
import {verifyOrderMetadata} from './shopify-intents.mjs';

const issue=(code,message)=>({code,message});
const hex=/^[a-f0-9]{64}$/;
const productPattern=/^gid:\/\/shopify\/Product\/[1-9]\d*$/;
const variantPattern=/^gid:\/\/shopify\/ProductVariant\/[1-9]\d*$/;
const refPattern=/^TJ-[A-F0-9]{24}$/;
const validObj=v=>v!==null&&typeof v==='object'&&!Array.isArray(v);

/** Transport adapters cannot bypass the store's grant and content-integrity controls.
 * For local storage only: remote/signed URL implementations must enforce the same
 * ownership and checksum promises with private buckets and explicit authorization.
 */
export function localArtworkStorageInterface(store){
 if(!store||!['putArtwork','readArtwork','assertGrant','assertArtworkIntegrity'].every(k=>typeof store[k]==='function'))throw Error('STORAGE_INTERFACE_REQUIRED');
 return Object.freeze({
  async upload(bytes,mediaType){return store.putArtwork(bytes,mediaType);},
  async read({artworkId,accessGrant}){const {meta,bytes}=await store.readArtwork(artworkId,accessGrant);
   const integrity=await store.assertArtworkIntegrity(artworkId);
   if(integrity.sha256!==meta.sha256)throw Error('ARTWORK_INTEGRITY_FAILURE');
   return {mediaType:meta.mediaType,bytes,sha256:integrity.sha256};},
  async assertBound({artworkId,accessGrant}){await store.assertGrant(artworkId,accessGrant);return store.assertArtworkIntegrity(artworkId);},
  // No public download URLs, no arbitrary keys or filesystem paths.
  publicUrl(){return null;}
 });
}

/** Validate a hypothetical cart/order line against the exact authenticated binding.
 * A preview binding is always rejected even when all identities match.
 * A signature is evidence of metadata integrity, NEVER evidence of checkout or payment.
 */
export function reviewCommerceLine({line,productGid,variantGid,reference,revision,compositionSha256,secret,authorized=false}={}){
 const issues=[];
 if(authorized!==true)issues.push(issue('NO_PRODUCTION_AUTHORIZATION','Preview-only or unauthenticated context'));
 if(!productPattern.test(productGid||'')||!variantPattern.test(variantGid||'')||!refPattern.test(reference||'')||!Number.isSafeInteger(revision)||revision<1||!hex.test(compositionSha256||''))issues.push(issue('INVALID_EXPECTED_IDENTITY','Trusted binding identities required'));
 if(!validObj(line)||!Number.isSafeInteger(line.quantity)||line.quantity<=0||line.quantity>1000||!Number.isSafeInteger(line.id)||line.id<=0||String(line.id)!==String(variantGid||'').split('/').at(-1))issues.push(issue('CART_LINE_IDENTITY','Cart must match the exact server-bound numeric variant and quantity'));
 const props=line?.properties;
 const expectedKeys=['_TJ Design Reference','_TJ Design Revision','_TJ Product GID','_TJ Variant GID','_TJ Composition SHA256','_TJ Binding HMAC'];
 if(!validObj(props)||Object.keys(props).length!==expectedKeys.length||expectedKeys.some(k=>!Object.hasOwn(props,k)))issues.push(issue('CART_METADATA_KEYS','Expected complete and exclusive private metadata keys'));
 else if(props['_TJ Design Reference']!==reference||props['_TJ Design Revision']!==String(revision)||props['_TJ Product GID']!==productGid||props['_TJ Variant GID']!==variantGid||props['_TJ Composition SHA256']!==compositionSha256||!verifyOrderMetadata(props,secret,{productGid,variantGid}))issues.push(issue('CART_METADATA_SIGNATURE','Invalid, stale or tampered order metadata'));
 return {metadataMatches:issues.filter(x=>x.code!=='NO_PRODUCTION_AUTHORIZATION').length===0,
  acceptedForCheckout:false,acceptedForProduction:false,issues};
}

/** Static manufacturing worksheet review. Does not turn an unapproved worksheet
 * into a calibrated product or authorize any machine operation.
 */
export function reviewManufacturingGeometry({manifest,worksheet,design}={}){
 const issues=[...validateManifest(manifest),...validateComposition(manifest,design)];
 if(!worksheet||worksheet.schema!=='TJ-CALIBRATION-DRAFT-1'||worksheet.productManifestId!==manifest?.id||worksheet.status!=='DRAFT_REQUIRES_PHYSICAL_VERIFICATION'||worksheet.manufacturingApproved!==false||worksheet.checkoutEnabled!==false||!Array.isArray(worksheet.zones)||worksheet.issues?.length)issues.push(issue('WORKSHEET_NOT_VERIFIED','Valid review worksheet required'));
 if(!Array.isArray(design?.layers)||!design.layers.length)issues.push(issue('EMPTY_MANUFACTURING_DESIGN','A manufacturing review needs design layers'));
 const layers=Array.isArray(design?.layers)?design.layers:[];
 const used=new Set(layers.map(l=>l?.surfaceId));
 const ids=new Set();
 const zones=Array.isArray(worksheet?.zones)?worksheet.zones:[];
 for(const zone of zones){
  if(!zone||ids.has(zone.surfaceId)) {issues.push(issue('DUPLICATE_ZONE','Duplicate or invalid calibrated zones'));continue;}
  ids.add(zone.surfaceId);
  const surface=manifest?.surfaces?.find(s=>s.id===zone.surfaceId);
  if(!surface||!surface.allowableMethods?.includes(zone.processCode)||!manifest?.manufacturing?.candidateMethods?.includes(zone.processCode))issues.push(issue('MANUFACTURING_ROUTE','Process not available for measured surface'));
  if(![zone.printableWidthMm,zone.printableHeightMm,zone.blankWidthMm,zone.blankHeightMm].every(n=>Number.isFinite(n)&&n>0)||zone.printableWidthMm>zone.blankWidthMm||zone.printableHeightMm>zone.blankHeightMm||zone.blankWidthMm>5000||zone.blankHeightMm>5000)issues.push(issue('PHYSICAL_BOUNDS','Invalid or oversized measured geometry'));
  if(!Number.isFinite(zone.safetyInsetMm)||zone.safetyInsetMm<0||zone.safetyInsetMm*2>=Math.min(zone.printableWidthMm,zone.printableHeightMm))issues.push(issue('SAFETY_INSET','Invalid safety inset'));
  if(zone.curveCircumferenceMm!==null&&zone.curveCircumferenceMm!==undefined&&(!Number.isFinite(zone.curveCircumferenceMm)||zone.curveCircumferenceMm<=0||zone.printableWidthMm>zone.curveCircumferenceMm))issues.push(issue('CURVED_SURFACE_BOUNDS','Measured wrap exceeds circumference'));
 }
 for(const s of used){if(!ids.has(s))issues.push(issue('MISSING_MEASURED_SURFACE',`Missing physical dimensions for ${s}`));}
 const modelSha=manifest?.geometry?.modelAsset?.sha256;
 if(modelSha&&(!hex.test(modelSha)||worksheet?.modelSha256!==modelSha))issues.push(issue('MODEL_SHA_MISMATCH','Worksheet must identify exact verified model asset'));
 for(const layer of layers){
  if(!layer||!ids.has(layer.surfaceId))continue;
  const placement=estimateLayerPhysicalPlacement(worksheet,layer);
  if(!placement.ok)issues.push(...placement.issues);
 }
 return {reviewReady:issues.length===0,productionApproved:false,checkoutEnabled:false,machineOutput:null,issues};
}
