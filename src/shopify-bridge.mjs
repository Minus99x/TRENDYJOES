/** Shopify Admin product snapshots -> conservative universal manifests.
 * Pure staging adapter: no network requests, authorization, or Shopify writes.
 * A merchant's ENTIRE catalog is supported through configurable families rather than a fixed SKU list.
 */
import {validateManifest,validateComposition,preflight} from './core.mjs';
import {CONCEPT_SWATCHES,CONCEPT_APPAREL_FORMATS} from './catalog.mjs';

const gid=(kind,value)=>typeof value==='string'&&new RegExp(`^gid://shopify/${kind}/[1-9][0-9]*$`).test(value);
const rect=(x,y,width,height)=>({x,y,width,height});
const surface=(id,label,previewRect,method)=>({id,label,previewRect,printableWidthMm:null,printableHeightMm:null,allowableMethods:method?[method]:[],uvRegion:null,calibrated:false});

/** Explicit process profiles for the six existing internal Shopify template types.
 * All surface extents are DESIGN PREVIEWS; NOT measured dimensions or real printer capabilities.
 */
export const TEMPLATE_PROFILES=Object.freeze({
 'draft-template-custom-dtf-transfer':{expectedType:'Made to Order - DTF',skuPrefix:'MTO-DTF-',method:'DTF-TEXTILE',kind:'flat',subtype:'transfer-sheet-unverified',category:'printed-goods',surfaces:[surface('transfer-face','Transfer artwork',rect(.1,.1,.8,.8),'DTF-TEXTILE')]},
 'draft-template-custom-uv-dtf-decal':{expectedType:'Made to Order - UV DTF',skuPrefix:'MTO-UVD-',method:'UV-DTF',kind:'flat',subtype:'decal-sheet-unverified',category:'printed-goods',surfaces:[surface('decal-face','Decal artwork',rect(.1,.1,.8,.8),'UV-DTF')]},
 'draft-template-custom-3d-printed-item':{expectedType:'Made to Order - 3D Printing',skuPrefix:'MTO-3DP-',method:'FDM-3D',kind:'other',subtype:'3d-item-unverified',category:'3d-manufacturing',surfaces:[surface('concept-face','Concept annotation only',rect(.1,.1,.8,.8),'FDM-3D')]},
 'draft-template-ready-to-ship-3d-printed-decor':{expectedType:'In Stock - 3D Printing',skuPrefix:'STK-3DP-',method:'FDM-3D',kind:'other',subtype:'finished-stock-unverified',category:'in-stock',surfaces:[],customizable:false},
 'draft-template-custom-dtg-printed-apparel':{expectedType:'Made to Order - DTG Apparel',skuPrefix:'MTO-DTG-',method:'DTG-TEXTILE',kind:'garment',subtype:'unknown-apparel-blank',category:'apparel',surfaces:[surface('front','Unmeasured front',rect(.3,.25,.4,.45),'DTG-TEXTILE'),surface('back','Unmeasured back',rect(.3,.25,.4,.45),'DTG-TEXTILE')]},
 'draft-template-custom-uv-printed-hard-goods':{expectedType:'Made to Order - UV Hard Goods',skuPrefix:'MTO-UVP-',method:'UV-FLAT',kind:'other',subtype:'unknown-hard-goods-blank',category:'hard-goods',surfaces:[surface('print-face','Unmeasured surface',rect(.25,.25,.5,.5),'UV-FLAT')]}
});

const str=(value,max=160)=>typeof value==='string'&&value.length>0&&value.length<=max;
const error=(code,message)=>({code,message});
function takeNode(raw){return raw?.node??raw;}
export function normalizeShopifyProduct(raw){
 const node=takeNode(raw);const issues=[];
 if(!gid('Product',node?.id))issues.push(error('PRODUCT_GID','Invalid Shopify product identity'));
 if(!str(node?.title,300))issues.push(error('PRODUCT_TITLE','Missing product name'));
 if(!str(node?.handle,220)||!/^[a-z0-9-]+$/.test(node.handle))issues.push(error('PRODUCT_HANDLE','Invalid product handle'));
 if(!['ACTIVE','DRAFT','ARCHIVED'].includes(node?.status))issues.push(error('PRODUCT_STATUS','Unknown product status'));
 const rawVariants=node?.variants?.edges?.map(takeNode)??node?.variants;
 if(!Array.isArray(rawVariants)||!rawVariants.length)issues.push(error('NO_VARIANTS','No Shopify variants available in snapshot'));
 if(node?.variants?.pageInfo?.hasNextPage||node?.variantsCount?.count!==undefined&&node.variantsCount.count!==rawVariants?.length)issues.push(error('PARTIAL_VARIANTS','Incomplete variant data: refuse identity binding'));
 const ids=new Set(),variants=[];
 for(const v of (Array.isArray(rawVariants)?rawVariants:[])){
  if(!gid('ProductVariant',v?.id)||ids.has(v.id)){issues.push(error('VARIANT_GID','Invalid or duplicate variant identity'));continue;}
  ids.add(v.id);
  const n=Number(v.price);
  if(!Number.isFinite(n)||n<0||!/^\d+(?:\.\d{1,2})?$/.test(String(v.price)))issues.push(error('PRICE','Invalid variant price'));
  variants.push({id:v.id,title:v.title??'',sku:v.sku??null,price:v.price??null});
 }
 return {issues,product:{id:node?.id??null,handle:node?.handle??null,title:node?.title??null,status:node?.status??null,
  productType:node?.productType??'',tags:Array.isArray(node?.tags)?node.tags:[],variants}};
}
/** Profiles can be extended per actual SKU or manufacturer, after calibration review.
 * Caller must provide a vetted profile explicitly; never accept input from shopper JSON.
 */
export function createStagingEntry(raw,{profiles=TEMPLATE_PROFILES,assets={}}={}){
 const {product:p,issues}=normalizeShopifyProduct(raw);
 if(issues.length)return {product:p,issues,customizable:false,manifest:null,checkoutEligible:false};
 const profile=profiles[p.handle];
 if(profile&&((profile.expectedType&&p.productType!==profile.expectedType)||(profile.skuPrefix&&p.variants.some(v=>!v.sku?.startsWith(profile.skuPrefix)))))return {product:p,issues:[error('PROCESS_IDENTITY_MISMATCH','Product type and variant SKU must match reviewed process profile')],customizable:false,manifest:null,checkoutEligible:false};
 if(!profile)return {product:p,issues:[error('UNMAPPED_PRODUCT','No reviewed family profile; product stays catalog-only')],customizable:false,manifest:null,checkoutEligible:false};
 if(profile.customizable===false)return {product:p,issues:[],customizable:false,manifest:null,checkoutEligible:false,manufacturingMethod:profile.method};
 const asset=assets[p.id];
 const assetIssues=[];
 if(asset!==undefined){
  if(!asset||typeof asset!=='object'||!/^[a-f0-9]{64}$/.test(asset.sha256||'')||!str(asset.storageKey,240)||!/^[A-Za-z0-9_./-]+$/.test(asset.storageKey)||asset.storageKey.split('/').includes('..')||!Array.isArray(asset.mappedSurfaceIds)||asset.mappedSurfaceIds.some(id=>!profile.surfaces.some(s=>s.id===id)))assetIssues.push(error('ASSET_PROFILE','Unrecognized model asset or surface binding'));
 }
 const modelAsset=assetIssues.length?null:asset?{sha256:asset.sha256,storageKey:asset.storageKey,mappedSurfaceIds:[...asset.mappedSurfaceIds],verificationStatus:'UNVERIFIED'}:null;
 const manifest={schemaVersion:'1.0',previewOptions:{colors:CONCEPT_SWATCHES.map(x=>({...x})),sizes:profile.category==='apparel'?CONCEPT_APPAREL_FORMATS.map(x=>({...x})):[]},id:`shopify-${p.id.split('/').at(-1)}`,label:p.title,category:profile.category,
  geometry:{kind:profile.kind,subtype:profile.subtype,previewShape:null,modelAsset,uvMaps:{}},
  surfaces:structuredClone(profile.surfaces),
  manufacturing:{candidateMethods:profile.method?[profile.method]:[],approvedMethods:[],commissioningStatus:'PRE-COMMISSIONING',materialsVerified:false},
  commerce:{shopifyProductGid:p.id,variantIds:p.variants.map(v=>v.id),pricingVerified:false},lifecycle:'CONCEPT'};
 const manifestErrors=validateManifest(manifest);
 return {product:p,manifest:manifestErrors.length||assetIssues.length?null:manifest,issues:[...assetIssues,...manifestErrors],customizable:true,manufacturingMethod:profile.method,checkoutEligible:false};
}
export function createStagingRegistry(rawProducts,options={}){
 if(!Array.isArray(rawProducts))throw new TypeError('Shopify product snapshot must be an array');
 const entries=rawProducts.map(p=>createStagingEntry(p,options));
 const ids=new Set();for(const entry of entries){if(entry.product.id&&ids.has(entry.product.id)){entry.issues.push(error('DUPLICATE_PRODUCT','Repeated Shopify product identity'));entry.manifest=null;}ids.add(entry.product.id);}
 return {snapshotOnly:true,checkoutEnabled:false,entries};
}
export function inspectStagingDesign({entry,variantGid,design}){
 const issues=[...(entry?.issues||[])];
 if(!entry?.manifest)issues.push(error('UNCONFIGURED','This product has no custom-design manifest'));
 if(!gid('ProductVariant',variantGid)||!entry?.product?.variants.some(v=>v.id===variantGid))issues.push(error('VARIANT_MISMATCH','Variant does not belong to selected Shopify product'));
 if(!entry?.product?.variants.find(v=>v.id===variantGid)?.price||Number(entry.product.variants.find(v=>v.id===variantGid)?.price)<=0)issues.push(error('UNPRICED_VARIANT','Actual Shopify variant has no positive price'));
 const check=entry?.manifest?preflight(entry.manifest,design):{previewValid:false,productionReady:false,errors:[],blockers:[]};
 issues.push(...check.errors);
 if(entry?.manifest){
  const applied=new Set(design?.layers?.map(l=>l.surfaceId));
  for(const id of applied){const surface=entry.manifest.surfaces.find(s=>s.id===id);if(surface&&!surface.allowableMethods.includes(entry.manufacturingMethod))issues.push(error('METHOD_SURFACE_MISMATCH',`Manufacturing route is not enabled for ${id}`));}
 }
 return {previewValid:!!entry?.manifest&&check.previewValid&&!issues.some(i=>!['UNPRICED_VARIANT'].includes(i.code)),
  checkoutEnabled:false,productionReady:false,issues,
  blockers:[error('SHOPIFY_SNAPSHOT_ONLY','Product snapshots are not a verified live checkout session'),
   ...(entry?.product?.status!=='ACTIVE'?[error('DRAFT_OR_INACTIVE','Shopify product is not active')]:[]),
   ...check.blockers]};
}
export function validateProfileCompatibility(entry){return entry?.manifest?validateManifest(entry.manifest):[error('NO_MANIFEST','Product not customizable')];}
