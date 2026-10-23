/**
 * Objective 34E: client-side, preview-only design review.
 * No commerce line, price, owner credential, artwork ID, imported model bytes,
 * customer data, or manufacturing authorization may leave this projection.
 * This is not a server-side security decision.
 */
import {MANIFEST_BY_ID} from './tj34i-src-catalog.js';
import {validateComposition} from './tj34i-src-core.js';
import {describePreviewSelection,normalizePreviewSelection} from './tj34i-src-preview-product-options.js';
import {savedDraftMatchesEditor} from './tj34i-src-preview-editor-state.js';
const own=(obj,key)=>Object.prototype.hasOwnProperty.call(obj,key);
const reject=code=>{throw new Error(code);};
const optionKeys=['colorId','sizeId'];
export function buildPreviewDesignSummary({productManifestId,surfaceId,previewSelection,layers,saved=null,savedSnapshot=null,availableArtworkIds=[],importedModelPresent=false},manifests=MANIFEST_BY_ID){
 if(typeof productManifestId!=='string'||!manifests||!own(manifests,productManifestId))reject('UNKNOWN_PRODUCT');
 const product=manifests[productManifestId];
 if(!product||product.id!==productManifestId||typeof product.label!=='string'||!product.label.trim())reject('INVALID_PRODUCT');
 if(typeof surfaceId!=='string'||!product.surfaces?.some(s=>s.id===surfaceId))reject('INVALID_SURFACE');
 if(!previewSelection||typeof previewSelection!=='object'||Array.isArray(previewSelection)||
    Object.keys(previewSelection).length!==2||Object.keys(previewSelection).some(k=>!optionKeys.includes(k)))reject('INVALID_OPTIONS');
 const normalized=normalizePreviewSelection(product,previewSelection);
 if(!Array.isArray(layers)||layers.length===0||layers.length>100)reject('INVALID_LAYERS');
 const errors=validateComposition(product,{layers});
 if(errors.length)reject('INVALID_COMPOSITION');
 if(!Array.isArray(availableArtworkIds)||availableArtworkIds.length>100||availableArtworkIds.some(id=>typeof id!=='string'))reject('INVALID_ARTWORK_PROOF');
 const available=new Set(availableArtworkIds);
 const artwork=layers.filter(l=>l.type==='artwork');
 if(artwork.some(l=>!available.has(l.artworkId)))reject('PRIVATE_ARTWORK_UNAVAILABLE');
 const described=describePreviewSelection(product,normalized);
 const current=savedDraftMatchesEditor({productManifestId,layers,previewSelection:normalized,saved,savedSnapshot});
 const surfaces=[...new Set(layers.map(l=>l.surfaceId))].map(id=>product.surfaces.find(s=>s.id===id).label);
 // Construct an explicit allowlist; never spread design, saved, or private artwork objects.
 return {
  schema:'TJ-PREVIEW-DESIGN-SUMMARY-1',scope:'OFFLINE_PREVIEW_ONLY',
  productManifestId,productLabel:product.label,
  surfaceLabel:product.surfaces.find(s=>s.id===surfaceId).label,
  colorLabel:described.color?.label??'Not specified',formatLabel:described.size?.label??'Not specified',
  designedSurfaces:surfaces,layerCount:layers.length,textLayerCount:layers.length-artwork.length,artworkLayerCount:artwork.length,
  draftState:current?'LOCAL_REVISION_CURRENT':'UNSAVED_PREVIEW',revision:current?saved.revision:null,
  modelStatus:importedModelPresent===true?'IMPORTED_UNVERIFIED':'CONCEPT_UNVERIFIED',
  manufacturingApproved:false,priceApproved:false,shopifyCustomerAuthenticated:false,checkoutEnabled:false,
  cartLine:null,orderId:null,
  blockers:['MANUFACTURING_UNAPPROVED','AUTHORITATIVE_PRICE_UNAVAILABLE','HOSTED_CUSTOMER_AUTH_UNAVAILABLE','CHECKOUT_NOT_CONNECTED']
 };
}
