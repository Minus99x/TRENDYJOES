/** Local explicit export, allowlisted and non-authorizing. Never includes asset tokens. */
import {validateComposition} from './core.mjs';
import {normalizePreviewSelection} from './preview-product-options.mjs';
import {validateLocalModelInspection} from './preview-model-receipt.mjs';
const deny=code=>{throw Object.assign(new Error(code),{code});};
export function buildPrivateConceptDesignEvidence({product,surfaceId,previewSelection,layers,availableArtworkIds=[],inspection=null}={}){
 if(!product?.surfaces?.some(s=>s.id===surfaceId)||!Array.isArray(layers)||!layers.length||layers.length>100||
  !Array.isArray(availableArtworkIds)||availableArtworkIds.some(x=>typeof x!=='string')||
  validateComposition(product,{layers}).length)deny('DESIGN_EVIDENCE_INVALID');
 let normalized;try{normalized=normalizePreviewSelection(product,previewSelection);}catch{deny('DESIGN_OPTIONS_INVALID');}
 // Do not embed local model triangle buffers, GLB bytes, origin paths or authorizations.
 // The inspection receipt is strictly checked before allowlisting the summary.
 const model=inspection===null?null:validateLocalModelInspection(inspection,product);
 const grants=new Set(availableArtworkIds);
 if(layers.some(l=>l.type==='artwork'&&!grants.has(l.artworkId)))deny('LOCAL_ARTWORK_UNAVAILABLE');
 return {schema:'TJ-LOCAL-CONCEPT-DESIGN-EVIDENCE-1',scope:'PRIVATE_OFFLINE_EXPLICIT_EXPORT',
  productManifestId:product.id,activeSurfaceId:surfaceId,
  previewSelection:{colorId:normalized.colorId??null,sizeId:normalized.sizeId??null},
  modelInspection:model===null?null:{sha256:model.sha256,byteLength:model.byteLength,triangleCount:model.triangleCount,
   mappedSurfaces:[...model.mappedSurfaces],missingSurfaces:[...model.missingSurfaces],
   status:'IMPORTED_UNVERIFIED',manufacturingApproved:false},
  layers:layers.map(l=>({id:l.id,type:l.type,surfaceId:l.surfaceId,x:l.x,y:l.y,width:l.width,height:l.height,
   rotationDeg:l.rotationDeg??0,scaleFactor:l.scaleFactor??1,
   contentKind:l.type==='text'?'TEXT_REDACTED':'LOCAL_ARTWORK_REDACTED'})),
  privateContentIncluded:false,customerAuthenticated:false,manufacturingApproved:false,
  pricingVerified:false,checkoutEnabled:false,cartLine:null,orderId:null};
}
