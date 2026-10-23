/** Objective 34H: intentionally ephemeral, client-only product preview state.
 * This module does not persist, upload, authenticate, price, or authorize commerce.
 */
import {MANIFEST_BY_ID,PRODUCT_MANIFESTS} from './tj34i-src-catalog.js';
import {normalizePreviewSelection} from './tj34i-src-preview-product-options.js';
import {validateComposition} from './tj34i-src-core.js';
import {buildPreviewDesignSummary} from './tj34i-src-preview-design-summary.js';
import {resolvePreviewEntry} from './tj34i-src-preview-entry.js';
const own=(o,k)=>Object.prototype.hasOwnProperty.call(o,k);
const fail=code=>{throw new Error(code);};
// Objective 34T: reject invisible or bidirectionally spoofed wording at BOTH
// entry and review boundaries. Preserve legitimate RTL scripts, combining accents
// and emoji ZWJ sequences. This is visual-integrity validation, not moderation.
const UNSAFE_STATIC_TEXT=/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\u00AD\u061C\u200B\u200E\u200F\u202A-\u202E\u2060\u2066-\u2069\uFEFF]/u;
const wellFormedStaticText=value=>{
 for(let i=0;i<value.length;i++){
  const code=value.charCodeAt(i);
  if(code>=0xD800&&code<=0xDBFF){
   if(i+1>=value.length||value.charCodeAt(i+1)<0xDC00||value.charCodeAt(i+1)>0xDFFF)return false;
   i++;
  }else if(code>=0xDC00&&code<=0xDFFF)return false;
 }
 return true;
};
const assertStaticText=value=>{
 if(typeof value!=='string')fail('INVALID_TEXT');
 const text=value.trim();
 if(!text||text.length>200||UNSAFE_STATIC_TEXT.test(text)||
    !wellFormedStaticText(text)||!/[\p{L}\p{N}\p{P}\p{S}]/u.test(text))fail('INVALID_TEXT');
 return text;
};
export const STATIC_PREVIEW_CAPABILITIES=Object.freeze({
 mode:'EPHEMERAL_CLIENT_ONLY',backendRequired:false,hostedAuthentication:false,
 privateDraftSave:false,artworkUpload:false,modelUpload:false,tabRecovery:false,
 authenticatedRevisions:false,customerStorage:false,priceVerified:false,
 manufacturingApproved:false,cartEnabled:false,checkoutEnabled:false,orderEnabled:false
});
export function createStaticPreviewState(search=''){
 const entry=resolvePreviewEntry(search);
 const product=MANIFEST_BY_ID[entry.manifestId];
 return {productManifestId:product.id,surfaceId:product.surfaces[0].id,
  previewSelection:normalizePreviewSelection(product),layers:[],selectedLayerId:null,
  nextLayerSequence:1,mode:'3d',review:null,entryStatus:entry.status};
}
const productOf=state=>{
 if(!state||typeof state.productManifestId!=='string'||!own(MANIFEST_BY_ID,state.productManifestId))fail('INVALID_STATE');
 return MANIFEST_BY_ID[state.productManifestId];
};
const validTransform=(product,layers)=>{const errors=validateComposition(product,{layers});if(errors.length)fail('INVALID_COMPOSITION:'+errors[0].code);};
// Defensive boundary for stale or externally reconstructed preview states. A hidden
// layer must never become an edit target merely because its id is still selected.
const activeLayerIndex=(state,{allowEmpty=false}={})=>{
 if(state.selectedLayerId===null && allowEmpty)return -1;
 if(typeof state.selectedLayerId!=='string')fail('NO_SELECTED_LAYER');
 const matches=state.layers.map((layer,index)=>layer.id===state.selectedLayerId?index:-1).filter(index=>index>=0);
 if(matches.length>1)fail('AMBIGUOUS_LAYER_ID');
 if(matches.length===0)fail('UNKNOWN_SELECTED_LAYER');
 if(state.layers[matches[0]].surfaceId!==state.surfaceId)fail('LAYER_NOT_ON_ACTIVE_SURFACE');
 return matches[0];
};
const validateId=(product,id,kind)=>{
 if(typeof id!=='string'||!product[kind].some(v=>v.id===id))fail('UNAVAILABLE_'+kind.toUpperCase());
};
const safeAction=action=>{
 if(!action||typeof action!=='object'||Array.isArray(action)||typeof action.type!=='string')fail('INVALID_ACTION');
 if(!['SELECT_PRODUCT','SELECT_SURFACE','SELECT_COLOR','SELECT_SIZE','ADD_TEXT','SELECT_LAYER','ROTATE_LAYER','SCALE_LAYER','REMOVE_LAYER','SET_MODE','RESET'].includes(action.type))fail('STATIC_PREVIEW_FORBIDDEN_ACTION');
};
export function updateStaticPreview(state,action){
 safeAction(action);
 // Objective 35B: mutations must never normalize or discard a reconstructed
 // invalid preview. Review and accessibility already reject these states; the
 // mutation ingress now shares their fail-closed boundary. Sanitize thrown
 // accessors so private customer input is not reflected in UI error messages.
 let product;
 try{
  product=productOf(state);
  try{assertStaticPreviewIntegrity(state,product);}
  catch{
   // Preserve the pre-existing, safe layer-target error codes used by the
   // editor controls. These are finite constants, never raw customer values.
   // A stale selection may also be repaired by explicitly reselecting a
   // surface, but ONLY if the rest of the preview passes full validation.
   if(action.type==='SELECT_SURFACE'){
    assertStaticPreviewIntegrity({...state,selectedLayerId:null},product);
   }else if(['ROTATE_LAYER','SCALE_LAYER','REMOVE_LAYER','SELECT_LAYER'].includes(action.type)){
    try{activeLayerIndex(state);}
    catch(error){
     if(['AMBIGUOUS_LAYER_ID','UNKNOWN_SELECTED_LAYER','LAYER_NOT_ON_ACTIVE_SURFACE'].includes(error?.message))throw error;
    }
    fail('INVALID_PREVIEW_SURFACE_STATE');
   }else fail('INVALID_PREVIEW_SURFACE_STATE');
  }
 }catch(error){
  if(['AMBIGUOUS_LAYER_ID','UNKNOWN_SELECTED_LAYER','LAYER_NOT_ON_ACTIVE_SURFACE'].includes(error?.message))throw error;
  fail('INVALID_PREVIEW_SURFACE_STATE');
 }
 const next={...state,layers:state.layers.map(l=>({...l})),previewSelection:{...state.previewSelection},review:null};
 switch(action.type){
  case 'SELECT_PRODUCT':{
   if(typeof action.productManifestId!=='string'||!own(MANIFEST_BY_ID,action.productManifestId))fail('UNKNOWN_PRODUCT');
   if(action.productManifestId===product.id)return next;
   if(staticPreviewHasPendingWork(state,'')&&action.confirmed!==true)fail('UNSAVED_WORK_CONFIRMATION_REQUIRED');
   const chosen=MANIFEST_BY_ID[action.productManifestId];
   return {...createStaticPreviewState('?product='+encodeURIComponent(chosen.id)),mode:state.mode,entryStatus:'SELECTED'};
  }
  case 'SELECT_SURFACE':{
   validateId(product,action.surfaceId,'surfaces');next.surfaceId=action.surfaceId;
   // A layer on another surface must never remain an invisible edit target.
   if(!next.layers.some(l=>l.id===next.selectedLayerId&&l.surfaceId===next.surfaceId))next.selectedLayerId=null;
   break;
  }
  case 'SELECT_COLOR':next.previewSelection=normalizePreviewSelection(product,{...next.previewSelection,colorId:action.colorId});break;
  case 'SELECT_SIZE':next.previewSelection=normalizePreviewSelection(product,{...next.previewSelection,sizeId:action.sizeId});break;
  case 'ADD_TEXT':{
   const value=assertStaticText(action.value);
   if(next.layers.length>=25)fail('LAYER_LIMIT');
   const layer={id:`static-layer-${next.nextLayerSequence}`,type:'text',surfaceId:next.surfaceId,
    value,x:.25,y:.38,width:.5,height:.16,rotationDeg:0,scaleFactor:1};
   const layers=[...next.layers,layer];validTransform(product,layers);
   next.layers=layers;next.selectedLayerId=layer.id;next.nextLayerSequence++;break;
  }
  case 'SELECT_LAYER':{
   if(action.layerId!==null){
    const matches=next.layers.filter(l=>l.id===action.layerId);
    if(matches.length>1)fail('AMBIGUOUS_LAYER_ID');
    const layer=matches[0];
    if(!layer)fail('UNKNOWN_LAYER');
    if(layer.surfaceId!==next.surfaceId)fail('LAYER_NOT_ON_ACTIVE_SURFACE');
   }
   next.selectedLayerId=action.layerId;break;
  }
  case 'ROTATE_LAYER':case 'SCALE_LAYER':{
   const i=activeLayerIndex(next);
   const layer=next.layers[i];
   if(action.type==='ROTATE_LAYER'){
    if(!Number.isInteger(action.degrees)||action.degrees < -180||action.degrees>180)fail('INVALID_ROTATION');
    layer.rotationDeg=action.degrees;
   }else{
    if(!Number.isInteger(action.percent)||action.percent<30||action.percent>200)fail('INVALID_SCALE');
    const ratio=(action.percent/100)/(layer.scaleFactor||1),w=layer.width*ratio,h=layer.height*ratio;
    layer.x+=(layer.width-w)/2;layer.y+=(layer.height-h)/2;
    layer.width=w;layer.height=h;layer.scaleFactor=action.percent/100;
   }
   validTransform(product,next.layers);break;
  }
  case 'REMOVE_LAYER':{
   const i=activeLayerIndex(next,{allowEmpty:true});
   if(i>=0)next.layers.splice(i,1);
   next.selectedLayerId=null;break;
  }
  case 'SET_MODE':if(!['2d','3d'].includes(action.mode))fail('INVALID_MODE');next.mode=action.mode;break;
  case 'RESET':return createStaticPreviewState('?product='+encodeURIComponent(product.id));
 }
 return next;
}
export function reviewStaticPreview(state){
 const product=productOf(state);
 validTransform(product,state.layers);
 // Strictly unsaved, text-only, no artwork proof, no private identity or commerce.
 if(state.layers.some(l=>l.type!=='text'))fail('STATIC_PREVIEW_FORBIDDEN_LAYER');
 for(const layer of state.layers)assertStaticText(layer.value);
 // Objective 34Z: review must enforce the same complete editor-state binding
 // as surface changes. A reconstructed/stale selection cannot be reviewed just
 // because its geometry happens to fit the product.
 assertStaticPreviewIntegrity(state,product);
 const summary=buildPreviewDesignSummary({productManifestId:product.id,surfaceId:state.surfaceId,
  previewSelection:state.previewSelection,layers:state.layers,
  saved:null,savedSnapshot:null,availableArtworkIds:[],importedModelPresent:false});
 // Concept-only, redacted per-surface counts prevent front/back review confusion.
 // Never return customer wording, layer IDs, artwork bytes or owner identity.
 const surfaceLayerCounts=product.surfaces.map(surface=>({
  surfaceLabel:surface.label,layerCount:state.layers.filter(layer=>layer.surfaceId===surface.id).length
 })).filter(surface=>surface.layerCount>0);
 return {...summary,surfaceLayerCounts};
}
/** A safe UI readiness projection. The review itself remains the authority for
 * validating a temporary concept; no private state or raw exception is exposed. */
export function staticPreviewReviewAvailability(state){
 try{reviewStaticPreview(state);return {ready:true,reason:null};}
 catch(error){return {ready:false,reason:error?.message==='INVALID_LAYERS' &&
  Array.isArray(state?.layers) && state.layers.length===0?'ADD_LETTERING':'INVALID_PREVIEW'};}
}
/** 34S: discard guards include committed layers, unadded private wording AND
 * changed illustrative color/size selections. Default choices are not work.
 * Fail closed on malformed/forged state, and never reflect customer values.
 * This remains an ephemeral UI/contract guard, NOT hosted authorization. */
export function staticPreviewHasPendingWork(state,textDraft){
 try{
  if(!state||typeof textDraft!=='string')return true;
  const product=productOf(state);
  // Objective 35B: an invalid empty editor is NOT safe to discard silently.
  // Validate before the quick pending-work shortcut; no identity, draft text
  // or exception is exposed. This remains client-only, not hosted auth.
  assertStaticPreviewIntegrity(state,product);
  if(state.layers.length>0||textDraft.length>0)return true;
  const selection=state.previewSelection;
  if(!selection||typeof selection!=='object'||Array.isArray(selection)||
    !own(selection,'colorId')||!own(selection,'sizeId'))return true;
  const current=normalizePreviewSelection(product,selection);
  const defaults=normalizePreviewSelection(product);
  return current.colorId!==defaults.colorId||current.sizeId!==defaults.sizeId;
 }catch{return true;}
}
/** Objective 34U: an unadded text composer belongs to the surface where it
 * was typed. Changing surfaces must not silently place that private wording on
 * a different print zone. This is an ephemeral UI decision, not authorization.
 * Return only finite status codes; never echo or store the customer's wording.
 */
/** Objective 34Y: the surface transition guard must not treat a reconstructed,
 * malformed or unsupported static preview as safe merely because its geometry
 * happens to validate. It is a client-only integrity check, NOT server auth.
 * Never echo the draft, layer IDs, customer wording or exception messages.
 */
/** Objective 34Z: one shared fail-closed state boundary for both review and
 * surface navigation. This validates ephemeral UI consistency, not identity,
 * production approval, Shopify authorization, or checkout. */
const assertStaticPreviewIntegrity=(state,product)=>{
 if(!Array.isArray(state.layers)||state.layers.length>25||
   !['2d','3d'].includes(state.mode)||
   !Number.isSafeInteger(state.nextLayerSequence)||state.nextLayerSequence<1)
  fail('INVALID_PREVIEW_SURFACE_STATE');
 validateId(product,state.surfaceId,'surfaces');
 const selection=state.previewSelection;
 if(!selection||typeof selection!=='object'||Array.isArray(selection)||
   Object.keys(selection).length!==2||!own(selection,'colorId')||!own(selection,'sizeId'))
  fail('INVALID_PREVIEW_SURFACE_STATE');
 normalizePreviewSelection(product,selection);
 validTransform(product,state.layers);
 for(const layer of state.layers){
  if(layer.type!=='text')fail('INVALID_PREVIEW_SURFACE_STATE');
  // Objective 35C: a reviewable layer must match the transforms that THIS
  // ephemeral editor can actually produce. Generic composition checks allow
  // NaN/fractional rotation and never inspect scaleFactor; a forged factor
  // can make the next customer resize jump or fail despite valid geometry.
  // The static editor creates centered .5 x .16 lettering and only scales
  // around that center. These are client consistency invariants, NOT proof
  // of a physical print size, GLB calibration or manufacturing approval.
  if(!Number.isInteger(layer.rotationDeg)||Math.abs(layer.rotationDeg)>180||
     typeof layer.scaleFactor!=='number'||!Number.isFinite(layer.scaleFactor)||
     layer.scaleFactor<.3||layer.scaleFactor>2||
     Math.abs(layer.width-.5*layer.scaleFactor)>1e-9||
     Math.abs(layer.height-.16*layer.scaleFactor)>1e-9||
     Math.abs(layer.x+layer.width/2-.5)>1e-9||
     Math.abs(layer.y+layer.height/2-.46)>1e-9)
   fail('INVALID_PREVIEW_SURFACE_STATE');
  assertStaticText(layer.value);
  if(!/^static-layer-[1-9]\d*$/.test(layer.id))fail('INVALID_PREVIEW_SURFACE_STATE');
  const sequence=Number(layer.id.slice('static-layer-'.length));
  if(!Number.isSafeInteger(sequence)||sequence>=state.nextLayerSequence)
   fail('INVALID_PREVIEW_SURFACE_STATE');
 }
 if(state.selectedLayerId!==null)activeLayerIndex(state);
};
export function staticPreviewSurfaceDraftTransition(state,textDraft,targetSurfaceId){
 try{
  const product=productOf(state);
  if(typeof textDraft!=='string')fail('INVALID_PREVIEW_SURFACE_STATE');
  assertStaticPreviewIntegrity(state,product);
  validateId(product,targetSurfaceId,'surfaces');
  if(targetSurfaceId===state.surfaceId)return 'SAME_SURFACE';
  return textDraft.length>0?'DISCARD_CONFIRMATION_REQUIRED':'SAFE';
 }catch{return 'REJECTED';}
}
export function staticPreviewProductOptions(){return PRODUCT_MANIFESTS.map(({id,label,category})=>({id,label,category}));}

/** Objective 34Q: screen-reader description derived ONLY from approved catalog
 * labels and counts. Customer wording, identifiers, owner data and action input
 * are never reflected in accessibility announcements. Malformed state fails
 * closed to a neutral description rather than throwing into the DOM. */
export function staticPreviewAccessibilitySummary(state){
 try{
  const product=productOf(state);
  // Objective 35A: accessibility status and live action announcements must
  // never certify a reconstructed state that review/surface guards reject.
  // Share the exact ephemeral integrity boundary; do not echo private values.
  assertStaticPreviewIntegrity(state,product);
  if(!Array.isArray(state.layers)||!['2d','3d'].includes(state.mode))fail('INVALID_STATE');
  const surface=product.surfaces.find(s=>s.id===state.surfaceId);
  if(!surface)fail('UNKNOWN_SURFACE');
  validTransform(product,state.layers);
  if(state.layers.some(l=>l.type!=='text'))fail('FORBIDDEN_LAYER');
  for(const layer of state.layers)assertStaticText(layer.value);
  const active=state.layers.filter(l=>l.surfaceId===surface.id);
  const selected=state.selectedLayerId===null?-1:active.findIndex(l=>l.id===state.selectedLayerId);
  if(state.selectedLayerId!==null&&(selected<0||active.filter(l=>l.id===state.selectedLayerId).length!==1))fail('INVALID_SELECTION');
  const count=active.length,total=state.layers.length;
  const description=`${product.label}. ${surface.label} design surface. ${state.mode.toUpperCase()} concept preview. `+
   `${count} lettering ${count===1?'layer':'layers'} on this surface; ${total} total. `+
   (selected>=0?`Layer ${selected+1} selected on this surface.`:'No lettering layer selected.');
  return Object.freeze({valid:true,description,productLabel:product.label,surfaceLabel:surface.label,
   activeLayerCount:count,totalLayerCount:total,mode:state.mode});
 }catch{return Object.freeze({valid:false,description:'Concept status unavailable. No changes were saved.'});}
}
/** Stable, finite announcements; never echo arbitrary text or exception details.
 * Continuous range input is intentionally silent because its native slider
 * already announces its current value. */
export function staticPreviewActionAnnouncement(action,state){
 if(!action||typeof action.type!=='string')return 'Preview change unavailable.';
 const view=staticPreviewAccessibilitySummary(state);
 if(!view.valid)return 'Preview change unavailable.';
 // Only healthy continuous controls stay silent; invalid state must not
 // suppress the neutral failure announcement.
 if(action.type==='ROTATE_LAYER'||action.type==='SCALE_LAYER')return null;
 const count=`${view.activeLayerCount} lettering ${view.activeLayerCount===1?'layer':'layers'} on this surface.`;
 switch(action.type){
  case 'SELECT_PRODUCT':return `${view.productLabel} selected. Previous temporary concept cleared.`;
  case 'SELECT_SURFACE':return `${view.surfaceLabel} surface selected. ${count}`;
  case 'ADD_TEXT':return `Lettering added to ${view.surfaceLabel}. ${count}`;
  case 'REMOVE_LAYER':return `Selected lettering removed from ${view.surfaceLabel}. ${count}`;
  case 'SELECT_LAYER':return `Lettering selection updated on ${view.surfaceLabel}.`;
  case 'SELECT_COLOR':return 'Illustrative color changed. Not a manufacturing color selection.';
  case 'SELECT_SIZE':return 'Illustrative size or format changed. Not an inventory selection.';
  case 'SET_MODE':return `${view.mode.toUpperCase()} concept preview selected.`;
  case 'RESET':return 'Temporary design cleared. Nothing was saved or purchased.';
  default:return 'Preview change unavailable.';
 }
}
export function staticPreviewErrorAnnouncement(error){
 const code=typeof error?.message==='string'?error.message:'';
 if(code==='INVALID_TEXT')return 'Enter 1 to 200 characters of wording without control characters.';
 if(code==='LAYER_LIMIT')return 'This concept supports up to 25 lettering layers.';
 if(code.startsWith('INVALID_COMPOSITION:'))return 'That change does not fit the conceptual design area.';
 if(code==='UNSAVED_WORK_CONFIRMATION_REQUIRED')return 'Confirm before discarding your temporary concept.';
 return 'That change could not be applied. Your concept remains unchanged.';
}
