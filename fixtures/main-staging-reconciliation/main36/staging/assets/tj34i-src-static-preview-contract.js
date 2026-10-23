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

/** Selective reconciliation of verified Night Watch 35B/35C client-side state guards.
 * The current preview has fixed centered wording, not movable design layers.
 * This supplies NO hosted authorization, saved data or manufacturing approval. */
const assertStaticPreviewIntegrity=(state,product)=>{
 if(!state||!Array.isArray(state.layers)||state.layers.length>25||
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
   if(layer.type!=='text'||
      !Number.isInteger(layer.rotationDeg)||Math.abs(layer.rotationDeg)>180||
      typeof layer.scaleFactor!=='number'||!Number.isFinite(layer.scaleFactor)||
      layer.scaleFactor<.3||layer.scaleFactor>2||
      Math.abs(layer.width-.5*layer.scaleFactor)>1e-9||
      Math.abs(layer.height-.16*layer.scaleFactor)>1e-9||
      Math.abs(layer.x+layer.width/2-.5)>1e-9||
      Math.abs(layer.y+layer.height/2-.46)>1e-9||
      !/^static-layer-[1-9]\d*$/.test(layer.id))
     fail('INVALID_PREVIEW_SURFACE_STATE');
   const seq=Number(layer.id.slice('static-layer-'.length));
   if(!Number.isSafeInteger(seq)||seq>=state.nextLayerSequence)
     fail('INVALID_PREVIEW_SURFACE_STATE');
 }
 if(state.selectedLayerId!==null)activeLayerIndex(state);
};
export function staticPreviewHasPendingWork(state,textDraft){
 try{
  if(typeof textDraft!=='string')return true;
  const product=productOf(state);
  assertStaticPreviewIntegrity(state,product);
  if(state.layers.length>0||textDraft.length>0)return true;
  const defaults=normalizePreviewSelection(product);
  return state.previewSelection.colorId!==defaults.colorId||
         state.previewSelection.sizeId!==defaults.sizeId;
 }catch{return true;}
}

const safeAction=action=>{
 if(!action||typeof action!=='object'||Array.isArray(action)||typeof action.type!=='string')fail('INVALID_ACTION');
 if(!['SELECT_PRODUCT','SELECT_SURFACE','SELECT_COLOR','SELECT_SIZE','ADD_TEXT','SELECT_LAYER','ROTATE_LAYER','SCALE_LAYER','REMOVE_LAYER','SET_MODE','RESET'].includes(action.type))fail('STATIC_PREVIEW_FORBIDDEN_ACTION');
};
export function updateStaticPreview(state,action){
 safeAction(action);
 const product=productOf(state);
 // A stale selection can be repaired only by explicitly changing surfaces;
 // all other mutations reject reconstructed, malformed preview state.
 try{assertStaticPreviewIntegrity(state,product);}
 catch(error){
  if(action.type==='SELECT_SURFACE')
    assertStaticPreviewIntegrity({...state,selectedLayerId:null},product);
  else fail('INVALID_PREVIEW_SURFACE_STATE');
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
   const value=typeof action.value==='string'?action.value.trim():'';
   if(!value||value.length>200||/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/.test(value))fail('INVALID_TEXT');
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
 try{assertStaticPreviewIntegrity(state,product);}catch{fail('INVALID_PREVIEW_SURFACE_STATE');}
 validTransform(product,state.layers);
 // Strictly unsaved, text-only, no artwork proof, no private identity or commerce.
 if(state.layers.some(l=>l.type!=='text'))fail('STATIC_PREVIEW_FORBIDDEN_LAYER');
 return buildPreviewDesignSummary({productManifestId:product.id,surfaceId:state.surfaceId,
  previewSelection:state.previewSelection,layers:state.layers,
  saved:null,savedSnapshot:null,availableArtworkIds:[],importedModelPresent:false});
}
export function staticPreviewProductOptions(){return PRODUCT_MANIFESTS.map(({id,label,category})=>({id,label,category}));}
