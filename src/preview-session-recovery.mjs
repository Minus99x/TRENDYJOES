/** Opt-in, tab-scoped TEXT-ONLY preview recovery. No bearer tokens, private art, or GLB bytes.
 * sessionStorage is NOT trusted: every restored field is revalidated against the local manifest.
 * This is a convenience cache, never authenticated persistence or a manufacturing approval.
 */
import {validateComposition} from './core.mjs';
import {normalizePreviewSelection} from './preview-product-options.mjs';

export const SESSION_KEY='tj-design-works-preview-session-v1';
export const SESSION_TTL_MS=30*60*1000;
const MAX_BYTES=32*1024;
const layerKeys=['id','type','surfaceId','x','y','width','height','rotationDeg','scaleFactor','value'];
const recordKeys=['format','createdAt','expiresAt','productManifestId','surfaceId','previewSelection','layers'];
const own=(o,k)=>Object.prototype.hasOwnProperty.call(o,k);
const exact=(o,keys)=>o!==null&&typeof o==='object'&&!Array.isArray(o)&&Object.keys(o).length===keys.length&&Object.keys(o).every(k=>keys.includes(k));
const fail=(code)=>{throw Object.assign(new Error(code),{code});};
const safeTime=(now)=>Number.isSafeInteger(now)&&now>=0;
function verifyDraft(draft,manifests){
 if(!exact(draft,['productManifestId','surfaceId','previewSelection','layers']))fail('INVALID_SESSION_SCHEMA');
 if(typeof draft.productManifestId!=='string'||!own(manifests,draft.productManifestId))fail('UNKNOWN_PRODUCT');
 const product=manifests[draft.productManifestId];
 if(typeof draft.surfaceId!=='string'||!product.surfaces.some(s=>s.id===draft.surfaceId))fail('INVALID_SURFACE');
 if(!exact(draft.previewSelection,['colorId','sizeId']))fail('INVALID_OPTIONS');
 let selection;
 try{selection=normalizePreviewSelection(product,draft.previewSelection);}catch{fail('INVALID_OPTIONS');}
 if(selection.colorId!==draft.previewSelection.colorId||selection.sizeId!==draft.previewSelection.sizeId)fail('INVALID_OPTIONS');
 if(!Array.isArray(draft.layers)||draft.layers.length>25)fail('INVALID_LAYERS');
 for(const layer of draft.layers){
  if(!exact(layer,layerKeys)||layer.type!=='text'||typeof layer.id!=='string'||!/^layer-[a-zA-Z0-9-]{1,110}$/.test(layer.id)||typeof layer.surfaceId!=='string')fail('UNSAFE_LAYER');
  if(typeof layer.value!=='string'||!layer.value.trim()||layer.value.length>200)fail('UNSAFE_LAYER');
  if(!['x','y','width','height','rotationDeg','scaleFactor'].every(k=>typeof layer[k]==='number'&&Number.isFinite(layer[k])))fail('UNSAFE_LAYER');
  if(layer.scaleFactor<.3||layer.scaleFactor>2||Math.abs(layer.rotationDeg)>180)fail('UNSAFE_LAYER');
 }
 if(validateComposition(product,{layers:draft.layers}).length)fail('INVALID_GEOMETRY');
 return draft;
}
export function encodePreviewSession(state,manifests,{now=Date.now()}={}){
 if(!safeTime(now))fail('INVALID_TIME');
 if(state?.imported||state?.calibration||state?.artGrants?.size||state?.artUrls?.size||state?.layers?.some(l=>l.type!=='text'))fail('PRIVATE_ASSETS_UNSUPPORTED');
 if(!Array.isArray(state?.layers))fail('INVALID_LAYERS');
 const draft={productManifestId:state.product?.id,surfaceId:state.surface,
  previewSelection:{colorId:state.previewSelection?.colorId??null,sizeId:state.previewSelection?.sizeId??null},
  layers:state.layers.map(l=>Object.fromEntries(layerKeys.map(k=>[k,l[k]])))};
 verifyDraft(draft,manifests);
 const raw=JSON.stringify({format:'TJ-TAB-PREVIEW-1',createdAt:now,expiresAt:now+SESSION_TTL_MS,...draft});
 if(new TextEncoder().encode(raw).length>MAX_BYTES)fail('SESSION_TOO_LARGE');
 return raw;
}
export function decodePreviewSession(raw,manifests,{now=Date.now()}={}){
 if(!safeTime(now)||typeof raw!=='string'||new TextEncoder().encode(raw).length>MAX_BYTES)fail('INVALID_SESSION');
 let record;try{record=JSON.parse(raw);}catch{fail('INVALID_SESSION');}
 if(!exact(record,recordKeys)||record.format!=='TJ-TAB-PREVIEW-1'||!safeTime(record.createdAt)||!safeTime(record.expiresAt))fail('INVALID_SESSION_SCHEMA');
 if(record.expiresAt-record.createdAt!==SESSION_TTL_MS||record.createdAt>now+30000||now>=record.expiresAt)fail('SESSION_EXPIRED');
 const draft=Object.fromEntries(['productManifestId','surfaceId','previewSelection','layers'].map(k=>[k,record[k]]));
 return verifyDraft(draft,manifests);
}
export function clearPreviewSession(storage){try{storage.removeItem(SESSION_KEY);return true;}catch{return false;}}
export function savePreviewSession(storage,state,manifests,options){
 try{const raw=encodePreviewSession(state,manifests,options);storage.setItem(SESSION_KEY,raw);return {status:'SAVED'};}
 catch(error){return {status:'UNAVAILABLE',reason:error.code||'STORAGE_DENIED'};}
}
export function loadPreviewSession(storage,manifests,options){
 let raw;try{raw=storage.getItem(SESSION_KEY);}catch{return {status:'UNAVAILABLE',reason:'STORAGE_DENIED'};}
 if(raw===null)return {status:'EMPTY'};
 try{return {status:'AVAILABLE',draft:decodePreviewSession(raw,manifests,options)};}
 catch(error){clearPreviewSession(storage);return {status:'REJECTED',reason:error.code||'INVALID_SESSION'};}
}
