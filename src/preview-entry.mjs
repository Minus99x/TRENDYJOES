/** Strict, preview-only product deep-link contract. No bearer credentials or commerce identifiers in URLs. */
import {MANIFEST_BY_ID,PRODUCT_MANIFESTS} from './catalog.mjs';
const safeId=/^[a-z][a-z0-9-]{0,63}$/;
const own=(obj,key)=>Object.prototype.hasOwnProperty.call(obj,key);
export function resolvePreviewEntry(search,manifests=MANIFEST_BY_ID){
 const fallback=PRODUCT_MANIFESTS[0].id;
 if(typeof search!=='string'||search.length>256)return {status:'INVALID_LINK',manifestId:fallback};
 const query=search.startsWith('?')?search.slice(1):search;
 if(query==='')return {status:'DEFAULT',manifestId:fallback};
 // Decode exactly once; malformed escapes and encoded query separators are not accepted.
 if(/%(?![0-9a-fA-F]{2})/.test(query))return {status:'INVALID_LINK',manifestId:fallback};
 const params=new URLSearchParams(query),pairs=[...params.entries()];
 if(pairs.length!==1||pairs[0][0]!=='product')return {status:'INVALID_LINK',manifestId:fallback};
 const id=pairs[0][1];
 if(!safeId.test(id))return {status:'INVALID_LINK',manifestId:fallback};
 if(!own(manifests,id)||!manifests[id]||manifests[id].id!==id)return {status:'UNKNOWN_PRODUCT',manifestId:fallback};
 return {status:'SELECTED',manifestId:id};
}
export function previewEntryHref(manifestId,manifests=MANIFEST_BY_ID){
 if(typeof manifestId!=='string'||!safeId.test(manifestId)||!own(manifests,manifestId)||manifests[manifestId]?.id!==manifestId)return null;
 return '/demo/?product='+encodeURIComponent(manifestId);
}
