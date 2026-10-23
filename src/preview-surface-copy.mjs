/** Offline design-only operation: duplicate one valid selected layer onto an explicit
 * different concept surface. Every rejection preserves the caller's original array.
 * The copied layer contains only renderable fields, never owner/authorization grants.
 * No physical geometry, production, persistence, or Shopify checkout approval.
 */
import {validateComposition} from './core.mjs';

export function duplicatePreviewLayerToSurface({product,layers,selectedId,sourceSurfaceId,targetSurfaceId,newId,placement="preserve"}={}){
 const denied=reason=>({applied:false,reason,layers});
 if(!Array.isArray(layers)||typeof selectedId!=='string'||
    typeof sourceSurfaceId!=='string'||typeof targetSurfaceId!=='string'||
    sourceSurfaceId===targetSurfaceId||!['preserve','center'].includes(placement)||!/^copy-[A-Za-z0-9_-]{1,88}$/.test(newId||''))return denied('INVALID_ACTION');
 if(!product?.surfaces?.some(s=>s.id===sourceSurfaceId)||
    !product.surfaces.some(s=>s.id===targetSurfaceId))return denied('INVALID_SURFACE');
 if(layers.some(l=>l?.id===newId))return denied('DUPLICATE_LAYER_ID');
 const source=layers.find(l=>l?.id===selectedId);
 if(!source)return denied('NO_SELECTED_LAYER');
 if(source.surfaceId!==sourceSurfaceId)return denied('DIFFERENT_SURFACE');
 if(validateComposition(product,{layers}).length)return denied('INVALID_COMPOSITION');
 // Do not spread source: reject accidental transference of authority-bearing fields.
 const copy={id:newId,type:source.type,surfaceId:targetSurfaceId,
  x:source.x,y:source.y,width:source.width,height:source.height,
  rotationDeg:source.rotationDeg||0,scaleFactor:source.scaleFactor??1};
 if(source.type==='text')copy.value=source.value;
 else if(source.type==='artwork')copy.artworkId=source.artworkId;
 // Center is an EXPLICIT user-selected concept placement, never silent resizing.
 // All transforms remain normalized to the destination surface's preview zone.
 if(placement==='center'){
  copy.x=(1-copy.width)/2;
  copy.y=(1-copy.height)/2;
 }
 const next=[...layers,copy];
 if(validateComposition(product,{layers:next}).length)return denied('TARGET_ZONE_INVALID');
 return {applied:true,reason:'COPIED',layers:next,selectedId:newId,targetSurfaceId,placement};
}
