import {assertWorkbenchDraft} from './workbench-draft-state.mjs';
/** Node-friendly view model; browser must render with textContent, never HTML injection. */
export function buildWorkbenchAriaView(d,{surfaceId=d?.activeSurface}={}){
 assertWorkbenchDraft(d);if(!d.surfaces.includes(surfaceId))throw new TypeError('WORKBENCH_ARIA_SURFACE');const visible=d.layers.filter(l=>l.surfaceId===surfaceId&&l.visible);
 return Object.freeze({heading:`Local concept: ${d.productId}`,surfaceLabel:`Surface ${surfaceId}`,layerCount:visible.length,layerLabels:Object.freeze(visible.map((l,i)=>`${i+1}. ${l.kind} ${l.id}${l.locked?' (locked)':''}`)),summary:`${visible.length} visible layers on ${surfaceId}. No manufacturing or checkout approval.`,localOnly:true});
}
