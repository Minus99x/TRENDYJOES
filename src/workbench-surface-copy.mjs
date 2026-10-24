import {assertWorkbenchDraft,nextWorkbenchDraft,workbenchId} from './workbench-draft-state.mjs';
/** Duplication requires an explicit separate target surface and new identity. */
export function copyWorkbenchLayerAcrossSurfaces(d,{id,newId,targetSurfaceId}={}){
 assertWorkbenchDraft(d);workbenchId(newId);const source=d.layers.find(l=>l.id===id);if(!source||source.locked||!d.surfaces.includes(targetSurfaceId)||targetSurfaceId===source.surfaceId||d.layers.some(l=>l.id===newId)||d.layers.length>=100)throw new TypeError('WORKBENCH_SURFACE_COPY');
 return nextWorkbenchDraft(d,{layers:[...d.layers,{...source,id:newId,surfaceId:targetSurfaceId,locked:false}]});
}
