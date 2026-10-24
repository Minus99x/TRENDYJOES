import {assertWorkbenchDraft} from './workbench-draft-state.mjs';import {reviewPreviewSafeArea} from './preview-safe-area.mjs';
export function reviewWorkbenchSafeZone(d,{surfaceId=d?.activeSurface,zoneWidth,zoneHeight,margin=0}={}){
 assertWorkbenchDraft(d);if(!d.surfaces.includes(surfaceId))throw new TypeError('WORKBENCH_SAFE_SURFACE');const layers=d.layers.filter(l=>l.surfaceId===surfaceId&&l.visible),warnings=[];
 for(const l of layers){const r=reviewPreviewSafeArea({zoneWidth,zoneHeight,x:l.x,y:l.y,width:l.width,height:l.height,margin});if(r.warning!=='NONE')warnings.push(Object.freeze({id:l.id,warning:r.warning}));}
 return Object.freeze({schema:'TJ-WORKBENCH-SAFE-ZONE-1',surfaceId,inspectedLayers:layers.length,warnings:Object.freeze(warnings),localOnly:true,manufacturingApproved:false});
}
