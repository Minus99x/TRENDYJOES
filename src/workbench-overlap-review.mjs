import {assertWorkbenchDraft} from './workbench-draft-state.mjs';import {analyzePreviewOverlaps} from './preview-surface-overlap.mjs';
/** Layer coordinates already entered explicitly for current concept; no physical calibration asserted. */
export function reviewWorkbenchOverlaps(d,{surfaceId=d?.activeSurface}={}){
 assertWorkbenchDraft(d);if(!d.surfaces.includes(surfaceId))throw new TypeError('WORKBENCH_OVERLAP_SURFACE');const rectangles=d.layers.filter(l=>l.visible).map(l=>({id:l.id,surfaceId:l.surfaceId,x:l.x,y:l.y,width:l.width,height:l.height}));
 return analyzePreviewOverlaps({surfaceId,rectangles});
}
