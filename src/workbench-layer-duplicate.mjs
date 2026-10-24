import {assertWorkbenchDraft,nextWorkbenchDraft,workbenchId,workbenchNumber} from './workbench-draft-state.mjs';
export function duplicateWorkbenchLayer(d,id,{newId,dx=3,dy=3}={}){
 assertWorkbenchDraft(d);workbenchId(newId);workbenchNumber(Math.abs(dx),{zero:true});workbenchNumber(Math.abs(dy),{zero:true});
 const layer=d.layers.find(l=>l.id===id);if(!layer||layer.locked||d.layers.some(l=>l.id===newId)||d.layers.length>=100)throw new TypeError('WORKBENCH_DUPLICATE');
 const x=layer.x+dx,y=layer.y+dy;workbenchNumber(x,{zero:true});workbenchNumber(y,{zero:true});
 const copy={...layer,id:newId,x,y,locked:false};return nextWorkbenchDraft(d,{layers:[...d.layers,copy]});
}
