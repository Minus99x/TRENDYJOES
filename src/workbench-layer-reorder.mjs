import {assertWorkbenchDraft,nextWorkbenchDraft} from './workbench-draft-state.mjs';
export function reorderWorkbenchLayer(d,id,targetIndex){
 assertWorkbenchDraft(d);const i=d.layers.findIndex(l=>l.id===id);if(i<0||!Number.isInteger(targetIndex)||targetIndex<0||targetIndex>=d.layers.length)throw new RangeError('WORKBENCH_REORDER');
 if(d.layers[i].locked)throw new TypeError('WORKBENCH_LAYER_LOCKED');
 const list=[...d.layers],item=list.splice(i,1)[0];list.splice(targetIndex,0,item);return nextWorkbenchDraft(d,{layers:list});
}
