import {assertWorkbenchDraft,nextWorkbenchDraft} from './workbench-draft-state.mjs';
export function removeWorkbenchLayer(d,id){assertWorkbenchDraft(d);const l=d.layers.find(l=>l.id===id);if(!l||l.locked)throw new TypeError('WORKBENCH_REMOVE');return nextWorkbenchDraft(d,{layers:d.layers.filter(x=>x.id!==id)});}
