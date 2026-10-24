import {assertWorkbenchDraft,nextWorkbenchDraft,workbenchNumber} from './workbench-draft-state.mjs';
const fields=['x','y','width','height','rotation','color','text'];
export function editWorkbenchLayer(d,id,patch){
 assertWorkbenchDraft(d);if(!patch||typeof patch!=='object'||Array.isArray(patch)||!Object.keys(patch).length||Object.keys(patch).some(k=>!fields.includes(k)))throw new TypeError('WORKBENCH_EDIT_PATCH');
 const current=d.layers.find(l=>l.id===id);if(!current||current.locked)throw new TypeError('WORKBENCH_EDIT_LOCKED');
 const next={...current,...patch};for(const p of ['x','y','width','height'])workbenchNumber(next[p],{zero:p==='x'||p==='y'});
 if(typeof next.rotation!=='number'||!Number.isFinite(next.rotation)||Math.abs(next.rotation)>360||!/^#[0-9a-fA-F]{6}$/.test(next.color)||typeof next.text!=='string'||next.text.length>2000||(next.kind==='text'&&!next.text.trim()))throw new TypeError('WORKBENCH_EDIT_INVALID');
 return nextWorkbenchDraft(d,{layers:d.layers.map(l=>l.id===id?next:l)});
}
