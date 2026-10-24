import {freezeDraft,assertWorkbenchDraft,workbenchId,workbenchNumber} from './workbench-draft-state.mjs';
const rootKeys=['schema','productId','surfaces','activeSurface','layers','revision','localOnly','manufacturingApproved','checkoutEnabled','priceApproved'];
const layerKeys=['id','kind','surfaceId','x','y','width','height','rotation','color','text','visible','locked'];
export function importWorkbenchSnapshot(json){
 if(typeof json!=='string'||json.length>120000)throw new TypeError('WORKBENCH_IMPORT_TEXT');let o;try{o=JSON.parse(json);}catch{throw new TypeError('WORKBENCH_IMPORT_JSON');}
 if(!o||o.schema!=='TJ-WORKBENCH-SNAPSHOT-1'||Object.keys(o).some(k=>!rootKeys.includes(k))||rootKeys.some(k=>!Object.hasOwn(o,k))||!Array.isArray(o.layers))throw new TypeError('WORKBENCH_IMPORT_SCHEMA');
 if(o.localOnly!==true||o.manufacturingApproved!==false||o.checkoutEnabled!==false||o.priceApproved!==false)throw new TypeError('WORKBENCH_IMPORT_AUTHORITY');
 const draft=freezeDraft({...o,schema:'TJ-WORKBENCH-1'});assertWorkbenchDraft(draft);
 for(const l of draft.layers){if(!l||Object.keys(l).some(k=>!layerKeys.includes(k))||layerKeys.some(k=>!Object.hasOwn(l,k))||!['artwork','shape','text'].includes(l.kind)||!draft.surfaces.includes(l.surfaceId))throw new TypeError('WORKBENCH_IMPORT_LAYER');
 workbenchId(l.id);for(const k of ['x','y','width','height'])workbenchNumber(l[k],{zero:k==='x'||k==='y'});
 if(typeof l.rotation!=='number'||!Number.isFinite(l.rotation)||Math.abs(l.rotation)>360||typeof l.color!=='string'||!/^#[0-9a-fA-F]{6}$/.test(l.color)||typeof l.text!=='string'||l.text.length>2000||(l.kind==='text'&&!l.text.trim())||typeof l.visible!=='boolean'||typeof l.locked!=='boolean')throw new TypeError('WORKBENCH_IMPORT_LAYER_VALUES');}
 return draft;
}
