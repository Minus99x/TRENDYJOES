import {assertWorkbenchDraft,nextWorkbenchDraft,workbenchId,workbenchNumber} from './workbench-draft-state.mjs';
const kinds=['text','artwork','shape'];
export function addWorkbenchLayer(d,{id,kind,surfaceId=d?.activeSurface,x=0,y=0,width,height,rotation=0,color='#000000',text=''}={}){
 assertWorkbenchDraft(d);workbenchId(id);workbenchId(surfaceId);if(!d.surfaces.includes(surfaceId)||d.layers.some(l=>l.id===id)||d.layers.length>=100||!kinds.includes(kind))throw new TypeError('WORKBENCH_LAYER');
 workbenchNumber(x,{zero:true});workbenchNumber(y,{zero:true});workbenchNumber(width);workbenchNumber(height);if(typeof rotation!=='number'||!Number.isFinite(rotation)||Math.abs(rotation)>360)throw new RangeError('WORKBENCH_ROTATION');
 if(typeof color!=='string'||!/^#[0-9a-fA-F]{6}$/.test(color)||typeof text!=='string'||text.length>2000)throw new TypeError('WORKBENCH_LAYER_CONTENT');
 if(kind==='text'&&!text.trim())throw new TypeError('WORKBENCH_EMPTY_TEXT');
 return nextWorkbenchDraft(d,{layers:[...d.layers,{id,kind,surfaceId,x,y,width,height,rotation,color,text,visible:true,locked:false}]});
}
