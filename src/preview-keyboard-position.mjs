/** Offline concept-editor keyboard positioning. This is NOT a manufacturing coordinate approval.
 * A rejected move leaves the exact input array and layers untouched.
 */
import {validateComposition} from './core.mjs';
const DIRECTIONS=Object.freeze({left:[-1,0],right:[1,0],up:[0,-1],down:[0,1]});
export function previewNudgeKeyAction(event){
 if(!event || typeof event!=='object'||event.ctrlKey||event.altKey||event.metaKey)return null;
 const direction={ArrowLeft:'left',ArrowRight:'right',ArrowUp:'up',ArrowDown:'down'}[event.key];
 return direction?{direction,step:event.shiftKey?.05:.01}:null;
}
export function nudgePreviewLayer({product,layers,selectedId,surfaceId,direction,step=.01}={}){
 const rejected=(reason)=>({applied:false,reason,layers});
 if(!Array.isArray(layers)||typeof selectedId!=='string'||typeof surfaceId!=='string'||
    !Object.hasOwn(DIRECTIONS,direction)||![.01,.05].includes(step))return rejected('INVALID_ACTION');
 const index=layers.findIndex(l=>l?.id===selectedId);
 if(index<0)return rejected('NO_SELECTED_LAYER');
 const original=layers[index];
 if(original.surfaceId!==surfaceId)return rejected('DIFFERENT_SURFACE');
 if(validateComposition(product,{layers}).length)return rejected('INVALID_COMPOSITION');
 const [dx,dy]=DIRECTIONS[direction];
 const moved={...original,x:Number((original.x+dx*step).toFixed(6)),y:Number((original.y+dy*step).toFixed(6))};
 const next=layers.map((layer,i)=>i===index?moved:layer);
 if(validateComposition(product,{layers:next}).length)return rejected('ZONE_BOUNDARY');
 return {applied:true,reason:'MOVED',layers:next};
}
