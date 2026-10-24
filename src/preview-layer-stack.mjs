/** Immutable z-order changes scoped to one selected surface; no cross-surface edits. */
const validId=(s)=>typeof s==='string'&&s.length>0&&s.length<=120;
export function movePreviewLayer({layers,surfaceId,layerId,direction}={}){
 if(!Array.isArray(layers)||layers.length>100||!validId(surfaceId)||!validId(layerId)||
   !['forward','backward','front','back'].includes(direction)||
   layers.some(l=>!l||typeof l!=='object'||!validId(l.id)||!validId(l.surfaceId))||
   new Set(layers.map(l=>l.id)).size!==layers.length)throw new TypeError('PREVIEW_LAYER_STACK_INPUT');
 const output=[...layers],indices=layers.flatMap((l,i)=>l.surfaceId===surfaceId?[i]:[]);
 const local=indices.findIndex(i=>layers[i].id===layerId);
 if(local<0)throw new RangeError('PREVIEW_LAYER_NOT_ON_SURFACE');
 const target=direction==='forward'?Math.min(indices.length-1,local+1):direction==='backward'?Math.max(0,local-1):direction==='front'?indices.length-1:0;
 if(target!==local){const ordered=indices.map(i=>layers[i]);const [selected]=ordered.splice(local,1);ordered.splice(target,0,selected);indices.forEach((index,i)=>{output[index]=ordered[i];});}
 return Object.freeze(output);
}
