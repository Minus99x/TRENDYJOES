/** Local-only design draft model. This is not a quote, print approval or checkout. */
const idPattern=/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/;
export function workbenchId(id){if(typeof id!=='string'||!idPattern.test(id))throw new TypeError('WORKBENCH_ID');return id;}
export function workbenchNumber(n,{zero=false,max=100000}={}){if(typeof n!=='number'||!Number.isFinite(n)||n<0||(!zero&&n===0)||n>max)throw new RangeError('WORKBENCH_NUMBER');return n;}
export function freezeDraft(d){return Object.freeze({...d,surfaces:Object.freeze([...d.surfaces]),layers:Object.freeze(d.layers.map(l=>Object.freeze({...l}))),localOnly:true,manufacturingApproved:false,checkoutEnabled:false,priceApproved:false});}
export function makeWorkbenchDraft({productId,surfaceIds=['front']}={}){
 workbenchId(productId);if(!Array.isArray(surfaceIds)||!surfaceIds.length||surfaceIds.length>32||new Set(surfaceIds).size!==surfaceIds.length)throw new TypeError('WORKBENCH_SURFACES');
 surfaceIds.forEach(workbenchId);
 return freezeDraft({schema:'TJ-WORKBENCH-1',productId,surfaces:surfaceIds,activeSurface:surfaceIds[0],layers:[],revision:0});
}
export function assertWorkbenchDraft(d){
 if(!d||d.schema!=='TJ-WORKBENCH-1'||typeof d!=='object'||!Array.isArray(d.layers)||d.layers.length>100||!Array.isArray(d.surfaces)||d.surfaces.length<1||d.surfaces.length>32||new Set(d.surfaces).size!==d.surfaces.length||!Number.isSafeInteger(d.revision)||d.revision<0||d.localOnly!==true||d.manufacturingApproved!==false||d.checkoutEnabled!==false||d.priceApproved!==false)throw new TypeError('WORKBENCH_DRAFT');
 workbenchId(d.productId);d.surfaces.forEach(workbenchId);if(!d.surfaces.includes(d.activeSurface)||new Set(d.layers.map(l=>l.id)).size!==d.layers.length)throw new TypeError('WORKBENCH_DRAFT_CONTEXT');
 return d;
}
export function nextWorkbenchDraft(d,change){assertWorkbenchDraft(d);return freezeDraft({...d,...change,revision:d.revision+1});}
