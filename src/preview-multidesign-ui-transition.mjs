/** Objective 35P: local-only asynchronous multi-design review presentation gate.
 * Superseded review results MUST NOT overwrite a later selection, clear, or
 * restored-receipt state. This is UI concurrency control, not authorization.
 */
const fail=code=>{throw Object.assign(new Error(code),{code});};
export function createLocalMultiReviewTransition({review}={}){
 if(!review||typeof review.review!=='function')fail('MULTI_PREVIEW_UI_CONFIGURATION');
 let generation=0,busy=false;
 const current=ticket=>Number.isSafeInteger(ticket)&&ticket>0&&ticket===generation;
 const status=()=>Object.freeze({scope:'OFFLINE_PREVIEW_ONLY',busy,checkoutEnabled:false});
 function invalidate(){generation++;busy=false;return status();}
 function start(){
  if(busy)fail('MULTI_PREVIEW_UI_BUSY');
  const ticket=++generation;busy=true;
  const promise=(async()=>{
   try{
    const result=await review.review();
    if(!current(ticket))fail('MULTI_PREVIEW_UI_STALE');
    return result;
   }catch(error){
    if(!current(ticket))fail('MULTI_PREVIEW_UI_STALE');
    throw error;
   }finally{if(current(ticket))busy=false;}
  })();
  return Object.freeze({ticket,promise});
 }
 return Object.freeze({start,invalidate,current,status,localOnly:true,checkoutEnabled:false});
}
