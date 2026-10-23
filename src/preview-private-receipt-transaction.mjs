/** Objective 35S — transactional local UI state restoration, not hosted authority.
 * A failed preview render must not strand half-restored private credentials or
 * destroy the previously selected design's in-memory artwork URLs.
 */
const fields=['product','surface','previewSelection','layers','selected','savedSnapshot',
 'saved','artGrants','artUrls','imported','calibration'];
const fail=()=>{throw Object.assign(new Error('PRIVATE_RESTORE_TRANSACTION_INVALID'),{code:'PRIVATE_RESTORE_TRANSACTION_INVALID'});};
export function commitPrivateReceiptRestore({state,next,render,revokeOldUrl}={}){
 if(!state||typeof state!=='object'||!next||typeof next!=='object'||
  typeof render!=='function'||typeof revokeOldUrl!=='function')fail();
 const descriptors=Object.getOwnPropertyDescriptors(next);
 if(Object.keys(descriptors).length!==fields.length||
  fields.some(k=>!Object.hasOwn(descriptors,k)||!Object.hasOwn(descriptors[k],'value')))fail();
 const candidate=Object.fromEntries(fields.map(k=>[k,descriptors[k].value]));
 if(!(candidate.artUrls instanceof Map)||!(candidate.artGrants instanceof Map)||
  !candidate.product||typeof candidate.product.id!=='string'||
  !Array.isArray(candidate.layers)||!candidate.saved||
  typeof candidate.saved.reference!=='string')fail();
 const before=Object.fromEntries(fields.map(k=>[k,state[k]]));
 try{
  for(const key of fields)state[key]=candidate[key];
  render();
 }catch(error){
  for(const key of fields)state[key]=before[key];
  // Best-effort restoration of the previous DOM after an interrupted render.
  // State rollback does not claim atomicity for external persistence or network.
  try{render();}catch{}
  throw error;
 }
 const retained=new Set(candidate.artUrls.values());
 for(const oldUrl of before.artUrls.values())if(!retained.has(oldUrl)){
  try{revokeOldUrl(oldUrl);}catch{} // Do not undo a successful restore if cleanup fails.
 }
 return true;
}
