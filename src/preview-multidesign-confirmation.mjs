/** Objective 35M: explicit per-receipt consent before recovering a local review.
 * A public checklist alone is never authority. Private capabilities remain only
 * inside this ephemeral controller and are never returned by status or results.
 */
import {validateEntry} from './preview-multidesign-review.mjs';

const fail=code=>{throw Object.assign(new Error(code),{code});};
const bindingKeys=['reference','revision','productManifestId','productLabel','productGid','variantGid'];
export function createLocalRecoveryConfirmation({recovery}={}){
 if(!recovery||typeof recovery.list!=='function'||typeof recovery.resume!=='function')
  fail('REVIEW_CONFIRM_CONFIGURATION');
 let prepared=null,epoch=0,busy=false,cancelled=false,total=0,completed=0;
 function status(){
  const pending=recovery.list();
  const selected=prepared&&pending.find(e=>e.reference===prepared.reference&&
   bindingKeys.every(k=>e[k]===prepared[k]));
  return Object.freeze({scope:'OFFLINE_PREVIEW_ONLY',total,pending:pending.length,completed,
   staged:selected?Object.freeze({reference:selected.reference,revision:selected.revision,
    productLabel:selected.productLabel,productManifestId:selected.productManifestId}):null,
   busy,cancelled,checkoutEnabled:false});
 }
 function reset(){epoch++;prepared=null;cancelled=busy;total=recovery.list().length;completed=0;return status();}
 function cancel(){epoch++;prepared=null;cancelled=busy;return status();}
 function stage(entry){
  if(busy)fail('REVIEW_CONFIRM_BUSY');
  try{validateEntry(entry);}catch{fail('REVIEW_CONFIRM_PRIVATE_ENTRY_INVALID');}
  const expected=recovery.list().find(e=>e.reference===entry.reference);
  if(!expected)fail('REVIEW_CONFIRM_NOT_PENDING');
  if(bindingKeys.some(k=>entry[k]!==expected[k]))fail('REVIEW_CONFIRM_BINDING_CHANGED');
  // Never serialize, expose or persist the private owner grant.
  epoch++;cancelled=false;prepared=Object.fromEntries([...bindingKeys,'ownerToken'].map(k=>[k,entry[k]]));
  return status();
 }
 async function confirm(accept){
  if(busy)fail('REVIEW_CONFIRM_BUSY');
  if(!prepared)fail('REVIEW_CONFIRM_EXPLICIT_CONSENT_REQUIRED');
  if(typeof accept!=='function')fail('REVIEW_CONFIRM_ACCEPT_REQUIRED');
  const candidate=prepared,started=epoch;
  prepared=null;busy=true;cancelled=false;
  try{
   const result=await recovery.resume(candidate,(entry,selected)=>{
    if(epoch!==started)fail('REVIEW_CONFIRM_CANCELLED');
    return accept(entry,selected);
   },()=>epoch===started);
   if(epoch!==started)fail('REVIEW_CONFIRM_CANCELLED');
   completed++;
   return Object.freeze({reference:result.reference,revision:result.revision,
    ...status(),staged:null,busy:false,checkoutEnabled:false});
  }catch(error){
   if(epoch!==started)fail('REVIEW_CONFIRM_CANCELLED');
   throw error;
  }finally{busy=false;cancelled=false;prepared=null;}
 }
 return Object.freeze({status,reset,cancel,stage,confirm,localOnly:true,checkoutEnabled:false});
}
