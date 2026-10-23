/** Objective 35L: explicit, portable, NON-AUTHORIZING review checklist recovery.
 * A checklist never carries owner capabilities, cart lines or artwork. It cannot
 * restore a saved design until the user separately reopens a private receipt and
 * the loopback readiness API independently verifies that exact saved binding.
 */
import {validateEntry,validateReadiness} from './preview-multidesign-review.mjs';

const fail=code=>{throw Object.assign(new Error(code),{code});};
const obj=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);
const exact=(x,keys)=>obj(x)&&Object.keys(x).length===keys.length&&keys.every(k=>Object.hasOwn(x,k));
const recordKeys=['format','createdAt','expiresAt','entries'];
const itemKeys=['reference','revision','productManifestId','productLabel','productGid','variantGid','selected'];
const entryKeys=['reference','revision','ownerToken','productManifestId','productLabel','productGid','variantGid'];
export const REVIEW_CHECKLIST_TTL_MS=30*60*1000;
const MAX_BYTES=16384;
const validTime=t=>Number.isSafeInteger(t)&&t>=0;
const safeNow=clock=>{let now;try{now=clock();}catch{fail('REVIEW_RECOVERY_CLOCK');}
 if(!validTime(now))fail('REVIEW_RECOVERY_CLOCK');return now;};
function checkRecord(r,now){
 if(!exact(r,recordKeys)||r.format!=='TJ-MULTI-REVIEW-CHECKLIST-1'||
  !validTime(r.createdAt)||!validTime(r.expiresAt)||
  r.expiresAt-r.createdAt!==REVIEW_CHECKLIST_TTL_MS||
  r.createdAt>now+30000||now>=r.expiresAt||
  !Array.isArray(r.entries)||r.entries.length<1||r.entries.length>25)
  fail('REVIEW_RECOVERY_INVALID_OR_EXPIRED');
 const seen=new Set();
 for(const e of r.entries){
  if(!exact(e,itemKeys)||typeof e.selected!=='boolean')fail('REVIEW_RECOVERY_ENTRY_INVALID');
  // Validate against the same canonical product/variant/revision constraints as
  // the original private review, without ever accepting a capability from disk.
  try{validateEntry(Object.fromEntries(entryKeys.map(k=>[k,k==='ownerToken'?'0'.repeat(64):e[k]])));}
  catch{fail('REVIEW_RECOVERY_ENTRY_INVALID');}
  if(seen.has(e.reference))fail('REVIEW_RECOVERY_DUPLICATE');seen.add(e.reference);
 }
 return r;
}
export function createReviewChecklist(reviewEntries,{now=Date.now()}={}){
 if(!validTime(now)||!Array.isArray(reviewEntries))fail('REVIEW_RECOVERY_INVALID');
 const entries=reviewEntries.map(e=>{
  if(!exact(e,itemKeys))fail('REVIEW_RECOVERY_INVALID');
  try{validateEntry(Object.fromEntries(entryKeys.map(k=>[k,k==='ownerToken'?'0'.repeat(64):e[k]])));}
  catch{fail('REVIEW_RECOVERY_INVALID');}
  if(typeof e.selected!=='boolean')fail('REVIEW_RECOVERY_INVALID');
  return Object.fromEntries(itemKeys.map(k=>[k,e[k]]));
 });
 const record={format:'TJ-MULTI-REVIEW-CHECKLIST-1',createdAt:now,
  expiresAt:now+REVIEW_CHECKLIST_TTL_MS,entries};
 checkRecord(record,now);
 const raw=JSON.stringify(record);
 if(new TextEncoder().encode(raw).length>MAX_BYTES)fail('REVIEW_RECOVERY_TOO_LARGE');
 return raw;
}
export function createLocalMultiReviewRecovery({readReadiness,clock=Date.now}={}){
 if(typeof readReadiness!=='function'||typeof clock!=='function')fail('REVIEW_RECOVERY_CONFIGURATION');
 let pending=new Map(),expiresAt=0,epoch=0;
 const ensureActive=()=>{if(!pending.size||safeNow(clock)>=expiresAt)fail('REVIEW_RECOVERY_EXPIRED');};
 function importChecklist(raw){
  if(typeof raw!=='string'||new TextEncoder().encode(raw).length>MAX_BYTES)fail('REVIEW_RECOVERY_INVALID');
  let parsed;try{parsed=JSON.parse(raw);}catch{fail('REVIEW_RECOVERY_INVALID');}
  const r=checkRecord(parsed,safeNow(clock));
  // Build a fresh map only after every entry has been validated.
  pending=new Map(r.entries.map(e=>[e.reference,{...e}]));expiresAt=r.expiresAt;epoch++;
  return list();
 }
 function list(){return Object.freeze([...pending.values()].map(e=>Object.freeze({...e})));}
 function clear(){pending.clear();expiresAt=0;epoch++;return list();}
 async function resume(privateEntry,accept,shouldContinue=()=>true){
  ensureActive();
  if(typeof accept!=='function'||typeof shouldContinue!=='function'||!exact(privateEntry,entryKeys))fail('REVIEW_RECOVERY_PRIVATE_ENTRY_INVALID');
  // Optional veto only. It can stop redundant bearer-authenticated readiness calls,
  // but can never authorize a receipt or replace independent server checks.
  const ensureNotCancelled=()=>{let active;try{active=shouldContinue();}catch{fail('REVIEW_RECOVERY_CANCELLED');}
   if(active!==true)fail('REVIEW_RECOVERY_CANCELLED');};
  try{validateEntry(privateEntry);}catch{fail('REVIEW_RECOVERY_PRIVATE_ENTRY_INVALID');}
  const expected=pending.get(privateEntry.reference);
  if(!expected)fail('REVIEW_RECOVERY_NOT_REQUESTED');
  if(itemKeys.some(k=>k!=='selected'&&privateEntry[k]!==expected[k]))fail('REVIEW_RECOVERY_BINDING_CHANGED');
  const start=epoch;let hash=null;
  for(let pass=0;pass<2;pass++){
   if(epoch!==start)fail('REVIEW_RECOVERY_CHANGED');ensureNotCancelled();ensureActive();
   let r;
   try{r=await readReadiness(Object.freeze({reference:privateEntry.reference,
    expectedRevision:privateEntry.revision,productGid:privateEntry.productGid,
    variantGid:privateEntry.variantGid,ownerToken:privateEntry.ownerToken}));}
   catch{fail('REVIEW_RECOVERY_READINESS_REFUSED');}
   if(epoch!==start)fail('REVIEW_RECOVERY_CHANGED');ensureNotCancelled();ensureActive();
   let observed;try{observed=validateReadiness(r,privateEntry);}
   catch{fail('REVIEW_RECOVERY_READINESS_REFUSED');}
   if(pass&&observed!==hash)fail('REVIEW_RECOVERY_DESIGN_CHANGED');
   hash=observed;
  }
  if(epoch!==start)fail('REVIEW_RECOVERY_CHANGED');ensureNotCancelled();ensureActive();
  // Accept is synchronous; pending state is only consumed if the actual review
  // controller accepted the reauthenticated draft. No partial list restoration.
  const accepted=accept(Object.freeze({...privateEntry}),expected.selected);
  if(accepted&&typeof accepted.then==='function')fail('REVIEW_RECOVERY_ASYNC_ACCEPT_UNSUPPORTED');
  if(accepted===false)fail('REVIEW_RECOVERY_ACCEPT_REFUSED');
  pending.delete(privateEntry.reference);epoch++;
  return Object.freeze({reference:privateEntry.reference,revision:privateEntry.revision,
   remaining:pending.size,scope:'OFFLINE_PREVIEW_ONLY',checkoutEnabled:false});
 }
 return Object.freeze({importChecklist,list,clear,resume,localOnly:true,checkoutEnabled:false});
}
