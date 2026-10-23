/** Objective 33A: bounded read-only multi-claim inventory and cross-observer
 * reconciliation. Scope IDs and pins MUST be independently retained; neither
 * local calculation nor supplied timestamps establish a global witness.
 */
import {createHash} from 'node:crypto';
import {verifyOfflineConflictManifestClaimContinuity} from './offline-conflict-manifest-claim-continuity.mjs';

export const OFFLINE_CONFLICT_MULTI_CLAIM_INVENTORY_SCHEMA='TJ-OFFLINE-CONFLICT-MULTI-CLAIM-INVENTORY-1';
export const OFFLINE_CONFLICT_MULTI_CLAIM_MAX_CLAIMS=32;
export const OFFLINE_CONFLICT_MULTI_CLAIM_MAX_OBSERVERS=8;
const HEX=/^[0-9a-f]{64}$/;
const ID=/^[A-Za-z0-9_-]{8,64}$/;
const isHex=x=>typeof x==='string'&&HEX.test(x);
const fail=code=>{throw Object.assign(new Error(code),{code});};
const hash=(domain,value)=>createHash('sha256').update(domain+'\0').update(JSON.stringify(value)).digest('hex');
const exact=(o,keys)=>o!==null&&typeof o==='object'&&!Array.isArray(o)&&
 [Object.prototype,null].includes(Object.getPrototypeOf(o))&&Reflect.ownKeys(o).length===keys.length&&
 keys.every(k=>{const d=Object.getOwnPropertyDescriptor(o,k);return d&&'value' in d&&d.enumerable;})&&
 Object.keys(o).every(k=>keys.includes(k));
const array=(a,min,max)=>Array.isArray(a)&&Object.getPrototypeOf(a)===Array.prototype&&
 a.length>=min&&a.length<=max&&Reflect.ownKeys(a).length===a.length+1&&
 Array.from({length:a.length},(_,i)=>Object.getOwnPropertyDescriptor(a,String(i)))
 .every(d=>d&&'value' in d&&d.enumerable);
const head=h=>exact(h,['count','headDigest'])&&Number.isSafeInteger(h.count)&&h.count>=1&&h.count<=64&&HEX.test(h.headDigest);
function buildInventory({journalScopeDigest,claims}={}){
 if(!isHex(journalScopeDigest)||!array(claims,1,OFFLINE_CONFLICT_MULTI_CLAIM_MAX_CLAIMS))
  fail('EXCHANGE33A_INVENTORY_INVALID');
 const records=[],slots=new Map(),seen=new Set();
 for(const claim of claims){
  if(!exact(claim,['entries','expectedHead'])||!head(claim.expectedHead))fail('EXCHANGE33A_CLAIM_INVALID');
  // The 32Z verifier recursively authenticates every 32Y Ed25519 transcript.
  const verified=verifyOfflineConflictManifestClaimContinuity(claim);
  const anchor=verified.claim;
  const claimDigest=hash('TJ-33A-CLAIM-IDENTITY',anchor);
  const slot=JSON.stringify([anchor.priorHead.count,anchor.priorHead.headDigest,anchor.pendingIndex]);
  if(seen.has(claimDigest))fail('EXCHANGE33A_DUPLICATE_CLAIM');
  if(slots.has(slot)&&slots.get(slot)!==claimDigest)fail('EXCHANGE33A_CROSS_CLAIM_FORK');
  seen.add(claimDigest);slots.set(slot,claimDigest);
  records.push({claimDigest,head:{...verified.head},lastObservedState:verified.lastObservedState,
   priorHead:{...anchor.priorHead},pendingIndex:anchor.pendingIndex});
 }
 records.sort((a,b)=>a.claimDigest<b.claimDigest?-1:a.claimDigest>b.claimDigest?1:0);
 const digest=hash('TJ-33A-MULTI-CLAIM-INVENTORY',{
  schema:OFFLINE_CONFLICT_MULTI_CLAIM_INVENTORY_SCHEMA,journalScopeDigest,records});
 return {journalScopeDigest,records,digest};
}
/** Candidate only; caller must obtain independently retained digest/count/scope. */
export function calculateOfflineConflictManifestMultiClaimInventory(input){
 const r=buildInventory(input);
 return Object.freeze({schema:OFFLINE_CONFLICT_MULTI_CLAIM_INVENTORY_SCHEMA,
  journalScopeDigest:r.journalScopeDigest,inventoryDigest:r.digest,claimCount:r.records.length,
  independentlyWitnessed:false,authorizesRepair:false,authorizesProduction:false});
}
export function verifyOfflineConflictManifestMultiClaimInventory({journalScopeDigest,claims,
 expectedJournalScopeDigest,expectedInventoryDigest,expectedClaimCount}={}){
 if(!isHex(expectedJournalScopeDigest)||!isHex(expectedInventoryDigest)||
  !Number.isSafeInteger(expectedClaimCount)||expectedClaimCount<1||
  expectedClaimCount>OFFLINE_CONFLICT_MULTI_CLAIM_MAX_CLAIMS)
  fail('EXCHANGE33A_EXTERNAL_PINS_REQUIRED');
 const r=buildInventory({journalScopeDigest,claims});
 if(r.journalScopeDigest!==expectedJournalScopeDigest||r.digest!==expectedInventoryDigest||
  r.records.length!==expectedClaimCount)fail('EXCHANGE33A_INVENTORY_PIN_MISMATCH');
 return Object.freeze({verified:true,readOnly:true,inventoryDigest:r.digest,
  claimCount:r.records.length,journalScopeDigest:r.journalScopeDigest,
  independentlyWitnessed:false,authorizesRepair:false,authorizesProduction:false,
  authorizesCheckout:false});
}
function buildReconciliation({journalScopeDigest,observations}={}){
 if(!isHex(journalScopeDigest)||!array(observations,2,OFFLINE_CONFLICT_MULTI_CLAIM_MAX_OBSERVERS))
  fail('EXCHANGE33A_OBSERVATIONS_INVALID');
 const seen=new Set(),snapshots=[];
 for(const o of observations){
  if(!exact(o,['observerId','claims','expectedInventoryDigest','expectedClaimCount'])||
   typeof o.observerId!=='string'||!ID.test(o.observerId)||seen.has(o.observerId))
   fail('EXCHANGE33A_OBSERVER_INVALID');
  seen.add(o.observerId);
  const verified=verifyOfflineConflictManifestMultiClaimInventory({
   journalScopeDigest,claims:o.claims,expectedJournalScopeDigest:journalScopeDigest,
   expectedInventoryDigest:o.expectedInventoryDigest,expectedClaimCount:o.expectedClaimCount});
  const snapshot=buildInventory({journalScopeDigest,claims:o.claims});
  snapshots.push({observerId:o.observerId,inventoryDigest:verified.inventoryDigest,
   claimCount:verified.claimCount,records:snapshot.records});
 }
 const base=snapshots[0].records;
 for(const snapshot of snapshots.slice(1)){
  if(snapshot.records.length!==base.length||
   snapshot.records.some((r,i)=>r.claimDigest!==base[i].claimDigest))
   fail('EXCHANGE33A_OBSERVER_OMISSION_OR_FORK');
  if(snapshot.records.some((r,i)=>r.head.count!==base[i].head.count||
   r.head.headDigest!==base[i].head.headDigest||
   r.lastObservedState!==base[i].lastObservedState))
   fail('EXCHANGE33A_OBSERVER_EQUIVOCATION');
 }
 snapshots.sort((a,b)=>a.observerId<b.observerId?-1:a.observerId>b.observerId?1:0);
 const digest=hash('TJ-33A-RECONCILIATION',{
  schema:OFFLINE_CONFLICT_MULTI_CLAIM_INVENTORY_SCHEMA,journalScopeDigest,
  observers:snapshots.map(x=>({observerId:x.observerId,inventoryDigest:x.inventoryDigest,
   claimCount:x.claimCount}))});
 return {digest,observerCount:snapshots.length,claimCount:base.length};
}
/** Candidate only; do not derive an external pin from the same untrusted data. */
export function calculateOfflineConflictManifestMultiClaimReconciliation(input){
 const r=buildReconciliation(input);
 return Object.freeze({reconciliationDigest:r.digest,observerCount:r.observerCount,
  claimCount:r.claimCount,independentlyWitnessed:false,authorizesRepair:false});
}
export function verifyOfflineConflictManifestMultiClaimReconciliation({journalScopeDigest,
 observations,expectedJournalScopeDigest,expectedReconciliationDigest,expectedObserverCount}={}){
 if(!isHex(expectedJournalScopeDigest)||!isHex(expectedReconciliationDigest)||
  !Number.isSafeInteger(expectedObserverCount)||expectedObserverCount<2||
  expectedObserverCount>OFFLINE_CONFLICT_MULTI_CLAIM_MAX_OBSERVERS)
  fail('EXCHANGE33A_EXTERNAL_RECONCILIATION_PINS_REQUIRED');
 const r=buildReconciliation({journalScopeDigest,observations});
 if(journalScopeDigest!==expectedJournalScopeDigest||r.digest!==expectedReconciliationDigest||
  r.observerCount!==expectedObserverCount)fail('EXCHANGE33A_RECONCILIATION_PIN_MISMATCH');
 return Object.freeze({verified:true,readOnly:true,reconciliationDigest:r.digest,
  observerCount:r.observerCount,claimCount:r.claimCount,
  independentlyWitnessed:false,authorizesRepair:false,authorizesProduction:false,
  authorizesCheckout:false});
}
