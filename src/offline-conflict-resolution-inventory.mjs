/**
 * Objective 32T: offline, READ-ONLY reconciliation of independently supplied
 * 32S resolution-attempt proofs. No signer, journal mutation, network, or
 * production authorization. All pins must arrive over a separate trust path.
 */
import {createHash} from 'node:crypto';
import {verifyOfflineConflictCutoverResolutionProof} from './offline-conflict-cutover-resolution-proof.mjs';

export const OFFLINE_CONFLICT_RESOLUTION_INVENTORY_SCHEMA='TJ-OFFLINE-CONFLICT-RESOLUTION-INVENTORY-1';
export const OFFLINE_CONFLICT_RESOLUTION_UNION_SCHEMA='TJ-OFFLINE-CONFLICT-RESOLUTION-UNION-1';
const HEX=/^[0-9a-f]{64}$/;
const OBSERVER=/^[A-Za-z0-9][A-Za-z0-9_-]{2,63}$/;
const ENTRY_KEYS=['genesisExchangeDigest','cutoverDigest','resolutionDigest','decisionDigest','proofDigest','action'];
const fail=code=>{throw Object.assign(new Error(code),{code});};
const hex=v=>typeof v==='string'&&HEX.test(v);
const observer=v=>typeof v==='string'&&OBSERVER.test(v);
const exact=(o,keys)=>o!==null&&typeof o==='object'&&!Array.isArray(o)&&
 [Object.prototype,null].includes(Object.getPrototypeOf(o))&&Reflect.ownKeys(o).length===keys.length&&
 keys.every(k=>{const d=Object.getOwnPropertyDescriptor(o,k);return d&&'value' in d&&d.enumerable;})&&
 Object.keys(o).every(k=>keys.includes(k));
const safeArray=(a,max)=>Array.isArray(a)&&Object.getPrototypeOf(a)===Array.prototype&&a.length<=max&&
 Reflect.ownKeys(a).length===a.length+1&&Array.from({length:a.length},(_,i)=>{
  const d=Object.getOwnPropertyDescriptor(a,String(i));return d&&'value' in d&&d.enumerable;
 }).every(Boolean);
const digest=(domain,value)=>createHash('sha256').update(domain+'\0').update(JSON.stringify(value)).digest('hex');
const entryKey=e=>[e.genesisExchangeDigest,e.cutoverDigest,e.resolutionDigest,e.decisionDigest,e.proofDigest,e.action].join(':');
function entriesValid(entries,{allowEmpty=true}={}){
 if(!safeArray(entries,32)||(!allowEmpty&&entries.length===0))fail('EXCHANGE32T_INVENTORY_INVALID');
 let previous='';const seen=new Set();
 for(const e of entries){
  if(!exact(e,ENTRY_KEYS)||!ENTRY_KEYS.slice(0,5).every(k=>hex(e[k]))||
   !['abort','finalize'].includes(e.action))fail('EXCHANGE32T_INVENTORY_INVALID');
  const key=entryKey(e);
  if(key<=previous||seen.has(e.genesisExchangeDigest))fail('EXCHANGE32T_DUPLICATE_OR_UNSORTED');
  previous=key;seen.add(e.genesisExchangeDigest);
 }
}
export function offlineConflictResolutionInventoryDigest(manifest){
 if(!exact(manifest,['schema','observerId','entries'])||
  manifest.schema!==OFFLINE_CONFLICT_RESOLUTION_INVENTORY_SCHEMA||
  !observer(manifest.observerId))fail('EXCHANGE32T_INVENTORY_INVALID');
 entriesValid(manifest.entries);
 return digest('TJ-32T-RESOLUTION-INVENTORY',manifest);
}
export function offlineConflictResolutionUnionDigest(union){
 if(!exact(union,['schema','entries'])||union.schema!==OFFLINE_CONFLICT_RESOLUTION_UNION_SCHEMA)
  fail('EXCHANGE32T_UNION_INVALID');
 entriesValid(union.entries,{allowEmpty:false});
 return digest('TJ-32T-RESOLUTION-UNION',union);
}
/**
 * views: untrusted manifests + untrusted proof bodies, positionally matched.
 * anchors: independently obtained exact inventory digest and 32S proof pins.
 * expectedUnionDigest: independently obtained COMPLETE inventory commitment.
 * expectedObserverIds: separately pinned exact roster; prevents observer removal.
 * A matching self-generated pin does not prove external publication.
 */
export function verifyOfflineConflictResolutionInventories({views,anchors,expectedObserverIds,expectedUnionDigest,nowMs}={}){
 if(!safeArray(views,8)||views.length<2||!safeArray(anchors,8)||
  !safeArray(expectedObserverIds,8)||expectedObserverIds.length!==views.length||
  expectedObserverIds.some((id,i)=>!observer(id)||(i>0&&id<=expectedObserverIds[i-1]))||
  anchors.length!==views.length||!hex(expectedUnionDigest)||
  !Number.isSafeInteger(nowMs)||nowMs<0)fail('EXCHANGE32T_EXTERNAL_PINS_REQUIRED');
 const trusted=new Map();
 for(const a of anchors){
  if(!exact(a,['observerId','inventoryDigest','proofPins'])||!observer(a.observerId)||
   !hex(a.inventoryDigest)||!safeArray(a.proofPins,32)||trusted.has(a.observerId))
   fail('EXCHANGE32T_EXTERNAL_PINS_REQUIRED');
  const pins=new Map();
  for(const p of a.proofPins){
   if(!exact(p,['proofDigest','pins'])||!hex(p.proofDigest)||pins.has(p.proofDigest)||
    !exact(p.pins,['proofDigest','decisionDigest','resolutionDigest','cutoverDigest','pendingBytesDigest',
     'genesisExchangeDigest','transitionHead','receiptHead','finalPolicyDigest','exchangeJournalHead'])||
    p.pins.proofDigest!==p.proofDigest)fail('EXCHANGE32T_EXTERNAL_PINS_REQUIRED');
   pins.set(p.proofDigest,p.pins);
  }
  if(!expectedObserverIds.includes(a.observerId))fail('EXCHANGE32T_OBSERVER_UNTRUSTED');
  trusted.set(a.observerId,{inventoryDigest:a.inventoryDigest,pins});
 }
 const seenObservers=new Set();const verifiedViews=[];
 for(const view of views){
  if(!exact(view,['manifest','proofs'])||!safeArray(view.proofs,32))fail('EXCHANGE32T_INVENTORY_INVALID');
  const manifest=view.manifest;
  const computed=offlineConflictResolutionInventoryDigest(manifest);
  const anchor=trusted.get(manifest.observerId);
  if(!anchor||seenObservers.has(manifest.observerId))fail('EXCHANGE32T_OBSERVER_UNTRUSTED');
  seenObservers.add(manifest.observerId);
  if(computed!==anchor.inventoryDigest)fail('EXCHANGE32T_INVENTORY_PIN_MISMATCH');
  if(manifest.entries.length!==view.proofs.length||anchor.pins.size!==view.proofs.length)
   fail('EXCHANGE32T_EVIDENCE_OMITTED');
  for(let i=0;i<manifest.entries.length;i++){
   const entry=manifest.entries[i],proof=view.proofs[i],pins=anchor.pins.get(entry.proofDigest);
   if(!pins||!exact(proof,['proof'])||pins.genesisExchangeDigest!==entry.genesisExchangeDigest||
    pins.cutoverDigest!==entry.cutoverDigest||pins.resolutionDigest!==entry.resolutionDigest||
    pins.decisionDigest!==entry.decisionDigest)fail('EXCHANGE32T_EVIDENCE_PIN_MISMATCH');
   const result=verifyOfflineConflictCutoverResolutionProof({proof:proof.proof,pins,nowMs});
   if(result.action!==entry.action||result.proofDigest!==entry.proofDigest)
    fail('EXCHANGE32T_EVIDENCE_PIN_MISMATCH');
  }
  verifiedViews.push({observerId:manifest.observerId,entries:manifest.entries});
 }
 if(seenObservers.size!==trusted.size)fail('EXCHANGE32T_OBSERVER_UNTRUSTED');
 const byGenesis=new Map();
 for(const view of verifiedViews){
  for(const entry of view.entries){
   const old=byGenesis.get(entry.genesisExchangeDigest);
   if(old&&entryKey(old)!==entryKey(entry))fail('EXCHANGE32T_EQUIVOCATION');
   byGenesis.set(entry.genesisExchangeDigest,entry);
  }
 }
 for(const view of verifiedViews){
  if(view.entries.length!==byGenesis.size||
   view.entries.some(e=>entryKey(byGenesis.get(e.genesisExchangeDigest))!==entryKey(e)))
   fail('EXCHANGE32T_OBSERVER_OMISSION');
 }
 const entries=[...byGenesis.values()].sort((a,b)=>entryKey(a)<entryKey(b)?-1:entryKey(a)>entryKey(b)?1:0);
 const unionDigest=offlineConflictResolutionUnionDigest({schema:OFFLINE_CONFLICT_RESOLUTION_UNION_SCHEMA,entries});
 if(unionDigest!==expectedUnionDigest)fail('EXCHANGE32T_UNION_PIN_MISMATCH');
 return Object.freeze({verified:true,readOnly:true,observerCount:verifiedViews.length,
  authenticatedAttemptCount:entries.length,unionDigest,authenticatedAttemptsOnly:true,
  locallyCompleted:false,independentlyPublished:false,globallyComplete:false,
  hostedAuthentication:false,authorizesCheckout:false,authorizesProduction:false});
}
