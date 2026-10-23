/** Objective 33M — verify externally pinned, canonical 33J inventory record
 * BYTES and the complete nested 33I signed reviewer/observer transcripts.
 * Offline supplied evidence only: never a claim of remote disk observation,
 * independent pin publication, historical-prefix validity, or production use.
 */
import {createHash} from 'node:crypto';
import {OFFLINE_CONFLICT_ADJUDICATION_INVENTORY_SCHEMA} from './offline-conflict-adjudication-transcript-inventory.mjs';
import {reconcileOfflineConflictInventoryHeadReceipts} from './offline-conflict-adjudication-inventory-head-receipts.mjs';
import {verifyOfflineConflictPendingAdjudicationTranscript,
 reconcileOfflineConflictPendingAdjudicationTranscripts} from './offline-conflict-pending-adjudication-transcript.mjs';

export const OFFLINE_CONFLICT_INVENTORY_RECORD_EVIDENCE_SCHEMA='TJ-OFFLINE-ADJUDICATION-INVENTORY-RECORD-EVIDENCE-1';
const HEX=/^[0-9a-f]{64}$/;
const PIN_KEYS=['expectedTranscriptDigest','expectedNamespaceId','expectedJournalScopeDigest',
 'expectedDecisionDigest','expectedReviewerGroupADigest','expectedReviewerGroupBDigest',
 'expectedPendingBytesDigest','expectedPreHead','expectedObservedHead',
 'expectedObserverId','expectedObserverPublicKey'];
const RECORD_KEYS=['schema','index','namespaceId','journalScopeDigest','previousRecordDigest','pair','recordDigest'];
const fail=code=>{throw Object.assign(new Error(code),{code});};
const sha=(domain,bytes)=>createHash('sha256').update(domain+'\0').update(bytes).digest('hex');
const exact=(o,keys)=>o!==null&&typeof o==='object'&&!Array.isArray(o)&&
 [Object.prototype,null].includes(Object.getPrototypeOf(o))&&Reflect.ownKeys(o).length===keys.length&&
 keys.every(k=>{const d=Object.getOwnPropertyDescriptor(o,k);return d&&'value' in d&&d.enumerable;})&&
 Object.keys(o).every(k=>keys.includes(k));
const dense=(a,min,max)=>Array.isArray(a)&&Object.getPrototypeOf(a)===Array.prototype&&
 a.length>=min&&a.length<=max&&Reflect.ownKeys(a).length===a.length+1&&
 Array.from({length:a.length},(_,i)=>Object.getOwnPropertyDescriptor(a,String(i))).every(d=>d&&'value' in d&&d.enumerable);
const head=h=>exact(h,['count','headDigest'])&&Number.isSafeInteger(h.count)&&h.count>=0&&h.count<=256&&
 typeof h.headDigest==='string'&&HEX.test(h.headDigest);
const same=(a,b)=>a.count===b.count&&a.headDigest===b.headDigest;
const b64=x=>typeof x==='string'&&x.length>0&&x.length<22000&&/^[A-Za-z0-9_-]+$/.test(x)&&
 Buffer.from(x,'base64url').toString('base64url')===x;
const recordDigest=body=>sha('TJ-33J-INVENTORY-RECORD',Buffer.from(JSON.stringify(body)));
/** Pin digest is a distinct domain-separated address for actual bytes. */
export function offlineConflictInventoryRecordBytesDigest(bytes){
 if(!Buffer.isBuffer(bytes)||bytes.length<50||bytes.length>65536)fail('EXCHANGE33M_RECORD_BYTES_INVALID');
 return sha('TJ-33M-PINNED-INVENTORY-RECORD-BYTES',bytes);
}
function parse(bytes){
 offlineConflictInventoryRecordBytesDigest(bytes);
 let r;
 try{r=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));}
 catch{fail('EXCHANGE33M_RECORD_BYTES_INVALID');}
 if(!exact(r,RECORD_KEYS)||Object.keys(r).join('|')!==RECORD_KEYS.join('|')||
  !Buffer.from(JSON.stringify(r)).equals(bytes)||r.schema!==OFFLINE_CONFLICT_ADJUDICATION_INVENTORY_SCHEMA||
  !Number.isSafeInteger(r.index)||r.index<1||r.index>256||
  typeof r.previousRecordDigest!=='string'||!HEX.test(r.previousRecordDigest)||
  typeof r.recordDigest!=='string'||!HEX.test(r.recordDigest)||!dense(r.pair,2,2))
  fail('EXCHANGE33M_RECORD_NONCANONICAL');
 const {recordDigest:claimed,...body}=r;
 if(recordDigest(body)!==claimed)fail('EXCHANGE33M_RECORD_HASH_MISMATCH');
 return r;
}
function rehydrate(entry){
 if(!exact(entry,['bytes','nowMs','pins'])||!exact(entry.pins,PIN_KEYS)||
  !b64(entry.bytes)||!Number.isSafeInteger(entry.nowMs)||entry.nowMs<0||
  !head(entry.pins.expectedPreHead)||!head(entry.pins.expectedObservedHead)||
  typeof entry.pins.expectedTranscriptDigest!=='string'||!HEX.test(entry.pins.expectedTranscriptDigest))
  fail('EXCHANGE33M_EMBEDDED_PINS_INVALID');
 return {bytes:Buffer.from(entry.bytes,'base64url'),nowMs:entry.nowMs,...entry.pins};
}
/** Each record is fully revalidated, including both independent Ed25519
 * observer signatures and the 2-of-3 approvals in BOTH reviewer groups.
 * Historical transcript validity is checked at the recorded acceptance time;
 * no claim is made that its signatures are currently unexpired.
 */
export function verifyOfflineConflictInventoryRecordEvidence(args={}){
 if(!exact(args,['receiptArgs','records','recordPins']))fail('EXCHANGE33M_ARGUMENTS_INVALID');
 const {receiptArgs,records,recordPins}=args;
 if(!exact(receiptArgs,['receipts','hostPins','expectedNamespaceId','expectedJournalScopeDigest',
  'expectedGenesisHead','nowMs','seenDigests','seenNonces'])||
  !dense(receiptArgs.receipts,2,2)||!dense(receiptArgs.hostPins,2,2)||
  !dense(records,0,32)||!dense(recordPins,0,32))fail('EXCHANGE33M_ARGUMENTS_INVALID');
 const heads=reconcileOfflineConflictInventoryHeadReceipts(receiptArgs);
 const result=(status,digests=[])=>Object.freeze({verifiedSignedReceipts:true,status,
  receiptEvidenceDigest:heads.evidenceDigest,
  recordEvidenceDigest:sha('TJ-33M-VERIFIED-RECORD-SUFFIX',Buffer.from(JSON.stringify(digests))),
  verifiedSuppliedRecordBytes:status==='verified-pinned-record-suffix',
  verifiedNestedSignedTranscripts:status==='verified-pinned-record-suffix',
  provesRemoteDiskState:false,provesHistoricalPrefix:false,independentlyPublished:false,
  independentTimestamp:false,globallyComplete:false,authorizesRepair:false,
  authorizesRecovery:false,authorizesCheckout:false,authorizesProduction:false});
 if(heads.status!=='unresolved-different-heights'){
  if(records.length||recordPins.length)fail('EXCHANGE33M_UNEXPECTED_RECORDS');
  return result(heads.status==='consistent-head'?'consistent-signed-heads':'conflicting-same-height');
 }
 const lowIndex=heads.heads[0].count<heads.heads[1].count?0:1,highIndex=1-lowIndex;
 const low=heads.heads[lowIndex],high=heads.heads[highIndex],gap=high.count-low.count;
 if(gap>32){if(records.length||recordPins.length)fail('EXCHANGE33M_GAP_EXCEEDS_BOUND');return result('unresolved-gap-exceeds-bound');}
 if(!records.length&&!recordPins.length)return result('unresolved-no-record-evidence');
 if(records.length!==gap||recordPins.length!==gap)fail('EXCHANGE33M_MISSING_RECORD');
 const upperReceipt=JSON.parse(receiptArgs.receipts[highIndex].toString('utf8'));
 const usedDigests=new Set(),usedNonces=new Set(),usedObservers=new Set(),digests=[];
 let current=low;
 for(let i=0;i<gap;i++){
  const pin=recordPins[i];
  if(!exact(pin,['expectedRecordBytesDigest','expectedFromHead','expectedToHead'])||
   typeof pin.expectedRecordBytesDigest!=='string'||!HEX.test(pin.expectedRecordBytesDigest)||
   !head(pin.expectedFromHead)||!head(pin.expectedToHead))fail('EXCHANGE33M_EXTERNAL_RECORD_PINS_REQUIRED');
  const bytes=records[i],r=parse(bytes);
  if(r.index!==current.count+1||r.previousRecordDigest!==current.headDigest||
   r.namespaceId!==receiptArgs.expectedNamespaceId||
   r.journalScopeDigest!==receiptArgs.expectedJournalScopeDigest||
   !same(pin.expectedFromHead,current)||!same(pin.expectedToHead,{count:r.index,headDigest:r.recordDigest}))
   fail('EXCHANGE33M_RECORD_CHAIN_MISMATCH');
  const digest=offlineConflictInventoryRecordBytesDigest(bytes);
  if(digest!==pin.expectedRecordBytesDigest)fail('EXCHANGE33M_RECORD_PIN_MISMATCH');
  const entries=r.pair.map(rehydrate);
  for(const entry of entries){
   if(entry.nowMs>receiptArgs.nowMs||entry.nowMs>upperReceipt.body.observedAt)
    fail('EXCHANGE33M_ACCEPTANCE_TIME_INVALID');
  }
  let verified;
  try{
   verified=entries.map(entry=>verifyOfflineConflictPendingAdjudicationTranscript(entry));
   reconcileOfflineConflictPendingAdjudicationTranscripts({left:entries[0],right:entries[1]});
  }catch(e){fail('EXCHANGE33M_EMBEDDED_SIGNATURE_OR_APPROVAL_INVALID');}
  for(const v of verified){
   if(v.namespaceId!==receiptArgs.expectedNamespaceId||
    v.journalScopeDigest!==receiptArgs.expectedJournalScopeDigest)
    fail('EXCHANGE33M_EMBEDDED_SCOPE_MISMATCH');
   if(usedDigests.has(v.digest)||usedNonces.has(v.nonce)||usedObservers.has(v.observerId+'|'+r.index))
    fail('EXCHANGE33M_EMBEDDED_REPLAY');
   usedDigests.add(v.digest);usedNonces.add(v.nonce);usedObservers.add(v.observerId+'|'+r.index);
  }
  current={count:r.index,headDigest:r.recordDigest};digests.push(digest);
 }
 if(!same(current,high))fail('EXCHANGE33M_FINAL_HEAD_MISMATCH');
 return result('verified-pinned-record-suffix',digests);
}
