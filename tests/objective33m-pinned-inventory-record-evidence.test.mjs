import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {offlineConflictEquivocationPendingReviewerGroupDigest,
 OFFLINE_CONFLICT_EQUIVOCATION_PENDING_DECISION_SCHEMA,
 offlineConflictEquivocationPendingDecisionBytes,
 offlineConflictEquivocationPendingDecisionDigest} from '../src/offline-conflict-equivocation-acceptance-registry.mjs';
import {OFFLINE_CONFLICT_PENDING_ADJUDICATION_TRANSCRIPT_SCHEMA,
 offlineConflictPendingAdjudicationTranscriptBodyBytes} from '../src/offline-conflict-pending-adjudication-transcript.mjs';
import {offlineConflictAdjudicationInventoryGenesisHead,
 OFFLINE_CONFLICT_ADJUDICATION_INVENTORY_SCHEMA} from '../src/offline-conflict-adjudication-transcript-inventory.mjs';
import {OFFLINE_CONFLICT_INVENTORY_HEAD_RECEIPT_SCHEMA,
 offlineConflictInventoryHeadReceiptBodyBytes,offlineConflictInventoryHeadReceiptDigest} from '../src/offline-conflict-adjudication-inventory-head-receipts.mjs';
import {verifyOfflineConflictInventoryRecordEvidence,offlineConflictInventoryRecordBytesDigest} from '../src/offline-conflict-adjudication-inventory-record-evidence.mjs';
const sha=x=>createHash('sha256').update(x).digest('hex');
const hash=(domain,bytes)=>createHash('sha256').update(domain+'\0').update(bytes).digest('hex');
const ns='namespace_33m_test',scope=sha('33m-scope'),now=1792280000000;
const genesis=offlineConflictAdjudicationInventoryGenesisHead(ns,scope);
const keys=(prefix,n)=>Array.from({length:n},(_,i)=>({id:`${prefix}_${String(i+1).padStart(2,'0')}`,...generateKeyPairSync('ed25519')}));
const reviewersA=keys('reviewers33mA',3),reviewersB=keys('reviewers33mB',3);
const observers=keys('observers33m',2),hosts=keys('hosts33m',2);
const pub=k=>k.publicKey.export({type:'spki',format:'der'}).toString('base64url');
const roster=g=>g.map(k=>({reviewerId:k.id,publicKey:pub(k)}));
const groupA=roster(reviewersA),groupB=roster(reviewersB);
const digestA=offlineConflictEquivocationPendingReviewerGroupDigest(groupA);
const digestB=offlineConflictEquivocationPendingReviewerGroupDigest(groupB);
const head=(count,headDigest)=>({count,headDigest});
const clone=x=>structuredClone(x);
function pair(index,opts={}){
 const preHead=head(0,sha('33m-pending-head'));
 const body={schema:OFFLINE_CONFLICT_EQUIVOCATION_PENDING_DECISION_SCHEMA,action:'inspect-only',
  namespaceId:ns,journalScopeDigest:scope,expectedPreHead:preHead,
  pendingBytesDigest:sha('33m-pending-bytes'),pendingRecordDigest:sha('33m-pending-record'),
  pendingIndex:1,expectedPendingState:'pending-only',reviewerGroupADigest:digestA,
  reviewerGroupBDigest:digestB,issuedAt:now-2000,expiresAt:now+50000,nonce:`decision_33m_${index}`};
 const bytes=offlineConflictEquivocationPendingDecisionBytes(body);
 const signatures=g=>g.slice(0,2).map(k=>({reviewerId:k.id,
  signature:sign(null,bytes,k.privateKey).toString('base64url')}));
 const decision={body,groupASignatures:signatures(reviewersA),groupBSignatures:signatures(reviewersB)};
 const decisionDigest=offlineConflictEquivocationPendingDecisionDigest(decision);
 return observers.map((o,i)=>{
  const tBody={schema:OFFLINE_CONFLICT_PENDING_ADJUDICATION_TRANSCRIPT_SCHEMA,
   namespaceId:ns,journalScopeDigest:scope,decisionDigest,reviewerGroupADigest:digestA,
   reviewerGroupBDigest:digestB,pendingBytesDigest:body.pendingBytesDigest,
   pendingRecordDigest:body.pendingRecordDigest,preHead,observedHead:preHead,
   pendingState:'pending-only',observerId:o.id,observerPublicKey:pub(o),
   observedAt:now-1000,expiresAt:now+30000,nonce:`nonce_33m_${index}_${i}`};
  const transcript={body:tBody,decision,reviewerGroupA:groupA,reviewerGroupB:groupB,
   observerSignature:sign(null,offlineConflictPendingAdjudicationTranscriptBodyBytes(tBody),o.privateKey).toString('base64url')};
  const raw=Buffer.from(JSON.stringify(transcript));
  const pins={expectedTranscriptDigest:hash('TJ-33I-TRANSCRIPT',raw),
   expectedNamespaceId:ns,expectedJournalScopeDigest:scope,expectedDecisionDigest:decisionDigest,
   expectedReviewerGroupADigest:digestA,expectedReviewerGroupBDigest:digestB,
   expectedPendingBytesDigest:body.pendingBytesDigest,expectedPreHead:preHead,
   expectedObservedHead:preHead,expectedObserverId:o.id,expectedObserverPublicKey:pub(o)};
  return {bytes:raw.toString('base64url'),nowMs:now,...{pins},...opts};
 });
}
function record(index,previous,options={}){
 const body={schema:OFFLINE_CONFLICT_ADJUDICATION_INVENTORY_SCHEMA,index,
  namespaceId:ns,journalScopeDigest:scope,previousRecordDigest:previous,pair:pair(index)};
 const raw=Buffer.from(JSON.stringify({...body,recordDigest:hash('TJ-33J-INVENTORY-RECORD',Buffer.from(JSON.stringify(body)))}));
 return raw;
}
function receipt(host,h,nonceSuffix=''){
 const body={schema:OFFLINE_CONFLICT_INVENTORY_HEAD_RECEIPT_SCHEMA,
  inventorySchema:OFFLINE_CONFLICT_ADJUDICATION_INVENTORY_SCHEMA,namespaceId:ns,
  journalScopeDigest:scope,hostId:host.id,genesisHead:genesis,inventoryHead:h,
  observedAt:now+1000,expiresAt:now+30000,nonce:`receipt_33m_${host.id}${nonceSuffix}`};
 return Buffer.from(JSON.stringify({body,signature:sign(null,
  offlineConflictInventoryHeadReceiptBodyBytes(body),host.privateKey).toString('base64url')}));
}
function fixture({lower=0,upper=2}={}){
 const all=[],heads=[genesis];
 for(let i=1;i<=3;i++){
  const b=record(i,heads.at(-1).headDigest);all.push(b);
  heads.push(head(i,JSON.parse(b).recordDigest));
 }
 const lowerHead=heads[lower],upperHead=heads[upper];
 const receipts=hosts.map((h,i)=>receipt(h,i===0?lowerHead:upperHead));
 const hostPins=hosts.map((h,i)=>({hostId:h.id,publicKey:pub(h),
  expectedReceiptDigest:offlineConflictInventoryHeadReceiptDigest(receipts[i]),
  expectedInventoryHead:i===0?lowerHead:upperHead}));
 const records=all.slice(lower,upper);
 const recordPins=records.map((b,i)=>({expectedRecordBytesDigest:offlineConflictInventoryRecordBytesDigest(b),
  expectedFromHead:heads[lower+i],expectedToHead:heads[lower+i+1]}));
 return {receiptArgs:{receipts,hostPins,expectedNamespaceId:ns,
  expectedJournalScopeDigest:scope,expectedGenesisHead:genesis,nowMs:now+2000,
  seenDigests:[],seenNonces:[]},records,recordPins,all,heads};
}
const verify=x=>verifyOfflineConflictInventoryRecordEvidence({receiptArgs:x.receiptArgs,records:x.records,recordPins:x.recordPins});
const reject=(x,code)=>assert.throws(()=>verify(x),e=>e?.code===code);
const t=(name,fn)=>test('33M '+name,fn);
t('valid two-record suffix verifies nested Ed25519 observer and reviewer approvals',()=>{
 const x=fixture(),v=verify(x);assert.equal(v.status,'verified-pinned-record-suffix');
 assert.equal(v.verifiedNestedSignedTranscripts,true);assert.equal(v.verifiedSuppliedRecordBytes,true);
});
t('valid one-record suffix from independently pinned non-genesis head',()=>{
 const x=fixture({lower:1,upper:2});assert.equal(verify(x).status,'verified-pinned-record-suffix');
});
t('no claim of remote disk, prefix, checkout, recovery or production authority',()=>{
 const v=verify(fixture());for(const k of ['provesRemoteDiskState','provesHistoricalPrefix',
  'independentlyPublished','independentTimestamp','globallyComplete','authorizesRepair',
  'authorizesRecovery','authorizesCheckout','authorizesProduction'])assert.equal(v[k],false);
});
t('no records remains unresolved',()=>{const x=fixture();x.records=[];x.recordPins=[];
 assert.equal(verify(x).status,'unresolved-no-record-evidence');});
t('missing middle record rejected',()=>{const x=fixture();x.records.splice(0,1);x.recordPins.splice(0,1);reject(x,'EXCHANGE33M_MISSING_RECORD');});
t('missing external record pin rejected',()=>{const x=fixture();x.recordPins.pop();reject(x,'EXCHANGE33M_MISSING_RECORD');});
t('reordered records rejected',()=>{const x=fixture();x.records.reverse();reject(x,'EXCHANGE33M_RECORD_CHAIN_MISMATCH');});
t('substituted signed record with wrong previous head rejected',()=>{
 const x=fixture();x.records[0]=record(1,sha('wrong'));reject(x,'EXCHANGE33M_RECORD_CHAIN_MISMATCH');
});
t('independent record bytes pin substitution rejected',()=>{const x=fixture();x.recordPins[0].expectedRecordBytesDigest=sha('forgery');reject(x,'EXCHANGE33M_RECORD_PIN_MISMATCH');});
t('independent predecessor pin substitution rejected',()=>{const x=fixture();x.recordPins[0].expectedFromHead=x.heads[1];reject(x,'EXCHANGE33M_RECORD_CHAIN_MISMATCH');});
t('independent successor pin substitution rejected',()=>{const x=fixture();x.recordPins[0].expectedToHead=x.heads[2];reject(x,'EXCHANGE33M_RECORD_CHAIN_MISMATCH');});
t('record digest tamper rejected even with attacker byte repin',()=>{
 const x=fixture(),r=JSON.parse(x.records[0]);r.recordDigest=sha('fake');x.records[0]=Buffer.from(JSON.stringify(r));
 x.recordPins[0].expectedRecordBytesDigest=offlineConflictInventoryRecordBytesDigest(x.records[0]);
 reject(x,'EXCHANGE33M_RECORD_HASH_MISMATCH');
});
t('tampered nested observer signature rejected even with attacker repins and recomputed record digest',()=>{
 const x=fixture(),r=JSON.parse(x.records[0]);const t0=JSON.parse(Buffer.from(r.pair[0].bytes,'base64url'));
 t0.observerSignature=sign(null,Buffer.from('forged'),observers[0].privateKey).toString('base64url');
 const raw=Buffer.from(JSON.stringify(t0));r.pair[0].bytes=raw.toString('base64url');
 r.pair[0].pins.expectedTranscriptDigest=hash('TJ-33I-TRANSCRIPT',raw);
 repinRecord(x,r);reject(x,'EXCHANGE33M_EMBEDDED_SIGNATURE_OR_APPROVAL_INVALID');
});
t('tampered reviewer approval rejected with recomputed nested and outer digests',()=>{
 const x=fixture(),r=JSON.parse(x.records[0]);const t0=JSON.parse(Buffer.from(r.pair[0].bytes,'base64url'));
 t0.decision.groupASignatures[0].signature=sign(null,Buffer.from('fake'),reviewersA[0].privateKey).toString('base64url');
 const raw=Buffer.from(JSON.stringify(t0));r.pair[0].bytes=raw.toString('base64url');
 r.pair[0].pins.expectedTranscriptDigest=hash('TJ-33I-TRANSCRIPT',raw);
 repinRecord(x,r);reject(x,'EXCHANGE33M_EMBEDDED_SIGNATURE_OR_APPROVAL_INVALID');
});
t('omitted signed observer transcript rejected',()=>{const x=fixture(),r=JSON.parse(x.records[0]);r.pair.pop();repinRecord(x,r);reject(x,'EXCHANGE33M_RECORD_NONCANONICAL');});
t('replayed nested transcript nonce across distinct records rejected',()=>{
 const x=fixture(),r=JSON.parse(x.records[1]);
 // Reuse the first signed pair verbatim; both signatures remain authentic.
 r.pair=JSON.parse(x.records[0]).pair;repinRecord(x,r,1);
 // Repin successor receipt to the new, otherwise valid record head.
 repinUpperReceipt(x);reject(x,'EXCHANGE33M_EMBEDDED_REPLAY');
});
t('wrong namespace in otherwise self-hashed record rejected',()=>{const x=fixture(),r=JSON.parse(x.records[0]);r.namespaceId='namespace_33m_other';repinRecord(x,r);reject(x,'EXCHANGE33M_RECORD_CHAIN_MISMATCH');});
t('wrong journal scope rejected',()=>{const x=fixture(),r=JSON.parse(x.records[0]);r.journalScopeDigest=sha('other');repinRecord(x,r);reject(x,'EXCHANGE33M_RECORD_CHAIN_MISMATCH');});
t('future acceptance timestamp rejected',()=>{const x=fixture(),r=JSON.parse(x.records[0]);r.pair[0].nowMs=now+5000;repinRecord(x,r);reject(x,'EXCHANGE33M_ACCEPTANCE_TIME_INVALID');});
t('invalid UTF-8 rejected',()=>{const x=fixture();x.records[0]=Buffer.from([0xff,0xfe]);reject(x,'EXCHANGE33M_RECORD_BYTES_INVALID');});
t('duplicate JSON keys rejected',()=>{const x=fixture();x.records[0]=Buffer.from(x.records[0].toString().replace('{"schema":','{"schema":"fake","schema":'));reject(x,'EXCHANGE33M_RECORD_NONCANONICAL');});
t('whitespace noncanonical record rejected',()=>{const x=fixture();x.records[0]=Buffer.concat([x.records[0],Buffer.from(' ')]);reject(x,'EXCHANGE33M_RECORD_NONCANONICAL');});
t('sparse records rejected',()=>{const x=fixture();delete x.records[0];reject(x,'EXCHANGE33M_ARGUMENTS_INVALID');});
t('extra top-level property rejected',()=>{const x=fixture();assert.throws(()=>verifyOfflineConflictInventoryRecordEvidence({receiptArgs:x.receiptArgs,records:x.records,recordPins:x.recordPins,unsafe:true}),e=>e?.code==='EXCHANGE33M_ARGUMENTS_INVALID');});
t('same head is not misrepresented as newly verified record bytes',()=>{const x=fixture({lower:1,upper:1});assert.equal(verify(x).status,'consistent-signed-heads');});
t('same-height fork is conflict, not verified ancestry',()=>{
 const x=fixture({lower:1,upper:1}),fork=head(1,sha('fork'));
 x.receiptArgs.receipts[1]=receipt(hosts[1],fork);
 x.receiptArgs.hostPins[1].expectedInventoryHead=fork;
 x.receiptArgs.hostPins[1].expectedReceiptDigest=offlineConflictInventoryHeadReceiptDigest(x.receiptArgs.receipts[1]);
 assert.equal(verify(x).status,'conflicting-same-height');
});
t('same-height supplied records rejected',()=>{const x=fixture({lower:1,upper:1});x.records=[x.all[0]];reject(x,'EXCHANGE33M_UNEXPECTED_RECORDS');});
t('invalid host receipt signature rejected',()=>{const x=fixture();x.receiptArgs.hostPins[1].publicKey=pub(hosts[0]);assert.throws(()=>verify(x));});
t('result is immutable',()=>{const v=verify(fixture());assert.throws(()=>{v.status='forged';},TypeError);});
t('different valid suffixes produce distinct evidence digests',()=>{
 assert.notEqual(verify(fixture({lower:0,upper:2})).recordEvidenceDigest,
  verify(fixture({lower:1,upper:2})).recordEvidenceDigest);
});
function repinRecord(x,r,index=0){
 const {recordDigest:_,...body}=r;
 r.recordDigest=hash('TJ-33J-INVENTORY-RECORD',Buffer.from(JSON.stringify(body)));
 x.records[index]=Buffer.from(JSON.stringify(r));
 x.recordPins[index].expectedRecordBytesDigest=offlineConflictInventoryRecordBytesDigest(x.records[index]);
 x.recordPins[index].expectedToHead=head(r.index,r.recordDigest);
}
function repinUpperReceipt(x){
 const final=JSON.parse(x.records.at(-1));const upper=head(final.index,final.recordDigest);
 x.receiptArgs.receipts[1]=receipt(hosts[1],upper);
 x.receiptArgs.hostPins[1].expectedInventoryHead=upper;
 x.receiptArgs.hostPins[1].expectedReceiptDigest=offlineConflictInventoryHeadReceiptDigest(x.receiptArgs.receipts[1]);
}
