/** Objective 33I: portable observer-signed transcript of 33H read-only local
 * adjudication. This authenticates an observer's assertion and the independent
 * dual-reviewer decision, NOT the underlying disk state or global completeness.
 * No filesystem writes, remote calls, repair, checkout or production authority.
 */
import {createHash,createPublicKey,sign,verify} from 'node:crypto';
import {
 offlineConflictEquivocationPendingDecisionDigest,
 verifyOfflineConflictEquivocationPendingDecisionApproval,
} from './offline-conflict-equivocation-acceptance-registry.mjs';

export const OFFLINE_CONFLICT_PENDING_ADJUDICATION_TRANSCRIPT_SCHEMA='TJ-OFFLINE-CONFLICT-PENDING-ADJUDICATION-TRANSCRIPT-1';
const HEX=/^[0-9a-f]{64}$/, ID=/^[A-Za-z0-9_-]{8,64}$/;
const fail=code=>{throw Object.assign(new Error(code),{code});};
const hash=(domain,bytes)=>createHash('sha256').update(domain+'\0').update(bytes).digest('hex');
const exact=(o,keys)=>o!==null&&typeof o==='object'&&!Array.isArray(o)&&
 [Object.prototype,null].includes(Object.getPrototypeOf(o))&&Reflect.ownKeys(o).length===keys.length&&
 keys.every(k=>{const d=Object.getOwnPropertyDescriptor(o,k);return d&&'value' in d&&d.enumerable;})&&
 Object.keys(o).every(k=>keys.includes(k));
const canonicalB64=x=>typeof x==='string'&&/^[A-Za-z0-9_-]+$/.test(x)&&Buffer.from(x,'base64url').toString('base64url')===x;
const head=h=>exact(h,['count','headDigest'])&&Number.isSafeInteger(h.count)&&h.count>=0&&h.count<=4096&&HEX.test(h.headDigest);
const same=(a,b)=>a.count===b.count&&a.headDigest===b.headDigest;
const BODY=['schema','namespaceId','journalScopeDigest','decisionDigest','reviewerGroupADigest',
 'reviewerGroupBDigest','pendingBytesDigest','pendingRecordDigest','preHead','observedHead',
 'pendingState','observerId','observerPublicKey','observedAt','expiresAt','nonce'];
const TRANSCRIPT=['body','decision','reviewerGroupA','reviewerGroupB','observerSignature'];
function validBody(b){
 if(!exact(b,BODY)||Object.keys(b).join('|')!==BODY.join('|')||b.schema!==OFFLINE_CONFLICT_PENDING_ADJUDICATION_TRANSCRIPT_SCHEMA||
  !ID.test(b.namespaceId)||!HEX.test(b.journalScopeDigest)||!HEX.test(b.decisionDigest)||
  !HEX.test(b.reviewerGroupADigest)||!HEX.test(b.reviewerGroupBDigest)||
  !HEX.test(b.pendingBytesDigest)||!HEX.test(b.pendingRecordDigest)||!head(b.preHead)||
  !head(b.observedHead)||!['pending-only','pending-linked'].includes(b.pendingState)||
  !ID.test(b.observerId)||!canonicalB64(b.observerPublicKey)||
  !Number.isSafeInteger(b.observedAt)||!Number.isSafeInteger(b.expiresAt)||
  b.expiresAt<=b.observedAt||b.expiresAt-b.observedAt>600000||!ID.test(b.nonce))
  fail('EXCHANGE33I_BODY_INVALID');
 if(b.pendingState==='pending-only'&&!same(b.observedHead,b.preHead)||
  b.pendingState==='pending-linked'&&(b.observedHead.count!==b.preHead.count+1||
  b.observedHead.headDigest!==b.pendingRecordDigest))fail('EXCHANGE33I_SNAPSHOT_INCONSISTENT');
}
export function offlineConflictPendingAdjudicationTranscriptBodyBytes(body){
 validBody(body);
 return Buffer.from('TJ-33I-OBSERVER-ADJUDICATION\0'+JSON.stringify(body));
}
function parse(bytes){
 if(!Buffer.isBuffer(bytes)||bytes.length<10||bytes.length>16384)
  fail('EXCHANGE33I_BYTES_INVALID');
 let value;
 try{value=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));}
 catch{fail('EXCHANGE33I_BYTES_INVALID');}
 if(!exact(value,TRANSCRIPT)||Object.keys(value).join('|')!==TRANSCRIPT.join('|')||!Buffer.from(JSON.stringify(value)).equals(bytes))
  fail('EXCHANGE33I_NONCANONICAL');
 return value;
}
function checkPins(body,pins){
 const fields=['expectedNamespaceId','expectedJournalScopeDigest','expectedDecisionDigest',
  'expectedReviewerGroupADigest','expectedReviewerGroupBDigest','expectedPendingBytesDigest',
  'expectedPreHead','expectedObservedHead','expectedObserverId','expectedObserverPublicKey'];
 if(!pins||!fields.every(k=>Object.hasOwn(pins,k))||
  !ID.test(pins.expectedNamespaceId)||!HEX.test(pins.expectedJournalScopeDigest)||
  !HEX.test(pins.expectedDecisionDigest)||!HEX.test(pins.expectedReviewerGroupADigest)||
  !HEX.test(pins.expectedReviewerGroupBDigest)||!HEX.test(pins.expectedPendingBytesDigest)||
  !head(pins.expectedPreHead)||!head(pins.expectedObservedHead)||
  !ID.test(pins.expectedObserverId)||!canonicalB64(pins.expectedObserverPublicKey))
  fail('EXCHANGE33I_EXTERNAL_PINS_REQUIRED');
 if(body.namespaceId!==pins.expectedNamespaceId||body.journalScopeDigest!==pins.expectedJournalScopeDigest||
  body.decisionDigest!==pins.expectedDecisionDigest||
  body.reviewerGroupADigest!==pins.expectedReviewerGroupADigest||
  body.reviewerGroupBDigest!==pins.expectedReviewerGroupBDigest||
  body.pendingBytesDigest!==pins.expectedPendingBytesDigest||
  !same(body.preHead,pins.expectedPreHead)||!same(body.observedHead,pins.expectedObservedHead)||
  body.observerId!==pins.expectedObserverId||body.observerPublicKey!==pins.expectedObserverPublicKey)
  fail('EXCHANGE33I_EXTERNAL_PINS_MISMATCH');
}
function checkDecision(t,at){
 const b=t.body;
 const d=verifyOfflineConflictEquivocationPendingDecisionApproval({
  decision:t.decision,reviewerGroupA:t.reviewerGroupA,reviewerGroupB:t.reviewerGroupB,
  expectedReviewerGroupADigest:b.reviewerGroupADigest,
  expectedReviewerGroupBDigest:b.reviewerGroupBDigest,
  expectedDecisionDigest:b.decisionDigest,nowMs:at,
  expectedNamespaceId:b.namespaceId,expectedJournalScopeDigest:b.journalScopeDigest,
 });
 if(d.pendingBytesDigest!==b.pendingBytesDigest||d.pendingRecordDigest!==b.pendingRecordDigest||
  d.expectedPendingState!==b.pendingState||!same(d.expectedPreHead,b.preHead)||
  offlineConflictEquivocationPendingDecisionDigest(t.decision)!==b.decisionDigest)
  fail('EXCHANGE33I_DECISION_MISMATCH');
}
export function exportOfflineConflictPendingAdjudicationTranscript({adjudication,decision,
 reviewerGroupA,reviewerGroupB,observerId,observerPublicKey,observerPrivateKey,
 observedAt,expiresAt,nonce}={}){
 if(!adjudication||adjudication.verified!==true||
  !['pending-only','pending-linked'].includes(adjudication.status)||
  adjudication.authorizesRepair!==false||adjudication.authorizesRecovery!==false||
  adjudication.authorizesCheckout!==false||adjudication.authorizesProduction!==false||
  adjudication.mutatedAcceptanceRecords!==false||!decision?.body)
  fail('EXCHANGE33I_UNVERIFIED_ADJUDICATION');
 const d=decision.body;
 const body={schema:OFFLINE_CONFLICT_PENDING_ADJUDICATION_TRANSCRIPT_SCHEMA,
  namespaceId:d.namespaceId,journalScopeDigest:d.journalScopeDigest,
  decisionDigest:offlineConflictEquivocationPendingDecisionDigest(decision),
  reviewerGroupADigest:d.reviewerGroupADigest,reviewerGroupBDigest:d.reviewerGroupBDigest,
  pendingBytesDigest:adjudication.pendingBytesDigest,
  pendingRecordDigest:adjudication.pendingRecordDigest,
  preHead:adjudication.preHead,observedHead:adjudication.observedHead,
  pendingState:adjudication.status,observerId,observerPublicKey,observedAt,expiresAt,nonce};
 const bytes=offlineConflictPendingAdjudicationTranscriptBodyBytes(body);
 checkDecision({body,decision,reviewerGroupA,reviewerGroupB},observedAt);
 if(adjudication.decisionDigest!==body.decisionDigest)fail('EXCHANGE33I_DECISION_MISMATCH');
 let signature;
 try{
  const pub=createPublicKey({key:Buffer.from(observerPublicKey,'base64url'),format:'der',type:'spki'});
  if(pub.asymmetricKeyType!=='ed25519')fail('EXCHANGE33I_OBSERVER_KEY_INVALID');
  signature=sign(null,bytes,observerPrivateKey).toString('base64url');
  if(!verify(null,bytes,pub,Buffer.from(signature,'base64url')))
   fail('EXCHANGE33I_OBSERVER_KEY_INVALID');
 }catch{fail('EXCHANGE33I_OBSERVER_KEY_INVALID');}
 const t={body,decision,reviewerGroupA,reviewerGroupB,observerSignature:signature};
 const raw=Buffer.from(JSON.stringify(t));
 if(raw.length>16384)fail('EXCHANGE33I_BYTES_INVALID');
 return Object.freeze({bytes:raw,digest:hash('TJ-33I-TRANSCRIPT',raw)});
}
export function verifyOfflineConflictPendingAdjudicationTranscript({bytes,expectedTranscriptDigest,
 nowMs,seenDigests=[],seenNonces=[],...pins}={}){
 if(!HEX.test(expectedTranscriptDigest)||!Number.isSafeInteger(nowMs)||
  !Array.isArray(seenDigests)||!Array.isArray(seenNonces)||
  seenDigests.some(x=>!HEX.test(x))||seenNonces.some(x=>!ID.test(x)))
  fail('EXCHANGE33I_VERIFICATION_REQUEST_INVALID');
 const t=parse(bytes);validBody(t.body);checkPins(t.body,pins);
 const digest=hash('TJ-33I-TRANSCRIPT',bytes);
 if(digest!==expectedTranscriptDigest)fail('EXCHANGE33I_TRANSCRIPT_DIGEST_MISMATCH');
 if(seenDigests.includes(digest)||seenNonces.includes(t.body.nonce))fail('EXCHANGE33I_REPLAY');
 if(nowMs<t.body.observedAt||nowMs>t.body.expiresAt)fail('EXCHANGE33I_TRANSCRIPT_EXPIRED');
 checkDecision(t,t.body.observedAt);
 if(!canonicalB64(t.observerSignature)||Buffer.from(t.observerSignature,'base64url').length!==64)
  fail('EXCHANGE33I_OBSERVER_SIGNATURE_INVALID');
 let ok=false;
 try{
  const key=createPublicKey({key:Buffer.from(t.body.observerPublicKey,'base64url'),format:'der',type:'spki'});
  ok=key.asymmetricKeyType==='ed25519'&&verify(null,
   offlineConflictPendingAdjudicationTranscriptBodyBytes(t.body),key,
   Buffer.from(t.observerSignature,'base64url'));
 }catch{}
 if(!ok)fail('EXCHANGE33I_OBSERVER_SIGNATURE_INVALID');
 return Object.freeze({verified:true,digest,nonce:t.body.nonce,observerId:t.body.observerId,observerPublicKey:t.body.observerPublicKey,
  namespaceId:t.body.namespaceId,journalScopeDigest:t.body.journalScopeDigest,
  decisionDigest:t.body.decisionDigest,pendingBytesDigest:t.body.pendingBytesDigest,
  pendingRecordDigest:t.body.pendingRecordDigest,preHead:Object.freeze({...t.body.preHead}),
  observedHead:Object.freeze({...t.body.observedHead}),status:t.body.pendingState,
  observerAssertionOnly:true,independentlyWitnessed:false,globallyComplete:false,
  authorizesRepair:false,authorizesRecovery:false,authorizesCheckout:false,
  authorizesProduction:false});
}
export function reconcileOfflineConflictPendingAdjudicationTranscripts({left,right}={}){
 if(!left||!right)fail('EXCHANGE33I_RECONCILIATION_REQUEST_INVALID');
 const a=verifyOfflineConflictPendingAdjudicationTranscript(left);
 const b=verifyOfflineConflictPendingAdjudicationTranscript(right);
 if(a.observerId===b.observerId||a.observerPublicKey===b.observerPublicKey||a.digest===b.digest||a.nonce===b.nonce)
  fail('EXCHANGE33I_OBSERVERS_NOT_INDEPENDENT');
 if(a.namespaceId!==b.namespaceId||a.journalScopeDigest!==b.journalScopeDigest||
  a.decisionDigest!==b.decisionDigest||a.pendingBytesDigest!==b.pendingBytesDigest||
  a.pendingRecordDigest!==b.pendingRecordDigest||!same(a.preHead,b.preHead))
  fail('EXCHANGE33I_CROSS_SCOPE_OR_OMISSION');
 if(a.status!==b.status||!same(a.observedHead,b.observedHead))
  fail('EXCHANGE33I_CONFLICTING_SNAPSHOTS');
 return Object.freeze({verified:true,status:'consistent',observerIds:Object.freeze([a.observerId,b.observerId].sort()),
  decisionDigest:a.decisionDigest,pendingState:a.status,observedHead:a.observedHead,
  globallyComplete:false,authorizesRepair:false,authorizesRecovery:false,
  authorizesCheckout:false,authorizesProduction:false});
}
