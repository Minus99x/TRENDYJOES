/**
 * Objective 32E: independently pinned, signed replay-head audit checkpoint.
 * Offline/read-only. It does not publish external pins, trust timestamps, hold
 * signing keys, finalize crash stages or authorize any downstream operation.
 */
import {createHash,verify as verifySignature} from 'node:crypto';
import {OFFLINE_SUPERVISOR_REPLAY_COMMIT_SCHEMA} from './offline-supervisor-replay-commit.mjs';
import {encodeOfflineOrphanReplaySnapshot,verifyOfflineOrphanSupervisorDecision,
 offlineOrphanSupervisorDecisionSigningBytes} from './offline-orphan-supervisor-decision.mjs';

export const OFFLINE_REPLAY_HEAD_CHECKPOINT_SCHEMA='TJ-OFFLINE-REPLAY-HEAD-CHECKPOINT-1';
const HEX=/^[a-f0-9]{64}$/, ID=/^[A-Za-z0-9_-]{12,80}$/;
const sha=b=>createHash('sha256').update(b).digest('hex');
const fail=code=>{throw Object.assign(new Error(code),{code});};
const plain=o=>o!==null&&typeof o==='object'&&!Array.isArray(o)&&[Object.prototype,null].includes(Object.getPrototypeOf(o));
const exact=(o,fields)=>plain(o)&&Object.keys(o).sort().join('|')===fields.slice().sort().join('|');
const cmp=(a,b)=>a<b?-1:a>b?1:0;
function clean(x,depth=0){
 if(depth>40)fail('CHECKPOINT32E_CANONICAL');
 if(x===null||typeof x==='string'||typeof x==='boolean'||typeof x==='number'&&Number.isFinite(x))return;
 if(!Array.isArray(x)&&!plain(x))fail('CHECKPOINT32E_CANONICAL');
 for(const d of Object.values(Object.getOwnPropertyDescriptors(x))){
  if(!Object.hasOwn(d,'value'))fail('CHECKPOINT32E_CANONICAL');clean(d.value,depth+1);
 }
}
function canonical(x){clean(x);let s;try{s=JSON.stringify(x);}catch{fail('CHECKPOINT32E_CANONICAL');}
 if(typeof s!=='string'||Buffer.byteLength(s)>16*1024*1024)fail('CHECKPOINT32E_CANONICAL');
 return Buffer.from(s);
}
const fields=['schema','registryId','genesisDigest','headDigest','commitCount','historyDigest','previousCheckpointDigest','sequence','issuedAt','auditorPolicyDigest'];
function checkedBody(b){
 if(!exact(b,fields)||b.schema!==OFFLINE_REPLAY_HEAD_CHECKPOINT_SCHEMA||!ID.test(b.registryId||'')||
  ![b.genesisDigest,b.headDigest,b.historyDigest,b.previousCheckpointDigest,b.auditorPolicyDigest].every(x=>HEX.test(x||''))||
  !Number.isSafeInteger(b.commitCount)||b.commitCount<0||b.commitCount>4096||
  !Number.isSafeInteger(b.sequence)||b.sequence<1||!Number.isSafeInteger(b.issuedAt)||b.issuedAt<0)
  fail('CHECKPOINT32E_BODY_INVALID');
}
export function offlineReplayHeadCheckpointSigningBytes(body){checkedBody(body);return Buffer.concat([Buffer.from(`${OFFLINE_REPLAY_HEAD_CHECKPOINT_SCHEMA}\0`),canonical(body)]);}
export function offlineReplayHeadCheckpointDigest(checkpoint){
 if(!exact(checkpoint,['body','signatures']))fail('CHECKPOINT32E_SIGNATURE_INVALID');
 offlineReplayHeadCheckpointSigningBytes(checkpoint.body);
 return sha(Buffer.concat([Buffer.from(`${OFFLINE_REPLAY_HEAD_CHECKPOINT_SCHEMA}-SIGNED\0`),canonical(checkpoint)]));
}
function checkedPolicy(auditors,quorum){
 if(!Array.isArray(auditors)||auditors.length<2||auditors.length>12||!Number.isSafeInteger(quorum)||quorum<=auditors.length/2||quorum>auditors.length)
  fail('CHECKPOINT32E_AUDITOR_POLICY_INVALID');
 const ids=new Set(),keys=new Set(),members=[];
 for(const a of auditors){
  if(!exact(a,['id','publicKey'])||!ID.test(a.id||'')||ids.has(a.id)||a.publicKey?.type!=='public'||a.publicKey?.asymmetricKeyType!=='ed25519')
   fail('CHECKPOINT32E_AUDITOR_POLICY_INVALID');
  const keyDigest=sha(a.publicKey.export({format:'der',type:'spki'}));
  if(keys.has(keyDigest))fail('CHECKPOINT32E_AUDITOR_POLICY_INVALID');
  ids.add(a.id);keys.add(keyDigest);members.push({id:a.id,keyDigest,publicKey:a.publicKey});
 }
 const sorted=members.slice().sort((a,b)=>cmp(a.id,b.id));
 const digest=sha(Buffer.from(`${OFFLINE_REPLAY_HEAD_CHECKPOINT_SCHEMA}-POLICY\0${JSON.stringify({quorum,auditors:sorted.map(({id,keyDigest})=>({id,keyDigest}))})}`));
 return {digest,quorum,members:new Map(members.map(a=>[a.id,a.publicKey])),keyDigests:keys};
}
export function offlineReplayHeadAuditorPolicyDigest({auditors,quorum}={}){return checkedPolicy(auditors,quorum).digest;}
function auditItemData(item){
 if(!exact(item,['record','report','expectedPins','decision','reviewers','quorum','expectedReviewerPolicyDigest','observedAtMs']))fail('CHECKPOINT32E_AUDIT_ITEM_INVALID');
 if(!Array.isArray(item.reviewers)||item.reviewers.length>12||item.reviewers.length<2||!Number.isSafeInteger(item.observedAtMs)||item.observedAtMs<0)
  fail('CHECKPOINT32E_AUDIT_ITEM_INVALID');
 const reviewers=item.reviewers.map(r=>{
  if(!exact(r,['id','publicKey'])||!ID.test(r.id||'')||r.publicKey?.type!=='public'||r.publicKey?.asymmetricKeyType!=='ed25519')
   fail('CHECKPOINT32E_AUDIT_ITEM_INVALID');
  return {id:r.id,spki:r.publicKey.export({format:'der',type:'spki'}).toString('base64url')};
 });
 return {record:item.record,report:item.report,expectedPins:item.expectedPins,decision:item.decision,
  reviewers,quorum:item.quorum,expectedReviewerPolicyDigest:item.expectedReviewerPolicyDigest,observedAtMs:item.observedAtMs};
}
export function offlineReplayHeadAuditHistoryDigest(items){
 if(!Array.isArray(items)||items.length>4096)fail('CHECKPOINT32E_AUDIT_ITEMS_INVALID');
 const bytes=canonical(items.map(auditItemData));
 return sha(Buffer.concat([Buffer.from(`${OFFLINE_REPLAY_HEAD_CHECKPOINT_SCHEMA}-HISTORY\0`),bytes]));
}
export function verifyOfflineReplayHeadCheckpoint({registryId,genesisBytes,expectedGenesisDigest,items,checkpoint,
 auditors,auditorQuorum,expectedAuditorPolicyDigest,expectedCheckpointDigest,expectedPreviousCheckpointDigest,expectedSequence}={}){
 if(!ID.test(registryId||'')||!Buffer.isBuffer(genesisBytes)||genesisBytes.length>1024*1024||
  !HEX.test(expectedGenesisDigest||'')||sha(genesisBytes)!==expectedGenesisDigest)fail('CHECKPOINT32E_GENESIS_PIN_REQUIRED');
 let genesis;try{genesis=JSON.parse(genesisBytes.toString('utf8'));}catch{fail('CHECKPOINT32E_GENESIS_INVALID');}
 if(genesis.registryId!==registryId||!encodeOfflineOrphanReplaySnapshot(genesis).equals(genesisBytes))fail('CHECKPOINT32E_GENESIS_INVALID');
 if(!HEX.test(expectedCheckpointDigest||'')||!HEX.test(expectedPreviousCheckpointDigest||'')||
  !Number.isSafeInteger(expectedSequence)||expectedSequence<1)fail('CHECKPOINT32E_EXTERNAL_ANCHORS_REQUIRED');
 if(!exact(checkpoint,['body','signatures']))fail('CHECKPOINT32E_SIGNATURE_INVALID');
 const b=checkpoint.body,signBytes=offlineReplayHeadCheckpointSigningBytes(b);
 if(offlineReplayHeadCheckpointDigest(checkpoint)!==expectedCheckpointDigest||
  b.previousCheckpointDigest!==expectedPreviousCheckpointDigest||b.sequence!==expectedSequence)
  fail('CHECKPOINT32E_EXTERNAL_ANCHOR_MISMATCH');
 const policy=checkedPolicy(auditors,auditorQuorum);
 if(!HEX.test(expectedAuditorPolicyDigest||'')||policy.digest!==expectedAuditorPolicyDigest||b.auditorPolicyDigest!==policy.digest)
  fail('CHECKPOINT32E_AUDITOR_POLICY_PIN_MISMATCH');
 if(!Array.isArray(checkpoint.signatures)||checkpoint.signatures.length<policy.quorum||checkpoint.signatures.length>policy.members.size)
  fail('CHECKPOINT32E_QUORUM_INVALID');
 let last='';for(const s of checkpoint.signatures){
  if(!exact(s,['auditorId','signature'])||typeof s.auditorId!=='string'||s.auditorId<=last||!policy.members.has(s.auditorId)||
   typeof s.signature!=='string'||!/^[A-Za-z0-9_-]{86}$/.test(s.signature)||
   Buffer.from(s.signature,'base64url').toString('base64url')!==s.signature||
   !verifySignature(null,signBytes,policy.members.get(s.auditorId),Buffer.from(s.signature,'base64url')))
   fail('CHECKPOINT32E_SIGNATURE_INVALID');
  last=s.auditorId;
 }
 if(!Array.isArray(items)||items.length!==b.commitCount||items.length>4096||
  b.registryId!==registryId||b.genesisDigest!==expectedGenesisDigest||
  offlineReplayHeadAuditHistoryDigest(items)!==b.historyDigest)fail('CHECKPOINT32E_HISTORY_MISMATCH');
 let replayBytes=genesisBytes,digest=expectedGenesisDigest,lastObserved=-1;
 for(const item of items){
  const {record,decision}=item;
  if(!exact(record,['schema','registryId','previousDigest','nextDigest','decisionId','nonce','decisionDigest'])||
   record.schema!==OFFLINE_SUPERVISOR_REPLAY_COMMIT_SCHEMA||record.registryId!==registryId||record.previousDigest!==digest||
   ![record.nextDigest,record.decisionDigest].every(x=>HEX.test(x||''))||
   item.observedAtMs<lastObserved||item.observedAtMs>b.issuedAt)fail('CHECKPOINT32E_CHAIN_INVALID');
  const verified=verifyOfflineOrphanSupervisorDecision({report:item.report,expectedPins:item.expectedPins,decision,
   reviewers:item.reviewers,quorum:item.quorum,expectedReviewerPolicyDigest:item.expectedReviewerPolicyDigest,
   replayBytes,expectedReplayDigest:digest,nowMs:item.observedAtMs});
  if(record.decisionId!==decision.body.decisionId||record.nonce!==decision.body.nonce||
   record.decisionDigest!==verified.decisionDigest||record.decisionDigest!==sha(offlineOrphanSupervisorDecisionSigningBytes(decision.body)))
   fail('CHECKPOINT32E_DECISION_BINDING_MISMATCH');
  const state=JSON.parse(replayBytes.toString('utf8'));
  const consumed=[...state.consumed,{decisionId:record.decisionId,nonce:record.nonce}].sort((a,c)=>cmp(a.decisionId,c.decisionId));
  replayBytes=encodeOfflineOrphanReplaySnapshot({registryId,consumed});digest=sha(replayBytes);
  if(record.nextDigest!==digest)fail('CHECKPOINT32E_CHAIN_INVALID');
  lastObserved=item.observedAtMs;
 }
 if(digest!==b.headDigest)fail('CHECKPOINT32E_HEAD_MISMATCH');
 return Object.freeze({verified:true,checkpointDigest:expectedCheckpointDigest,headDigest:digest,commitCount:items.length,
  historicalSignaturesVerified:true,externalPinPublicationVerified:false,trustedTimestampVerified:false,
  readOnly:true,authorizesRemediation:false,authorizesCheckout:false,productionApproved:false});
}
