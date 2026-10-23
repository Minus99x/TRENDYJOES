/**
 * Objective 32H: portable, auditor-signed witness-history checkpoints.
 * Read-only; caller-supplied anchors are NOT proof of independent publication.
 * Every checkpoint requires the complete bounded 32G evidence window.
 */
import {createHash,verify as verifySignature} from 'node:crypto';
import {verifyOfflinePortableReplayWitnessHistory} from './offline-portable-replay-witness-history.mjs';

export const OFFLINE_WITNESS_HISTORY_CHECKPOINT_SCHEMA='TJ-OFFLINE-WITNESS-HISTORY-CHECKPOINT-1';
export const OFFLINE_WITNESS_HISTORY_ANCHOR_SCHEMA='TJ-OFFLINE-WITNESS-HISTORY-ANCHOR-1';
const ID=/^[A-Za-z0-9_-]{12,80}$/;
const HEX=/^[0-9a-f]{64}$/;
const B64=/^[A-Za-z0-9_-]{86}$/;
const BODY=['schema','registryId','genesisDigest','startSequence','endSequence','previousReceiptDigest','headReceiptDigest',
 'historyDigest','previousCheckpointDigest','issuedAt','auditorPolicyDigest'];
const ANCHOR=['schema','registryId','genesisDigest','sequence','headReceiptDigest','checkpointDigest','issuedAt','auditorPolicyDigest'];
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const fail=code=>{throw Object.assign(new Error(code),{code});};
const plain=o=>o!==null&&typeof o==='object'&&!Array.isArray(o)&&[Object.prototype,null].includes(Object.getPrototypeOf(o));
const exact=(o,fields)=>plain(o)&&Object.keys(o).sort().join('|')===fields.slice().sort().join('|');
const seq=n=>Number.isSafeInteger(n)&&n>=0;
function safeObject(o,fields,code){
 if(!exact(o,fields))fail(code);
 for(const k of fields){const d=Object.getOwnPropertyDescriptor(o,k);if(!d||!Object.hasOwn(d,'value'))fail(code);}
}
function checkedBody(body){
 safeObject(body,BODY,'WITNESS32H_BODY_INVALID');
 if(body.schema!==OFFLINE_WITNESS_HISTORY_CHECKPOINT_SCHEMA||!ID.test(body.registryId||'')||
  ![body.genesisDigest,body.previousReceiptDigest,body.headReceiptDigest,body.historyDigest,
    body.previousCheckpointDigest,body.auditorPolicyDigest].every(v=>HEX.test(v||''))||
  !seq(body.startSequence)||body.startSequence<1||!seq(body.endSequence)||body.endSequence<body.startSequence||
  body.endSequence-body.startSequence>=32||!seq(body.issuedAt))fail('WITNESS32H_BODY_INVALID');
 return Object.fromEntries(BODY.map(k=>[k,body[k]]));
}
function checkedSignatures(signatures){
 if(!Array.isArray(signatures)||Object.getPrototypeOf(signatures)!==Array.prototype||
  signatures.length<1||signatures.length>12||Object.keys(signatures).length!==signatures.length)
  fail('WITNESS32H_SIGNATURES_INVALID');
 for(let i=0;i<signatures.length;i++){
  const d=Object.getOwnPropertyDescriptor(signatures,String(i));
  if(!d||!Object.hasOwn(d,'value'))fail('WITNESS32H_SIGNATURES_INVALID');
 }
 let last='';return signatures.map(s=>{
  safeObject(s,['auditorId','signature'],'WITNESS32H_SIGNATURES_INVALID');
  if(!ID.test(s.auditorId||'')||s.auditorId<=last||!B64.test(s.signature||'')||
   Buffer.from(s.signature,'base64url').toString('base64url')!==s.signature)fail('WITNESS32H_SIGNATURES_INVALID');
  last=s.auditorId;return {auditorId:s.auditorId,signature:s.signature};
 });
}
function normalized(checkpoint){
 safeObject(checkpoint,['body','signatures'],'WITNESS32H_CHECKPOINT_INVALID');
 return {body:checkedBody(checkpoint.body),signatures:checkedSignatures(checkpoint.signatures)};
}
export function offlineWitnessHistoryCheckpointSigningBytes(body){
 return Buffer.concat([Buffer.from(`${OFFLINE_WITNESS_HISTORY_CHECKPOINT_SCHEMA}\0`),Buffer.from(JSON.stringify(checkedBody(body)))]);
}
export function encodeOfflineWitnessHistoryCheckpoint(checkpoint){
 const bytes=Buffer.from(JSON.stringify(normalized(checkpoint)));
 if(bytes.length>64*1024)fail('WITNESS32H_CHECKPOINT_TOO_LARGE');
 return bytes;
}
export function decodeOfflineWitnessHistoryCheckpoint(bytes){
 if(!Buffer.isBuffer(bytes)||bytes.length<1||bytes.length>64*1024)fail('WITNESS32H_ENCODING_INVALID');
 let parsed;try{parsed=JSON.parse(bytes.toString('utf8'));}catch{fail('WITNESS32H_ENCODING_INVALID');}
 const canonical=encodeOfflineWitnessHistoryCheckpoint(parsed);
 if(!canonical.equals(bytes))fail('WITNESS32H_NONCANONICAL_ENCODING');
 return parsed;
}
export function offlineWitnessHistoryCheckpointDigest(checkpointOrBytes){
 const bytes=Buffer.isBuffer(checkpointOrBytes)?encodeOfflineWitnessHistoryCheckpoint(decodeOfflineWitnessHistoryCheckpoint(checkpointOrBytes)):
  encodeOfflineWitnessHistoryCheckpoint(checkpointOrBytes);
 return sha(Buffer.concat([Buffer.from(`${OFFLINE_WITNESS_HISTORY_CHECKPOINT_SCHEMA}-SIGNED\0`),bytes]));
}
function checkedAuditors(auditors,quorum){
 if(!Array.isArray(auditors)||auditors.length<2||auditors.length>12||!seq(quorum)||
  quorum<=auditors.length/2||quorum>auditors.length)fail('WITNESS32H_AUDITOR_POLICY_INVALID');
 const ids=new Set(),keys=new Set(),members=[];
 for(const a of auditors){
  safeObject(a,['id','publicKey'],'WITNESS32H_AUDITOR_POLICY_INVALID');
  if(!ID.test(a.id||'')||ids.has(a.id)||a.publicKey?.type!=='public'||a.publicKey?.asymmetricKeyType!=='ed25519')
   fail('WITNESS32H_AUDITOR_POLICY_INVALID');
  const keyDigest=sha(a.publicKey.export({type:'spki',format:'der'}));
  if(keys.has(keyDigest))fail('WITNESS32H_AUDITOR_POLICY_INVALID');
  ids.add(a.id);keys.add(keyDigest);members.push({id:a.id,keyDigest,publicKey:a.publicKey});
 }
 members.sort((a,b)=>a.id<b.id?-1:a.id>b.id?1:0);
 const digest=sha(Buffer.from(`${OFFLINE_WITNESS_HISTORY_CHECKPOINT_SCHEMA}-POLICY\0${JSON.stringify({quorum,auditors:members.map(({id,keyDigest})=>({id,keyDigest}))})}`));
 return {digest,quorum,members:new Map(members.map(m=>[m.id,m.publicKey]))};
}
export function offlineWitnessHistoryCheckpointAuditorPolicyDigest({auditors,quorum}={}){
 return checkedAuditors(auditors,quorum).digest;
}
function checkedAnchor(anchor){
 safeObject(anchor,ANCHOR,'WITNESS32H_EXTERNAL_ANCHOR_REQUIRED');
 if(anchor.schema!==OFFLINE_WITNESS_HISTORY_ANCHOR_SCHEMA||!ID.test(anchor.registryId||'')||
  ![anchor.genesisDigest,anchor.headReceiptDigest,anchor.checkpointDigest,anchor.auditorPolicyDigest].every(v=>HEX.test(v||''))||
  !seq(anchor.sequence)||!seq(anchor.issuedAt))fail('WITNESS32H_EXTERNAL_ANCHOR_REQUIRED');
 return anchor;
}
/** Generates an anchor *candidate* for independent storage, not proof it was published. */
export function offlineWitnessHistoryAnchorCandidate(checkpointOrBytes){
 const c=Buffer.isBuffer(checkpointOrBytes)?decodeOfflineWitnessHistoryCheckpoint(checkpointOrBytes):normalized(checkpointOrBytes);
 return Object.freeze({schema:OFFLINE_WITNESS_HISTORY_ANCHOR_SCHEMA,registryId:c.body.registryId,
  genesisDigest:c.body.genesisDigest,sequence:c.body.endSequence,headReceiptDigest:c.body.headReceiptDigest,
  checkpointDigest:offlineWitnessHistoryCheckpointDigest(c),issuedAt:c.body.issuedAt,auditorPolicyDigest:c.body.auditorPolicyDigest});
}
export function verifyOfflineWitnessHistoryCheckpoint({checkpointBytes,historyArgs,auditors,auditorQuorum,
 expectedAuditorPolicyDigest,anchor,expectedCandidateCheckpointDigest=null}={}){
 const c=decodeOfflineWitnessHistoryCheckpoint(checkpointBytes),b=c.body,a=checkedAnchor(anchor);
 const pol=checkedAuditors(auditors,auditorQuorum);
 if(!HEX.test(expectedAuditorPolicyDigest||'')||pol.digest!==expectedAuditorPolicyDigest||
  b.auditorPolicyDigest!==pol.digest||a.auditorPolicyDigest!==pol.digest)fail('WITNESS32H_AUDITOR_POLICY_PIN_MISMATCH');
 if(c.signatures.length<pol.quorum||c.signatures.length>pol.members.size)fail('WITNESS32H_QUORUM_INVALID');
 const signing=offlineWitnessHistoryCheckpointSigningBytes(b);
 for(const s of c.signatures){
  if(!pol.members.has(s.auditorId)||!verifySignature(null,signing,pol.members.get(s.auditorId),Buffer.from(s.signature,'base64url')))
   fail('WITNESS32H_SIGNATURE_INVALID');
 }
 if(!plain(historyArgs)||historyArgs.registryId!==b.registryId||historyArgs.expectedGenesisDigest!==b.genesisDigest||
  historyArgs.expectedStartSequence!==b.startSequence||historyArgs.expectedEndSequence!==b.endSequence||
  historyArgs.expectedInitialPreviousReceiptDigest!==b.previousReceiptDigest||
  historyArgs.expectedHeadReceiptDigest!==b.headReceiptDigest||historyArgs.expectedHistoryDigest!==b.historyDigest)
  fail('WITNESS32H_HISTORY_BINDING_INVALID');
 const history=verifyOfflinePortableReplayWitnessHistory(historyArgs);
 if(!history.verified||history.headReceiptDigest!==b.headReceiptDigest||history.historyDigest!==b.historyDigest)
  fail('WITNESS32H_HISTORY_BINDING_INVALID');
 const digest=offlineWitnessHistoryCheckpointDigest(checkpointBytes);
 if(expectedCandidateCheckpointDigest!==null&&(!HEX.test(expectedCandidateCheckpointDigest||'')||digest!==expectedCandidateCheckpointDigest))
  fail('WITNESS32H_CANDIDATE_PIN_MISMATCH');
 if(b.registryId!==a.registryId||b.genesisDigest!==a.genesisDigest)fail('WITNESS32H_ANCHOR_IDENTITY_MISMATCH');
 if(b.endSequence<a.sequence)fail('WITNESS32H_STALE_CHECKPOINT');
 if(b.endSequence===a.sequence){
  if(digest!==a.checkpointDigest||b.headReceiptDigest!==a.headReceiptDigest||b.issuedAt!==a.issuedAt)
   fail('WITNESS32H_ANCHORED_FORK');
 }else{
  if(b.startSequence!==a.sequence+1||b.previousReceiptDigest!==a.headReceiptDigest||
   b.previousCheckpointDigest!==a.checkpointDigest)fail('WITNESS32H_ANCHOR_CONTINUITY_INVALID');
  if(b.issuedAt<a.issuedAt)fail('WITNESS32H_TIMESTAMP_ROLLBACK');
 }
 return Object.freeze({verified:true,readOnly:true,checkpointDigest:digest,headReceiptDigest:b.headReceiptDigest,
  startSequence:b.startSequence,endSequence:b.endSequence,anchoredMatch:b.endSequence===a.sequence,
  extendsSuppliedAnchor:b.endSequence>a.sequence,candidateDigestPinned:expectedCandidateCheckpointDigest!==null,
  independentlyPublished:false,externalPinPublicationVerified:false,trustedTimestampVerified:false,
  fullGenesisHistoryVerified:false,authorizesRemediation:false,authorizesCheckout:false,productionApproved:false});
}
