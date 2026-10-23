/**
 * Objective 32G: read-only, independently pinned witness receipt continuity.
 * No network, publication, remediation, checkout or key custody.
 * This verifies a bounded historical WINDOW, not proof of genesis publication.
 */
import {createHash,verify as verifySignature} from 'node:crypto';
import {offlinePortableReplayWitnessPolicyDigest,offlinePortableReplayWitnessReceiptDigest,
 verifyOfflinePortableReplayAuditBundle} from './offline-portable-replay-audit-bundle.mjs';

export const OFFLINE_PORTABLE_REPLAY_WITNESS_HISTORY_SCHEMA='TJ-OFFLINE-PORTABLE-REPLAY-WITNESS-HISTORY-1';
export const OFFLINE_PORTABLE_REPLAY_WITNESS_TRANSITION_SCHEMA='TJ-OFFLINE-PORTABLE-REPLAY-WITNESS-TRANSITION-1';
const HEX=/^[0-9a-f]{64}$/;
const ID=/^[A-Za-z0-9_-]{12,80}$/;
const fail=code=>{throw Object.assign(new Error(code),{code});};
const plain=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&[Object.prototype,null].includes(Object.getPrototypeOf(x));
const exact=(o,keys)=>plain(o)&&Object.keys(o).sort().join('|')===keys.slice().sort().join('|');
const sha=x=>createHash('sha256').update(x).digest('hex');
const safe=x=>Number.isSafeInteger(x)&&x>=0;
function canonical(x){
 const seen=new Set();
 function check(v,depth=0){
  if(depth>32)fail('HISTORY32G_CANONICAL_INVALID');
  if(v===null||typeof v==='string'||typeof v==='boolean'||typeof v==='number'&&Number.isFinite(v))return;
  if(!plain(v)&&!Array.isArray(v))fail('HISTORY32G_CANONICAL_INVALID');
  if(seen.has(v))fail('HISTORY32G_CANONICAL_INVALID');seen.add(v);
  if(Array.isArray(v)&&Object.keys(v).length!==v.length)fail('HISTORY32G_CANONICAL_INVALID');
  for(const [k,d] of Object.entries(Object.getOwnPropertyDescriptors(v))){
   if(['__proto__','constructor','prototype'].includes(k)||!Object.hasOwn(d,'value'))fail('HISTORY32G_CANONICAL_INVALID');
   check(d.value,depth+1);
  }
  seen.delete(v);
 }
 check(x);const s=JSON.stringify(x);
 if(!s||Buffer.byteLength(s)>1024*1024)fail('HISTORY32G_CANONICAL_INVALID');
 return Buffer.from(s);
}
const TRANSITION_FIELDS=['schema','registryId','atSequence','previousReceiptDigest','oldPolicyDigest','newPolicyDigest','issuedAt'];
export function offlinePortableReplayWitnessTransitionSigningBytes(body){
 if(!exact(body,TRANSITION_FIELDS)||body.schema!==OFFLINE_PORTABLE_REPLAY_WITNESS_TRANSITION_SCHEMA||
  !ID.test(body.registryId||'')||!safe(body.atSequence)||body.atSequence<2||!safe(body.issuedAt)||
  ![body.previousReceiptDigest,body.oldPolicyDigest,body.newPolicyDigest].every(x=>HEX.test(x||''))||
  body.oldPolicyDigest===body.newPolicyDigest)fail('HISTORY32G_TRANSITION_BODY_INVALID');
 return Buffer.concat([Buffer.from(`${OFFLINE_PORTABLE_REPLAY_WITNESS_TRANSITION_SCHEMA}\0`),canonical(body)]);
}
export function offlinePortableReplayWitnessTransitionDigest(transition){
 if(!exact(transition,['body','outgoingSignatures','incomingSignatures']))fail('HISTORY32G_TRANSITION_INVALID');
 offlinePortableReplayWitnessTransitionSigningBytes(transition.body);
 return sha(Buffer.concat([Buffer.from(`${OFFLINE_PORTABLE_REPLAY_WITNESS_TRANSITION_SCHEMA}-SIGNED\0`),canonical(transition)]));
}
function policy(p){
 if(!exact(p,['witnesses','quorum','expectedPolicyDigest','transition','expectedTransitionDigest']))fail('HISTORY32G_POLICY_INVALID');
 let digest;try{digest=offlinePortableReplayWitnessPolicyDigest({witnesses:p.witnesses,quorum:p.quorum});}
 catch{fail('HISTORY32G_POLICY_INVALID');}
 if(!HEX.test(p.expectedPolicyDigest||'')||digest!==p.expectedPolicyDigest)fail('HISTORY32G_POLICY_PIN_MISMATCH');
 return {digest,quorum:p.quorum,witnesses:p.witnesses,keys:new Set(p.witnesses.map(w=>sha(w.publicKey.export({type:'spki',format:'der'}))))};
}
function quorumSignatures(signatures,pol,bytes){
 if(!Array.isArray(signatures)||signatures.length<pol.quorum||signatures.length>pol.witnesses.length)
  fail('HISTORY32G_TRANSITION_QUORUM_INVALID');
 const members=new Map(pol.witnesses.map(w=>[w.id,w.publicKey]));let last='';
 for(const s of signatures){
  if(!exact(s,['witnessId','signature'])||typeof s.witnessId!=='string'||s.witnessId<=last||!members.has(s.witnessId)||
   typeof s.signature!=='string'||!/^[A-Za-z0-9_-]{86}$/.test(s.signature)||
   Buffer.from(s.signature,'base64url').toString('base64url')!==s.signature||
   !verifySignature(null,bytes,members.get(s.witnessId),Buffer.from(s.signature,'base64url')))
   fail('HISTORY32G_TRANSITION_SIGNATURE_INVALID');
  last=s.witnessId;
 }
}
export function offlinePortableReplayWitnessHistoryDigest({registryId,initialPreviousReceiptDigest,records}={}){
 if(!ID.test(registryId||'')||!HEX.test(initialPreviousReceiptDigest||'')||!Array.isArray(records)||
  records.length<1||records.length>32||!records.every(r=>exact(r,['sequence','receiptDigest','policyDigest','transitionDigest'])&&
   safe(r.sequence)&&r.sequence>0&&[r.receiptDigest,r.policyDigest].every(x=>HEX.test(x||''))&&
   (r.transitionDigest===null||HEX.test(r.transitionDigest||''))))fail('HISTORY32G_DIGEST_INPUT_INVALID');
 return sha(Buffer.concat([Buffer.from(`${OFFLINE_PORTABLE_REPLAY_WITNESS_HISTORY_SCHEMA}\0`),
  canonical({registryId,initialPreviousReceiptDigest,records})]));
}
export function verifyOfflinePortableReplayWitnessHistory({registryId,entries,policies,
 expectedInitialPreviousReceiptDigest,expectedStartSequence,expectedEndSequence,expectedHeadReceiptDigest,
 expectedHistoryDigest,expectedGenesisDigest}={}){
 if(!ID.test(registryId||'')||!Array.isArray(entries)||entries.length<1||entries.length>32||
  !Array.isArray(policies)||policies.length<1||policies.length>8||
  ![expectedInitialPreviousReceiptDigest,expectedHeadReceiptDigest,expectedHistoryDigest,expectedGenesisDigest].every(x=>HEX.test(x||''))||
  !safe(expectedStartSequence)||expectedStartSequence<1||!safe(expectedEndSequence)||
  expectedEndSequence!==expectedStartSequence+entries.length-1)
  fail('HISTORY32G_EXTERNAL_PINS_REQUIRED');
 const total=entries.reduce((n,e)=>n+(Buffer.isBuffer(e?.verificationArgs?.bundleBytes)?e.verificationArgs.bundleBytes.length:0),0);
 if(total>64*1024*1024)fail('HISTORY32G_WINDOW_TOO_LARGE');
 const checkedPolicies=policies.map(policy);
 if(policies[0].transition!==null||policies[0].expectedTransitionDigest!==null)
  fail('HISTORY32G_INITIAL_POLICY_INVALID');
 const records=[];let previous=expectedInitialPreviousReceiptDigest,previousTime=-1,previousCount=-1,
  previousCheckpointSequence=-1,activeIndex=0,usedPolicyIndices=new Set([0]);
 for(let i=0;i<entries.length;i++){
  const entry=entries[i];if(!exact(entry,['policyIndex','verificationArgs'])||!safe(entry.policyIndex)||entry.policyIndex>=policies.length||
   !plain(entry.verificationArgs))fail('HISTORY32G_ENTRY_INVALID');
  const args=entry.verificationArgs,receipt=args.witnessReceipt,body=receipt?.body,seq=expectedStartSequence+i;
  if(!body||body.registryId!==registryId||body.sequence!==seq||body.previousWitnessReceiptDigest!==previous||
   args.expectedWitnessSequence!==seq||args.expectedPreviousWitnessReceiptDigest!==previous||
   args.expectedGenesisDigest!==expectedGenesisDigest)fail('HISTORY32G_CHAIN_INVALID');
  if(entry.policyIndex<activeIndex||entry.policyIndex>activeIndex+1)fail('HISTORY32G_POLICY_ORDER_INVALID');
  let transitionDigest=null;
  if(entry.policyIndex===activeIndex+1){
   const next=policies[entry.policyIndex],old=checkedPolicies[activeIndex],incoming=checkedPolicies[entry.policyIndex];
   if(!next.transition||!HEX.test(next.expectedTransitionDigest||'')||
    offlinePortableReplayWitnessTransitionDigest(next.transition)!==next.expectedTransitionDigest)
    fail('HISTORY32G_TRANSITION_PIN_MISMATCH');
   const t=next.transition.body;
   if(t.registryId!==registryId||t.atSequence!==seq||t.previousReceiptDigest!==previous||
    t.oldPolicyDigest!==old.digest||t.newPolicyDigest!==incoming.digest||
    t.issuedAt<previousTime||t.issuedAt>body.issuedAt)fail('HISTORY32G_TRANSITION_BINDING_INVALID');
   // A rotated policy must prove possession of genuinely new keys, not count a shared key twice.
   if([...old.keys].some(k=>incoming.keys.has(k)))fail('HISTORY32G_ROTATION_KEY_REUSE');
   const bytes=offlinePortableReplayWitnessTransitionSigningBytes(t);
   quorumSignatures(next.transition.outgoingSignatures,old,bytes);
   quorumSignatures(next.transition.incomingSignatures,incoming,bytes);
   transitionDigest=next.expectedTransitionDigest;activeIndex=entry.policyIndex;usedPolicyIndices.add(activeIndex);
  }else if(entry.policyIndex!==activeIndex)fail('HISTORY32G_POLICY_ORDER_INVALID');
  const p=checkedPolicies[activeIndex];
  if(args.expectedWitnessPolicyDigest!==p.digest||body.witnessPolicyDigest!==p.digest)
   fail('HISTORY32G_POLICY_BINDING_INVALID');
  const result=verifyOfflinePortableReplayAuditBundle({...args,witnesses:p.witnesses,witnessQuorum:p.quorum});
  if(!result.verified||body.issuedAt<previousTime||body.commitCount<previousCount||
   args.expectedSequence<previousCheckpointSequence)fail('HISTORY32G_ROLLBACK_OR_TIME_INVALID');
  const receiptDigest=offlinePortableReplayWitnessReceiptDigest(receipt);
  if(receiptDigest!==args.expectedWitnessReceiptDigest)fail('HISTORY32G_RECEIPT_PIN_MISMATCH');
  records.push({sequence:seq,receiptDigest,policyDigest:p.digest,transitionDigest});
  previous=receiptDigest;previousTime=body.issuedAt;previousCount=body.commitCount;
  previousCheckpointSequence=args.expectedSequence;
 }
 if(usedPolicyIndices.size!==policies.length)fail('HISTORY32G_UNUSED_POLICY_INVALID');
 if(previous!==expectedHeadReceiptDigest)fail('HISTORY32G_HEAD_PIN_MISMATCH');
 const historyDigest=offlinePortableReplayWitnessHistoryDigest({registryId,initialPreviousReceiptDigest:expectedInitialPreviousReceiptDigest,records});
 if(historyDigest!==expectedHistoryDigest)fail('HISTORY32G_HISTORY_PIN_MISMATCH');
 return Object.freeze({verified:true,readOnly:true,windowVerified:true,entryCount:entries.length,
  startSequence:expectedStartSequence,endSequence:expectedEndSequence,headReceiptDigest:previous,historyDigest,
  policyEpochs:policies.length,fullGenesisHistoryVerified:false,independentlyPublished:false,
  externalPinPublicationVerified:false,trustedTimestampVerified:false,
  authorizesRemediation:false,authorizesCheckout:false,productionApproved:false});
}
