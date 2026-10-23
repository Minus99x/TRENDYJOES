/**
 * Objective 32I — bounded offline ancestry of signed 32H checkpoints.
 * Caller-supplied anchors/pins are assertions, NOT evidence of external publication.
 * Policy rotation requires disjoint Ed25519 keysets and dual majority signatures.
 * Read-only: no trusted clock, custody, checkout, network or remediation.
 */
import {createHash,verify as cryptoVerify} from 'node:crypto';
import {
 OFFLINE_WITNESS_HISTORY_ANCHOR_SCHEMA,decodeOfflineWitnessHistoryCheckpoint,
 offlineWitnessHistoryCheckpointAuditorPolicyDigest,offlineWitnessHistoryAnchorCandidate,
 verifyOfflineWitnessHistoryCheckpoint
} from './offline-portable-witness-history-checkpoint.mjs';

export const OFFLINE_WITNESS_CHECKPOINT_AUDITOR_TRANSITION_SCHEMA='TJ-OFFLINE-WITNESS-CHECKPOINT-AUDITOR-TRANSITION-1';
const ID=/^[A-Za-z0-9_-]{12,80}$/;
const HEX=/^[0-9a-f]{64}$/;
const B64=/^[A-Za-z0-9_-]{86}$/;
const BODY=['schema','registryId','genesisDigest','atStartSequence','previousCheckpointDigest','previousReceiptDigest','oldPolicyDigest','newPolicyDigest','issuedAt'];
const ENTRY=['checkpointBytes','historyArgs','auditors','auditorQuorum','expectedAuditorPolicyDigest','transition','expectedTransitionDigest'];
const ANCHOR=['schema','registryId','genesisDigest','sequence','headReceiptDigest','checkpointDigest','issuedAt','auditorPolicyDigest'];
const sha=b=>createHash('sha256').update(b).digest('hex');
const fail=code=>{throw Object.assign(new Error(code),{code});};
const plain=o=>o!==null&&typeof o==='object'&&!Array.isArray(o)&&[Object.prototype,null].includes(Object.getPrototypeOf(o));
const exact=(o,fields)=>plain(o)&&Object.keys(o).sort().join('|')===fields.slice().sort().join('|')&&fields.every(k=>Object.hasOwn(Object.getOwnPropertyDescriptor(o,k)||{},'value'));
const seq=n=>Number.isSafeInteger(n)&&n>=0;
function checkedAnchor(a){
 if(!exact(a,ANCHOR)||a.schema!==OFFLINE_WITNESS_HISTORY_ANCHOR_SCHEMA||!ID.test(a.registryId||'')||
  ![a.genesisDigest,a.headReceiptDigest,a.checkpointDigest,a.auditorPolicyDigest].every(v=>HEX.test(v||''))||
  !seq(a.sequence)||!seq(a.issuedAt))fail('ANCESTRY32I_EXTERNAL_ANCHORS_REQUIRED');
 return a;
}
function checkedBody(body){
 if(!exact(body,BODY)||body.schema!==OFFLINE_WITNESS_CHECKPOINT_AUDITOR_TRANSITION_SCHEMA||
  !ID.test(body.registryId||'')||![body.genesisDigest,body.previousCheckpointDigest,body.previousReceiptDigest,
  body.oldPolicyDigest,body.newPolicyDigest].every(v=>HEX.test(v||''))||body.oldPolicyDigest===body.newPolicyDigest||
  !seq(body.atStartSequence)||body.atStartSequence<1||!seq(body.issuedAt))fail('ANCESTRY32I_TRANSITION_BODY_INVALID');
 return Object.fromEntries(BODY.map(k=>[k,body[k]]));
}
export function offlineWitnessCheckpointAuditorTransitionSigningBytes(body){
 return Buffer.concat([Buffer.from(`${OFFLINE_WITNESS_CHECKPOINT_AUDITOR_TRANSITION_SCHEMA}\0`),Buffer.from(JSON.stringify(checkedBody(body)))]);
}
function signatures(sigs){
 if(!Array.isArray(sigs)||Object.getPrototypeOf(sigs)!==Array.prototype||sigs.length<1||sigs.length>12||
  Object.keys(sigs).length!==sigs.length)fail('ANCESTRY32I_TRANSITION_SIGNATURES_INVALID');
 let prev='';return Array.from({length:sigs.length},(_,i)=>{
  const descriptor=Object.getOwnPropertyDescriptor(sigs,String(i));
  if(!descriptor||!Object.hasOwn(descriptor,'value'))fail('ANCESTRY32I_TRANSITION_SIGNATURES_INVALID');
  const s=descriptor.value;
  if(!exact(s,['auditorId','signature'])||!ID.test(s.auditorId||'')||s.auditorId<=prev||
   !B64.test(s.signature||'')||Buffer.from(s.signature,'base64url').toString('base64url')!==s.signature)
   fail('ANCESTRY32I_TRANSITION_SIGNATURES_INVALID');
  prev=s.auditorId;return {auditorId:s.auditorId,signature:s.signature};
 });
}
function checkedTransition(t){
 if(!exact(t,['body','outgoingSignatures','incomingSignatures']))fail('ANCESTRY32I_TRANSITION_INVALID');
 return {body:checkedBody(t.body),outgoingSignatures:signatures(t.outgoingSignatures),incomingSignatures:signatures(t.incomingSignatures)};
}
export function offlineWitnessCheckpointAuditorTransitionDigest(t){
 return sha(Buffer.concat([Buffer.from(`${OFFLINE_WITNESS_CHECKPOINT_AUDITOR_TRANSITION_SCHEMA}-SIGNED\0`),
  Buffer.from(JSON.stringify(checkedTransition(t)))]));
}
function checkedPolicy(auditors,quorum,expectedDigest){
 let digest;try{digest=offlineWitnessHistoryCheckpointAuditorPolicyDigest({auditors,quorum});}
 catch{fail('ANCESTRY32I_AUDITOR_POLICY_INVALID');}
 if(!HEX.test(expectedDigest||'')||digest!==expectedDigest)fail('ANCESTRY32I_AUDITOR_POLICY_PIN_MISMATCH');
 const members=new Map(auditors.map(a=>[a.id,a.publicKey]));
 const keys=new Set(auditors.map(a=>sha(a.publicKey.export({type:'spki',format:'der'}))));
 return {digest,quorum,members,keys};
}
function verifyQuorum(sigs,policy,bytes){
 if(sigs.length<policy.quorum||sigs.length>policy.members.size)fail('ANCESTRY32I_TRANSITION_QUORUM_INVALID');
 for(const s of sigs){
  const key=policy.members.get(s.auditorId);
  if(!key||!cryptoVerify(null,bytes,key,Buffer.from(s.signature,'base64url')))
   fail('ANCESTRY32I_TRANSITION_SIGNATURE_INVALID');
 }
}
/** Every supplied window must include its full 32G evidence. */
export function verifyOfflineWitnessCheckpointAncestry({initialAnchor,terminalAnchor,entries}={}){
 const root=checkedAnchor(initialAnchor),terminal=checkedAnchor(terminalAnchor);
 if(!Array.isArray(entries)||Object.getPrototypeOf(entries)!==Array.prototype||entries.length<1||entries.length>16||
  Object.keys(entries).length!==entries.length)fail('ANCESTRY32I_ENTRIES_INVALID');
 if(root.registryId!==terminal.registryId||root.genesisDigest!==terminal.genesisDigest||
  terminal.sequence<=root.sequence)fail('ANCESTRY32I_TERMINAL_IDENTITY_OR_ROLLBACK');
 let anchor=root,previousPolicy=null,rotations=0,totalWindows=0;
 const historicalPolicies=new Set(),historicalKeys=new Set();
 const seenDigests=new Set([root.checkpointDigest]);
 for(let i=0;i<entries.length;i++){
  if(!Object.hasOwn(Object.getOwnPropertyDescriptor(entries,String(i))||{},'value'))fail('ANCESTRY32I_ENTRIES_INVALID');
  const entry=entries[i];if(!exact(entry,ENTRY)||!Buffer.isBuffer(entry.checkpointBytes))fail('ANCESTRY32I_ENTRY_INVALID');
  const checkpoint=decodeOfflineWitnessHistoryCheckpoint(entry.checkpointBytes),body=checkpoint.body;
  const policy=checkedPolicy(entry.auditors,entry.auditorQuorum,entry.expectedAuditorPolicyDigest);
  if(body.registryId!==root.registryId||body.genesisDigest!==root.genesisDigest||
   body.startSequence!==anchor.sequence+1||body.previousReceiptDigest!==anchor.headReceiptDigest||
   body.previousCheckpointDigest!==anchor.checkpointDigest||body.issuedAt<anchor.issuedAt)
   fail('ANCESTRY32I_WINDOW_CONTINUITY_INVALID');
  if(policy.digest!==anchor.auditorPolicyDigest){
   if(!previousPolicy||entry.transition===null||!HEX.test(entry.expectedTransitionDigest||'')||
    offlineWitnessCheckpointAuditorTransitionDigest(entry.transition)!==entry.expectedTransitionDigest)
    fail('ANCESTRY32I_TRANSITION_PIN_REQUIRED');
   const transition=checkedTransition(entry.transition),t=transition.body;
   if(t.registryId!==root.registryId||t.genesisDigest!==root.genesisDigest||
    t.atStartSequence!==body.startSequence||t.previousCheckpointDigest!==anchor.checkpointDigest||
    t.previousReceiptDigest!==anchor.headReceiptDigest||t.oldPolicyDigest!==previousPolicy.digest||
    t.newPolicyDigest!==policy.digest||t.issuedAt<anchor.issuedAt||t.issuedAt>body.issuedAt)
    fail('ANCESTRY32I_TRANSITION_BINDING_INVALID');
   if(historicalPolicies.has(policy.digest))fail('ANCESTRY32I_POLICY_ROLLBACK');
   if([...policy.keys].some(k=>historicalKeys.has(k)))fail('ANCESTRY32I_ROTATION_KEY_REUSE');
   const bytes=offlineWitnessCheckpointAuditorTransitionSigningBytes(t);
   verifyQuorum(transition.outgoingSignatures,previousPolicy,bytes);
   verifyQuorum(transition.incomingSignatures,policy,bytes);
   rotations++;
  }else if(entry.transition!==null||entry.expectedTransitionDigest!==null){
   fail('ANCESTRY32I_UNEXPECTED_TRANSITION');
  }
  // 32H requires a same-policy anchor. Only after dual-quorum validation do we
  // bridge the policy digest; all receipt/checkpoint continuity pins stay intact.
  const bridged=Object.freeze({...anchor,auditorPolicyDigest:policy.digest});
  const verified=verifyOfflineWitnessHistoryCheckpoint({checkpointBytes:entry.checkpointBytes,
   historyArgs:entry.historyArgs,auditors:entry.auditors,auditorQuorum:entry.auditorQuorum,
   expectedAuditorPolicyDigest:entry.expectedAuditorPolicyDigest,anchor:bridged});
  if(!verified.verified||!verified.extendsSuppliedAnchor)fail('ANCESTRY32I_WINDOW_UNVERIFIED');
  const candidate=offlineWitnessHistoryAnchorCandidate(entry.checkpointBytes);
  if(seenDigests.has(candidate.checkpointDigest))fail('ANCESTRY32I_REPLAYED_CHECKPOINT');
  seenDigests.add(candidate.checkpointDigest);anchor=candidate;previousPolicy=policy;totalWindows++;
  historicalPolicies.add(policy.digest);for(const key of policy.keys)historicalKeys.add(key);
 }
 if(Object.keys(terminal).some(k=>anchor[k]!==terminal[k]))fail('ANCESTRY32I_TERMINAL_PIN_MISMATCH');
 return Object.freeze({verified:true,readOnly:true,windowCount:totalWindows,rotationCount:rotations,
  firstSequence:root.sequence+1,lastSequence:anchor.sequence,checkpointDigest:anchor.checkpointDigest,
  suppliedTerminalPinMatched:true,independentlyPublished:false,externalPinPublicationVerified:false,
  trustedTimestampVerified:false,fullGenesisHistoryVerified:false,authorizesCheckout:false,
  authorizesRemediation:false,productionApproved:false});
}
