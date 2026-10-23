/**
 * Objective 32J: read-only comparison of two fully authenticated, caller-pinned
 * 32I checkpoint ancestries. Two supplied pins are NOT independently published
 * anchors. Fork evidence is local cryptographic evidence, not global uniqueness.
 */
import {createHash} from 'node:crypto';
import {verifyOfflineWitnessCheckpointAncestry} from './offline-witness-checkpoint-ancestry.mjs';
import {decodeOfflineWitnessHistoryCheckpoint,offlineWitnessHistoryAnchorCandidate} from './offline-portable-witness-history-checkpoint.mjs';

export const OFFLINE_WITNESS_SPLIT_VIEW_SCHEMA='TJ-OFFLINE-WITNESS-CHECKPOINT-SPLIT-VIEW-1';
const fail=code=>{throw Object.assign(new Error(code),{code});};
const plain=o=>o!==null&&typeof o==='object'&&!Array.isArray(o)&&[Object.prototype,null].includes(Object.getPrototypeOf(o));
const exact=(o,fields)=>plain(o)&&Object.keys(o).sort().join('|')===fields.slice().sort().join('|')&&
 fields.every(k=>Object.hasOwn(Object.getOwnPropertyDescriptor(o,k)||{},'value'));
const sha=b=>createHash('sha256').update(b).digest('hex');
const keyHash=key=>sha(key.export({type:'spki',format:'der'}));
function checkedPair(observations){
 if(!Array.isArray(observations)||Object.getPrototypeOf(observations)!==Array.prototype||observations.length!==2||
  Object.keys(observations).length!==2||![0,1].every(i=>Object.hasOwn(Object.getOwnPropertyDescriptor(observations,String(i))||{},'value')))
  fail('SPLIT32J_TWO_OBSERVATIONS_REQUIRED');
 return observations.map(o=>{
  if(!exact(o,['terminalAnchor','entries']))fail('SPLIT32J_OBSERVATION_INVALID');
  return o;
 });
}
function verifiedPath(root,observation){
 const result=verifyOfflineWitnessCheckpointAncestry({initialAnchor:root,terminalAnchor:observation.terminalAnchor,entries:observation.entries});
 if(!result.verified||!result.suppliedTerminalPinMatched)fail('SPLIT32J_ANCESTRY_NOT_VERIFIED');
 const nodes=observation.entries.map(entry=>({
  checkpoint:decodeOfflineWitnessHistoryCheckpoint(entry.checkpointBytes),
  anchor:offlineWitnessHistoryAnchorCandidate(entry.checkpointBytes),
  entry
 }));
 return {nodes,terminal:observation.terminalAnchor};
}
function signedOverlap(left,right){
 const leftKeys=new Map(left.entry.auditors.map(a=>[a.id,keyHash(a.publicKey)]));
 const rightKeys=new Map(right.entry.auditors.map(a=>[a.id,keyHash(a.publicKey)]));
 const signers=new Map(left.checkpoint.signatures.map(s=>[s.auditorId,s.signature]));
 const intersection=[];
 for(const s of right.checkpoint.signatures){
  if(signers.has(s.auditorId)&&leftKeys.get(s.auditorId)===rightKeys.get(s.auditorId))
   intersection.push(Object.freeze({auditorId:s.auditorId,publicKeyDigest:leftKeys.get(s.auditorId)}));
 }
 return Object.freeze(intersection);
}
function transitionOverlap(left,right){
 const l=left.entry.transition,r=right.entry.transition;
 if(!l||!r||left.entry.expectedTransitionDigest===right.entry.expectedTransitionDigest)return Object.freeze([]);
 // The 32I verifier has already authenticated both outgoing quorums against
 // their immediate predecessor policies. Here both paths share that predecessor.
 const la=new Map(l.outgoingSignatures.map(s=>[s.auditorId,s.signature]));
 const ids=r.outgoingSignatures.filter(s=>la.has(s.auditorId)).map(s=>s.auditorId);
 return Object.freeze(ids);
}
/**
 * All input evidence is verified by Objective 32I before comparison.
 * Consistent paths are NOT proof that there are no other forks elsewhere.
 * A fork is evidence of competing authenticated successors of one predecessor.
 */
export function verifyOfflineWitnessCheckpointSplitView(args={}){
 if(!exact(args,['initialAnchor','observations']))fail('SPLIT32J_INPUT_INVALID');
 const {initialAnchor,observations}=args;
 const pair=checkedPair(observations);
 // Fail closed if either branch is invalid, even when the other branch is valid.
 const left=verifiedPath(initialAnchor,pair[0]),right=verifiedPath(initialAnchor,pair[1]);
 let common=0;
 while(common<left.nodes.length&&common<right.nodes.length&&
  left.nodes[common].anchor.checkpointDigest===right.nodes[common].anchor.checkpointDigest)common++;
 const shorter=Math.min(left.nodes.length,right.nodes.length);
 const fork=common<shorter;
 if(!fork){
  const status=left.nodes.length===right.nodes.length?'IDENTICAL_AUTHENTICATED_PATH':'AUTHENTICATED_PREFIX_EXTENSION';
  return Object.freeze({schema:OFFLINE_WITNESS_SPLIT_VIEW_SCHEMA,verified:true,readOnly:true,
   status,forkDetected:false,sharedCheckpointCount:common,
   leftCheckpointCount:left.nodes.length,rightCheckpointCount:right.nodes.length,
   competingSuccessorsVerified:false,intersectionGuaranteed:false,sharedSignerEvidence:Object.freeze([]),
   independentlyPublished:false,externalPinPublicationVerified:false,globalUniquenessVerified:false,
   trustedTimestampVerified:false,authorizesCheckout:false,authorizesRemediation:false,productionApproved:false});
 }
 const a=left.nodes[common],b=right.nodes[common];
 // A checkpoint divergence can only be treated as a sibling fork if both
 // authenticated bodies extend the same previous checkpoint AND receipt head.
 if(a.checkpoint.body.previousCheckpointDigest!==b.checkpoint.body.previousCheckpointDigest||
  a.checkpoint.body.previousReceiptDigest!==b.checkpoint.body.previousReceiptDigest||
  a.checkpoint.body.startSequence!==b.checkpoint.body.startSequence)
  fail('SPLIT32J_DIVERGENCE_NOT_COMPARABLE');
 const samePolicy=a.checkpoint.body.auditorPolicyDigest===b.checkpoint.body.auditorPolicyDigest;
 const signers=samePolicy?signedOverlap(a,b):Object.freeze([]);
 const n=a.entry.auditors.length,q=a.entry.auditorQuorum;
 const guaranteed=samePolicy&&2*q>n;
 if(guaranteed&&signers.length<2*q-n)fail('SPLIT32J_QUORUM_INTERSECTION_INVALID');
 const rotatedBoth=!samePolicy&&a.entry.transition!==null&&b.entry.transition!==null;
 const transitionSigners=rotatedBoth?transitionOverlap(a,b):Object.freeze([]);
 const prior=common>0?left.nodes[common-1].entry:null;
 const transitionMinimum=rotatedBoth&&prior?2*prior.auditorQuorum-prior.auditors.length:0;
 const transitionGuaranteed=rotatedBoth&&transitionMinimum>0;
 if(transitionGuaranteed&&transitionSigners.length<transitionMinimum)
  fail('SPLIT32J_TRANSITION_QUORUM_INTERSECTION_INVALID');
 const evidenceKind=signers.length?'CONFLICTING_CHECKPOINT_SIGNATURES':
  transitionSigners.length?'CONFLICTING_AUDITOR_TRANSITION_SIGNATURES':'CONFLICTING_AUTHENTICATED_SUCCESSORS';
 const evidence=Object.freeze({kind:evidenceKind,predecessorCheckpointDigest:a.checkpoint.body.previousCheckpointDigest,
  predecessorReceiptDigest:a.checkpoint.body.previousReceiptDigest,
  atStartSequence:a.checkpoint.body.startSequence,
  leftCheckpointDigest:a.anchor.checkpointDigest,rightCheckpointDigest:b.anchor.checkpointDigest,
  leftPolicyDigest:a.checkpoint.body.auditorPolicyDigest,rightPolicyDigest:b.checkpoint.body.auditorPolicyDigest,
  minimumQuorumIntersection:guaranteed?2*q-n:transitionGuaranteed?transitionMinimum:0,
  sharedAuditors:signers,sharedTransitionAuditorIds:transitionSigners});
 return Object.freeze({schema:OFFLINE_WITNESS_SPLIT_VIEW_SCHEMA,verified:true,readOnly:true,
  status:'AUTHENTICATED_SPLIT_VIEW_DETECTED',forkDetected:true,sharedCheckpointCount:common,
  leftCheckpointCount:left.nodes.length,rightCheckpointCount:right.nodes.length,
  competingSuccessorsVerified:true,intersectionGuaranteed:guaranteed||transitionGuaranteed,
  sharedSignerEvidence:signers,conflict:evidence,
  independentlyPublished:false,externalPinPublicationVerified:false,globalUniquenessVerified:false,
  trustedTimestampVerified:false,authorizesCheckout:false,authorizesRemediation:false,productionApproved:false});
}
