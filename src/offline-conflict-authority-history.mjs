/** Objective 33D: bounded read-only verification of an independently pinned
 * multi-transition authority history. No external publication, global
 * consensus, protected keys, or trusted clock is provided here.
 */
import {createHash} from 'node:crypto';
import {offlineConflictAuthorityRotationDigest,
 verifyOfflineConflictAuthorityPolicyRotation} from './offline-conflict-authority-policy-rotation.mjs';

export const OFFLINE_CONFLICT_AUTHORITY_HISTORY_SCHEMA='TJ-OFFLINE-CONFLICT-AUTHORITY-HISTORY-1';
const HEX=/^[0-9a-f]{64}$/;
const ID=/^[A-Za-z0-9_-]{8,64}$/;
const fail=code=>{throw Object.assign(new Error(code),{code});};
const hex=x=>typeof x==='string'&&HEX.test(x);
const id=x=>typeof x==='string'&&ID.test(x);
const exact=(o,keys)=>o!==null&&typeof o==='object'&&!Array.isArray(o)&&
 [Object.prototype,null].includes(Object.getPrototypeOf(o))&&Reflect.ownKeys(o).length===keys.length&&
 keys.every(k=>{const d=Object.getOwnPropertyDescriptor(o,k);return d&&'value' in d&&d.enumerable;})&&
 Object.keys(o).every(k=>keys.includes(k));
const dense=(a,min,max)=>Array.isArray(a)&&Object.getPrototypeOf(a)===Array.prototype&&
 a.length>=min&&a.length<=max&&Reflect.ownKeys(a).length===a.length+1&&
 Array.from({length:a.length},(_,i)=>Object.getOwnPropertyDescriptor(a,String(i)))
 .every(d=>d&&'value' in d&&d.enumerable);
const sha=x=>createHash('sha256').update(x).digest('hex');
/** A candidate chain head only: a digest is trustworthy solely if an
 * independent custodian authenticates and retains it outside this verifier. */
export function offlineConflictAuthorityHistoryNextHead(previousHead,transitionDigest,
 toEpoch,successorCommitmentDigest){
 if(!hex(previousHead)||!hex(transitionDigest)||!Number.isSafeInteger(toEpoch)||toEpoch<2||
  !hex(successorCommitmentDigest))fail('EXCHANGE33D_HEAD_INPUT_INVALID');
 return sha(Buffer.from('TJ-33D-AUTHORITY-HISTORY-HEAD\0'+JSON.stringify([
  OFFLINE_CONFLICT_AUTHORITY_HISTORY_SCHEMA,previousHead,transitionDigest,toEpoch,
  successorCommitmentDigest]),'utf8'));
}
/** Requires externally authenticated genesis/terminal anchors AND final chain
 * head. Each 33C rotation re-verifies complete signed 33B evidence, not just
 * digests. No intermediate omission or reordered/forked chain is accepted. */
export function verifyOfflineConflictAuthorityHistory({entries,expectedNamespaceId,
 expectedJournalScopeDigest,expectedFirstEpoch,expectedPreviousTransitionDigest,
 expectedInitialAuthorityPolicyDigest,expectedInitialCommitmentDigest,
 expectedGenesisHead,expectedFinalAuthorityPolicyDigest,
 expectedFinalCommitmentDigest,expectedChainHead,nowMs}={}){
 if(!id(expectedNamespaceId)||!hex(expectedJournalScopeDigest)||
  !Number.isSafeInteger(expectedFirstEpoch)||expectedFirstEpoch<1||
  !hex(expectedPreviousTransitionDigest)||!hex(expectedInitialAuthorityPolicyDigest)||
  !hex(expectedInitialCommitmentDigest)||!hex(expectedGenesisHead)||
  !hex(expectedFinalAuthorityPolicyDigest)||!hex(expectedFinalCommitmentDigest)||
  !hex(expectedChainHead)||!Number.isSafeInteger(nowMs)||nowMs<0)
  fail('EXCHANGE33D_EXTERNAL_PINS_REQUIRED');
 if(!dense(entries,2,8))fail('EXCHANGE33D_ENTRIES_INVALID');
 let epoch=expectedFirstEpoch,policy=expectedInitialAuthorityPolicyDigest,
  commitment=expectedInitialCommitmentDigest,previous=expectedPreviousTransitionDigest,
  head=expectedGenesisHead;
 const seen=new Set();
 for(const entry of entries){
  if(!exact(entry,['transition','predecessor','successor'])||
   !exact(entry.transition,['body','predecessorSignatures','successorSignatures']))
   fail('EXCHANGE33D_ENTRY_INVALID');
  const body=entry.transition.body;
  // Validate the signed body shape before reading any fields (reject getters).
  const digest=offlineConflictAuthorityRotationDigest(body);
  // Enforce continuity before expensive recursive signature verification.
  if(body.fromEpoch!==epoch||body.toEpoch!==epoch+1||
   body.previousTransitionDigest!==previous||
   body.predecessorAuthorityPolicyDigest!==policy||
   body.predecessorCommitmentDigest!==commitment)
   fail('EXCHANGE33D_LINK_MISMATCH');
  if(seen.has(digest))fail('EXCHANGE33D_DUPLICATE_TRANSITION');
  seen.add(digest);
  verifyOfflineConflictAuthorityPolicyRotation({transition:entry.transition,
   predecessor:entry.predecessor,successor:entry.successor,
   expectedNamespaceId,expectedJournalScopeDigest,expectedFromEpoch:epoch,
   expectedPredecessorAuthorityPolicyDigest:policy,
   expectedSuccessorAuthorityPolicyDigest:body.successorAuthorityPolicyDigest,
   expectedPredecessorCommitmentDigest:commitment,
   expectedSuccessorCommitmentDigest:body.successorCommitmentDigest,
   expectedPreviousTransitionDigest:previous,expectedTransitionDigest:digest,nowMs});
  head=offlineConflictAuthorityHistoryNextHead(head,digest,body.toEpoch,
   body.successorCommitmentDigest);
  epoch=body.toEpoch;policy=body.successorAuthorityPolicyDigest;
  commitment=body.successorCommitmentDigest;previous=digest;
 }
 if(policy!==expectedFinalAuthorityPolicyDigest||commitment!==expectedFinalCommitmentDigest||
  head!==expectedChainHead)fail('EXCHANGE33D_TERMINAL_PIN_MISMATCH');
 return Object.freeze({verified:true,readOnly:true,namespaceId:expectedNamespaceId,
  firstEpoch:expectedFirstEpoch,finalEpoch:epoch,transitionCount:entries.length,
  chainHead:head,finalTransitionDigest:previous,finalCommitmentDigest:commitment,
  independentlyPublished:false,globalForkPrevention:false,trustedTimestamp:false,
  authorizesRepair:false,authorizesProduction:false,authorizesCheckout:false});
}
