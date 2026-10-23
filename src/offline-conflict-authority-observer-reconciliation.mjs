/** Objective 33E: independently pinned, two-observer signed authority-history
 * reconciliation. All data is caller supplied; neither external publication
 * nor global completeness is established by this offline read-only verifier.
 */
import {createHash,createPublicKey,verify as verifySignature} from 'node:crypto';
import {verifyOfflineConflictAuthorityHistory} from './offline-conflict-authority-history.mjs';
import {offlineConflictAuthorityRotationDigest} from './offline-conflict-authority-policy-rotation.mjs';
export const OFFLINE_CONFLICT_AUTHORITY_OBSERVER_SCHEMA='TJ-OFFLINE-CONFLICT-AUTHORITY-OBSERVER-1';
const HEX=/^[0-9a-f]{64}$/;
const ID=/^[A-Za-z0-9_-]{8,64}$/;
const SIG=/^[A-Za-z0-9_-]{86}$/;
const B64=/^[A-Za-z0-9_-]+$/;
const fields=['schema','observerId','namespaceId','journalScopeDigest','firstEpoch',
 'previousTransitionDigest','initialAuthorityPolicyDigest','initialCommitmentDigest',
 'genesisHead','finalAuthorityPolicyDigest','finalCommitmentDigest','chainHead',
 'transitionCount','observedAt','expiresAt','nonce'];
const fail=code=>{throw Object.assign(new Error(code),{code});};
const hex=x=>typeof x==='string'&&HEX.test(x);
const id=x=>typeof x==='string'&&ID.test(x);
const exact=(o,keys)=>o!==null&&typeof o==='object'&&!Array.isArray(o)&&
 [Object.prototype,null].includes(Object.getPrototypeOf(o))&&Reflect.ownKeys(o).length===keys.length&&
 keys.every(k=>{const d=Object.getOwnPropertyDescriptor(o,k);return d&&'value' in d&&d.enumerable;})&&
 Object.keys(o).every(k=>keys.includes(k));
const dense=(a,n)=>Array.isArray(a)&&Object.getPrototypeOf(a)===Array.prototype&&
 a.length===n&&Reflect.ownKeys(a).length===n+1&&
 Array.from({length:n},(_,i)=>Object.getOwnPropertyDescriptor(a,String(i)))
 .every(d=>d&&'value' in d&&d.enumerable);
const sha=x=>createHash('sha256').update(x).digest('hex');
function keyFromPinnedDer(s){
 if(typeof s!=='string'||s.length>256||!B64.test(s))fail('EXCHANGE33E_OBSERVER_KEY_INVALID');
 const der=Buffer.from(s,'base64url');
 if(der.toString('base64url')!==s)fail('EXCHANGE33E_OBSERVER_KEY_INVALID');
 let k;try{k=createPublicKey({key:der,format:'der',type:'spki'});}catch{fail('EXCHANGE33E_OBSERVER_KEY_INVALID');}
 if(k.asymmetricKeyType!=='ed25519'||k.export({format:'der',type:'spki'}).toString('base64url')!==s)
  fail('EXCHANGE33E_OBSERVER_KEY_INVALID');
 return k;
}
function bodyBytes(body){
 if(!exact(body,fields)||body.schema!==OFFLINE_CONFLICT_AUTHORITY_OBSERVER_SCHEMA||
  !id(body.observerId)||!id(body.namespaceId)||!hex(body.journalScopeDigest)||
  !Number.isSafeInteger(body.firstEpoch)||body.firstEpoch<1||
  !hex(body.previousTransitionDigest)||!hex(body.initialAuthorityPolicyDigest)||
  !hex(body.initialCommitmentDigest)||!hex(body.genesisHead)||
  !hex(body.finalAuthorityPolicyDigest)||!hex(body.finalCommitmentDigest)||!hex(body.chainHead)||
  !Number.isSafeInteger(body.transitionCount)||body.transitionCount<2||body.transitionCount>8||
  !Number.isSafeInteger(body.observedAt)||body.observedAt<0||
  !Number.isSafeInteger(body.expiresAt)||body.expiresAt<=body.observedAt||
  body.expiresAt-body.observedAt>3600000||!id(body.nonce))fail('EXCHANGE33E_BODY_INVALID');
 return Buffer.from('TJ-33E-OBSERVER-HISTORY-VIEW\0'+JSON.stringify(body),'utf8');
}
/** Candidate signed bytes: signing and external custody are not provided. */
export function offlineConflictAuthorityObserverBodyBytes(body){return bodyBytes(body);}
export function offlineConflictAuthorityObserverAttestationDigest(attestation){
 if(!exact(attestation,['body','signature'])||typeof attestation.signature!=='string'||
  !SIG.test(attestation.signature))fail('EXCHANGE33E_ATTESTATION_INVALID');
 const raw=Buffer.from(attestation.signature,'base64url');
 if(raw.length!==64||raw.toString('base64url')!==attestation.signature)
  fail('EXCHANGE33E_ATTESTATION_INVALID');
 return sha(Buffer.concat([Buffer.from('TJ-33E-ATTESTATION-DIGEST\0'),bodyBytes(attestation.body),raw]));
}
/** Two distinct, externally pinned observers and their externally retained
 * attestation digests. Each view is fully reverified through 33D -> 33C ->
 * 33B -> 33A -> 32Z/32Y. Returns signed conflicting transitions on a fork.
 * A signed fork is evidence of conflicting authorization, NOT a license to
 * repair, settle, or declare either branch canonical. */
export function verifyOfflineConflictAuthorityObserverReconciliation({views,observerPins,
 expectedNamespaceId,expectedJournalScopeDigest,expectedFirstEpoch,
 expectedPreviousTransitionDigest,expectedInitialAuthorityPolicyDigest,
 expectedInitialCommitmentDigest,expectedGenesisHead,nowMs}={}){
 if(!id(expectedNamespaceId)||!hex(expectedJournalScopeDigest)||
  !Number.isSafeInteger(expectedFirstEpoch)||expectedFirstEpoch<1||
  !hex(expectedPreviousTransitionDigest)||!hex(expectedInitialAuthorityPolicyDigest)||
  !hex(expectedInitialCommitmentDigest)||!hex(expectedGenesisHead)||
  !Number.isSafeInteger(nowMs)||nowMs<0)fail('EXCHANGE33E_EXTERNAL_PINS_REQUIRED');
 if(!dense(views,2)||!dense(observerPins,2))fail('EXCHANGE33E_OBSERVER_SET_INVALID');
 const observed=[];let previousId='',previousKey='';
 for(let i=0;i<2;i++){
  const pin=observerPins[i],view=views[i];
  if(!exact(pin,['observerId','publicKey','expectedAttestationDigest'])||
   !id(pin.observerId)||pin.observerId<=previousId||
   !hex(pin.expectedAttestationDigest)||!exact(view,['observerId','history','attestation'])||
   view.observerId!==pin.observerId||
   !exact(view.attestation,['body','signature']))fail('EXCHANGE33E_OBSERVER_SET_INVALID');
  const key=keyFromPinnedDer(pin.publicKey),fingerprint=sha(key.export({type:'spki',format:'der'}));
  if(fingerprint===previousKey)fail('EXCHANGE33E_DUPLICATE_OBSERVER_KEY');
  previousId=pin.observerId;previousKey=fingerprint;
  const body=view.attestation.body,bytes=bodyBytes(body);
  if(body.observerId!==pin.observerId||body.namespaceId!==expectedNamespaceId||
   body.journalScopeDigest!==expectedJournalScopeDigest||
   body.firstEpoch!==expectedFirstEpoch||
   body.previousTransitionDigest!==expectedPreviousTransitionDigest||
   body.initialAuthorityPolicyDigest!==expectedInitialAuthorityPolicyDigest||
   body.initialCommitmentDigest!==expectedInitialCommitmentDigest||
   body.genesisHead!==expectedGenesisHead||nowMs<body.observedAt||nowMs>body.expiresAt)
   fail('EXCHANGE33E_VIEW_SCOPE_OR_EXPIRY');
  const digest=offlineConflictAuthorityObserverAttestationDigest(view.attestation);
  if(digest!==pin.expectedAttestationDigest)fail('EXCHANGE33E_ATTESTATION_PIN_MISMATCH');
  const sig=Buffer.from(view.attestation.signature,'base64url');
  if(!verifySignature(null,bytes,key,sig))fail('EXCHANGE33E_SIGNATURE_INVALID');
  const history=view.history;
  if(!exact(history,['entries','expectedNamespaceId','expectedJournalScopeDigest',
   'expectedFirstEpoch','expectedPreviousTransitionDigest',
   'expectedInitialAuthorityPolicyDigest','expectedInitialCommitmentDigest',
   'expectedGenesisHead','expectedFinalAuthorityPolicyDigest',
   'expectedFinalCommitmentDigest','expectedChainHead','nowMs'])||
   history.expectedNamespaceId!==expectedNamespaceId||
   history.expectedJournalScopeDigest!==expectedJournalScopeDigest||
   history.expectedFirstEpoch!==expectedFirstEpoch||
   history.expectedPreviousTransitionDigest!==expectedPreviousTransitionDigest||
   history.expectedInitialAuthorityPolicyDigest!==expectedInitialAuthorityPolicyDigest||
   history.expectedInitialCommitmentDigest!==expectedInitialCommitmentDigest||
   history.expectedGenesisHead!==expectedGenesisHead||history.nowMs!==nowMs||
   history.expectedFinalAuthorityPolicyDigest!==body.finalAuthorityPolicyDigest||
   history.expectedFinalCommitmentDigest!==body.finalCommitmentDigest||
   history.expectedChainHead!==body.chainHead||history.entries?.length!==body.transitionCount)
   fail('EXCHANGE33E_HISTORY_BINDING_MISMATCH');
  const verified=verifyOfflineConflictAuthorityHistory(history);
  observed.push({id:pin.observerId,digest,history,verified});
 }
 const [left,right]=observed;
 let shared=0;
 while(shared<Math.min(left.history.entries.length,right.history.entries.length)&&
  offlineConflictAuthorityRotationDigest(left.history.entries[shared].transition.body)===
  offlineConflictAuthorityRotationDigest(right.history.entries[shared].transition.body))shared++;
 const status=shared===left.history.entries.length&&shared===right.history.entries.length?'consistent':
  shared===Math.min(left.history.entries.length,right.history.entries.length)?'extension':'equivocation';
 let evidence=null;
 if(status==='equivocation'){
  const a=left.history.entries[shared].transition,b=right.history.entries[shared].transition;
  // These signed bodies share an authenticated predecessor. The JSON snapshots
  // include the original authority signatures for independent re-verification.
  evidence=Object.freeze({forkIndex:shared,fromEpoch:expectedFirstEpoch+shared,
   predecessorTransitionDigest:a.body.previousTransitionDigest,
   leftTransitionDigest:offlineConflictAuthorityRotationDigest(a.body),
   rightTransitionDigest:offlineConflictAuthorityRotationDigest(b.body),
   leftSignedTransitionJson:JSON.stringify(a),rightSignedTransitionJson:JSON.stringify(b),
   leftObserverAttestationJson:JSON.stringify(views[0].attestation),
   rightObserverAttestationJson:JSON.stringify(views[1].attestation)});
 }
 return Object.freeze({verified:true,readOnly:true,status,sharedTransitions:shared,
  observerIds:Object.freeze([left.id,right.id]),
  attestationDigests:Object.freeze([left.digest,right.digest]),
  chainHeads:Object.freeze([left.verified.chainHead,right.verified.chainHead]),
  evidence,independentlyPublished:false,globallyComplete:false,
  globalForkPrevention:false,authorizesRepair:false,authorizesProduction:false,
  authorizesCheckout:false});
}
