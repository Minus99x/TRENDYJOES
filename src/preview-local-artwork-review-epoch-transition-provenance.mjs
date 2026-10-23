/** Objective 35AK — offline issuer-signed provenance for portable 35AJ epoch chains.
 * Every trust pin, Ed25519 issuer key, and clock comes from the caller, NEVER
 * from the transported evidence. Historical transitions are checked at their
 * cutovers; the latest roster is checked at the caller's current trusted time.
 * This is NOT hosted auth, external custody, replay consensus, or production. */
import {createHash,timingSafeEqual} from 'node:crypto';
import {verifyOfflineEpochChainEvidence,inspectOfflineEpochObserverViews}
 from './preview-local-artwork-review-epoch-observer-evidence.mjs';
import {verifyOfflineWitnessRosterEpochTransition}
 from './preview-local-artwork-review-witness-epoch.mjs';
import {verifyOfflinePinnedWitnessRoster}
 from './preview-local-artwork-review-witness-roster-ledger.mjs';
export const OFFLINE_EPOCH_PROVENANCE_SCHEMA='TJ-LOCAL-EPOCH-PROVENANCE-35AK-1';
const HEX=/^[0-9a-f]{64}$/;
const MAX_BUNDLE=2_000_000,MAX_TRANSITIONS=255;
const FIELDS=['schema','evidence','genesisRoster','transitions','authority'];
const STEP=['transition','nextRoster'];
const fail=code=>{throw Object.assign(new Error(code),{code});};
const sha=b=>createHash('sha256').update(b).digest('hex');
const hex=x=>typeof x==='string'&&HEX.test(x);
const eq=(a,b)=>hex(a)&&hex(b)&&timingSafeEqual(Buffer.from(a,'hex'),Buffer.from(b,'hex'));
const time=x=>Number.isSafeInteger(x)&&x>=0&&x<1e15;
const exact=(o,fields)=>o!==null&&typeof o==='object'&&!Array.isArray(o)&&
 [Object.prototype,null].includes(Object.getPrototypeOf(o))&&Reflect.ownKeys(o).length===fields.length&&
 fields.every(k=>{const d=Object.getOwnPropertyDescriptor(o,k);return d?.enumerable&&'value'in d;});
const array=(a,max)=>Array.isArray(a)&&a.length<=max&&Reflect.ownKeys(a).length===a.length+1;
function bytes(b,max,code){if(!Buffer.isBuffer(b)||b.length<2||b.length>max)fail(code);return Buffer.from(b);}
function canonical(b,fields,code){let o;try{o=JSON.parse(b.toString('utf8'));}catch{fail(code);}
 if(!exact(o,fields)||!Object.keys(o).every((k,i)=>k===fields[i])||
  !Buffer.from(JSON.stringify(o)).equals(b))fail(code);return o;}
const encode=b=>b.toString('base64url');
function decode(s,max){if(typeof s!=='string'||s.length<3||s.length>Math.ceil(max*4/3)+4||
 !/^[A-Za-z0-9_-]+$/.test(s))fail('OFFLINE_EPOCH_PROVENANCE_INVALID_BYTES');
 const b=Buffer.from(s,'base64url');if(encode(b)!==s)fail('OFFLINE_EPOCH_PROVENANCE_NONCANONICAL');
 return bytes(b,max,'OFFLINE_EPOCH_PROVENANCE_INVALID_BYTES');}
function validatePins(p){
 if(!p||![p.expectedNamespacePin,p.expectedRootPin,p.expectedRegistryId,
  p.expectedGenesisSha256,p.expectedEvidenceSha256,p.expectedPolicySignerFingerprint,
  p.expectedAudience,p.expectedGenesisRosterSha256].every(hex)||
  !time(p.trustedNowMs))fail('OFFLINE_EPOCH_PROVENANCE_MISSING_EXTERNAL_PINS');
 if(!exact(p.expectedHead,['epoch','rosterSha256','recordSha256'])||
  !time(p.expectedHead.epoch)||!hex(p.expectedHead.rosterSha256)||
  !hex(p.expectedHead.recordSha256))fail('OFFLINE_EPOCH_PROVENANCE_MISSING_EXTERNAL_PINS');
}
/** Transport serialization only. Verification requires independent caller pins. */
export function createOfflineEpochTransitionProvenance({evidenceBytes,genesisRosterBytes,transitions}={}){
 const evidence=bytes(evidenceBytes,600000,'OFFLINE_EPOCH_PROVENANCE_INVALID_BYTES');
 const genesis=bytes(genesisRosterBytes,16384,'OFFLINE_EPOCH_PROVENANCE_INVALID_BYTES');
 if(!array(transitions,MAX_TRANSITIONS))fail('OFFLINE_EPOCH_PROVENANCE_INVALID_STEPS');
 const steps=transitions.map(s=>{
  if(!exact(s,['transitionBytes','nextRosterBytes']))fail('OFFLINE_EPOCH_PROVENANCE_INVALID_STEPS');
  return {transition:encode(bytes(s.transitionBytes,4096,'OFFLINE_EPOCH_PROVENANCE_INVALID_BYTES')),
   nextRoster:encode(bytes(s.nextRosterBytes,16384,'OFFLINE_EPOCH_PROVENANCE_INVALID_BYTES'))};
 });
 const raw=Buffer.from(JSON.stringify({schema:OFFLINE_EPOCH_PROVENANCE_SCHEMA,
  evidence:encode(evidence),genesisRoster:encode(genesis),transitions:steps,authority:'NONE'}));
 if(raw.length>MAX_BUNDLE)fail('OFFLINE_EPOCH_PROVENANCE_TOO_LARGE');
 return Object.freeze({bytes:raw,sha256:sha(raw),transitionSignaturesVerified:false,
  independentCustodyVerified:false,authorizesProduction:false});
}
/** Requires a separately pinned issuer public key for EACH transition. The
 * package's own digest and issuer material are never accepted as trust roots. */
export function verifyOfflineEpochTransitionProvenance({provenanceBytes,expectedProvenanceSha256,
 expectedIssuerPins,...pins}={}){
 validatePins(pins);
 if(!hex(expectedProvenanceSha256)||!array(expectedIssuerPins,MAX_TRANSITIONS))
  fail('OFFLINE_EPOCH_PROVENANCE_MISSING_EXTERNAL_PINS');
 const raw=bytes(provenanceBytes,MAX_BUNDLE,'OFFLINE_EPOCH_PROVENANCE_INVALID_BYTES');
 if(!eq(sha(raw),expectedProvenanceSha256))fail('OFFLINE_EPOCH_PROVENANCE_DIGEST_MISMATCH');
 const pkg=canonical(raw,FIELDS,'OFFLINE_EPOCH_PROVENANCE_NONCANONICAL');
 if(pkg.schema!==OFFLINE_EPOCH_PROVENANCE_SCHEMA||pkg.authority!=='NONE'||
  !array(pkg.transitions,MAX_TRANSITIONS)||pkg.transitions.length!==expectedIssuerPins.length)
  fail('OFFLINE_EPOCH_PROVENANCE_INVALID_STEPS');
 const evidenceBytes=decode(pkg.evidence,600000);
 if(!eq(sha(evidenceBytes),pins.expectedEvidenceSha256))
  fail('OFFLINE_EPOCH_PROVENANCE_EVIDENCE_MISMATCH');
 const chain=verifyOfflineEpochChainEvidence({evidenceBytes,
  expectedNamespacePin:pins.expectedNamespacePin,expectedRootPin:pins.expectedRootPin,
  expectedRegistryId:pins.expectedRegistryId,expectedGenesisSha256:pins.expectedGenesisSha256,
  expectedHead:pins.expectedHead,expectedEvidenceSha256:pins.expectedEvidenceSha256});
 const evidence=JSON.parse(evidenceBytes.toString('utf8'));
 const records=evidence.records.map(r=>JSON.parse(Buffer.from(r,'base64url').toString('utf8')));
 if(pkg.transitions.length!==records.length-1)fail('OFFLINE_EPOCH_PROVENANCE_INCOMPLETE_CHAIN');
 let previousRosterBytes=decode(pkg.genesisRoster,16384);
 if(!eq(sha(previousRosterBytes),pins.expectedGenesisRosterSha256)||
  !eq(pins.expectedGenesisRosterSha256,records[0].rosterSha256))
  fail('OFFLINE_EPOCH_PROVENANCE_GENESIS_ROSTER_MISMATCH');
 let previousCutover=-1;
 for(let i=0;i<pkg.transitions.length;i++){
  const step=pkg.transitions[i],issuer=expectedIssuerPins[i];
  if(!exact(step,STEP)||!exact(issuer,['issuerPublicKey','expectedIssuerKeyFingerprint'])||
   !hex(issuer.expectedIssuerKeyFingerprint))fail('OFFLINE_EPOCH_PROVENANCE_MISSING_EXTERNAL_PINS');
  const transitionBytes=decode(step.transition,4096),nextRosterBytes=decode(step.nextRoster,16384);
  const prior=records[i],next=records[i+1];
  if(!eq(sha(transitionBytes),next.transitionSha256)||
   !eq(sha(previousRosterBytes),prior.rosterSha256)||
   !eq(sha(nextRosterBytes),next.rosterSha256))
   fail('OFFLINE_EPOCH_PROVENANCE_RECORD_MISMATCH');
  // The cutover is untrusted until the 35AH signature and policy verifier passes.
  let cutover;try{cutover=JSON.parse(transitionBytes.toString('utf8')).cutoverMs;}
  catch{fail('OFFLINE_EPOCH_PROVENANCE_INVALID_TRANSITION');}
  if(!time(cutover)||cutover<1||cutover<=previousCutover||cutover>pins.trustedNowMs)
   fail('OFFLINE_EPOCH_PROVENANCE_INVALID_CUTOVER');
  const verified=verifyOfflineWitnessRosterEpochTransition({transitionBytes,
   expectedTransitionSha256:next.transitionSha256,issuerPublicKey:issuer.issuerPublicKey,
   expectedIssuerKeyFingerprint:issuer.expectedIssuerKeyFingerprint,
   previousRosterBytes,nextRosterBytes,expectedPreviousRosterSha256:prior.rosterSha256,
   expectedNextRosterSha256:next.rosterSha256,expectedRootPin:pins.expectedRootPin,
   expectedRegistryId:pins.expectedRegistryId,
   expectedPolicySignerFingerprint:pins.expectedPolicySignerFingerprint,
   expectedAudience:pins.expectedAudience,expectedPreviousEpoch:prior.epoch,
   expectedNextEpoch:next.epoch,trustedNowMs:cutover});
  if(verified.cutoverMs!==cutover)fail('OFFLINE_EPOCH_PROVENANCE_INVALID_CUTOVER');
  previousRosterBytes=nextRosterBytes;previousCutover=cutover;
 }
 // Historical cutover validity alone does not prove the final roster is active now.
 const current=verifyOfflinePinnedWitnessRoster({rosterBytes:previousRosterBytes,
  expectedRosterSha256:pins.expectedHead.rosterSha256,
  expectedRootPin:pins.expectedRootPin,expectedRegistryId:pins.expectedRegistryId,
  expectedPolicySignerFingerprint:pins.expectedPolicySignerFingerprint,
  expectedAudience:pins.expectedAudience,trustedNowMs:pins.trustedNowMs});
 return Object.freeze({head:chain.head,provenanceSha256:sha(raw),
  transitionCount:pkg.transitions.length,chainHashesVerified:true,
  transitionSignaturesVerified:true,rosterPoliciesVerified:true,
  latestRosterSha256:current.rosterSha256,independentCustodyVerified:false,
  trustedClockIndependentlyVerified:false,crossHostConsensusVerified:false,
  replayConsumed:false,authorizesProduction:false});
}
/** Adjudicate 35AJ observer views ONLY after validating each independently
 * pinned issuer-provenance bundle for the exact evidence that observer signed. */
export function inspectOfflineEpochObserverViewsWithProvenance({views,observerPins,
 provenanceBundles,issuerPinsByView,expectedNamespacePin,expectedRootPin,
 expectedRegistryId,expectedGenesisSha256,expectedPolicySignerFingerprint,
 expectedAudience,expectedGenesisRosterSha256,trustedNowMs}={}){
 if(!array(views,16)||views.length<2||!array(observerPins,16)||
  !array(provenanceBundles,16)||!array(issuerPinsByView,16)||
  views.length!==observerPins.length||views.length!==provenanceBundles.length||
  views.length!==issuerPinsByView.length)fail('OFFLINE_EPOCH_PROVENANCE_INVALID_VIEWS');
 // Check observer signature/pins first; no fork decision escapes on failed provenance.
 const observed=inspectOfflineEpochObserverViews({views,observerPins,expectedNamespacePin,
  expectedRootPin,expectedRegistryId,expectedGenesisSha256,expectedAudience,trustedNowMs});
 const verified=[];
 for(let i=0;i<views.length;i++){
  const b=provenanceBundles[i];
  if(!exact(b,['provenanceBytes','expectedProvenanceSha256']))
   fail('OFFLINE_EPOCH_PROVENANCE_INVALID_VIEWS');
  const result=verifyOfflineEpochTransitionProvenance({
   provenanceBytes:b.provenanceBytes,expectedProvenanceSha256:b.expectedProvenanceSha256,
   expectedIssuerPins:issuerPinsByView[i],expectedNamespacePin,expectedRootPin,
   expectedRegistryId,expectedGenesisSha256,expectedHead:observerPins[i].expectedHead,
   expectedEvidenceSha256:sha(views[i].evidenceBytes),expectedPolicySignerFingerprint,
   expectedAudience,expectedGenesisRosterSha256,trustedNowMs});
  verified.push(result);
 }
 return Object.freeze({...observed,transitionSignaturesVerified:true,
  rosterPoliciesVerified:true,provenanceVerifiedViews:verified.length,
  independentCustodyVerified:false,crossHostConsensusVerified:false,
  authorizesProduction:false});
}
