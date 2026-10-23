/** Objective 35AL — independently retained, offline epoch-history continuity.
 * Snapshots are untrusted transports. Every pin (including historic observation
 * time, issuer keys and SHA-256 roots) MUST come from separate trusted custody.
 * This compares fully issuer-verified chains, NOT hosted consensus or authority.
 */
import {createHash,timingSafeEqual} from 'node:crypto';
import {verifyOfflineEpochTransitionProvenance}
 from './preview-local-artwork-review-epoch-transition-provenance.mjs';
import {verifyOfflineEpochChainEvidence}
 from './preview-local-artwork-review-epoch-observer-evidence.mjs';
export const OFFLINE_RETAINED_EPOCH_CONTINUITY_SCHEMA='TJ-LOCAL-RETAINED-EPOCH-CONTINUITY-35AL-1';
const HEX=/^[0-9a-f]{64}$/;
const fail=code=>{throw Object.assign(new Error(code),{code});};
const sha=b=>createHash('sha256').update(b).digest('hex');
const hex=s=>typeof s==='string'&&HEX.test(s);
const eq=(a,b)=>hex(a)&&hex(b)&&timingSafeEqual(Buffer.from(a,'hex'),Buffer.from(b,'hex'));
const time=x=>Number.isSafeInteger(x)&&x>=0&&x<1e15;
const exact=(o,fields)=>o!==null&&typeof o==='object'&&!Array.isArray(o)&&
 [Object.prototype,null].includes(Object.getPrototypeOf(o))&&Reflect.ownKeys(o).length===fields.length&&
 fields.every(k=>{const d=Object.getOwnPropertyDescriptor(o,k);return d?.enumerable&&'value'in d;});
const dense=(a,max)=>Array.isArray(a)&&a.length>=2&&a.length<=max&&
 Reflect.ownKeys(a).length===a.length+1;
const SNAP=['provenanceBytes'];
const PIN=['expectedProvenanceSha256','expectedEvidenceSha256','expectedHead','expectedIssuerPins','observedAtMs'];
const HEAD=['epoch','rosterSha256','recordSha256'];
function canonicalTransport(bytes){
 if(!Buffer.isBuffer(bytes)||bytes.length<2||bytes.length>2_000_000)
  fail('OFFLINE_RETAINED_EPOCH_INVALID_TRANSPORT');
 let pkg;try{pkg=JSON.parse(bytes.toString('utf8'));}catch{fail('OFFLINE_RETAINED_EPOCH_INVALID_TRANSPORT');}
 if(!exact(pkg,['schema','evidence','genesisRoster','transitions','authority'])||
  pkg.schema!=='TJ-LOCAL-EPOCH-PROVENANCE-35AK-1'||pkg.authority!=='NONE'||
  !Buffer.from(JSON.stringify(pkg)).equals(bytes)||typeof pkg.evidence!=='string'||
  !/^[A-Za-z0-9_-]+$/.test(pkg.evidence))fail('OFFLINE_RETAINED_EPOCH_INVALID_TRANSPORT');
 const evidence=Buffer.from(pkg.evidence,'base64url');
 if(evidence.toString('base64url')!==pkg.evidence)
  fail('OFFLINE_RETAINED_EPOCH_INVALID_TRANSPORT');
 return evidence;
}
/** Verify at least two externally retained checkpoints, each with a complete
 * signed provenance bundle. Missing history, rollback and forks fail closed.
 * No receipt, time or trust pin is derived from a transported snapshot.
 */
export function verifyOfflineRetainedEpochContinuity({snapshots,retainedPins,
 expectedNamespacePin,expectedRootPin,expectedRegistryId,expectedGenesisSha256,
 expectedGenesisRosterSha256,expectedPolicySignerFingerprint,expectedAudience,
 trustedNowMs}={}){
 if(!dense(snapshots,32)||!dense(retainedPins,32)||snapshots.length!==retainedPins.length||
  ![expectedNamespacePin,expectedRootPin,expectedRegistryId,expectedGenesisSha256,
    expectedGenesisRosterSha256,expectedPolicySignerFingerprint,expectedAudience].every(hex)||
  !time(trustedNowMs))fail('OFFLINE_RETAINED_EPOCH_MISSING_EXTERNAL_PINS');
 const checked=[];let previous=null;
 for(let i=0;i<snapshots.length;i++){
  const snapshot=snapshots[i],pin=retainedPins[i];
  if(!exact(snapshot,SNAP)||!exact(pin,PIN)||
   !hex(pin.expectedProvenanceSha256)||!hex(pin.expectedEvidenceSha256)||
   !exact(pin.expectedHead,HEAD)||!time(pin.expectedHead.epoch)||
   !hex(pin.expectedHead.rosterSha256)||!hex(pin.expectedHead.recordSha256)||
   !Array.isArray(pin.expectedIssuerPins)||!time(pin.observedAtMs)||
   pin.observedAtMs>trustedNowMs||(previous&&pin.observedAtMs<=previous.observedAtMs))
   fail('OFFLINE_RETAINED_EPOCH_MISSING_EXTERNAL_PINS');
  // Full issuer/policy signature validation precedes ANY continuity conclusion.
  const validated=verifyOfflineEpochTransitionProvenance({
   provenanceBytes:snapshot.provenanceBytes,
   expectedProvenanceSha256:pin.expectedProvenanceSha256,
   expectedIssuerPins:pin.expectedIssuerPins,
   expectedNamespacePin,expectedRootPin,expectedRegistryId,
   expectedGenesisSha256,expectedHead:pin.expectedHead,
   expectedEvidenceSha256:pin.expectedEvidenceSha256,
   expectedPolicySignerFingerprint,expectedAudience,expectedGenesisRosterSha256,
   trustedNowMs:pin.observedAtMs});
  const evidenceBytes=canonicalTransport(snapshot.provenanceBytes);
  const chain=verifyOfflineEpochChainEvidence({evidenceBytes,expectedNamespacePin,
   expectedRootPin,expectedRegistryId,expectedGenesisSha256,
   expectedHead:pin.expectedHead,expectedEvidenceSha256:pin.expectedEvidenceSha256});
  const records=new Map(chain.recordDigests.map(r=>[r.epoch,r.sha256]));
  if(previous){
   // Check shared epoch identities BEFORE ordering: signed, conflicting
   // histories are equivocation even when their head epochs differ.
   for(const [epoch,digest] of previous.records){
    if(records.has(epoch)&&!eq(digest,records.get(epoch)))
     fail('OFFLINE_RETAINED_EPOCH_EQUIVOCATION');
   }
   if(pin.expectedHead.epoch<previous.epoch)
    fail('OFFLINE_RETAINED_EPOCH_ROLLBACK');
   if(pin.expectedHead.epoch===previous.epoch)
    fail('OFFLINE_RETAINED_EPOCH_REPLAY');
   if(!eq(records.get(previous.epoch),previous.headSha256))
    fail('OFFLINE_RETAINED_EPOCH_HISTORY_PRUNED');
  }
  previous={epoch:pin.expectedHead.epoch,headSha256:pin.expectedHead.recordSha256,
   observedAtMs:pin.observedAtMs,records};
  checked.push(Object.freeze({epoch:validated.head.epoch,
   recordSha256:validated.head.recordSha256,
   provenanceSha256:validated.provenanceSha256,observedAtMs:pin.observedAtMs}));
 }
 // Digest of the externally supplied ordered checkpoint *identities* for
 // portable comparison. It is not a signature, clock, or custody proof.
 const continuityDigest=sha(Buffer.from(JSON.stringify({
  schema:OFFLINE_RETAINED_EPOCH_CONTINUITY_SCHEMA,
  checkpoints:checked,authority:'NONE'})));
 return Object.freeze({schema:OFFLINE_RETAINED_EPOCH_CONTINUITY_SCHEMA,
  checkpoints:Object.freeze(checked),checkpointCount:checked.length,
  latestHead:Object.freeze({...retainedPins.at(-1).expectedHead}),
  continuityDigest,issuerSignaturesVerified:true,historyContinuityVerified:true,
  independentCustodyVerified:false,trustedClockIndependentlyVerified:false,
  crossHostConsensusVerified:false,authorizesProduction:false});
}
