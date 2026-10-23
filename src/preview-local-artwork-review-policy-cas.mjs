/** Objective 35AE — OFFLINE policy-head compare-and-swap and fork evidence.
 * Single-host Linux filesystem fixture, not an independently controlled registry.
 * Caller must supply an out-of-band authenticated initial head and signing key.
 * No Shopify, checkout, production or external network capabilities.
 */
import {createHash,timingSafeEqual} from 'node:crypto';
import {createOfflineDurableAnchorAdapter} from './offline-durable-anchor-adapter.mjs';
import {verifyLocalReviewPolicyCheckpointAdvancement,
 LOCAL_REVIEW_RETAINED_HEAD_SCHEMA} from './preview-local-artwork-review-policy-checkpoints.mjs';

export const LOCAL_REVIEW_POLICY_CAS_EVIDENCE_SCHEMA='TJ-LOCAL-REVIEW-POLICY-FORK-EVIDENCE-35AE-1';
const HEX=/^[0-9a-f]{64}$/;
const FIELDS=['schema','rootPin','registryId','signerFingerprint','checkpointSha256','revision'];
const fail=code=>{throw Object.assign(new Error(code),{code});};
const hash=b=>createHash('sha256').update(b).digest('hex');
const hex=x=>typeof x==='string'&&HEX.test(x);
const same=(a,b)=>hex(a)&&hex(b)&&timingSafeEqual(Buffer.from(a,'hex'),Buffer.from(b,'hex'));
const exact=(x,fields)=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&
 [Object.prototype,null].includes(Object.getPrototypeOf(x))&&
 Reflect.ownKeys(x).length===fields.length&&fields.every(k=>{
  const d=Object.getOwnPropertyDescriptor(x,k);return d&&'value'in d&&d.enumerable;
 });
function pin(head,pins){
 if(!exact(head,FIELDS)||head.schema!==LOCAL_REVIEW_RETAINED_HEAD_SCHEMA||
  !hex(head.rootPin)||!hex(head.registryId)||!hex(head.signerFingerprint)||
  !hex(head.checkpointSha256)||!Number.isSafeInteger(head.revision)||head.revision<1||
  !same(head.rootPin,pins.expectedRootPin)||
  !same(head.registryId,pins.expectedRegistryId)||
  !same(head.signerFingerprint,pins.expectedSignerFingerprint))
  fail('LOCAL_REVIEW_CAS_INVALID_HEAD');
 return Object.freeze(Object.fromEntries(FIELDS.map(k=>[k,head[k]])));
}
function pinsValid(pins){
 if(!hex(pins.expectedRootPin)||!hex(pins.expectedRegistryId)||
  !hex(pins.expectedSignerFingerprint))fail('LOCAL_REVIEW_CAS_INVALID_PINS');
}
function next(head,digest,revision){
 return Object.freeze({...head,checkpointSha256:digest,revision});
}
/** Uses the already-tested single-host flock + append-only fsync CAS adapter.
 * Bootstrap is explicit and only accepts revision 1 from a separately pinned
 * checkpoint. The local filesystem can be rolled back by its administrator.
 * Pending crash records fail closed and require separate authorized recovery.
 */
export function createOfflineLocalReviewPolicyHeadRegistry({directory,expectedRootPin,
 expectedRegistryId,expectedSignerFingerprint,recoveryPublicKey,lockTimeoutMs,
 injectFault}={}){
 const pins={expectedRootPin,expectedRegistryId,expectedSignerFingerprint};
 pinsValid(pins);
 if(recoveryPublicKey?.type!=='public'||recoveryPublicKey?.asymmetricKeyType!=='ed25519')
  fail('LOCAL_REVIEW_CAS_INVALID_RECOVERY_KEY');
 const adapter=createOfflineDurableAnchorAdapter({directory,registryId:expectedRegistryId,
  anchorType:'registry',recovery:{publicKey:recoveryPublicKey},lockTimeoutMs,injectFault});
 const toAnchor=h=>h===null?null:{sequence:h.revision,mac:h.checkpointSha256};
 const fromAnchor=a=>a===null?null:Object.freeze({schema:LOCAL_REVIEW_RETAINED_HEAD_SCHEMA,
  rootPin:expectedRootPin,registryId:expectedRegistryId,
  signerFingerprint:expectedSignerFingerprint,checkpointSha256:a.mac,revision:a.sequence});
 async function readRetainedHead(){
  const a=await adapter.read();
  if(a===null)fail('LOCAL_REVIEW_CAS_UNINITIALIZED');
  return fromAnchor(a);
 }
 async function initializePinnedHead(initialHead){
  const pinned=pin(initialHead,pins);
  if(pinned.revision!==1)fail('LOCAL_REVIEW_CAS_INITIAL_PIN_REQUIRED');
  // The caller, NOT this local fixture, authenticates this first checkpoint.
  return adapter.compareAndSet(null,toAnchor(pinned));
 }
 async function compareAndSwapRetainedHead(expectedHead,candidateHead){
  // Clone and validate synchronously, before entering the async lock.
  const expected=pin(expectedHead,pins),candidate=pin(candidateHead,pins);
  if(candidate.revision!==expected.revision+1||
   candidate.checkpointSha256===expected.checkpointSha256)
   fail('LOCAL_REVIEW_CAS_NON_MONOTONIC');
  return adapter.compareAndSet(toAnchor(expected),toAnchor(candidate));
 }
 async function inspectRecoveryState(){
  const s=await adapter.inspectRecoveryState();
  return Object.freeze({pending:s.pending,pendingDigest:s.pendingDigest,
   retainedHead:fromAnchor(s.anchor),historyDigest:s.historyDigest,
   requiresIndependentRecoveryAuthorization:s.pending,
   independentCustodyVerified:false,authorizesProduction:false});
 }
 return Object.freeze({readRetainedHead,initializePinnedHead,
  compareAndSwapRetainedHead,inspectRecoveryState});
}
function registryValid(registry){
 if(registry===null||typeof registry!=='object'||
  typeof registry.readRetainedHead!=='function'||
  typeof registry.compareAndSwapRetainedHead!=='function')
  fail('LOCAL_REVIEW_CAS_INVALID_REGISTRY');
}
/** Validate signed advancement, then atomically attempt promotion.
 * A concurrent writer can win between verification and CAS; no blind retry.
 * Successful return means local CAS was observed, NOT independent retention.
 */
export async function advanceOfflineLocalReviewPolicyHead({checkpointBytes,registry,
 signerPublicKey,expectedRootPin,expectedRegistryId,expectedSignerFingerprint}={}){
 const pins={expectedRootPin,expectedRegistryId,expectedSignerFingerprint};
 pinsValid(pins);registryValid(registry);
 // The verifier snapshots input bytes before calling the untrusted adapter.
 const checked=await verifyLocalReviewPolicyCheckpointAdvancement({checkpointBytes,
  readRetainedHead:()=>registry.readRetainedHead(),signerPublicKey,...pins});
 const expected=pin({schema:LOCAL_REVIEW_RETAINED_HEAD_SCHEMA,...pinsToHead(pins),
  checkpointSha256:checked.retainedHeadSha256,revision:checked.retainedRevision},pins);
 const candidate=next(expected,checked.candidateSha256,checked.candidateRevision);
 if(candidate.revision!==expected.revision+1)
  fail('LOCAL_REVIEW_CAS_SINGLE_STEP_REQUIRED');
 let committed;
 try{committed=await registry.compareAndSwapRetainedHead(expected,candidate);}
 catch(e){if(e?.code)throw e;fail('LOCAL_REVIEW_CAS_ADAPTER_UNAVAILABLE');}
 if(committed!==true){
  if(committed!==false)fail('LOCAL_REVIEW_CAS_ADAPTER_INVALID_RESULT');
  // Never auto-retry a fork against the newly observed head.
  fail('LOCAL_REVIEW_CAS_CONFLICT');
 }
 let observed;
 try{observed=pin(await registry.readRetainedHead(),pins);}
 catch{fail('LOCAL_REVIEW_CAS_COMMIT_UNCERTAIN');}
 if(observed.checkpointSha256!==candidate.checkpointSha256||
  observed.revision!==candidate.revision)fail('LOCAL_REVIEW_CAS_COMMIT_UNCERTAIN');
 return Object.freeze({retainedRevision:expected.revision,
  committedRevision:candidate.revision,committedSha256:candidate.checkpointSha256,
  signaturesVerified:true,localCASObserved:true,independentCustodyVerified:false,
  globalForkPreventionVerified:false,authorizesProduction:false,shopifyWritesAllowed:false});
}
function pinsToHead(p){return {rootPin:p.expectedRootPin,registryId:p.expectedRegistryId,
 signerFingerprint:p.expectedSignerFingerprint};}
function copyChain(chain){
 if(!Array.isArray(chain)||chain.length!==2||Reflect.ownKeys(chain).length!==3)
  fail('LOCAL_REVIEW_CAS_FORK_INVALID_CHAIN');
 const snapshots=[];
 for(let i=0;i<chain.length;i++){
  const d=Object.getOwnPropertyDescriptor(chain,i);
  if(!d||!('value'in d)||!d.enumerable||!Buffer.isBuffer(d.value)||
   d.value.length<2||d.value.length>16384)
   fail('LOCAL_REVIEW_CAS_FORK_INVALID_CHAIN');
  snapshots.push(Buffer.from(d.value));
 }
 return snapshots;
}
/** Produces portable evidence of TWO independently verified, signer-valid forks.
 * The pinned head is supplied externally. Evidence is not itself witnessed,
 * timestamped or signed, and a local disk cannot prove global uniqueness.
 */
export async function inspectOfflineLocalReviewPolicySplitView({leftCheckpointBytes,
 rightCheckpointBytes,pinnedHead,signerPublicKey,expectedRootPin,
 expectedRegistryId,expectedSignerFingerprint}={}){
 const pins={expectedRootPin,expectedRegistryId,expectedSignerFingerprint};
 pinsValid(pins);
 const head=pin(pinnedHead,pins);
 const left=copyChain(leftCheckpointBytes),right=copyChain(rightCheckpointBytes);
 if(!left[0].equals(right[0]))fail('LOCAL_REVIEW_CAS_FORK_DIFFERENT_PREDECESSORS');
 const common={signerPublicKey,...pins,readRetainedHead:async()=>({...head})};
 const a=await verifyLocalReviewPolicyCheckpointAdvancement({...common,checkpointBytes:left});
 const b=await verifyLocalReviewPolicyCheckpointAdvancement({...common,checkpointBytes:right});
 if(a.candidateRevision!==b.candidateRevision||
  a.candidateSha256===b.candidateSha256)
  fail('LOCAL_REVIEW_CAS_NO_FORK');
 const ordered=Object.freeze([a.candidateSha256,b.candidateSha256].sort());
 const body={schema:LOCAL_REVIEW_POLICY_CAS_EVIDENCE_SCHEMA,
  rootPin:head.rootPin,registryId:head.registryId,
  signerFingerprint:head.signerFingerprint,
  parentCheckpointSha256:head.checkpointSha256,parentRevision:head.revision,
  forkRevision:a.candidateRevision,candidateSha256:ordered};
 return Object.freeze({...body,evidenceSha256:hash(Buffer.from(
  `${LOCAL_REVIEW_POLICY_CAS_EVIDENCE_SCHEMA}\n${JSON.stringify(body)}`)),
  leftSignedCheckpointBase64url:left[1].toString('base64url'),
  rightSignedCheckpointBase64url:right[1].toString('base64url'),
  signerValidForksDetected:true,independentlyWitnessed:false,
  globalForkPreventionVerified:false,authorizesProduction:false,
  shopifyWritesAllowed:false});
}
