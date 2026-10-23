import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,createHash} from 'node:crypto';
import {mkdtemp,rm,symlink,writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawn} from 'node:child_process';
import {LOCAL_REVIEW_REVOCATION_SCHEMA} from '../src/preview-local-artwork-review-rotation-lineage.mjs';
import {createLocalReviewPolicyCheckpoint,LOCAL_REVIEW_POLICY_GENESIS_DIGEST,
 LOCAL_REVIEW_RETAINED_HEAD_SCHEMA} from '../src/preview-local-artwork-review-policy-checkpoints.mjs';
import {createOfflineLocalReviewPolicyHeadRegistry,advanceOfflineLocalReviewPolicyHead,
 inspectOfflineLocalReviewPolicySplitView,
 LOCAL_REVIEW_POLICY_CAS_EVIDENCE_SCHEMA} from '../src/preview-local-artwork-review-policy-cas.mjs';
const digest=x=>createHash('sha256').update(x).digest('hex');
const signer=generateKeyPairSync('ed25519'),recovery=generateKeyPairSync('ed25519');
const other=generateKeyPairSync('ed25519');
const rootPin=digest('35AE-root'),registryId=digest('35AE-registry');
const keyA=digest('keyA'),keyB=digest('keyB'),keyC=digest('keyC');
const policy=(revision,keys=[])=>({schema:LOCAL_REVIEW_REVOCATION_SCHEMA,
 revision,revokedKeyFingerprints:[...keys].sort(),revokedRotationDigests:[],authority:'NONE'});
const issue=(p,prev=LOCAL_REVIEW_POLICY_GENESIS_DIGEST,opts={})=>
 createLocalReviewPolicyCheckpoint({policy:p,rootPin,registryId,
 previousCheckpointSha256:prev,signingKey:signer.privateKey,...opts});
const first=issue(policy(1,[keyA]));
const branchA=issue(policy(2,[keyA,keyB]),first.sha256);
const branchB=issue(policy(2,[keyA,keyC]),first.sha256);
const third=issue(policy(3,[keyA,keyB,keyC]),branchA.sha256);
const head=c=>({schema:LOCAL_REVIEW_RETAINED_HEAD_SCHEMA,rootPin,registryId,
 signerFingerprint:c.signerFingerprint,checkpointSha256:c.sha256,revision:c.revision});
const pins={expectedRootPin:rootPin,expectedRegistryId:registryId,
 expectedSignerFingerprint:first.signerFingerprint};
const common={...pins,signerPublicKey:signer.publicKey};
const chain=(candidate=branchA)=>[first.bytes,candidate.bytes];
const split=extra=>inspectOfflineLocalReviewPolicySplitView({
 leftCheckpointBytes:chain(branchA),rightCheckpointBytes:chain(branchB),
 pinnedHead:head(first),...common,...extra});
async function fixture(t){
 const directory=await mkdtemp(join(tmpdir(),'tj35ae-'));
 t.after(()=>rm(directory,{recursive:true,force:true}));
 const options={directory:join(directory,'registry'),...pins,recoveryPublicKey:recovery.publicKey};
 const registry=createOfflineLocalReviewPolicyHeadRegistry(options);
 await registry.initializePinnedHead(head(first));
 return {directory,options,registry};
}
const advance=(registry,candidate=branchA,extra={})=>advanceOfflineLocalReviewPolicyHead({
 checkpointBytes:chain(candidate),registry,...common,...extra});
const rejects=(promise,code)=>assert.rejects(promise,{code});

test('35AE initializes a separately pinned revision-one local head',async t=>{
 const f=await fixture(t);assert.deepEqual(await f.registry.readRetainedHead(),head(first));
 const s=await f.registry.inspectRecoveryState();assert.equal(s.pending,false);
 assert.equal(s.independentCustodyVerified,false);assert.equal(s.authorizesProduction,false);
});
test('35AE signed successor advances durable local head via atomic CAS',async t=>{
 const f=await fixture(t),r=await advance(f.registry);
 assert.equal(r.committedRevision,2);assert.equal(r.committedSha256,branchA.sha256);
 assert.equal(r.localCASObserved,true);assert.equal(r.independentCustodyVerified,false);
 assert.equal(r.globalForkPreventionVerified,false);assert.equal(r.shopifyWritesAllowed,false);
 assert.deepEqual(await f.registry.readRetainedHead(),head(branchA));
});
test('35AE retains committed head across adapter re-instantiation',async t=>{
 const f=await fixture(t);await advance(f.registry);
 const reopened=createOfflineLocalReviewPolicyHeadRegistry(f.options);
 assert.deepEqual(await reopened.readRetainedHead(),head(branchA));
});
test('35AE rejects second bootstrap even if identical',async t=>{
 const f=await fixture(t);assert.equal(await f.registry.initializePinnedHead(head(first)),false);
});
test('35AE rejects bootstrap of revision greater than one',async t=>{
 const f=await fixture(t);await rejects(f.registry.initializePinnedHead(head(branchA)),'LOCAL_REVIEW_CAS_INITIAL_PIN_REQUIRED');
});
test('35AE rejects uninitialized head read',async t=>{
 const f=await fixture(t),empty=createOfflineLocalReviewPolicyHeadRegistry({...f.options,
  directory:join(f.directory,'uninitialized')});
 await rejects(empty.readRetainedHead(),'LOCAL_REVIEW_CAS_UNINITIALIZED');
});
test('35AE rejects invalid external pins at construction',()=>{
 assert.throws(()=>createOfflineLocalReviewPolicyHeadRegistry({directory:'/tmp/no',...pins,
  expectedRootPin:'wrong',recoveryPublicKey:recovery.publicKey}),{code:'LOCAL_REVIEW_CAS_INVALID_PINS'});
});
test('35AE rejects missing recovery public key at construction',()=>{
 assert.throws(()=>createOfflineLocalReviewPolicyHeadRegistry({directory:'/tmp/no',...pins}),{code:'LOCAL_REVIEW_CAS_INVALID_RECOVERY_KEY'});
});
test('35AE rejects wrong recovery key type',()=>{
 assert.throws(()=>createOfflineLocalReviewPolicyHeadRegistry({directory:'/tmp/no',...pins,
  recoveryPublicKey:recovery.privateKey}),{code:'LOCAL_REVIEW_CAS_INVALID_RECOVERY_KEY'});
});
test('35AE rejects extra privilege on pinned head',async t=>{
 const f=await fixture(t);await rejects(f.registry.initializePinnedHead({...head(first),canPublish:true}),'LOCAL_REVIEW_CAS_INVALID_HEAD');
});
test('35AE rejects substituted registry identity',async t=>{
 const f=await fixture(t);await rejects(f.registry.compareAndSwapRetainedHead({...head(first),registryId:digest('other')},head(branchA)),'LOCAL_REVIEW_CAS_INVALID_HEAD');
});
test('35AE rejects substituted signing fingerprint',async t=>{
 const f=await fixture(t);await rejects(f.registry.compareAndSwapRetainedHead(head(first),{...head(branchA),signerFingerprint:digest('other')}),'LOCAL_REVIEW_CAS_INVALID_HEAD');
});
test('35AE rejects revision skips at CAS',async t=>{
 const f=await fixture(t);await rejects(f.registry.compareAndSwapRetainedHead(head(first),{...head(branchA),revision:3}),'LOCAL_REVIEW_CAS_NON_MONOTONIC');
});
test('35AE rejects same digest with incremented revision',async t=>{
 const f=await fixture(t);await rejects(f.registry.compareAndSwapRetainedHead(head(first),{...head(first),revision:2}),'LOCAL_REVIEW_CAS_NON_MONOTONIC');
});
test('35AE rejects a stale CAS after winner has advanced',async t=>{
 const f=await fixture(t);await advance(f.registry);
 assert.equal(await f.registry.compareAndSwapRetainedHead(head(first),head(branchB)),false);
 assert.deepEqual(await f.registry.readRetainedHead(),head(branchA));
});
test('35AE rejects replay of already committed signed advancement',async t=>{
 const f=await fixture(t);await advance(f.registry);
 await rejects(advance(f.registry),'LOCAL_REVIEW_POLICY_RETAINED_HEAD_MISMATCH');
});
test('35AE rejects forged candidate signature before any CAS',async t=>{
 const f=await fixture(t),bad=JSON.parse(branchA.bytes);
 bad.signature=(bad.signature[0]==='A'?'B':'A')+bad.signature.slice(1);
 await rejects(advanceOfflineLocalReviewPolicyHead({checkpointBytes:[first.bytes,Buffer.from(JSON.stringify(bad))],
  registry:f.registry,...common}),'LOCAL_REVIEW_POLICY_BAD_SIGNATURE');
 assert.deepEqual(await f.registry.readRetainedHead(),head(first));
});
test('35AE rejects key substitution before CAS',async t=>{
 const f=await fixture(t);await rejects(advance(f.registry,branchA,{signerPublicKey:other.publicKey}),'LOCAL_REVIEW_POLICY_UNTRUSTED_SIGNER');
});
test('35AE rejects revocation rollback before CAS',async t=>{
 const f=await fixture(t),bad=issue(policy(2,[]),first.sha256);
 await rejects(advance(f.registry,bad),'LOCAL_REVIEW_POLICY_REVOCATION_ROLLBACK');
});
test('35AE rejects multi-step chain as one CAS promotion',async t=>{
 const f=await fixture(t);await rejects(advanceOfflineLocalReviewPolicyHead({
  checkpointBytes:[first.bytes,branchA.bytes,third.bytes],registry:f.registry,...common}),
  'LOCAL_REVIEW_CAS_SINGLE_STEP_REQUIRED');
});
test('35AE rejects missing CAS adapter',async()=>{
 await rejects(advanceOfflineLocalReviewPolicyHead({checkpointBytes:chain(),registry:{readRetainedHead:async()=>head(first)},...common}),
  'LOCAL_REVIEW_CAS_INVALID_REGISTRY');
});
test('35AE rejects lying CAS adapter return value',async()=>{
 const registry={readRetainedHead:async()=>head(first),compareAndSwapRetainedHead:async()=>1};
 await rejects(advance(registry),'LOCAL_REVIEW_CAS_ADAPTER_INVALID_RESULT');
});
test('35AE rejects adapter that returns false rather than silently retrying',async()=>{
 const registry={readRetainedHead:async()=>head(first),compareAndSwapRetainedHead:async()=>false};
 await rejects(advance(registry),'LOCAL_REVIEW_CAS_CONFLICT');
});
test('35AE rejects lying CAS success with no durable readback',async()=>{
 const registry={readRetainedHead:async()=>head(first),compareAndSwapRetainedHead:async()=>true};
 await rejects(advance(registry),'LOCAL_REVIEW_CAS_COMMIT_UNCERTAIN');
});
test('35AE rejects disappearing registry after reported CAS success',async()=>{
 let reads=0;const registry={readRetainedHead:async()=>++reads>2?Promise.reject(Error('offline')):head(first),
  compareAndSwapRetainedHead:async()=>true};
 await rejects(advance(registry),'LOCAL_REVIEW_CAS_COMMIT_UNCERTAIN');
});
test('35AE detects two distinct valid signed successors of same pinned head',async()=>{
 const r=await split();assert.equal(r.schema,LOCAL_REVIEW_POLICY_CAS_EVIDENCE_SCHEMA);
 assert.equal(r.signerValidForksDetected,true);assert.equal(r.forkRevision,2);
 assert.equal(r.candidateSha256.length,2);assert.notEqual(...r.candidateSha256);
 assert.equal(r.independentlyWitnessed,false);assert.equal(r.globalForkPreventionVerified,false);
 assert.equal(r.authorizesProduction,false);assert.equal(r.shopifyWritesAllowed,false);
});
test('35AE fork evidence digest is order-independent',async()=>{
 const a=await split(),b=await split({leftCheckpointBytes:chain(branchB),rightCheckpointBytes:chain(branchA)});
 assert.equal(a.evidenceSha256,b.evidenceSha256);
});
test('35AE fork evidence includes portable signer-authenticated candidate bytes',async()=>{
 const r=await split();assert.deepEqual(Buffer.from(r.leftSignedCheckpointBase64url,'base64url'),branchA.bytes);
 assert.deepEqual(Buffer.from(r.rightSignedCheckpointBase64url,'base64url'),branchB.bytes);
 assert.equal(Object.isFrozen(r.candidateSha256),true);
 assert.throws(()=>r.candidateSha256.push('forged'),TypeError);
});
test('35AE rejects identical signed branches as non-fork',async()=>{
 await rejects(split({rightCheckpointBytes:chain(branchA)}),'LOCAL_REVIEW_CAS_NO_FORK');
});
test('35AE rejects fork claim with forged right signature',async()=>{
 const forged=JSON.parse(branchB.bytes);forged.signature=(forged.signature[0]==='A'?'B':'A')+forged.signature.slice(1);
 await rejects(split({rightCheckpointBytes:[first.bytes,Buffer.from(JSON.stringify(forged))]}),'LOCAL_REVIEW_POLICY_BAD_SIGNATURE');
});
test('35AE rejects fork claim with different signed predecessor bytes',async()=>{
 const otherParent=issue(policy(1,[keyB]));
 await rejects(split({rightCheckpointBytes:[otherParent.bytes,branchB.bytes]}),'LOCAL_REVIEW_CAS_FORK_DIFFERENT_PREDECESSORS');
});
test('35AE rejects fork claim with changed externally pinned head',async()=>{
 await rejects(split({pinnedHead:head(branchA)}),'LOCAL_REVIEW_POLICY_RETAINED_HEAD_MISMATCH');
});
test('35AE rejects fork claim with different registry pin',async()=>{
 await rejects(split({expectedRegistryId:digest('different')}),'LOCAL_REVIEW_CAS_INVALID_HEAD');
});
test('35AE rejects fork claim with missing signer',async()=>{
 await rejects(split({signerPublicKey:undefined}),'LOCAL_REVIEW_POLICY_INVALID_OPTIONS');
});
test('35AE rejects malformed fork chain length',async()=>{
 await rejects(split({leftCheckpointBytes:[first.bytes]}),'LOCAL_REVIEW_CAS_FORK_INVALID_CHAIN');
});
test('35AE rejects accessor-based fork chain',async()=>{
 const c=chain();Object.defineProperty(c,1,{get:()=>branchA.bytes,enumerable:true});
 await rejects(split({leftCheckpointBytes:c}),'LOCAL_REVIEW_CAS_FORK_INVALID_CHAIN');
});
test('35AE rejects sparse fork chain',async()=>{
 const c=chain();delete c[1];await rejects(split({leftCheckpointBytes:c}),'LOCAL_REVIEW_CAS_FORK_INVALID_CHAIN');
});
test('35AE rejects oversized fork checkpoint',async()=>{
 await rejects(split({leftCheckpointBytes:[first.bytes,Buffer.alloc(16385)]}),'LOCAL_REVIEW_CAS_FORK_INVALID_CHAIN');
});
test('35AE preserves fork evidence despite caller mutation after async verification begins',async()=>{
 const c=chain().map(b=>Buffer.from(b)),promise=split({leftCheckpointBytes:c});c[1].fill(0);
 const r=await promise;assert.equal(r.signerValidForksDetected,true);
});
test('35AE durable local CAS rejects concurrent competing signed forks',async t=>{
 const f=await fixture(t);
 const [a,b]=await Promise.allSettled([advance(f.registry,branchA),advance(f.registry,branchB)]);
 assert.equal([a,b].filter(x=>x.status==='fulfilled').length,1);
 const observed=await f.registry.readRetainedHead();
 assert.ok([branchA.sha256,branchB.sha256].includes(observed.checkpointSha256));
 assert.equal(observed.revision,2);
});
test('35AE cross-process CAS admits one winner and rejects competing revision',async t=>{
 const f=await fixture(t);
 const url=new URL('../src/preview-local-artwork-review-policy-cas.mjs',import.meta.url).href;
 const worker=`import {createPublicKey} from 'node:crypto';\nimport {createOfflineLocalReviewPolicyHeadRegistry} from ${JSON.stringify(url)};\nconst a=JSON.parse(process.env.TJ35AE_ARGS);\nconst r=createOfflineLocalReviewPolicyHeadRegistry({...a.options,recoveryPublicKey:createPublicKey(a.recoveryPem)});\nconst result=await r.compareAndSwapRetainedHead(a.expected,a.candidate);\nconsole.log(JSON.stringify(result));`;
 const run=candidate=>new Promise((resolve,reject)=>{
  const env={...process.env,TJ35AE_ARGS:JSON.stringify({options:{directory:f.options.directory,...pins},
   recoveryPem:recovery.publicKey.export({type:'spki',format:'pem'}),expected:head(first),candidate:head(candidate)})};
  const child=spawn(process.execPath,['--input-type=module','-e',worker],{env});
  let output='',error='';child.stdout.on('data',b=>output+=b);child.stderr.on('data',b=>error+=b);
  child.on('error',reject);child.on('close',code=>code===0?resolve(JSON.parse(output.trim())):reject(Error(error)));
 });
 const results=await Promise.all([run(branchA),run(branchB),run(branchA)]);
 assert.equal(results.filter(Boolean).length,1);
 assert.equal((await f.registry.readRetainedHead()).revision,2);
});
test('35AE crash after pending sync blocks reads and all future CAS',async t=>{
 const f=await fixture(t);
 const faulty=createOfflineLocalReviewPolicyHeadRegistry({...f.options,
  injectFault:async stage=>{if(stage==='after-pending-sync')throw Error('simulated-crash');}});
 await assert.rejects(faulty.compareAndSwapRetainedHead(head(first),head(branchA)),/simulated-crash/);
 await rejects(f.registry.readRetainedHead(),'DURABLE_ANCHOR_PENDING_RECOVERY_REQUIRED');
 await rejects(f.registry.compareAndSwapRetainedHead(head(first),head(branchB)),
  'DURABLE_ANCHOR_PENDING_RECOVERY_REQUIRED');
 const state=await f.registry.inspectRecoveryState();assert.equal(state.pending,true);
 assert.equal(state.requiresIndependentRecoveryAuthorization,true);
 assert.equal(state.retainedHead.revision,1);
});
test('35AE crash after committed rename is detectable without duplicate write',async t=>{
 const f=await fixture(t);
 const faulty=createOfflineLocalReviewPolicyHeadRegistry({...f.options,
  injectFault:async stage=>{if(stage==='after-commit-sync')throw Error('post-commit-fault');}});
 await assert.rejects(faulty.compareAndSwapRetainedHead(head(first),head(branchA)),/post-commit-fault/);
 assert.deepEqual(await f.registry.readRetainedHead(),head(branchA));
 assert.equal(await f.registry.compareAndSwapRetainedHead(head(first),head(branchB)),false);
});
test('35AE refuses symlinked local registry history',async t=>{
 const f=await fixture(t);await advance(f.registry);
 const history=join(f.options.directory,'0000000002.json');
 const fake=join(f.directory,'fake');await writeFile(fake,'{}');
 await rm(history);await symlink(fake,history);
 await rejects(f.registry.readRetainedHead(),'DURABLE_ANCHOR_FILE_UNSAFE');
});
