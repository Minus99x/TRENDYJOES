import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHash,generateKeyPairSync,randomBytes} from 'node:crypto';
import {LocalDesignStore} from '../src/local-store.mjs';
import {createLocalArtworkQuarantineIntent} from '../src/preview-local-artwork-quarantine-review.mjs';
import {createLocalArtworkReviewEvidence} from '../src/preview-local-artwork-review-evidence.mjs';
import {createLocalArtworkReviewJournal,localArtworkReviewJournalGenesisHead as genesis} from '../src/preview-local-artwork-review-journal.mjs';
import {LOCAL_REVIEW_OBSERVER_SCHEMA,issueLocalReviewObserverReceipt as issue,
 verifyLocalReviewObserverReceipt as verify,reconcileLocalReviewObserverReceipts as reconcile}
 from '../src/preview-local-artwork-review-observer.mjs';
const PNG=Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/lIgAAAAASUVORK5CYII=','base64');
const now=1800000000000,reviewKey=randomBytes(32),reviewer=generateKeyPairSync('ed25519');
const alice=generateKeyPairSync('ed25519'),bob=generateKeyPairSync('ed25519'),eve=generateKeyPairSync('ed25519');
const keyMap={alice:alice.publicKey,bob:bob.publicKey,eve:eve.publicKey};
const reviewResolver=async id=>id==='reviewer'?reviewer.publicKey:null;
const observerResolver=async(id,keyId)=>keyId==='key-1'?keyMap[id]:null;
const reject=(p,code)=>assert.rejects(p,e=>e?.code===code);
const rootPin=root=>createHash('sha256').update(root).digest('hex');
const h=n=>createHash('sha256').update(String(n)).digest('hex');
async function setup(t){
 const base=await mkdtemp(join(tmpdir(),'tj35aa-'));t.after(()=>rm(base,{recursive:true,force:true}));
 const root=join(base,'artwork'),directory=join(base,'journal');
 const store=new LocalDesignStore(root);await store.init();
 const art=await store.putArtwork(PNG,'image/png');
 await store.putDesign({productManifestId:'concept-crew-tee',layers:[{id:'art',type:'artwork',surfaceId:'front',x:.1,y:.1,width:.2,height:.2,rotationDeg:0,artworkId:art.id}],artworkGrants:{[art.id]:art.grant}});
 return {root,directory,journal:createLocalArtworkReviewJournal({root,directory}),rootPin:rootPin(root)};
}
async function admit(v,head=genesis()){
 const ticket=await createLocalArtworkQuarantineIntent(v.root,{reviewKey,now,nonce:randomBytes(16).toString('hex')});
 const challenge=randomBytes(16).toString('hex');
 const evidence=await createLocalArtworkReviewEvidence(v.root,ticket,{reviewKey,signingKey:reviewer.privateKey,keyId:'reviewer',challenge,now});
 return v.journal.admit({ticket,evidence,reviewKey,resolvePublicKey:reviewResolver,expectedChallenge:challenge,expectedHead:head,now});
}
const args=(v,observerId='alice',expectedHead=genesis(),extra={})=>({journal:v.journal,expectedHead,
 resolveReviewPublicKey:reviewResolver,rootPin:v.rootPin,observerId,keyId:'key-1',
 signingKey:{alice,bob,eve}[observerId].privateKey,observedAt:now,resolveObserverPublicKey:observerResolver,...extra});
const verifyArgs=v=>({resolveObserverPublicKey:observerResolver,expectedRootPin:v.rootPin});
const recArgs=(v,receipts,pins,extra={})=>({receipts,pins,...verifyArgs(v),...extra});
const clone=o=>structuredClone(o);
function mockJournal(digests,root){
 return {inspect:async({expectedHead})=>({head:expectedHead,historySignaturesVerified:true,
  independentlyWitnessed:false,shopifyWritesAllowed:false,authorizesProduction:false,
  entries:digests.map((recordDigest,i)=>({index:i+1,rootPin:root,recordDigest,authority:'NONE'}))})};
}
async function synthetic(v,observerId,digests,extra={}){
 const expectedHead={count:digests.length,headDigest:digests.at(-1)||genesis().headDigest};
 return issue(args(v,observerId,expectedHead,{journal:mockJournal(digests,v.rootPin),...extra}));
}
test('35AA real signed journal yields portable observer receipt without authority',async t=>{
 const v=await setup(t),r=await admit(v),receipt=await issue(args(v,'alice',r.head));
 const checked=await verify(receipt,verifyArgs(v));
 assert.equal(receipt.schema,LOCAL_REVIEW_OBSERVER_SCHEMA);assert.equal(receipt.head.headDigest,r.head.headDigest);
 assert.deepEqual(receipt.recordDigests,r.entries.map(x=>x.recordDigest));
 assert.equal(checked.signatureVerified,true);assert.equal(checked.shopifyWritesAllowed,false);
 assert.equal(checked.authorizesProduction,false);assert.equal(checked.externallyWitnessed,false);
 assert.equal(checked.trustedTime,false);assert.equal(checked.observerKeyCustodyVerified,false);
 assert.equal(Object.isFrozen(receipt),true);assert.equal(Object.isFrozen(receipt.recordDigests),true);
});
test('35AA real two-observer same-head external pin reconciliation',async t=>{
 const v=await setup(t),r=await admit(v);
 const a=await issue(args(v,'alice',r.head)),b=await issue(args(v,'bob',r.head));
 const report=await reconcile(recArgs(v,[b],[a]));
 assert.equal(report.verifiedReceipts,2);assert.equal(report.distinctObserverKeys,2);
 assert.equal(report.status,'CONSISTENT_WITH_SUPPLIED_EXTERNAL_PINS');
 assert.equal(report.independentlyWitnessed,false);assert.equal(report.independentlyRetainedPinsVerified,false);
});
test('35AA independently pinned history accepts verified extension with previous receipt',async t=>{
 const v=await setup(t),one=await admit(v),a=await issue(args(v,'alice',one.head));
 const two=await admit(v,one.head),b=await issue(args(v,'alice',two.head,{previousReceipt:a}));
 assert.equal(b.sequence,2);assert.equal(b.previousReceiptDigest,a.receiptDigest);
 assert.equal(b.recordDigests[0],a.recordDigests[0]);
 const r=await reconcile(recArgs(v,[b],[a]));assert.equal(r.head.count,2);
});
test('35AA genesis receipt is signed, deterministic head, but not a global anchor',async t=>{
 const v=await setup(t),r=await issue(args(v,'alice',genesis(),{journal:mockJournal([],v.rootPin)}));
 assert.equal(r.head.count,0);assert.deepEqual(r.recordDigests,[]);
 assert.equal((await verify(r,verifyArgs(v))).receipt.head.headDigest,genesis().headDigest);
});
test('35AA stale pinned head fails in real journal inspect before signing',async t=>{
 const v=await setup(t);await admit(v);
 await reject(issue(args(v)),'LOCAL_REVIEW_JOURNAL_STALE_OR_ROLLED_BACK_HEAD');
});
test('35AA invalid review public key fails historical journal verification',async t=>{
 const v=await setup(t),r=await admit(v);
 await reject(issue(args(v,'alice',r.head,{resolveReviewPublicKey:async()=>eve.publicKey})),
  'LOCAL_REVIEW_JOURNAL_HISTORY_INVALID');
});
test('35AA issue requires an independently supplied exact head',async t=>{
 const v=await setup(t);await reject(issue(args(v,'alice',undefined,{expectedHead:undefined})),
  'LOCAL_REVIEW_OBSERVER_INVALID_OPTIONS');
});
test('35AA issue rejects fake journal lacking historical verification',async t=>{
 const v=await setup(t),bad={inspect:async()=>({head:genesis(),entries:[],historySignaturesVerified:false,
 independentlyWitnessed:false,shopifyWritesAllowed:false,authorizesProduction:false})};
 await reject(issue(args(v,'alice',genesis(),{journal:bad})),'LOCAL_REVIEW_OBSERVER_UNVERIFIED_JOURNAL');
});
test('35AA issue rejects fake journal claiming production authority',async t=>{
 const v=await setup(t),bad={inspect:async()=>({head:genesis(),entries:[],historySignaturesVerified:true,
 independentlyWitnessed:false,shopifyWritesAllowed:false,authorizesProduction:true})};
 await reject(issue(args(v,'alice',genesis(),{journal:bad})),'LOCAL_REVIEW_OBSERVER_UNVERIFIED_JOURNAL');
});
test('35AA issue rejects forged root pin on journal entries',async t=>{
 const v=await setup(t),d=h('entry'),bad=mockJournal([d],h('other'));
 await reject(issue(args(v,'alice',{count:1,headDigest:d},{journal:bad})),'LOCAL_REVIEW_OBSERVER_UNVERIFIED_JOURNAL');
});
test('35AA receipt rejects modified signed head',async t=>{
 const v=await setup(t),r=await synthetic(v,'alice',[h(1)]),f=clone(r);f.head.headDigest=h(2);
 await reject(verify(f,verifyArgs(v)),'LOCAL_REVIEW_OBSERVER_MALFORMED');
});
test('35AA receipt rejects modified signed record prefix',async t=>{
 const v=await setup(t),r=await synthetic(v,'alice',[h(1),h(2)]),f=clone(r);f.recordDigests[0]=h(3);
 await reject(verify(f,verifyArgs(v)),'LOCAL_REVIEW_OBSERVER_TAMPERED');
});
test('35AA receipt rejects altered observedAt timestamp',async t=>{
 const v=await setup(t),r=await synthetic(v,'alice',[h(1)]),f=clone(r);f.observedAt++;
 await reject(verify(f,verifyArgs(v)),'LOCAL_REVIEW_OBSERVER_TAMPERED');
});
test('35AA receipt rejects substituted observer identity',async t=>{
 const v=await setup(t),r=await synthetic(v,'alice',[h(1)]),f=clone(r);f.observerId='bob';
 await reject(verify(f,verifyArgs(v)),'LOCAL_REVIEW_OBSERVER_TAMPERED');
});
test('35AA receipt rejects wrong trusted observer key',async t=>{
 const v=await setup(t),r=await synthetic(v,'alice',[h(1)]);
 await reject(verify(r,{...verifyArgs(v),resolveObserverPublicKey:async()=>eve.publicKey}),
  'LOCAL_REVIEW_OBSERVER_BAD_SIGNATURE');
});
test('35AA receipt rejects wrong root pin',async t=>{
 const v=await setup(t),r=await synthetic(v,'alice',[h(1)]);
 await reject(verify(r,{...verifyArgs(v),expectedRootPin:h('another-root')}),'LOCAL_REVIEW_OBSERVER_MALFORMED');
});
test('35AA receipt rejects unsigned extra privilege',async t=>{
 const v=await setup(t),r=await synthetic(v,'alice',[h(1)]);
 await reject(verify({...r,canDelete:true},verifyArgs(v)),'LOCAL_REVIEW_OBSERVER_MALFORMED');
});
test('35AA receipt rejects noncanonical signature and receipt digest',async t=>{
 const v=await setup(t),r=await synthetic(v,'alice',[h(1)]);
 await reject(verify({...r,signature:'A'.repeat(86)},verifyArgs(v)),'LOCAL_REVIEW_OBSERVER_TAMPERED');
 await reject(verify({...r,receiptDigest:h('false')},verifyArgs(v)),'LOCAL_REVIEW_OBSERVER_TAMPERED');
});
test('35AA receipt rejects sparse and oversized histories',async t=>{
 const v=await setup(t),r=await synthetic(v,'alice',[h(1)]),f=clone(r);
 f.recordDigests=new Array(1);await reject(verify(f,verifyArgs(v)),'LOCAL_REVIEW_OBSERVER_MALFORMED');
 f.recordDigests=Array.from({length:257},(_,i)=>h(i));f.head.count=257;
 await reject(verify(f,verifyArgs(v)),'LOCAL_REVIEW_OBSERVER_MALFORMED');
});
test('35AA receipt rejects a forged signature even if digest is recomputed externally',async t=>{
 const v=await setup(t),r=await synthetic(v,'alice',[h(1)]),f=clone(r);
 f.signature=Buffer.alloc(64).toString('base64url');
 f.receiptDigest=createHash('sha256').update('TJ-35AA-RECEIPT\n'+JSON.stringify(Object.fromEntries(
  Object.entries(f).filter(([k])=>k!=='receiptDigest')))).digest('hex');
 await reject(verify(f,verifyArgs(v)),'LOCAL_REVIEW_OBSERVER_BAD_SIGNATURE');
});
test('35AA split-view detection rejects equal-height divergent observer histories',async t=>{
 const v=await setup(t),a=await synthetic(v,'alice',[h('A')]),b=await synthetic(v,'bob',[h('B')]);
 await reject(reconcile(recArgs(v,[b],[a])),'LOCAL_REVIEW_OBSERVER_SPLIT_VIEW');
});
test('35AA split-view detection rejects divergent prefixes at different heights',async t=>{
 const v=await setup(t),a=await synthetic(v,'alice',[h('A')]),b=await synthetic(v,'bob',[h('B'),h('C')]);
 await reject(reconcile(recArgs(v,[b],[a])),'LOCAL_REVIEW_OBSERVER_SPLIT_VIEW');
});
test('35AA external historical pin rejects rollback to shorter signed head',async t=>{
 const v=await setup(t),a=await synthetic(v,'alice',[h('A'),h('B')]),b=await synthetic(v,'bob',[h('A')]);
 await reject(reconcile(recArgs(v,[b],[a])),'LOCAL_REVIEW_OBSERVER_ROLLBACK');
});
test('35AA detects same-observer same-sequence equivocation',async t=>{
 const v=await setup(t),a=await synthetic(v,'alice',[h('A')]),b=await synthetic(v,'alice',[h('A'),h('B')]);
 await reject(reconcile(recArgs(v,[b],[a])),'LOCAL_REVIEW_OBSERVER_EQUIVOCATION');
});
test('35AA detects same-observer missing chain predecessor',async t=>{
 const v=await setup(t),a=await synthetic(v,'alice',[h('A')]),b=await synthetic(v,'alice',[h('A'),h('B')],{previousReceipt:a});
 const f=clone(b);f.previousReceiptDigest=h('forged');
 await reject(reconcile(recArgs(v,[f],[a])),'LOCAL_REVIEW_OBSERVER_TAMPERED');
});
test('35AA previous receipt cannot be from another observer',async t=>{
 const v=await setup(t),a=await synthetic(v,'bob',[h('A')]);
 await reject(synthetic(v,'alice',[h('A'),h('B')],{previousReceipt:a}),
  'LOCAL_REVIEW_OBSERVER_WRONG_PREDECESSOR');
});
test('35AA previous receipt must be strict extension, not a replay',async t=>{
 const v=await setup(t),a=await synthetic(v,'alice',[h('A')]);
 await reject(synthetic(v,'alice',[h('A')],{previousReceipt:a}),'LOCAL_REVIEW_OBSERVER_NON_EXTENSION');
});
test('35AA previous receipt must be strict extension, not fork',async t=>{
 const v=await setup(t),a=await synthetic(v,'alice',[h('A')]);
 await reject(synthetic(v,'alice',[h('B'),h('C')],{previousReceipt:a}),'LOCAL_REVIEW_OBSERVER_NON_EXTENSION');
});
test('35AA external pins are mandatory even with a signed current receipt',async t=>{
 const v=await setup(t),a=await synthetic(v,'alice',[h('A')]);
 await reject(reconcile(recArgs(v,[a],[])),'LOCAL_REVIEW_OBSERVER_EXTERNAL_PINS_REQUIRED');
});
test('35AA externally pinned forged receipt fails signature validation',async t=>{
 const v=await setup(t),a=await synthetic(v,'alice',[h('A')]),b=await synthetic(v,'bob',[h('A')]);
 const f=clone(a);f.signature='A'.repeat(86);
 await reject(reconcile(recArgs(v,[b],[f])),'LOCAL_REVIEW_OBSERVER_TAMPERED');
});
test('35AA observers sharing one key are not accepted as independent keys',async t=>{
 const v=await setup(t),a=await synthetic(v,'alice',[h('A')]);
 const sharedResolver=async(id,keyId)=>keyId==='key-1'?alice.publicKey:null;
 const b=await issue(args(v,'bob',{count:1,headDigest:h('A')},
  {journal:mockJournal([h('A')],v.rootPin),signingKey:alice.privateKey,resolveObserverPublicKey:sharedResolver}));
 await reject(reconcile(recArgs(v,[b],[a],{resolveObserverPublicKey:sharedResolver})),
  'LOCAL_REVIEW_OBSERVER_SHARED_KEY');
});
test('35AA two different keys do not imply independently controlled custody',async t=>{
 const v=await setup(t),a=await synthetic(v,'alice',[h('A')]),b=await synthetic(v,'bob',[h('A')]);
 const r=await reconcile(recArgs(v,[b],[a]));
 assert.equal(r.cryptographicallyDistinctObserverKeys,true);
 assert.equal(r.observerKeyCustodyVerified,false);assert.equal(r.independentlyWitnessed,false);
 assert.equal(r.shopifyWritesAllowed,false);
});
test('35AA rejects invalid journal index ordering',async t=>{
 const v=await setup(t),d=h('A');
 const bad={inspect:async({expectedHead})=>({head:expectedHead,historySignaturesVerified:true,
 independentlyWitnessed:false,shopifyWritesAllowed:false,authorizesProduction:false,
 entries:[{index:2,rootPin:v.rootPin,recordDigest:d,authority:'NONE'}]})};
 await reject(issue(args(v,'alice',{count:1,headDigest:d},{journal:bad})),
  'LOCAL_REVIEW_OBSERVER_UNVERIFIED_JOURNAL');
});
test('35AA rejects untrusted resolver and invalid private signing key',async t=>{
 const v=await setup(t),r=await synthetic(v,'alice',[h('A')]);
 await reject(verify(r,{...verifyArgs(v),resolveObserverPublicKey:async()=>null}),
  'LOCAL_REVIEW_OBSERVER_UNTRUSTED_KEY');
 await reject(issue(args(v,'alice',genesis(),{signingKey:alice.publicKey})),
  'LOCAL_REVIEW_OBSERVER_INVALID_OPTIONS');
});

test('35AA issue refuses a signer private key inconsistent with trusted observer registry',async t=>{
 const v=await setup(t);
 await reject(synthetic(v,'alice',[h('A')],{signingKey:eve.privateKey}),
  'LOCAL_REVIEW_OBSERVER_BAD_SIGNATURE');
});
test('35AA reconciliation rejects unanchored sequence two even if signed',async t=>{
 const v=await setup(t),a=await synthetic(v,'alice',[h('A')]);
 const b=await synthetic(v,'alice',[h('A'),h('B')],{previousReceipt:a});
 const p=await synthetic(v,'bob',[h('A')]);
 await reject(reconcile(recArgs(v,[b],[p])),'LOCAL_REVIEW_OBSERVER_CHAIN_GAP');
});
test('35AA reconciliation accepts pinned genesis then later signed append',async t=>{
 const v=await setup(t);
 const p=await synthetic(v,'bob',[]),r=await synthetic(v,'alice',[h('A')]);
 const result=await reconcile(recArgs(v,[r],[p]));
 assert.equal(result.head.count,1);assert.equal(result.shopifyWritesAllowed,false);
});
test('35AA receipt signature is portable through JSON encode/decode',async t=>{
 const v=await setup(t),r=await synthetic(v,'alice',[h('A')]);
 const imported=JSON.parse(JSON.stringify(r));
 assert.equal((await verify(imported,verifyArgs(v))).receipt.receiptDigest,r.receiptDigest);
});

test('35AA replaying exact pinned receipt as current is rejected',async t=>{
 const v=await setup(t),a=await synthetic(v,'alice',[h('A')]);
 await reject(reconcile(recArgs(v,[a],[a])),'LOCAL_REVIEW_OBSERVER_REPLAYED_RECEIPT');
});
test('35AA duplicate current observer receipt cannot masquerade as two attestations',async t=>{
 const v=await setup(t),a=await synthetic(v,'alice',[h('A')]),b=await synthetic(v,'bob',[h('A')]);
 await reject(reconcile(recArgs(v,[b,b],[a])),'LOCAL_REVIEW_OBSERVER_REPLAYED_RECEIPT');
});
