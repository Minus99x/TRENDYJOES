import test,{before,after} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,readFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {fixturePack} from './support/objective32w-fixture.mjs';
import {createOfflineConflictManifestJournal,offlineConflictManifestJournalGenesisHead} from '../src/offline-conflict-resolution-manifest-journal.mjs';
import {offlineConflictExchangeRecoveryReviewerPolicyDigest} from '../src/offline-conflict-exchange-recovery.mjs';
import {OFFLINE_CONFLICT_MANIFEST_CLAIM_ADJUDICATION_SCHEMA,offlineConflictManifestClaimDecisionBytes,offlineConflictManifestClaimDecisionDigest} from '../src/offline-conflict-manifest-claim-adjudication.mjs';
import {calculateOfflineConflictManifestClaimContinuity} from '../src/offline-conflict-manifest-claim-continuity.mjs';
import {calculateOfflineConflictManifestMultiClaimInventory as calc,
 verifyOfflineConflictManifestMultiClaimInventory as verify,
 calculateOfflineConflictManifestMultiClaimReconciliation as reconcileCandidate,
 verifyOfflineConflictManifestMultiClaimReconciliation as reconcile,
 OFFLINE_CONFLICT_MULTI_CLAIM_MAX_CLAIMS,OFFLINE_CONFLICT_MULTI_CLAIM_MAX_OBSERVERS} from '../src/offline-conflict-manifest-multi-claim-inventory.mjs';
const sha=x=>createHash('sha256').update(x).digest('hex');
const err=code=>e=>e?.code===code;
const now=1792280000000,scope=sha('externally designated journal scope 33a');
const a=[1,2,3].map(i=>({reviewerId:`alpha33a_reviewer_${i}`,...generateKeyPairSync('ed25519')}));
const b=[1,2,3].map(i=>({reviewerId:`bravo33a_reviewer_${i}`,...generateKeyPairSync('ed25519')}));
const pub=g=>g.map(({reviewerId,publicKey})=>({reviewerId,publicKey}));
const policy=g=>offlineConflictExchangeRecoveryReviewerPolicyDigest(pub(g));
const signed=(body,g)=>g.slice(0,2).map(k=>({reviewerId:k.reviewerId,signature:sign(null,offlineConflictManifestClaimDecisionBytes(body),k.privateKey).toString('base64url')}));
const t=(name,fn)=>test('33A '+name,fn);
let root,c1,c2,fork,extended;
async function makeClaim(label,prior=false){
 const dir=join(root,label);let head=offlineConflictManifestJournalGenesisHead();
 if(prior){const r=await createOfflineConflictManifestJournal({directory:dir}).claim({
  verificationArgs:fixturePack(`session_33a_prior_${label}_0001`,2048,'a'),expectedHead:head});
  head={count:r.count,headDigest:r.headDigest};}
 const j=createOfflineConflictManifestJournal({directory:dir,injectFault:stage=>{
  if(stage==='after-pending-sync')throw Error('simulated crash');}});
 await assert.rejects(j.claim({verificationArgs:fixturePack(`session_33a_pending_${label}_0002`,2048,prior?'b':'a'),expectedHead:head}),/simulated crash/);
 const pending=await readFile(join(dir,'.pending.json')),record=JSON.parse(pending);
 const inspector=createOfflineConflictManifestJournal({directory:dir});
 async function makeEntry(i){
  const body={schema:OFFLINE_CONFLICT_MANIFEST_CLAIM_ADJUDICATION_SCHEMA,action:'inspect-only',journalHead:head,
   pendingBytesDigest:sha(pending),pendingRecordDigest:record.recordDigest,pendingIndex:head.count+1,
   expectedPendingState:'pending-only',reviewerGroupADigest:policy(a),reviewerGroupBDigest:policy(b),
   issuedAt:now-1000,expiresAt:now+10000,nonce:`nonce33a_${label}_${String(i).padStart(4,'0')}`};
  const decision={body,groupASignatures:signed(body,a),groupBSignatures:signed(body,b)};
  const args={decision,reviewerGroupA:pub(a),reviewerGroupB:pub(b),
   expectedDecisionDigest:offlineConflictManifestClaimDecisionDigest(decision),
   expectedReviewerGroupADigest:policy(a),expectedReviewerGroupBDigest:policy(b),
   expectedHead:head,expectedPendingBytesDigest:sha(pending),nowMs:now+i};
  const out=await inspector.exportInterruptedClaimTranscriptReadOnly(args);
  const {nowMs:discard,...pins}=args;
  return {...pins,bytes:out.bytes,expectedTranscriptDigest:out.transcriptDigest,expectedSnapshotDigest:out.snapshotDigest};
 }
 const entries=[await makeEntry(1)];
 return {entries,expectedHead:calculateOfflineConflictManifestClaimContinuity({entries}).head,makeEntry};
}
const compact=c=>({entries:c.entries,expectedHead:c.expectedHead});
const inventory=claims=>({journalScopeDigest:scope,claims});
const pinned=claims=>({...inventory(claims),expectedJournalScopeDigest:scope,
 expectedInventoryDigest:calc(inventory(claims)).inventoryDigest,expectedClaimCount:claims.length});
const observer=(observerId,claims)=>({observerId,claims,expectedInventoryDigest:calc(inventory(claims)).inventoryDigest,
 expectedClaimCount:claims.length});
const recArgs=observations=>({journalScopeDigest:scope,observations});
const recPins=observations=>({...recArgs(observations),expectedJournalScopeDigest:scope,
 expectedReconciliationDigest:reconcileCandidate(recArgs(observations)).reconciliationDigest,
 expectedObserverCount:observations.length});
before(async()=>{
 root=await mkdtemp(join(tmpdir(),'trendy33a-'));
 c1=await makeClaim('claimone');c2=await makeClaim('claimtwo',true);
 fork=await makeClaim('forksame');
 const entries=[...c1.entries,await c1.makeEntry(2)];
 extended={entries,expectedHead:calculateOfflineConflictManifestClaimContinuity({entries}).head};
});
after(async()=>{if(root)await rm(root,{recursive:true,force:true});});
t('two distinct signed claims with separate predecessor slots verify',()=>{
 const r=verify(pinned([compact(c1),compact(c2)]));assert.equal(r.verified,true);assert.equal(r.claimCount,2);
 assert.equal(r.authorizesRepair,false);assert.equal(r.authorizesProduction,false);assert.equal(r.independentlyWitnessed,false);
});
t('canonical inventory digest independent of claim ordering',()=>{
 assert.equal(calc(inventory([compact(c1),compact(c2)])).inventoryDigest,
  calc(inventory([compact(c2),compact(c1)])).inventoryDigest);
});
t('single claim inventory verifies',()=>assert.equal(verify(pinned([compact(c1)])).claimCount,1));
t('two independent matching observer inventories reconcile',()=>{
 const r=reconcile(recPins([observer('observer_A_33a',[compact(c1),compact(c2)]),
  observer('observer_B_33a',[compact(c2),compact(c1)])]));
 assert.equal(r.verified,true);assert.equal(r.observerCount,2);assert.equal(r.authorizesCheckout,false);
});
t('observer ordering canonicalizes reconciliation',()=>{
 const a=observer('observer_A_33a',[compact(c1)]),b=observer('observer_B_33a',[compact(c1)]);
 assert.equal(reconcileCandidate(recArgs([a,b])).reconciliationDigest,
  reconcileCandidate(recArgs([b,a])).reconciliationDigest);
});
t('missing inventory pin rejected',()=>assert.throws(()=>verify({...pinned([compact(c1)]),expectedInventoryDigest:undefined}),err('EXCHANGE33A_EXTERNAL_PINS_REQUIRED')));
t('missing scope pin rejected',()=>assert.throws(()=>verify({...pinned([compact(c1)]),expectedJournalScopeDigest:undefined}),err('EXCHANGE33A_EXTERNAL_PINS_REQUIRED')));
t('missing count pin rejected',()=>assert.throws(()=>verify({...pinned([compact(c1)]),expectedClaimCount:undefined}),err('EXCHANGE33A_EXTERNAL_PINS_REQUIRED')));
t('independent wrong scope pin rejected',()=>assert.throws(()=>verify({...pinned([compact(c1)]),expectedJournalScopeDigest:sha('different')}),err('EXCHANGE33A_INVENTORY_PIN_MISMATCH')));
t('wrong inventory pin rejected',()=>assert.throws(()=>verify({...pinned([compact(c1)]),expectedInventoryDigest:sha('wrong')}),err('EXCHANGE33A_INVENTORY_PIN_MISMATCH')));
t('wrong claim count rejected',()=>assert.throws(()=>verify({...pinned([compact(c1)]),expectedClaimCount:2}),err('EXCHANGE33A_INVENTORY_PIN_MISMATCH')));
t('omitting a claim cannot satisfy retained full inventory pin',()=>{
 const full=pinned([compact(c1),compact(c2)]);
 assert.throws(()=>verify({...full,claims:[compact(c1)]}),err('EXCHANGE33A_INVENTORY_PIN_MISMATCH'));
});
t('same predecessor slot with different pending record is a cross-claim fork',()=>{
 assert.throws(()=>calc(inventory([compact(c1),compact(fork)])),err('EXCHANGE33A_CROSS_CLAIM_FORK'));
});
t('duplicate same claim rejected',()=>assert.throws(()=>calc(inventory([compact(c1),compact(c1)])),err('EXCHANGE33A_DUPLICATE_CLAIM')));
t('same claim alternate continuation with same slot rejected',()=>{
 assert.throws(()=>calc(inventory([compact(c1),extended])),err('EXCHANGE33A_DUPLICATE_CLAIM'));
});
t('observer omitted one claim is detected',()=>{
 const obs=[observer('observer_A_33a',[compact(c1),compact(c2)]),observer('observer_B_33a',[compact(c1)])];
 assert.throws(()=>reconcileCandidate(recArgs(obs)),err('EXCHANGE33A_OBSERVER_OMISSION_OR_FORK'));
});
t('concurrent snapshots with different pinned head fail closed, no guessed ordering',()=>{
 const obs=[observer('observer_A_33a',[compact(c1)]),observer('observer_B_33a',[extended])];
 assert.throws(()=>reconcileCandidate(recArgs(obs)),err('EXCHANGE33A_OBSERVER_EQUIVOCATION'));
});
t('two observers with different valid claims at same slot fail as omitted or forked',()=>{
 const obs=[observer('observer_A_33a',[compact(c1)]),observer('observer_B_33a',[compact(fork)])];
 assert.throws(()=>reconcileCandidate(recArgs(obs)),err('EXCHANGE33A_OBSERVER_OMISSION_OR_FORK'));
});
t('replayed observer identity rejected',()=>{
 const o=observer('observer_A_33a',[compact(c1)]);
 assert.throws(()=>reconcileCandidate(recArgs([o,o])),err('EXCHANGE33A_OBSERVER_INVALID'));
});
t('missing external reconciliation pin rejected',()=>{
 const observations=[observer('observer_A_33a',[compact(c1)]),observer('observer_B_33a',[compact(c1)])];
 assert.throws(()=>reconcile({...recPins(observations),expectedReconciliationDigest:undefined}),err('EXCHANGE33A_EXTERNAL_RECONCILIATION_PINS_REQUIRED'));
});
t('wrong external reconciliation pin rejected',()=>{
 const observations=[observer('observer_A_33a',[compact(c1)]),observer('observer_B_33a',[compact(c1)])];
 assert.throws(()=>reconcile({...recPins(observations),expectedReconciliationDigest:sha('wrong')}),err('EXCHANGE33A_RECONCILIATION_PIN_MISMATCH'));
});
t('missing observer count pin rejected',()=>{
 const observations=[observer('observer_A_33a',[compact(c1)]),observer('observer_B_33a',[compact(c1)])];
 assert.throws(()=>reconcile({...recPins(observations),expectedObserverCount:undefined}),err('EXCHANGE33A_EXTERNAL_RECONCILIATION_PINS_REQUIRED'));
});
t('tampered observer inventory digest rejected even if both claim sets match',()=>{
 const obs=[observer('observer_A_33a',[compact(c1)]),observer('observer_B_33a',[compact(c1)])];
 obs[1]={...obs[1],expectedInventoryDigest:sha('tamper')};
 assert.throws(()=>reconcileCandidate(recArgs(obs)),err('EXCHANGE33A_INVENTORY_PIN_MISMATCH'));
});
t('forged signature in a claim is reverified, not trusted from a digest',()=>{
 const entry=c1.entries[0],decision=structuredClone(entry.decision),old=decision.groupASignatures[0].signature;
 decision.groupASignatures[0].signature=(old[0]==='A'?'B':'A')+old.slice(1);
 const changed={...compact(c1),entries:[{...entry,decision}]};
 assert.throws(()=>calc(inventory([changed])));
});
t('substituted transcript pin fails even with retained continuity head',()=>{
 const entry=c1.entries[0],changed={...compact(c1),entries:[{...entry,expectedTranscriptDigest:sha('wrong')}]};
 assert.throws(()=>calc(inventory([changed])),err('EXCHANGE32Y_TRANSCRIPT_PIN_MISMATCH'));
});
t('forked 32Z checkpoint rejected before inventory',()=>{
 const changed={...compact(c1),expectedHead:{count:1,headDigest:sha('fake')}};
 assert.throws(()=>calc(inventory([changed])),err('EXCHANGE32Z_CHECKPOINT_MISMATCH'));
});
t('claim input extra authorization field rejected',()=>{
 assert.throws(()=>calc(inventory([{...compact(c1),authorizesProduction:true}])),err('EXCHANGE33A_CLAIM_INVALID'));
});
t('observer extra authorization field rejected',()=>{
 const o=observer('observer_A_33a',[compact(c1)]);
 assert.throws(()=>reconcileCandidate(recArgs([o,{...o,observerId:'observer_B_33a',authorizesRepair:true}])),err('EXCHANGE33A_OBSERVER_INVALID'));
});
t('claim array with holes rejected',()=>{
 assert.throws(()=>calc(inventory([compact(c1),,compact(c2)])),err('EXCHANGE33A_INVENTORY_INVALID'));
});
t('claim array with custom enumerable metadata rejected',()=>{
 const claims=[compact(c1)];claims.productionApproved=true;
 assert.throws(()=>calc(inventory(claims)),err('EXCHANGE33A_INVENTORY_INVALID'));
});
t('claim array with accessor entry rejected before getter runs',()=>{
 const claims=[compact(c1)];Object.defineProperty(claims,'0',{get(){throw Error('getter executed');},enumerable:true});
 assert.throws(()=>calc(inventory(claims)),err('EXCHANGE33A_INVENTORY_INVALID'));
});
t('null scope rejected',()=>assert.throws(()=>calc({journalScopeDigest:null,claims:[compact(c1)]}),err('EXCHANGE33A_INVENTORY_INVALID')));
t('nonhex scope rejected',()=>assert.throws(()=>calc({journalScopeDigest:'not-hex',claims:[compact(c1)]}),err('EXCHANGE33A_INVENTORY_INVALID')));
t('empty inventory rejected',()=>assert.throws(()=>calc(inventory([])),err('EXCHANGE33A_INVENTORY_INVALID')));
t('overlimit claim inventory rejected before crypto verification',()=>{
 assert.throws(()=>calc(inventory(Array(OFFLINE_CONFLICT_MULTI_CLAIM_MAX_CLAIMS+1).fill(compact(c1)))),err('EXCHANGE33A_INVENTORY_INVALID'));
});
t('observer list too short rejected',()=>{
 assert.throws(()=>reconcileCandidate(recArgs([observer('observer_A_33a',[compact(c1)])])),err('EXCHANGE33A_OBSERVATIONS_INVALID'));
});
t('observer list too long rejected',()=>{
 const obs=Array.from({length:OFFLINE_CONFLICT_MULTI_CLAIM_MAX_OBSERVERS+1},(_,i)=>observer(`observer_${i}_33a`,[compact(c1)]));
 assert.throws(()=>reconcileCandidate(recArgs(obs)),err('EXCHANGE33A_OBSERVATIONS_INVALID'));
});
t('malformed observer identity rejected',()=>{
 const obs=[observer('short',[compact(c1)]),observer('observer_B_33a',[compact(c1)])];
 assert.throws(()=>reconcileCandidate(recArgs(obs)),err('EXCHANGE33A_OBSERVER_INVALID'));
});
t('reconciliation observation list with holes rejected',()=>{
 const obs=[observer('observer_A_33a',[compact(c1)]),,observer('observer_B_33a',[compact(c1)])];
 assert.throws(()=>reconcileCandidate(recArgs(obs)),err('EXCHANGE33A_OBSERVATIONS_INVALID'));
});
t('candidate digest is not a claim of external witness',()=>{
 const r=calc(inventory([compact(c1)]));assert.equal(r.independentlyWitnessed,false);assert.equal(r.authorizesRepair,false);
 const o=observer('observer_A_33a',[compact(c1)]),p=observer('observer_B_33a',[compact(c1)]);
 assert.equal(reconcileCandidate(recArgs([o,p])).independentlyWitnessed,false);
});
