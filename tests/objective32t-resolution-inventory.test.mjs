import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {offlineConflictRecoveryReceiptGenesisHead} from '../src/offline-conflict-exchange-recovery-receipts.mjs';
import {offlineConflictExchangeRecoveryReviewerPolicyDigest} from '../src/offline-conflict-exchange-recovery.mjs';
import {OFFLINE_CONFLICT_RECOVERY_POLICY_EPOCH_SCHEMA,offlineConflictRecoveryPolicyEpochGenesisDigest,
 offlineConflictRecoveryPolicyTransitionBytes,offlineConflictRecoveryPolicyTransitionDigest} from '../src/offline-conflict-recovery-policy-epochs.mjs';
import {OFFLINE_CONFLICT_RECOVERY_CUTOVER_SCHEMA,offlineConflictRecoveryCutoverDigest} from '../src/offline-conflict-recovery-policy-cutover.mjs';
import {OFFLINE_CONFLICT_CUTOVER_ADJUDICATION_SCHEMA,offlineConflictCutoverAdjudicationBytes,
 offlineConflictCutoverAdjudicationDigest} from '../src/offline-conflict-recovery-cutover-adjudication.mjs';
import {OFFLINE_CONFLICT_CUTOVER_RESOLUTION_PROOF_SCHEMA,offlineConflictCutoverResolutionProofDigest} from '../src/offline-conflict-cutover-resolution-proof.mjs';
import {OFFLINE_CONFLICT_RESOLUTION_INVENTORY_SCHEMA,OFFLINE_CONFLICT_RESOLUTION_UNION_SCHEMA,
 offlineConflictResolutionInventoryDigest,offlineConflictResolutionUnionDigest,
 verifyOfflineConflictResolutionInventories} from '../src/offline-conflict-resolution-inventory.mjs';

const sha=b=>createHash('sha256').update(b).digest('hex');
const now=1792200000000;
const signers=(seed,role)=>[1,2,3].map(i=>({reviewerId:`${role}_review_${seed}_${i}`,...generateKeyPairSync('ed25519')}));
const pub=g=>g.map(x=>({reviewerId:x.reviewerId,publicKey:x.publicKey.export({format:'pem',type:'spki'})}));
const policy=g=>offlineConflictExchangeRecoveryReviewerPolicyDigest(pub(g));
const signatures=(body,g,fn)=>g.slice(0,2).map(k=>({reviewerId:k.reviewerId,signature:sign(null,fn(body),k.privateKey).toString('base64url')}));
const signerCache=new Map();
function fixture(seed,action='abort'){
 if(!signerCache.has(seed))signerCache.set(seed,{old:signers(seed,'old'),next:signers(seed,'next')});
 const genesisExchangeDigest=sha('32t-'+seed),{old,next}=signerCache.get(seed);
 const receiptHead=offlineConflictRecoveryReceiptGenesisHead(genesisExchangeDigest);
 const transitionBody={schema:OFFLINE_CONFLICT_RECOVERY_POLICY_EPOCH_SCHEMA,sequence:1,
  previousTransitionDigest:offlineConflictRecoveryPolicyEpochGenesisDigest({genesisExchangeDigest,initialPolicyDigest:policy(old)}),
  genesisExchangeDigest,fromPolicyDigest:policy(old),toPolicyDigest:policy(next),receiptHead,
  issuedAt:now-1000,expiresAt:now+30000,nonce:`epoch_nonce_${seed}_01`};
 const transition={body:transitionBody,outgoingSignatures:signatures(transitionBody,old,offlineConflictRecoveryPolicyTransitionBytes),
  incomingSignatures:signatures(transitionBody,next,offlineConflictRecoveryPolicyTransitionBytes)};
 const transitionHead={count:1,headDigest:offlineConflictRecoveryPolicyTransitionDigest({transition})};
 const history={genesisExchangeDigest,reviewerPolicies:[pub(old),pub(next)],transitions:[transition],segments:[[],[]],
  expectedTransitionHead:transitionHead,expectedFinalReceiptHead:receiptHead,expectedFinalPolicyDigest:policy(next),nowMs:now};
 const cutoverBody={schema:OFFLINE_CONFLICT_RECOVERY_CUTOVER_SCHEMA,genesisExchangeDigest,
  previousPolicyDigest:policy(old),activePolicyDigest:policy(next),transitionHead,receiptHead,activatedAt:now};
 const cutoverDigest=offlineConflictRecoveryCutoverDigest(cutoverBody);
 const cutoverMarker={...cutoverBody,cutoverDigest};
 const pending=Buffer.from(JSON.stringify(cutoverMarker)),pendingBytesDigest=sha(pending);
 const exchangeJournalHead={count:0,headDigest:sha('journal-'+seed)};
 const body={schema:OFFLINE_CONFLICT_CUTOVER_ADJUDICATION_SCHEMA,action,genesisExchangeDigest,
  cutoverDigest,pendingBytesDigest,previousPolicyDigest:policy(old),activePolicyDigest:policy(next),
  exchangeJournalHead,receiptHead,issuedAt:now-500,expiresAt:now+10000,nonce:`resolution_nonce_${seed}_${action}`};
 const decision={body,outgoingSignatures:signatures(body,old,offlineConflictCutoverAdjudicationBytes),
  incomingSignatures:signatures(body,next,offlineConflictCutoverAdjudicationBytes)};
 const decisionDigest=offlineConflictCutoverAdjudicationDigest(decision);
 const receiptBody={schema:'TJ-OFFLINE-CONFLICT-CUTOVER-RESOLUTION-1',action,genesisExchangeDigest,
  cutoverDigest,pendingBytesDigest,decisionDigest,resolvedAt:now};
 const resolutionReceipt={...receiptBody,receiptDigest:sha('TJ-32R-RESOLUTION-RECEIPT\0'+JSON.stringify(receiptBody))};
 const proof={schema:OFFLINE_CONFLICT_CUTOVER_RESOLUTION_PROOF_SCHEMA,history,cutoverMarker,
  pendingMarkerBase64url:pending.toString('base64url'),decision,resolutionReceipt};
 const pins={proofDigest:offlineConflictCutoverResolutionProofDigest(proof),decisionDigest,
  resolutionDigest:resolutionReceipt.receiptDigest,cutoverDigest,pendingBytesDigest,genesisExchangeDigest,
  transitionHead,receiptHead,finalPolicyDigest:policy(next),exchangeJournalHead};
 const entry={genesisExchangeDigest,cutoverDigest,resolutionDigest:pins.resolutionDigest,
  decisionDigest,proofDigest:pins.proofDigest,action};
 return {proof,pins,entry};
}
const f1=fixture('a'),f2=fixture('b');
const key=e=>[e.genesisExchangeDigest,e.cutoverDigest,e.resolutionDigest,e.decisionDigest,e.proofDigest,e.action].join(':');
const sorted=entries=>entries.sort((a,b)=>key(a)<key(b)?-1:key(a)>key(b)?1:0);
function build(entries=[f1,f2],ids=['observer_alpha','observer_beta']){
 const views=[],anchors=[];
 for(const observerId of ids){
  const ordered=sorted(entries.map(f=>f.entry));
  const manifest={schema:OFFLINE_CONFLICT_RESOLUTION_INVENTORY_SCHEMA,observerId,entries:structuredClone(ordered)};
  const lookup=new Map(entries.map(f=>[f.entry.proofDigest,f]));
  views.push({manifest,proofs:ordered.map(e=>({proof:structuredClone(lookup.get(e.proofDigest).proof)}))});
  anchors.push({observerId,inventoryDigest:offlineConflictResolutionInventoryDigest(manifest),
   proofPins:ordered.map(e=>({proofDigest:e.proofDigest,pins:structuredClone(lookup.get(e.proofDigest).pins)}))});
 }
 const union={schema:OFFLINE_CONFLICT_RESOLUTION_UNION_SCHEMA,entries:structuredClone(sorted(entries.map(f=>f.entry)))};
 return {views,anchors,expectedObserverIds:[...ids].sort(),expectedUnionDigest:offlineConflictResolutionUnionDigest(union),nowMs:now+100000};
}
const audit=f=>verifyOfflineConflictResolutionInventories(f);
const reject=(f,code)=>assert.throws(()=>audit(f),e=>e?.code===code);
const t=(name,fn)=>test('32T '+name,fn);

t('two pinned observers independently verify two signed histories',()=>{
 const result=audit(build());assert.equal(result.verified,true);assert.equal(result.observerCount,2);
 assert.equal(result.authenticatedAttemptCount,2);assert.equal(result.authorizesProduction,false);
 assert.equal(result.independentlyPublished,false);assert.equal(result.globallyComplete,false);
});
t('three pinned observers reconcile without granting production authority',()=>{
 const result=audit(build([f1,f2],['observer_alpha','observer_beta','observer_gamma']));
 assert.equal(result.observerCount,3);assert.equal(result.locallyCompleted,false);
});
t('single signed history across observers is valid',()=>assert.equal(audit(build([f1])).authenticatedAttemptCount,1));
t('absent independent union pin fails closed',()=>{const f=build();delete f.expectedUnionDigest;reject(f,'EXCHANGE32T_EXTERNAL_PINS_REQUIRED');});
t('absent independently pinned observer rejected',()=>{const f=build();f.anchors.pop();reject(f,'EXCHANGE32T_EXTERNAL_PINS_REQUIRED');});
t('duplicate observer identity rejected',()=>{const f=build();f.views[1].manifest.observerId='observer_alpha';reject(f,'EXCHANGE32T_OBSERVER_UNTRUSTED');});
t('duplicate anchor identity rejected',()=>{const f=build();f.anchors[1].observerId='observer_alpha';reject(f,'EXCHANGE32T_EXTERNAL_PINS_REQUIRED');});
t('single observer is insufficient for cross-observer reconciliation',()=>{const f=build([f1],['observer_alpha']);reject(f,'EXCHANGE32T_EXTERNAL_PINS_REQUIRED');});
t('tampered manifest rejected by independently pinned digest',()=>{const f=build();f.views[0].manifest.entries[0].action='finalize';reject(f,'EXCHANGE32T_INVENTORY_PIN_MISMATCH');});
t('omitted evidence without repinning rejected',()=>{const f=build();f.views[0].proofs.pop();reject(f,'EXCHANGE32T_EVIDENCE_OMITTED');});
t('omitted manifest entry with matching compromised inventory pin still rejected',()=>{
 const f=build();f.views[0].manifest.entries.pop();f.views[0].proofs.pop();f.anchors[0].proofPins.pop();
 f.anchors[0].inventoryDigest=offlineConflictResolutionInventoryDigest(f.views[0].manifest);
 reject(f,'EXCHANGE32T_OBSERVER_OMISSION');
});
t('both observers omit same history but independent union pin catches rollback',()=>{
 const f=build();for(let i=0;i<2;i++){
  f.views[i].manifest.entries.pop();f.views[i].proofs.pop();f.anchors[i].proofPins.pop();
  f.anchors[i].inventoryDigest=offlineConflictResolutionInventoryDigest(f.views[i].manifest);
 }reject(f,'EXCHANGE32T_UNION_PIN_MISMATCH');
});
t('two fully signed opposing actions for same cutover detect equivocation',()=>{
 const opposing=fixture('a','finalize'),f=build([f1]);
 f.views[1]=build([opposing]).views[1];f.anchors[1]=build([opposing]).anchors[1];
 reject(f,'EXCHANGE32T_EQUIVOCATION');
});
t('two signed receipts with distinct valid signatures for same genesis detect fork',()=>{
 const opposing=fixture('a','finalize'),f=build([f1]);
 const other=build([opposing]);f.views[1]=other.views[1];f.anchors[1]=other.anchors[1];
 reject(f,'EXCHANGE32T_EQUIVOCATION');
});
t('replaced proof body fails despite unchanged manifest',()=>{const f=build();f.views[0].proofs[0].proof.resolutionReceipt.resolvedAt++;
 reject(f,'EXCHANGE32S_PROOF_PIN_MISMATCH');});
t('forged signature fails even with re-pinned manifest, proof and union',()=>{
 const forgery=structuredClone(f1);forgery.proof.decision.incomingSignatures[0].signature='A'.repeat(86);
 const decisionDigest=offlineConflictCutoverAdjudicationDigest(forgery.proof.decision);
 forgery.proof.resolutionReceipt.decisionDigest=decisionDigest;
 const body={...forgery.proof.resolutionReceipt};delete body.receiptDigest;
 forgery.proof.resolutionReceipt.receiptDigest=sha('TJ-32R-RESOLUTION-RECEIPT\0'+JSON.stringify(body));
 forgery.pins.decisionDigest=decisionDigest;forgery.pins.resolutionDigest=forgery.proof.resolutionReceipt.receiptDigest;
 forgery.pins.proofDigest=offlineConflictCutoverResolutionProofDigest(forgery.proof);
 forgery.entry.decisionDigest=decisionDigest;forgery.entry.resolutionDigest=forgery.pins.resolutionDigest;
 forgery.entry.proofDigest=forgery.pins.proofDigest;
 const f=build([forgery]);reject(f,'EXCHANGE32R_SIGNATURE_INVALID');
});
t('external proof pin substitution rejected',()=>{const f=build();f.anchors[0].proofPins[0].pins.resolutionDigest=sha('substitution');
 reject(f,'EXCHANGE32T_EVIDENCE_PIN_MISMATCH');});
t('independently pinned union digest substitution rejected',()=>{const f=build();f.expectedUnionDigest=sha('wrong');
 reject(f,'EXCHANGE32T_UNION_PIN_MISMATCH');});
t('missing one externally supplied proof pin rejected',()=>{const f=build();f.anchors[0].proofPins.pop();reject(f,'EXCHANGE32T_EVIDENCE_OMITTED');});
t('untrusted observer id rejected',()=>{const f=build();f.views[0].manifest.observerId='intruder_001';reject(f,'EXCHANGE32T_OBSERVER_UNTRUSTED');});
t('unsorted manifest rejected even with rewritten inventory digest',()=>{const f=build();f.views[0].manifest.entries.reverse();
 assert.throws(()=>offlineConflictResolutionInventoryDigest(f.views[0].manifest),e=>e?.code==='EXCHANGE32T_DUPLICATE_OR_UNSORTED');});
t('duplicate genesis entry rejected',()=>{const f=build();f.views[0].manifest.entries.push(structuredClone(f.views[0].manifest.entries[0]));
 assert.throws(()=>offlineConflictResolutionInventoryDigest(f.views[0].manifest),e=>e?.code==='EXCHANGE32T_DUPLICATE_OR_UNSORTED');});
t('unexpected productionApproved manifest field rejected',()=>{const f=build();f.views[0].manifest.productionApproved=true;
 reject(f,'EXCHANGE32T_INVENTORY_INVALID');});
t('unexpected productionApproved entry field rejected',()=>{const f=build();f.views[0].manifest.entries[0].productionApproved=true;
 reject(f,'EXCHANGE32T_INVENTORY_INVALID');});
t('extra proof body is rejected rather than silently ignored',()=>{const f=build();f.views[0].proofs.push({proof:f1.proof});
 reject(f,'EXCHANGE32T_EVIDENCE_OMITTED');});
t('missing 32S signed history fails closed',()=>{const f=build();f.views[0].proofs[0].proof.history.transitions=[];
 reject(f,'EXCHANGE32S_PROOF_PIN_MISMATCH');});
t('empty union is rejected',()=>assert.throws(()=>offlineConflictResolutionUnionDigest({schema:OFFLINE_CONFLICT_RESOLUTION_UNION_SCHEMA,entries:[]}),
 e=>e?.code==='EXCHANGE32T_INVENTORY_INVALID'));
t('oversized manifest inventory rejected',()=>{const f=build();f.views[0].manifest.entries=Array.from({length:33},()=>structuredClone(f1.entry));
 reject(f,'EXCHANGE32T_INVENTORY_INVALID');});
t('malformed digest rejected',()=>{const f=build();f.views[0].manifest.entries[0].proofDigest='not-a-hash';
 reject(f,'EXCHANGE32T_INVENTORY_INVALID');});
t('invalid clock rejected',()=>{const f=build();f.nowMs=NaN;reject(f,'EXCHANGE32T_EXTERNAL_PINS_REQUIRED');});
t('prototype pollution field rejected',()=>{const f=build();f.views[0].manifest.entries[0].__proto__={productionApproved:true};
 reject(f,'EXCHANGE32T_INVENTORY_INVALID');});
t('sparse proof array rejected',()=>{const f=build();delete f.views[0].proofs[0];reject(f,'EXCHANGE32T_INVENTORY_INVALID');});
t('array extra property rejected',()=>{const f=build();f.views[0].manifest.entries.productionApproved=true;
 reject(f,'EXCHANGE32T_INVENTORY_INVALID');});
t('getter on manifest entry rejected without invocation',()=>{const f=build();Object.defineProperty(f.views[0].manifest.entries[0],'action',{
 enumerable:true,get(){throw new Error('getter must not run');}});
 reject(f,'EXCHANGE32T_INVENTORY_INVALID');});

t('missing pinned observer roster rejected',()=>{const f=build();delete f.expectedObserverIds;
 reject(f,'EXCHANGE32T_EXTERNAL_PINS_REQUIRED');});
t('observer and anchor removal from a three-party view rejected by roster',()=>{
 const f=build([f1,f2],['observer_alpha','observer_beta','observer_gamma']);f.views.pop();f.anchors.pop();
 reject(f,'EXCHANGE32T_EXTERNAL_PINS_REQUIRED');});
t('reordered independent observer roster rejected',()=>{const f=build();f.expectedObserverIds.reverse();
 reject(f,'EXCHANGE32T_EXTERNAL_PINS_REQUIRED');});
t('unapproved observer substitution with fully repinned inventory rejected by roster',()=>{
 const f=build();f.views[1].manifest.observerId='observer_evil';f.anchors[1].observerId='observer_evil';
 f.anchors[1].inventoryDigest=offlineConflictResolutionInventoryDigest(f.views[1].manifest);
 reject(f,'EXCHANGE32T_OBSERVER_UNTRUSTED');});
t('read-only verifier does not mutate any supplied proof, pin or inventory',()=>{
 const f=build();const before=structuredClone(f);audit(f);assert.deepEqual(f,before);});
t('retrospectively expired signed evidence is valid only at its historical receipt time',()=>{
 const f=build();f.nowMs=now+10000000;assert.equal(audit(f).authenticatedAttemptsOnly,true);});
t('future proof receipt rejected against independent audit time',()=>{const f=build();f.nowMs=now-1;
 assert.throws(()=>audit(f),e=>typeof e?.code==='string'&&e.code.startsWith('EXCHANGE32S_'));});
t('duplicate proof pin in one observer trust set rejected',()=>{const f=build();f.anchors[0].proofPins.push(structuredClone(f.anchors[0].proofPins[0]));
 reject(f,'EXCHANGE32T_EXTERNAL_PINS_REQUIRED');});
t('extra unrecognized manifest proof field rejected',()=>{const f=build();f.views[0].proofs[0].isCompleted=true;
 reject(f,'EXCHANGE32T_EVIDENCE_PIN_MISMATCH');});

t('symbol-keyed hidden production claim rejected',()=>{const f=build();f.views[0].manifest[Symbol('productionApproved')]=true;
 reject(f,'EXCHANGE32T_INVENTORY_INVALID');});
t('non-string digest with custom coercion rejected without calling coercion',()=>{
 const f=build();f.views[0].manifest.entries[0].proofDigest={toString(){throw Error('coercion');}};
 reject(f,'EXCHANGE32T_INVENTORY_INVALID');});
t('non-string pinned observer identifier rejected',()=>{const f=build();f.expectedObserverIds[0]={toString(){throw Error('coercion');}};
 reject(f,'EXCHANGE32T_EXTERNAL_PINS_REQUIRED');});
