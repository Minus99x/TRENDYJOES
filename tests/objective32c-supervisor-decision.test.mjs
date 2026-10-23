import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {OFFLINE_PINNED_ORPHAN_REPORT_SCHEMA} from '../src/offline-pinned-orphan-classifier.mjs';
import {
 OFFLINE_ORPHAN_SUPERVISOR_DECISION_SCHEMA,offlineOrphanSupervisorPolicyDigest,
 offlineOrphanReportIssueDigest,offlineOrphanSupervisorDecisionSigningBytes,
 encodeOfflineOrphanReplaySnapshot,verifyOfflineOrphanSupervisorDecision
} from '../src/offline-orphan-supervisor-decision.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex');
const ROOT='0'.repeat(64),registryId='orphan_registry_32c',nowMs=1800000000000;
const keys=[0,1,2].map(i=>({id:`reviewer_32c_${i}`, ...generateKeyPairSync('ed25519')}));
const reviewers=keys.map(k=>({id:k.id,publicKey:k.publicKey})),quorum=2;
const reviewerPolicyDigest=offlineOrphanSupervisorPolicyDigest({reviewers,quorum});
const reject=(f,code)=>assert.throws(f,e=>e?.code===code,code);
const clone=x=>structuredClone(x);
function reportOf({anomalies=true}={}){
 const evidence=[{directoryIndex:0,name:'archive.tjexport',nameDigest:sha('archive.tjexport'),classification:'SIGNED_ARCHIVE',digest:sha('archive'),bytes:123},
  ...(anomalies?[{directoryIndex:1,name:'untracked.tjexport',nameDigest:sha('untracked.tjexport'),classification:'UNTRACKED_ARCHIVE_UNVERIFIED',digest:sha('untrusted'),bytes:8}]:[])];
 const body={schema:OFFLINE_PINNED_ORPHAN_REPORT_SCHEMA,registryId,manifestDigest:sha('manifest'),head:{count:1,headDigest:sha('head')},epoch:0,
  transitionDigest:ROOT,recordsDigest:sha('records'),evidence,status:anomalies?'SUPERVISORY_REVIEW_REQUIRED':'NO_ANOMALIES_OBSERVED',
  issueCount:anomalies?1:0,supervisoryDisposition:'EXTERNAL_DECISION_REQUIRED_FOR_ANY_REMEDIATION',readOnly:true,
  productionApproved:false,mayDelete:false,mayRepair:false,mayManufacture:false,mayAcknowledge:false};
 return {...body,reportDigest:sha(Buffer.from(`${OFFLINE_PINNED_ORPHAN_REPORT_SCHEMA}\0${JSON.stringify(body)}`))};
}
function pinsFor(r){return {reportDigest:r.reportDigest,manifestDigest:r.manifestDigest,head:r.head,epoch:r.epoch,transitionDigest:r.transitionDigest,recordsDigest:r.recordsDigest};}
function fixture({anomalies=true}={}){
 const report=reportOf({anomalies}),expectedPins=pinsFor(report);
 const replayBytes=encodeOfflineOrphanReplaySnapshot({registryId,consumed:[]}),expectedReplayDigest=sha(replayBytes);
 const body={schema:OFFLINE_ORPHAN_SUPERVISOR_DECISION_SCHEMA,registryId,reportDigest:report.reportDigest,manifestDigest:report.manifestDigest,
  head:report.head,epoch:report.epoch,transitionDigest:report.transitionDigest,recordsDigest:report.recordsDigest,
  issueDigest:offlineOrphanReportIssueDigest(report),issueCount:report.issueCount,
  disposition:anomalies?'REQUIRE_INDEPENDENT_REVIEW':'NO_ANOMALIES_REVIEWED',decisionId:'decision_32c_0001',nonce:'nonce_32c_0001',
  issuedAt:nowMs-1000,expiresAt:nowMs+60000,replayDigest:expectedReplayDigest,reviewerPolicyDigest};
 const decision={body,signatures:[]};
 const signBody=()=>{decision.signatures=keys.slice(0,2).map(k=>({reviewerId:k.id,signature:sign(null,offlineOrphanSupervisorDecisionSigningBytes(body),k.privateKey).toString('base64url')}));};
 signBody();
 const args={report,expectedPins,decision,reviewers,quorum,expectedReviewerPolicyDigest:reviewerPolicyDigest,replayBytes,expectedReplayDigest,nowMs};
 const run=(changes={})=>verifyOfflineOrphanSupervisorDecision({...args,...changes});
 return {args,run,signBody};
}
const safe=r=>{assert.equal(r.signatureVerified,true);assert.equal(r.readOnly,true);assert.equal(r.authorizesRemediation,false);assert.equal(r.mayRepair,false);assert.equal(r.mayDelete,false);assert.equal(r.mayManufacture,false);assert.equal(r.mayAcknowledge,false);assert.equal(r.productionApproved,false);assert.equal(r.requiresIndependentAtomicReplayCommit,true);assert.equal(Object.isFrozen(r),true);};

test('32C genuine quorum verifies pinned anomaly report but grants no authority',()=>{const x=fixture(),r=x.run();safe(r);assert.equal(r.issueCount,1);assert.equal(r.disposition,'REQUIRE_INDEPENDENT_REVIEW');});
test('32C clean report can be marked reviewed without granting authority',()=>{const x=fixture({anomalies:false}),r=x.run();safe(r);assert.equal(r.issueCount,0);assert.equal(r.disposition,'NO_ANOMALIES_REVIEWED');});
test('32C deterministic signatures and result for identical immutable evidence',()=>{const x=fixture();assert.deepEqual(x.run(),x.run());});
test('32C independently pinned report digest cannot be replaced',()=>{const x=fixture();reject(()=>x.run({expectedPins:{...x.args.expectedPins,reportDigest:sha('forged')}}),'SUPERVISOR_REPORT_PIN_MISMATCH');});
test('32C independent manifest pin cannot be replaced',()=>{const x=fixture();reject(()=>x.run({expectedPins:{...x.args.expectedPins,manifestDigest:sha('wrong')}}),'SUPERVISOR_REPORT_PIN_MISMATCH');});
test('32C independent registry head pin cannot be replaced',()=>{const x=fixture();reject(()=>x.run({expectedPins:{...x.args.expectedPins,head:{count:1,headDigest:sha('other')}}}),'SUPERVISOR_REPORT_PIN_MISMATCH');});
test('32C independent transition digest pin cannot be replaced',()=>{const x=fixture();reject(()=>x.run({expectedPins:{...x.args.expectedPins,transitionDigest:sha('other')}}),'SUPERVISOR_REPORT_PIN_MISMATCH');});
test('32C independent records digest pin cannot be replaced',()=>{const x=fixture();reject(()=>x.run({expectedPins:{...x.args.expectedPins,recordsDigest:sha('other')}}),'SUPERVISOR_REPORT_PIN_MISMATCH');});
test('32C independent epoch pin cannot be replaced',()=>{const x=fixture();reject(()=>x.run({expectedPins:{...x.args.expectedPins,epoch:1}}),'SUPERVISOR_REPORT_PIN_MISMATCH');});
test('32C altered orphan classification invalidates report digest',()=>{const x=fixture(),r=clone(x.args.report);r.evidence[1].classification='SIGNED_ARCHIVE';reject(()=>x.run({report:r}),'SUPERVISOR_REPORT_PIN_MISMATCH');});
test('32C altered orphan byte hash invalidates report digest',()=>{const x=fixture(),r=clone(x.args.report);r.evidence[1].digest=sha('altered');reject(()=>x.run({report:r}),'SUPERVISOR_REPORT_PIN_MISMATCH');});
test('32C altered directory index invalidates report digest',()=>{const x=fixture(),r=clone(x.args.report);r.evidence[1].directoryIndex=2;reject(()=>x.run({report:r}),'SUPERVISOR_REPORT_PIN_MISMATCH');});
test('32C fabricated unpinned report rejected',()=>{const x=fixture(),r=reportOf({anomalies:false});reject(()=>x.run({report:r}),'SUPERVISOR_REPORT_PIN_MISMATCH');});
test('32C duplicate report evidence entries rejected even if rehashed',()=>{const x=fixture(),r=clone(x.args.report);r.evidence.push(clone(r.evidence[1]));r.issueCount=2;const {reportDigest,...body}=r;r.reportDigest=sha(Buffer.from(`${OFFLINE_PINNED_ORPHAN_REPORT_SCHEMA}\0${JSON.stringify(body)}`));reject(()=>x.run({report:r,expectedPins:pinsFor(r)}),'SUPERVISOR_REPORT_DUPLICATE_ENTRY');});
test('32C forged report safety flag rejected even if rehashed',()=>{const x=fixture(),r=clone(x.args.report);r.mayRepair=true;const {reportDigest,...body}=r;r.reportDigest=sha(Buffer.from(`${OFFLINE_PINNED_ORPHAN_REPORT_SCHEMA}\0${JSON.stringify(body)}`));reject(()=>x.run({report:r,expectedPins:pinsFor(r)}),'SUPERVISOR_REPORT_INVALID');});
test('32C forged report anomaly count rejected even if rehashed',()=>{const x=fixture(),r=clone(x.args.report);r.issueCount=0;const {reportDigest,...body}=r;r.reportDigest=sha(Buffer.from(`${OFFLINE_PINNED_ORPHAN_REPORT_SCHEMA}\0${JSON.stringify(body)}`));reject(()=>x.run({report:r,expectedPins:pinsFor(r)}),'SUPERVISOR_REPORT_INVALID');});
test('32C report with extra field rejected',()=>{const x=fixture(),r={...x.args.report,checkoutAuthorized:true};reject(()=>x.run({report:r}),'SUPERVISOR_REPORT_INVALID');});
test('32C decision tampered report digest rejected',()=>{const x=fixture(),d=clone(x.args.decision);d.body.reportDigest=sha('other');reject(()=>x.run({decision:d}),'SUPERVISOR_DECISION_REPORT_MISMATCH');});
test('32C decision tampered issue digest rejected',()=>{const x=fixture(),d=clone(x.args.decision);d.body.issueDigest=sha('other');reject(()=>x.run({decision:d}),'SUPERVISOR_DECISION_REPORT_MISMATCH');});
test('32C decision tampered issue count rejected',()=>{const x=fixture(),d=clone(x.args.decision);d.body.issueCount=2;reject(()=>x.run({decision:d}),'SUPERVISOR_DECISION_REPORT_MISMATCH');});
test('32C decision tampered disposition cannot be accepted under old signature',()=>{const x=fixture(),d=clone(x.args.decision);d.body.disposition='REJECT_EVIDENCE';reject(()=>x.run({decision:d}),'SUPERVISOR_DECISION_SIGNATURE_INVALID');});
test('32C cannot claim no anomalies when signed report has issues',()=>{const x=fixture();x.args.decision.body.disposition='NO_ANOMALIES_REVIEWED';x.signBody();reject(()=>x.run(),'SUPERVISOR_DISPOSITION_INVALID');});
test('32C cannot require investigation when no issues',()=>{const x=fixture({anomalies:false});x.args.decision.body.disposition='REQUIRE_INDEPENDENT_REVIEW';x.signBody();reject(()=>x.run(),'SUPERVISOR_DISPOSITION_INVALID');});
test('32C no remediation action vocabulary accepted',()=>{const x=fixture();x.args.decision.body.disposition='DELETE_ORPHANS';reject(()=>x.run(),'SUPERVISOR_DECISION_INVALID');});
test('32C missing quorum rejected',()=>{const x=fixture(),d=clone(x.args.decision);d.signatures.pop();reject(()=>x.run({decision:d}),'SUPERVISOR_DECISION_QUORUM_INVALID');});
test('32C duplicate reviewer signature rejected',()=>{const x=fixture(),d=clone(x.args.decision);d.signatures[1]=d.signatures[0];reject(()=>x.run({decision:d}),'SUPERVISOR_DECISION_SIGNATURE_INVALID');});
test('32C unsorted reviewer signatures rejected',()=>{const x=fixture(),d=clone(x.args.decision);d.signatures.reverse();reject(()=>x.run({decision:d}),'SUPERVISOR_DECISION_SIGNATURE_INVALID');});
test('32C forged signature rejected',()=>{const x=fixture(),d=clone(x.args.decision);d.signatures[0].signature=sign(null,offlineOrphanSupervisorDecisionSigningBytes(d.body),keys[2].privateKey).toString('base64url');reject(()=>x.run({decision:d}),'SUPERVISOR_DECISION_SIGNATURE_INVALID');});
test('32C duplicate reviewer public key under another id rejected',()=>{const x=fixture(),r=[reviewers[0],{id:'reviewer_fake_32c',publicKey:reviewers[0].publicKey},reviewers[2]];reject(()=>x.run({reviewers:r}),'SUPERVISOR_POLICY_DUPLICATE_KEY');});
test('32C minority reviewer quorum rejected',()=>{const x=fixture();reject(()=>x.run({quorum:1}),'SUPERVISOR_POLICY_INVALID');});
test('32C reviewer input ordering does not alter canonical policy',()=>{const x=fixture();safe(x.run({reviewers:[reviewers[0],reviewers[2],reviewers[1]]}));});
test('32C substituted reviewer key rejected against external policy pin',()=>{const x=fixture(),alternate=generateKeyPairSync('ed25519').publicKey;reject(()=>x.run({reviewers:[reviewers[0],{id:reviewers[1].id,publicKey:alternate},reviewers[2]]}),'SUPERVISOR_EXTERNAL_REVIEWER_POLICY_PIN_REQUIRED');});
test('32C missing independently pinned supervisor policy rejected',()=>{const x=fixture();reject(()=>x.run({expectedReviewerPolicyDigest:undefined}),'SUPERVISOR_EXTERNAL_REVIEWER_POLICY_PIN_REQUIRED');});
test('32C forged alternate policy pin rejected',()=>{const x=fixture();reject(()=>x.run({expectedReviewerPolicyDigest:sha('other-policy')}),'SUPERVISOR_EXTERNAL_REVIEWER_POLICY_PIN_REQUIRED');});
test('32C future decision rejected',()=>{const x=fixture();reject(()=>x.run({nowMs:nowMs-2000}),'SUPERVISOR_DECISION_EXPIRED_OR_FUTURE');});
test('32C expiry boundary rejected',()=>{const x=fixture();reject(()=>x.run({nowMs:nowMs+60000}),'SUPERVISOR_DECISION_EXPIRED_OR_FUTURE');});
test('32C overlong decision validity rejected',()=>{const x=fixture();x.args.decision.body.expiresAt=nowMs+400000;reject(()=>x.run(),'SUPERVISOR_DECISION_INVALID');});
test('32C missing trusted clock rejected',()=>{const x=fixture();reject(()=>x.run({nowMs:undefined}),'SUPERVISOR_TRUSTED_TIME_REQUIRED');});
test('32C reused decision id rejected with independently pinned replay state',()=>{const x=fixture(),replayBytes=encodeOfflineOrphanReplaySnapshot({registryId,consumed:[{decisionId:x.args.decision.body.decisionId,nonce:'other_nonce_32c'}]});const digest=sha(replayBytes);x.args.decision.body.replayDigest=digest;x.signBody();reject(()=>x.run({replayBytes,expectedReplayDigest:digest}),'SUPERVISOR_DECISION_REPLAY');});
test('32C reused nonce under new decision id rejected',()=>{const x=fixture(),replayBytes=encodeOfflineOrphanReplaySnapshot({registryId,consumed:[{decisionId:'another_decision_32c',nonce:x.args.decision.body.nonce}]});const digest=sha(replayBytes);x.args.decision.body.replayDigest=digest;x.signBody();reject(()=>x.run({replayBytes,expectedReplayDigest:digest}),'SUPERVISOR_DECISION_REPLAY');});
test('32C replay snapshot rollback rejected against independently pinned digest',()=>{const x=fixture(),replayBytes=encodeOfflineOrphanReplaySnapshot({registryId,consumed:[{decisionId:'prior_decision_32c',nonce:'prior_nonce_32c'}]});reject(()=>x.run({replayBytes,expectedReplayDigest:x.args.expectedReplayDigest}),'SUPERVISOR_REPLAY_PIN_MISMATCH');});
test('32C stale signed replay anchor rejected after ledger advancement',()=>{const x=fixture(),replayBytes=encodeOfflineOrphanReplaySnapshot({registryId,consumed:[{decisionId:'prior_decision_32c',nonce:'prior_nonce_32c'}]});reject(()=>x.run({replayBytes,expectedReplayDigest:sha(replayBytes)}),'SUPERVISOR_REPLAY_PIN_MISMATCH');});
test('32C duplicate nonce in replay snapshot rejected',()=>reject(()=>encodeOfflineOrphanReplaySnapshot({registryId,consumed:[{decisionId:'decision_0001_32c',nonce:'nonce_32c_dup'},{decisionId:'decision_0002_32c',nonce:'nonce_32c_dup'}]}),'SUPERVISOR_REPLAY_SNAPSHOT_INVALID'));
test('32C unsorted replay snapshot rejected',()=>reject(()=>encodeOfflineOrphanReplaySnapshot({registryId,consumed:[{decisionId:'decision_0002_32c',nonce:'nonce_32c_a'},{decisionId:'decision_0001_32c',nonce:'nonce_32c_b'}]}),'SUPERVISOR_REPLAY_SNAPSHOT_INVALID'));
test('32C replay snapshot registry substitution rejected',()=>{const x=fixture(),replayBytes=encodeOfflineOrphanReplaySnapshot({registryId:'different_registry_32c',consumed:[]}),digest=sha(replayBytes);x.args.decision.body.replayDigest=digest;x.signBody();reject(()=>x.run({replayBytes,expectedReplayDigest:digest}),'SUPERVISOR_REPLAY_SNAPSHOT_INVALID');});
test('32C replay snapshot noncanonical JSON rejected',()=>{const x=fixture(),replayBytes=Buffer.from(JSON.stringify(JSON.parse(x.args.replayBytes.toString()),null,2)),digest=sha(replayBytes);x.args.decision.body.replayDigest=digest;x.signBody();reject(()=>x.run({replayBytes,expectedReplayDigest:digest}),'SUPERVISOR_REPLAY_SNAPSHOT_INVALID');});
test('32C unsigned extra decision field rejected',()=>{const x=fixture(),d=clone(x.args.decision);d.body.mayDelete=true;reject(()=>x.run({decision:d}),'SUPERVISOR_DECISION_INVALID');});
test('32C verified result cannot mutate report or ledger',()=>{const x=fixture(),beforeReport=JSON.stringify(x.args.report),beforeReplay=Buffer.from(x.args.replayBytes);safe(x.run());assert.equal(JSON.stringify(x.args.report),beforeReport);assert.ok(x.args.replayBytes.equals(beforeReplay));});

test('32C unknown classifier status rejected despite attacker-rehashed report',()=>{const x=fixture(),r=clone(x.args.report);r.evidence[1].classification='INVENTED_SAFE_STATE';const {reportDigest,...body}=r;r.reportDigest=sha(Buffer.from(`${OFFLINE_PINNED_ORPHAN_REPORT_SCHEMA}\0${JSON.stringify(body)}`));reject(()=>x.run({report:r,expectedPins:pinsFor(r)}),'SUPERVISOR_REPORT_INVALID');});
test('32C name digest mismatch rejected despite attacker-rehashed report',()=>{const x=fixture(),r=clone(x.args.report);r.evidence[1].nameDigest=sha('substituted');const {reportDigest,...body}=r;r.reportDigest=sha(Buffer.from(`${OFFLINE_PINNED_ORPHAN_REPORT_SCHEMA}\0${JSON.stringify(body)}`));reject(()=>x.run({report:r,expectedPins:pinsFor(r)}),'SUPERVISOR_REPORT_INVALID');});
test('32C report accessor cannot mutate between hashing and issue classification',()=>{const x=fixture(),r=clone(x.args.report);Object.defineProperty(r.evidence[1],'classification',{enumerable:true,get(){return 'UNTRACKED_ARCHIVE_UNVERIFIED';}});reject(()=>x.run({report:r}),'SUPERVISOR_CANONICAL_INVALID');});
test('32C unchanged replay snapshot may be reverified and is explicitly not consumed',()=>{const x=fixture();safe(x.run());safe(x.run());assert.equal(x.args.replayBytes.toString(),encodeOfflineOrphanReplaySnapshot({registryId,consumed:[]}).toString());});
