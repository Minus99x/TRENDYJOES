import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {OFFLINE_PINNED_ORPHAN_REPORT_SCHEMA} from '../src/offline-pinned-orphan-classifier.mjs';
import {OFFLINE_ORPHAN_SUPERVISOR_DECISION_SCHEMA,offlineOrphanSupervisorPolicyDigest,
 offlineOrphanReportIssueDigest,offlineOrphanSupervisorDecisionSigningBytes,encodeOfflineOrphanReplaySnapshot} from '../src/offline-orphan-supervisor-decision.mjs';
import {OFFLINE_SUPERVISOR_REPLAY_COMMIT_SCHEMA} from '../src/offline-supervisor-replay-commit.mjs';
import {OFFLINE_REPLAY_HEAD_CHECKPOINT_SCHEMA,offlineReplayHeadAuditorPolicyDigest,offlineReplayHeadAuditHistoryDigest,
 offlineReplayHeadCheckpointSigningBytes,offlineReplayHeadCheckpointDigest} from '../src/offline-supervisor-replay-checkpoint.mjs';
import {OFFLINE_PORTABLE_REPLAY_AUDIT_SCHEMA,OFFLINE_PORTABLE_REPLAY_WITNESS_SCHEMA,
 encodeOfflinePortableReplayAuditBundle,offlinePortableReplayAuditBundleDigest,offlinePortableReplayWitnessSigningBytes,
 offlinePortableReplayWitnessReceiptDigest,offlinePortableReplayWitnessPolicyDigest,verifyOfflinePortableReplayAuditBundle} from '../src/offline-portable-replay-audit-bundle.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex');
const ZERO='0'.repeat(64),registryId='orphan_registry_32f',now=1800000000000;
const keys=prefix=>[0,1,2].map(i=>({id:`${prefix}_32f_${i}`,...generateKeyPairSync('ed25519')}));
const reviewersK=keys('reviewer'),auditorsK=keys('auditor'),witnessesK=keys('witness');
const pub=keys=>keys.map(({id,publicKey})=>({id,publicKey}));
const reviewers=pub(reviewersK),auditors=pub(auditorsK),witnesses=pub(witnessesK);
const reviewerPin=offlineOrphanSupervisorPolicyDigest({reviewers,quorum:2});
const auditorPin=offlineReplayHeadAuditorPolicyDigest({auditors,quorum:2});
const witnessPin=offlinePortableReplayWitnessPolicyDigest({witnesses,quorum:2});
const err=code=>e=>e?.code===code;
function report(){
 const evidence=[{directoryIndex:0,name:'orphan-32f.tjexport',nameDigest:sha('orphan-32f.tjexport'),classification:'UNTRACKED_ARCHIVE_UNVERIFIED',digest:sha('bytes'),bytes:10}];
 const body={schema:OFFLINE_PINNED_ORPHAN_REPORT_SCHEMA,registryId,manifestDigest:sha('manifest'),head:{count:1,headDigest:sha('head')},epoch:0,transitionDigest:ZERO,recordsDigest:sha('records'),evidence,
  status:'SUPERVISORY_REVIEW_REQUIRED',issueCount:1,supervisoryDisposition:'EXTERNAL_DECISION_REQUIRED_FOR_ANY_REMEDIATION',
  readOnly:true,productionApproved:false,mayDelete:false,mayRepair:false,mayManufacture:false,mayAcknowledge:false};
 return {...body,reportDigest:sha(Buffer.from(`${OFFLINE_PINNED_ORPHAN_REPORT_SCHEMA}\0${JSON.stringify(body)}`))};
}
const pins=r=>({reportDigest:r.reportDigest,manifestDigest:r.manifestDigest,head:r.head,epoch:r.epoch,transitionDigest:r.transitionDigest,recordsDigest:r.recordsDigest});
function decision(r,head,n){
 const body={schema:OFFLINE_ORPHAN_SUPERVISOR_DECISION_SCHEMA,registryId,reportDigest:r.reportDigest,manifestDigest:r.manifestDigest,
  head:r.head,epoch:r.epoch,transitionDigest:r.transitionDigest,recordsDigest:r.recordsDigest,issueDigest:offlineOrphanReportIssueDigest(r),
  issueCount:1,disposition:'REJECT_EVIDENCE',decisionId:`decision_32f_${String(n).padStart(4,'0')}`,nonce:`nonce_32f_${String(n).padStart(4,'0')}`,
  issuedAt:now-1000,expiresAt:now+60000,replayDigest:head,reviewerPolicyDigest:reviewerPin};
 const bytes=offlineOrphanSupervisorDecisionSigningBytes(body);
 return {body,signatures:reviewersK.slice(0,2).map(k=>({reviewerId:k.id,signature:sign(null,bytes,k.privateKey).toString('base64url')}))};
}
function checkpoint(body){const bytes=offlineReplayHeadCheckpointSigningBytes(body);
 return {body,signatures:auditorsK.slice(0,2).map(k=>({auditorId:k.id,signature:sign(null,bytes,k.privateKey).toString('base64url')}))};}
function witnessReceipt(body,signers=witnessesK.slice(0,2)){
 const bytes=offlinePortableReplayWitnessSigningBytes(body);
 return {body,signatures:signers.map(k=>({witnessId:k.id,signature:sign(null,bytes,k.privateKey).toString('base64url')}))};
}
function fixture(count=2){
 const genesisBytes=encodeOfflineOrphanReplaySnapshot({registryId,consumed:[]}),expectedGenesisDigest=sha(genesisBytes);
 let head=expectedGenesisDigest;const r=report(),items=[];
 for(let n=1;n<=count;n++){
  const d=decision(r,head,n),prev=head;
  const state=encodeOfflineOrphanReplaySnapshot({registryId,consumed:Array.from({length:n},(_,i)=>({decisionId:`decision_32f_${String(i+1).padStart(4,'0')}`,nonce:`nonce_32f_${String(i+1).padStart(4,'0')}`}))});
  head=sha(state);
  const record={schema:OFFLINE_SUPERVISOR_REPLAY_COMMIT_SCHEMA,registryId,previousDigest:prev,nextDigest:head,
   decisionId:d.body.decisionId,nonce:d.body.nonce,decisionDigest:sha(offlineOrphanSupervisorDecisionSigningBytes(d.body))};
  items.push({record,report:r,expectedPins:pins(r),decision:d,reviewers,quorum:2,expectedReviewerPolicyDigest:reviewerPin,observedAtMs:now});
 }
 const expectedPreviousCheckpointDigest=sha('previous-checkpoint');
 const body={schema:OFFLINE_REPLAY_HEAD_CHECKPOINT_SCHEMA,registryId,genesisDigest:expectedGenesisDigest,headDigest:head,
  commitCount:items.length,historyDigest:offlineReplayHeadAuditHistoryDigest(items),previousCheckpointDigest:expectedPreviousCheckpointDigest,
  sequence:7,issuedAt:now+5000,auditorPolicyDigest:auditorPin};
 const c=checkpoint(body),expectedCheckpointDigest=offlineReplayHeadCheckpointDigest(c);
 const source={registryId,genesisBytes,expectedGenesisDigest,items,checkpoint:c,auditors,auditorQuorum:2,
  expectedAuditorPolicyDigest:auditorPin,expectedCheckpointDigest,expectedPreviousCheckpointDigest,expectedSequence:7};
 const bundleBytes=encodeOfflinePortableReplayAuditBundle(source),expectedBundleDigest=offlinePortableReplayAuditBundleDigest(bundleBytes);
 const receiptBody={schema:OFFLINE_PORTABLE_REPLAY_WITNESS_SCHEMA,registryId,bundleDigest:expectedBundleDigest,
  checkpointDigest:expectedCheckpointDigest,historyDigest:c.body.historyDigest,genesisDigest:expectedGenesisDigest,commitCount:items.length,
  previousWitnessReceiptDigest:sha('previous-witness'),sequence:19,issuedAt:now+7000,witnessPolicyDigest:witnessPin};
 const receipt=witnessReceipt(receiptBody),expectedWitnessReceiptDigest=offlinePortableReplayWitnessReceiptDigest(receipt);
 const args={bundleBytes,expectedBundleDigest,witnessReceipt:receipt,witnesses,witnessQuorum:2,
  expectedWitnessPolicyDigest:witnessPin,expectedWitnessReceiptDigest,
  expectedPreviousWitnessReceiptDigest:receiptBody.previousWitnessReceiptDigest,expectedWitnessSequence:19,
  expectedGenesisDigest,expectedCheckpointDigest,expectedPreviousCheckpointDigest,expectedSequence:7,expectedAuditorPolicyDigest:auditorPin};
 return {args,source,bundleBytes,receipt,receiptBody};
}
const editBundle=(f,edit)=>{
 const b=JSON.parse(f.bundleBytes.toString('utf8'));edit(b);const bundleBytes=Buffer.from(JSON.stringify(b));
 return {...f.args,bundleBytes,expectedBundleDigest:offlinePortableReplayAuditBundleDigest(bundleBytes)};
};
const editReceipt=(f,edit)=>{
 const body={...f.receiptBody};edit(body);
 const receipt=witnessReceipt(body);
 return {...f.args,witnessReceipt:receipt,expectedWitnessReceiptDigest:offlinePortableReplayWitnessReceiptDigest(receipt)};
};
test('32F portable bundle round-trips two historical signatures and independent witness quorum',()=>{
 const f=fixture(),v=verifyOfflinePortableReplayAuditBundle(f.args);
 assert.equal(v.verified,true);assert.equal(v.commitCount,2);assert.equal(v.historyVerified,true);
 assert.equal(v.independentlyPublished,false);assert.equal(v.authorizesRemediation,false);assert.equal(v.authorizesCheckout,false);
});
test('32F empty history is complete and independently witnessed',()=>{assert.equal(verifyOfflinePortableReplayAuditBundle(fixture(0).args).commitCount,0);});
test('32F single-item complete history verifies',()=>{assert.equal(verifyOfflinePortableReplayAuditBundle(fixture(1).args).commitCount,1);});
test('32F serialization is deterministic for unchanged source',()=>{const f=fixture();assert.deepEqual(encodeOfflinePortableReplayAuditBundle(f.source),f.bundleBytes);});
test('32F missing external bundle pin fails closed',()=>{const f=fixture();assert.throws(()=>verifyOfflinePortableReplayAuditBundle({...f.args,expectedBundleDigest:undefined}),err('PORTABLE32F_EXTERNAL_BUNDLE_PIN_REQUIRED'));});
test('32F substituted bundle bytes rejected before parsing',()=>{const f=fixture();assert.throws(()=>verifyOfflinePortableReplayAuditBundle({...f.args,bundleBytes:Buffer.from('{}')}),err('PORTABLE32F_EXTERNAL_BUNDLE_PIN_REQUIRED'));});
test('32F JSON whitespace cannot masquerade as canonical bundle',()=>{const f=fixture();const bundleBytes=Buffer.from(' '+f.bundleBytes);assert.throws(()=>verifyOfflinePortableReplayAuditBundle({...f.args,bundleBytes,expectedBundleDigest:offlinePortableReplayAuditBundleDigest(bundleBytes)}),err('PORTABLE32F_NONCANONICAL_BUNDLE'));});
test('32F duplicate JSON key cannot masquerade as canonical bundle',()=>{const f=fixture();const s=f.bundleBytes.toString('utf8').replace('"schema":','"schema":"junk","schema":');const bundleBytes=Buffer.from(s);assert.throws(()=>verifyOfflinePortableReplayAuditBundle({...f.args,bundleBytes,expectedBundleDigest:offlinePortableReplayAuditBundleDigest(bundleBytes)}),err('PORTABLE32F_NONCANONICAL_BUNDLE'));});
test('32F omitted historical item rejected even with newly computed bundle pin',()=>{const f=fixture();assert.throws(()=>verifyOfflinePortableReplayAuditBundle(editBundle(f,b=>{b.items.pop();})),err('PORTABLE32F_INVENTORY_INVALID'));});
test('32F tampered inventory digest rejected',()=>{const f=fixture();assert.throws(()=>verifyOfflinePortableReplayAuditBundle(editBundle(f,b=>{b.inventory.inventoryDigest=sha('bad');})),err('PORTABLE32F_INVENTORY_MISMATCH'));});
test('32F tampered individual item rejected',()=>{const f=fixture();assert.throws(()=>verifyOfflinePortableReplayAuditBundle(editBundle(f,b=>{b.items[0].record.nextDigest=sha('wrong');})),err('PORTABLE32F_INVENTORY_MISMATCH'));});
test('32F reordered items rejected',()=>{const f=fixture();assert.throws(()=>verifyOfflinePortableReplayAuditBundle(editBundle(f,b=>{b.items.reverse();})),err('PORTABLE32F_INVENTORY_MISMATCH'));});
test('32F forged inventory and bundle pins cannot replace auditor signed history',()=>{const f=fixture();const args=editBundle(f,b=>{b.items[0].record.nextDigest=sha('wrong');b.inventory.itemDigests[0]=sha('wrong');});assert.throws(()=>verifyOfflinePortableReplayAuditBundle(args),err('PORTABLE32F_INVENTORY_MISMATCH'));});
test('32F checkpoint rollback pin mismatch',()=>{const f=fixture();assert.throws(()=>verifyOfflinePortableReplayAuditBundle({...f.args,expectedCheckpointDigest:sha('rollback')}),err('PORTABLE32F_CHECKPOINT_PINS_MISMATCH'));});
test('32F historical predecessor pin mismatch',()=>{const f=fixture();assert.throws(()=>verifyOfflinePortableReplayAuditBundle({...f.args,expectedPreviousCheckpointDigest:sha('rollback')}),err('PORTABLE32F_CHECKPOINT_PINS_MISMATCH'));});
test('32F historical sequence rollback mismatch',()=>{const f=fixture();assert.throws(()=>verifyOfflinePortableReplayAuditBundle({...f.args,expectedSequence:6}),err('PORTABLE32F_CHECKPOINT_PINS_MISMATCH'));});
test('32F forged auditor SPKI cannot satisfy pinned policy',()=>{const f=fixture();assert.throws(()=>verifyOfflinePortableReplayAuditBundle(editBundle(f,b=>{b.auditors[0].spki=witnessesK[0].publicKey.export({format:'der',type:'spki'}).toString('base64url');})),err('CHECKPOINT32E_AUDITOR_POLICY_PIN_MISMATCH'));});
test('32F missing independent witness receipt pin fails closed',()=>{const f=fixture();assert.throws(()=>verifyOfflinePortableReplayAuditBundle({...f.args,expectedWitnessReceiptDigest:undefined}),err('PORTABLE32F_EXTERNAL_RECEIPT_PIN_REQUIRED'));});
test('32F witness receipt rollback pin rejected',()=>{const f=fixture();assert.throws(()=>verifyOfflinePortableReplayAuditBundle({...f.args,expectedPreviousWitnessReceiptDigest:sha('wrong')}),err('PORTABLE32F_EXTERNAL_RECEIPT_PIN_REQUIRED'));});
test('32F witness receipt sequence rollback rejected',()=>{const f=fixture();assert.throws(()=>verifyOfflinePortableReplayAuditBundle({...f.args,expectedWitnessSequence:18}),err('PORTABLE32F_EXTERNAL_RECEIPT_PIN_REQUIRED'));});
test('32F forked signed witness receipt cannot satisfy independent winning pin',()=>{const f=fixture();const receipt=witnessReceipt({...f.receiptBody,issuedAt:now+8000});assert.throws(()=>verifyOfflinePortableReplayAuditBundle({...f.args,witnessReceipt:receipt}),err('PORTABLE32F_EXTERNAL_RECEIPT_PIN_REQUIRED'));});
test('32F witness receipt binds exact bundle digest',()=>{const f=fixture();assert.throws(()=>verifyOfflinePortableReplayAuditBundle(editReceipt(f,b=>{b.bundleDigest=sha('another-bundle');})),err('PORTABLE32F_RECEIPT_BINDING_MISMATCH'));});
test('32F witness receipt binds historical commit count',()=>{const f=fixture();assert.throws(()=>verifyOfflinePortableReplayAuditBundle(editReceipt(f,b=>{b.commitCount=1;})),err('PORTABLE32F_RECEIPT_BINDING_MISMATCH'));});
test('32F witness receipt binds exact history digest',()=>{const f=fixture();assert.throws(()=>verifyOfflinePortableReplayAuditBundle(editReceipt(f,b=>{b.historyDigest=sha('wrong');})),err('PORTABLE32F_RECEIPT_BINDING_MISMATCH'));});
test('32F witness receipt must not claim earlier observation than checkpoint',()=>{const f=fixture();assert.throws(()=>verifyOfflinePortableReplayAuditBundle(editReceipt(f,b=>{b.issuedAt=now;})),err('PORTABLE32F_RECEIPT_BINDING_MISMATCH'));});
test('32F forged witness signature rejected even with attacker-supplied receipt digest',()=>{const f=fixture();const receipt={body:f.receipt.body,signatures:f.receipt.signatures.map(s=>({...s}))};receipt.signatures[0].signature=sign(null,offlinePortableReplayWitnessSigningBytes(receipt.body),witnessesK[2].privateKey).toString('base64url');assert.throws(()=>verifyOfflinePortableReplayAuditBundle({...f.args,witnessReceipt:receipt,expectedWitnessReceiptDigest:offlinePortableReplayWitnessReceiptDigest(receipt)}),err('PORTABLE32F_WITNESS_SIGNATURE_INVALID'));});
test('32F minority witness quorum rejected',()=>{const f=fixture();const receipt={...f.receipt,signatures:f.receipt.signatures.slice(0,1)};assert.throws(()=>verifyOfflinePortableReplayAuditBundle({...f.args,witnessReceipt:receipt,expectedWitnessReceiptDigest:offlinePortableReplayWitnessReceiptDigest(receipt)}),err('PORTABLE32F_WITNESS_QUORUM_INVALID'));});
test('32F duplicate witness identity rejected',()=>{const f=fixture();assert.throws(()=>verifyOfflinePortableReplayAuditBundle({...f.args,witnesses:[witnesses[0],witnesses[0],witnesses[2]]}),err('PORTABLE32F_WITNESS_POLICY_INVALID'));});
test('32F witness policy cannot reuse auditor signing keys',()=>{const f=fixture();const policy=[auditors[0],auditors[1],auditors[2]];const p=offlinePortableReplayWitnessPolicyDigest({witnesses:policy,quorum:2});assert.throws(()=>verifyOfflinePortableReplayAuditBundle({...f.args,witnesses:policy,expectedWitnessPolicyDigest:p,witnessReceipt:witnessReceipt({...f.receiptBody,witnessPolicyDigest:p}),expectedWitnessReceiptDigest:offlinePortableReplayWitnessReceiptDigest(witnessReceipt({...f.receiptBody,witnessPolicyDigest:p}))}),err('PORTABLE32F_WITNESS_NOT_INDEPENDENT'));});
test('32F witness policy cannot reuse historical reviewer signing keys',()=>{const f=fixture();const p=offlinePortableReplayWitnessPolicyDigest({witnesses:reviewers,quorum:2});const receipt=witnessReceipt({...f.receiptBody,witnessPolicyDigest:p});assert.throws(()=>verifyOfflinePortableReplayAuditBundle({...f.args,witnesses:reviewers,expectedWitnessPolicyDigest:p,witnessReceipt:receipt,expectedWitnessReceiptDigest:offlinePortableReplayWitnessReceiptDigest(receipt)}),err('PORTABLE32F_WITNESS_NOT_INDEPENDENT'));});
test('32F malformed witness receipt unknown field rejected',()=>{const f=fixture();assert.throws(()=>offlinePortableReplayWitnessSigningBytes({...f.receiptBody,allowProduction:true}),err('PORTABLE32F_RECEIPT_BODY_INVALID'));});
test('32F noncanonical key encoding rejected',()=>{const f=fixture();assert.throws(()=>verifyOfflinePortableReplayAuditBundle(editBundle(f,b=>{b.auditors[0].spki+='=';})),err('PORTABLE32F_ENCODING_INVALID'));});
test('32F malformed witness receipt signatures rejected',()=>{const f=fixture();const receipt={...f.receipt,signatures:[{...f.receipt.signatures[0],signature:'invalid'},f.receipt.signatures[1]]};assert.throws(()=>verifyOfflinePortableReplayAuditBundle({...f.args,witnessReceipt:receipt,expectedWitnessReceiptDigest:offlinePortableReplayWitnessReceiptDigest(receipt)}),err('PORTABLE32F_WITNESS_SIGNATURE_INVALID'));});
test('32F bundle refuses additional production authorization fields',()=>{const f=fixture();assert.throws(()=>verifyOfflinePortableReplayAuditBundle(editBundle(f,b=>{b.authorizeCheckout=true;})),err('PORTABLE32F_INVENTORY_INVALID'));});
test('32F receipt and bundle do not claim publication or trusted timestamps',()=>{const f=fixture();const r=verifyOfflinePortableReplayAuditBundle(f.args);assert.equal(r.externalPinPublicationVerified,false);assert.equal(r.trustedTimestampVerified,false);assert.equal(r.productionApproved,false);assert.equal(OFFLINE_PORTABLE_REPLAY_AUDIT_SCHEMA,'TJ-OFFLINE-PORTABLE-REPLAY-AUDIT-1');});
test('32F attacker rebuilding all inventory hashes cannot bypass historical checkpoint pin',()=>{
 const f=fixture(),b=JSON.parse(f.bundleBytes.toString('utf8'));
 b.items[0].record.nextDigest=sha('attacker-modified');
 const itemHash=i=>sha(Buffer.concat([Buffer.from(`${OFFLINE_PORTABLE_REPLAY_AUDIT_SCHEMA}-ITEM\0`),Buffer.from(JSON.stringify(i))]));
 b.inventory.itemDigests=b.items.map(itemHash);
 b.inventory.inventoryDigest=sha(Buffer.from(`${OFFLINE_PORTABLE_REPLAY_AUDIT_SCHEMA}-INVENTORY\0${JSON.stringify(b.inventory.itemDigests)}`));
 const bundleBytes=Buffer.from(JSON.stringify(b));
 assert.throws(()=>verifyOfflinePortableReplayAuditBundle({...f.args,bundleBytes,expectedBundleDigest:offlinePortableReplayAuditBundleDigest(bundleBytes)}),err('CHECKPOINT32E_HISTORY_MISMATCH'));
});
test('32F witness signature roster cannot repeat a signer',()=>{
 const f=fixture(),receipt={...f.receipt,signatures:[f.receipt.signatures[0],f.receipt.signatures[0]]};
 assert.throws(()=>verifyOfflinePortableReplayAuditBundle({...f.args,witnessReceipt:receipt,expectedWitnessReceiptDigest:offlinePortableReplayWitnessReceiptDigest(receipt)}),err('PORTABLE32F_WITNESS_SIGNATURE_INVALID'));
});
test('32F forged witness policy digest rejected even with valid witness signatures',()=>{
 const f=fixture();assert.throws(()=>verifyOfflinePortableReplayAuditBundle({...f.args,expectedWitnessPolicyDigest:sha('forged-policy')}),err('PORTABLE32F_WITNESS_POLICY_PIN_MISMATCH'));
});
test('32F swapped witness public key rejected despite intact receipt pin',()=>{
 const f=fixture(),swapped=[{id:witnesses[0].id,publicKey:auditorsK[2].publicKey},witnesses[1],witnesses[2]];
 assert.throws(()=>verifyOfflinePortableReplayAuditBundle({...f.args,witnesses:swapped}),err('PORTABLE32F_WITNESS_POLICY_PIN_MISMATCH'));
});
