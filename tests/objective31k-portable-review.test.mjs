import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,readFile,writeFile,unlink} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {OFFLINE_FORENSIC_PUBLICATION_SCHEMA,forensicPublicationPolicyDigest,forensicPublicationSigningBytes,createOfflineForensicPublicationStore} from '../src/offline-forensic-head-publication.mjs';
import {OFFLINE_FORENSIC_ACK_SCHEMA,forensicPublicationAcknowledgementBytes,createOfflineForensicPublicationOutbox,verifyOfflineForensicOutboxHistory} from '../src/offline-forensic-publication-outbox.mjs';
import {createOfflineForensicPortableReviewBundle,verifyOfflineForensicPortableReviewBundle} from '../src/offline-forensic-portable-review.mjs';
const ROOT='0'.repeat(64),zero={count:0,headDigest:ROOT};
const registryId='synthetic-portable-review-31k',anchorType='registry';
const sha=x=>createHash('sha256').update(x).digest('hex');
const key=()=>generateKeyPairSync('ed25519');
const sig=(k,b)=>sign(null,b,k.privateKey).toString('base64url');
const throws=(fn,code)=>assert.throws(fn,e=>e?.code===code);
const rejects=(fn,code)=>assert.rejects(fn,e=>e?.code===code);
async function fixture(t){
 const dir=await mkdtemp(join(tmpdir(),'tj31k-'));
 t.after(()=>rm(dir,{recursive:true,force:true}));
 const witnessKeys=[key(),key(),key()],reviewKeys=[key(),key()];
 const witnesses=witnessKeys.map((k,i)=>({id:`synthetic-witness-31k-${i}`,publicKey:k.publicKey}));
 const reviewerPolicies=[{quorum:2,reviewers:reviewKeys.map((k,i)=>({id:`synthetic-reviewer-31k-${i}`,publicKey:k.publicKey,readLatest:async()=>null}))}];
 const trust={registryId,anchorType,witnesses,witnessQuorum:2,reviewerPolicies,reviewerEpochs:[{startIndex:1,...reviewerPolicies[0]}]};
 const store=()=>createOfflineForensicPublicationStore({...trust,directory:join(dir,'publication')});
 const outbox=()=>createOfflineForensicPublicationOutbox({...trust,directory:join(dir,'outbox'),publicationStore:store()});
 function publication(previous=null){
  const body={schema:OFFLINE_FORENSIC_PUBLICATION_SCHEMA,registryId,anchorType,index:previous?2:1,previousDigest:previous?.digest??ROOT,forensicCount:0,forensicHeadDigest:ROOT,policyIndex:0,policyDigest:forensicPublicationPolicyDigest(reviewerPolicies[0]),publishedAt:previous?1700000001000:1700000000000};
  const rotationApprovals=[],witnessSignatures=witnessKeys.slice(0,2).map((k,i)=>({witnessId:witnesses[i].id,signature:sig(k,forensicPublicationSigningBytes(body,rotationApprovals))}));
  const unsigned={...body,rotationApprovals,witnessSignatures};return {...unsigned,digest:sha(Buffer.from(`${OFFLINE_FORENSIC_PUBLICATION_SCHEMA}\0${JSON.stringify(unsigned)}`))};
 }
 function acknowledgement(r){
  const body={schema:OFFLINE_FORENSIC_ACK_SCHEMA,registryId,anchorType,publicationIndex:r.index,publicationDigest:r.digest,publicationHeadDigest:r.digest,acknowledgedAt:r.publishedAt+1000};
  return {body,witnessSignatures:witnessKeys.slice(0,2).map((k,i)=>({witnessId:witnesses[i].id,signature:sig(k,forensicPublicationAcknowledgementBytes(body))}))};
 }
 async function snapshot(){
  const p=await store().inspectHistory(),o=await outbox().inspectHistory();
  const pins={forensic:zero,publication:{count:p.count,headDigest:p.headDigest},outbox:{count:o.count,headDigest:o.headDigest}};
  const envelope=createOfflineForensicPortableReviewBundle({registryId,anchorType,forensicEvents:[],publications:p.publications,transitionCertificates:[],outboxEvents:o.events,declaredHeads:pins});
  return {envelope:JSON.parse(JSON.stringify(envelope)),independentPins:structuredClone(pins),trust};
 }
 return {dir,trust,store,outbox,publication,acknowledgement,snapshot};
}
async function prepared(t,{published=false,acked=false}={}){
 const f=await fixture(t),r=f.publication(),o=f.outbox();
 const p=await o.prepare({record:r,expectedOutboxHead:zero,expectedPublicationHead:zero});
 if(published)await f.store().append({record:r,expectedHead:zero});
 if(acked)await o.acknowledge({acknowledgement:f.acknowledgement(r),expectedOutboxHead:{count:1,headDigest:p.headDigest},expectedPublicationHead:{count:1,headDigest:r.digest}});
 return {f,r};
}
const verify=x=>verifyOfflineForensicPortableReviewBundle(x);
test('31K empty independently pinned portable bundle is read-only with no authority',async t=>{
 const f=await fixture(t),s=await f.snapshot(),r=verify(s);assert.equal(r.classification,'EMPTY_VERIFIED_NO_AUTHORITY');assert.equal(r.mayRetry,false);assert.equal(r.productionApproved,false);
});
test('31K independently pinned complete signed outbox/publication is read-only consistent',async t=>{
 const {f}=await prepared(t,{published:true,acked:true}),r=verify(await f.snapshot());assert.equal(r.classification,'CONSISTENT_READ_ONLY');assert.equal(r.acknowledgedCount,1);assert.equal(r.mayAcknowledge,false);
});
test('31K portable JSON round-trip remains independently verifiable',async t=>{
 const {f}=await prepared(t,{published:true,acked:true}),s=await f.snapshot();s.envelope=JSON.parse(JSON.stringify(s.envelope));assert.equal(verify(s).verified,true);
});
test('31K prepared but unpublished evidence is explicitly review-required',async t=>{
 const {f}=await prepared(t),r=verify(await f.snapshot());assert.equal(r.classification,'PREPARED_UNCERTAIN_REVIEW');assert.equal(r.unacknowledgedPublicationIndex,1);assert.equal(r.mayRetry,false);
});
test('31K signed publication without ACK is explicitly review-required',async t=>{
 const {f}=await prepared(t,{published:true}),r=verify(await f.snapshot());assert.equal(r.classification,'PUBLISHED_UNACKNOWLEDGED_REVIEW');assert.equal(r.mayAcknowledge,false);
});
test('31K signed orphan publication is review-required and cannot be silently accepted',async t=>{
 const f=await fixture(t),r=f.publication();await f.store().append({record:r,expectedHead:zero});assert.equal(verify(await f.snapshot()).classification,'ORPHAN_PUBLICATION_REVIEW');
});
test('31K independent forensic head pin cannot be supplied from bundle',async t=>{
 const f=await fixture(t),s=await f.snapshot();s.independentPins.forensic={count:1,headDigest:'a'.repeat(64)};throws(()=>verify(s),'FORENSIC_PORTABLE_REVIEW_INDEPENDENT_PIN_MISMATCH');
});
test('31K independent publication pin detects rollback',async t=>{
 const {f}=await prepared(t,{published:true,acked:true}),s=await f.snapshot();s.independentPins.publication=zero;throws(()=>verify(s),'FORENSIC_PORTABLE_REVIEW_INDEPENDENT_PIN_MISMATCH');
});
test('31K independent outbox pin detects rollback',async t=>{
 const {f}=await prepared(t,{published:true,acked:true}),s=await f.snapshot();s.independentPins.outbox=zero;throws(()=>verify(s),'FORENSIC_PORTABLE_REVIEW_INDEPENDENT_PIN_MISMATCH');
});
test('31K bundle digest detects accidental in-transit alteration',async t=>{
 const f=await fixture(t),s=await f.snapshot();s.envelope.payload.anchorType='journal';throws(()=>verify(s),'FORENSIC_PORTABLE_REVIEW_TRANSPORT_INVALID');
});
test('31K bundle digest is NOT a trust anchor: recomputed digest cannot bypass pinned head',async t=>{
 const {f}=await prepared(t,{published:true,acked:true}),s=await f.snapshot();s.envelope.payload.declaredHeads.outbox=zero;s.envelope.transportDigest=sha(Buffer.from(JSON.stringify(s.envelope.payload)));throws(()=>verify(s),'FORENSIC_PORTABLE_REVIEW_INDEPENDENT_PIN_MISMATCH');
});
test('31K forged signed publication fails cryptographic verification even with recomputed transport hash',async t=>{
 const {f}=await prepared(t,{published:true,acked:true}),s=await f.snapshot();s.envelope.payload.publications[0].witnessSignatures[0].signature='A'.repeat(86);s.envelope.transportDigest=sha(Buffer.from(JSON.stringify(s.envelope.payload)));throws(()=>verify(s),'FORENSIC_PUBLICATION_WITNESS_INVALID');
});
test('31K forged outbox ACK fails even with recomputed transport hash',async t=>{
 const {f}=await prepared(t,{published:true,acked:true}),s=await f.snapshot();s.envelope.payload.outboxEvents[1].acknowledgement.witnessSignatures[0].signature='A'.repeat(86);const event=s.envelope.payload.outboxEvents[1],{digest:old,...body}=event;event.digest=sha(Buffer.from(`TJ-OFFLINE-FORENSIC-OUTBOX-1\0${JSON.stringify(body)}`));s.independentPins.outbox={count:2,headDigest:event.digest};s.envelope.payload.declaredHeads.outbox={...s.independentPins.outbox};s.envelope.transportDigest=sha(Buffer.from(JSON.stringify(s.envelope.payload)));throws(()=>verify(s),'FORENSIC_OUTBOX_ACK_SIGNATURE_INVALID');
});
test('31K tampered outbox event fails digest verification',async t=>{
 const {f}=await prepared(t,{published:true}),s=await f.snapshot();s.envelope.payload.outboxEvents[0].publicationDigest='f'.repeat(64);s.envelope.transportDigest=sha(Buffer.from(JSON.stringify(s.envelope.payload)));throws(()=>verify(s),'FORENSIC_OUTBOX_DIGEST_INVALID');
});
test('31K independently trusted wrong witness key rejects otherwise valid signatures',async t=>{
 const {f}=await prepared(t,{published:true,acked:true}),s=await f.snapshot();s.trust={...s.trust,witnesses:s.trust.witnesses.map((w,i)=>i===0?{...w,publicKey:key().publicKey}:w)};throws(()=>verify(s),'FORENSIC_PUBLICATION_WITNESS_INVALID');
});
test('31K independent wrong registry fails closed',async t=>{
 const f=await fixture(t),s=await f.snapshot();s.trust={...s.trust,registryId:'synthetic-other-registry-31k'};throws(()=>verify(s),'FORENSIC_PORTABLE_REVIEW_INDEPENDENT_PIN_MISMATCH');
});
test('31K extra top-level envelope field rejected',async t=>{
 const f=await fixture(t),s=await f.snapshot();s.envelope.unexpected=true;throws(()=>verify(s),'FORENSIC_PORTABLE_REVIEW_REQUEST_INVALID');
});
test('31K extra payload field rejected',async t=>{
 const f=await fixture(t),s=await f.snapshot();s.envelope.payload.unexpected=true;throws(()=>verify(s),'FORENSIC_PORTABLE_REVIEW_SCHEMA_INVALID');
});
test('31K missing external pins rejected',async t=>{
 const f=await fixture(t),s=await f.snapshot();delete s.independentPins;throws(()=>verify(s),'FORENSIC_PORTABLE_REVIEW_REQUEST_INVALID');
});
test('31K malformed head rejected even if supplied as declared pin',async t=>{
 const f=await fixture(t),s=await f.snapshot();s.envelope.payload.declaredHeads.outbox={count:0,headDigest:'f'.repeat(64)};throws(()=>verify(s),'FORENSIC_PORTABLE_REVIEW_SCHEMA_INVALID');
});
test('31K malformed policy certificates are rejected, not silently ignored',async t=>{
 const f=await fixture(t),s=await f.snapshot();s.envelope.payload.transitionCertificates=[{fake:true}];s.envelope.transportDigest=sha(Buffer.from(JSON.stringify(s.envelope.payload)));throws(()=>verify(s),'FORENSIC_TRANSITION_CERTIFICATE_COUNT');
});
test('31K exported outbox history roundtrips and remains cryptographically checked',async t=>{
 const {f}=await prepared(t,{published:true,acked:true}),o=await f.outbox().inspectHistory();assert.equal(o.count,2);assert.equal(verifyOfflineForensicOutboxHistory({events:o.events,expectedHead:{count:o.count,headDigest:o.headDigest},...f.trust}).completed,1);
});
test('31K exported outbox history rejects independent valid-prefix rollback',async t=>{
 const {f}=await prepared(t,{published:true,acked:true}),o=await f.outbox().inspectHistory();throws(()=>verifyOfflineForensicOutboxHistory({events:o.events.slice(0,1),expectedHead:{count:o.count,headDigest:o.headDigest},...f.trust}),'FORENSIC_OUTBOX_PIN_MISMATCH');
});
test('31K outbox inspectHistory rejects tampered on-disk event before export',async t=>{
 const {f}=await prepared(t),path=join(f.dir,'outbox','0000000001.json'),e=JSON.parse(await readFile(path,'utf8'));e.publicationDigest='f'.repeat(64);await writeFile(path,JSON.stringify(e));await rejects(()=>f.outbox().inspectHistory(),'FORENSIC_OUTBOX_DIGEST_INVALID');
});
test('31K outbox inspectHistory fails closed on pending crash marker',async t=>{
 const f=await fixture(t);await f.outbox().inspect();await writeFile(join(f.dir,'outbox','.pending.json'),'{}');await rejects(()=>f.outbox().inspectHistory(),'FORENSIC_OUTBOX_PENDING_REVIEW_REQUIRED');
});
test('31K missing outbox ACK after completed history is rejected',async t=>{
 const {f}=await prepared(t,{published:true,acked:true}),o=await f.outbox().inspectHistory();const events=o.events.slice(0,1);throws(()=>verifyOfflineForensicOutboxHistory({events,expectedHead:{count:o.count,headDigest:o.headDigest},...f.trust}),'FORENSIC_OUTBOX_PIN_MISMATCH');
});
test('31K malformed request cannot promote a consistent snapshot to production',async t=>{
 const {f}=await prepared(t,{published:true,acked:true}),s=await f.snapshot();s.envelope.productionApproved=true;throws(()=>verify(s),'FORENSIC_PORTABLE_REVIEW_REQUEST_INVALID');
});
// Crash evidence: a separate process exits after durable PREPARE commit.
test('31K real child-process crash after outbox PREPARE is portable and review-required',async t=>{
 const f=await fixture(t),r=f.publication();
 const mod=fileURLToPath(new URL('../src/offline-forensic-publication-outbox.mjs',import.meta.url));
 const pub=fileURLToPath(new URL('../src/offline-forensic-head-publication.mjs',import.meta.url));
 const c={registryId,anchorType,witnessQuorum:2,witnesses:f.trust.witnesses.map(w=>({id:w.id,pem:w.publicKey.export({type:'spki',format:'pem'})})),reviewerPolicies:f.trust.reviewerPolicies.map(p=>({quorum:p.quorum,reviewers:p.reviewers.map(w=>({id:w.id,pem:w.publicKey.export({type:'spki',format:'pem'})}))}))};
 const script=`import {createPublicKey} from 'node:crypto';import {createOfflineForensicPublicationOutbox} from ${JSON.stringify(mod)};import {createOfflineForensicPublicationStore} from ${JSON.stringify(pub)};const c=JSON.parse(process.argv[3]);c.witnesses=c.witnesses.map(w=>({id:w.id,publicKey:createPublicKey(w.pem)}));c.reviewerPolicies=c.reviewerPolicies.map(p=>({quorum:p.quorum,reviewers:p.reviewers.map(w=>({id:w.id,publicKey:createPublicKey(w.pem),readLatest:async()=>null}))}));const pub=createOfflineForensicPublicationStore({...c,directory:process.argv[1]});const o=createOfflineForensicPublicationOutbox({...c,directory:process.argv[2],publicationStore:pub,injectFault:stage=>{if(stage==='after-commit-sync')process.exit(81)}});await o.prepare({record:JSON.parse(process.argv[4]),expectedOutboxHead:{count:0,headDigest:'0'.repeat(64)},expectedPublicationHead:{count:0,headDigest:'0'.repeat(64)}});`;
 const p=spawnSync(process.execPath,['--input-type=module','-e',script,join(f.dir,'publication'),join(f.dir,'outbox'),JSON.stringify(c),JSON.stringify(r)],{encoding:'utf8',timeout:12000});assert.equal(p.status,81,p.stderr);
 const result=verify(await f.snapshot());assert.equal(result.classification,'PREPARED_UNCERTAIN_REVIEW');assert.equal(result.mayRetry,false);
});
