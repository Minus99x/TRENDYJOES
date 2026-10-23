import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,readFile,writeFile,unlink,symlink} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {OFFLINE_FORENSIC_PUBLICATION_SCHEMA,forensicPublicationPolicyDigest,forensicPublicationSigningBytes,createOfflineForensicPublicationStore} from '../src/offline-forensic-head-publication.mjs';
import {OFFLINE_FORENSIC_ACK_SCHEMA,forensicPublicationAcknowledgementBytes,createOfflineForensicPublicationOutbox} from '../src/offline-forensic-publication-outbox.mjs';

const ROOT='0'.repeat(64),registryId='synthetic-outbox-registry-31j',anchorType='registry',zero={count:0,headDigest:ROOT};
const sha=x=>createHash('sha256').update(x).digest('hex');
const pk=()=>generateKeyPairSync('ed25519');
const signature=(k,b)=>sign(null,b,k.privateKey).toString('base64url');
const rejects=(f,code)=>assert.rejects(f,e=>e?.code===code);
async function fixture(t){
 const directory=await mkdtemp(join(tmpdir(),'tj31j-outbox-'));
 const publicationDirectory=join(directory,'publications'),outboxDirectory=join(directory,'outbox');
 t.after(()=>rm(directory,{recursive:true,force:true}));
 const wk=[pk(),pk(),pk()],rk=[pk(),pk()];
 const witnesses=wk.map((k,i)=>({id:`synthetic-witness-31j-${i}`,publicKey:k.publicKey}));
 const reviewerPolicies=[{reviewers:rk.map((k,i)=>({id:`synthetic-reviewer-31j-${i}`,publicKey:k.publicKey,readLatest:async()=>null})),quorum:2}];
 const config={registryId,anchorType,witnesses,witnessQuorum:2,reviewerPolicies};
 const store=()=>createOfflineForensicPublicationStore({directory:publicationDirectory,...config});
 const outbox=(extra={})=>createOfflineForensicPublicationOutbox({directory:outboxDirectory,publicationStore:store(),...config,...extra});
 function record(previous=null){
  const b={schema:OFFLINE_FORENSIC_PUBLICATION_SCHEMA,registryId,anchorType,index:previous?2:1,previousDigest:previous?.digest??ROOT,forensicCount:previous?2:1,forensicHeadDigest:previous?'b'.repeat(64):'a'.repeat(64),policyIndex:0,policyDigest:forensicPublicationPolicyDigest(reviewerPolicies[0]),publishedAt:previous?1700000001000:1700000000000};
  const rotationApprovals=[];
  const witnessSignatures=wk.slice(0,2).map((k,i)=>({witnessId:witnesses[i].id,signature:signature(k,forensicPublicationSigningBytes(b,rotationApprovals))}));
  const unsigned={...b,rotationApprovals,witnessSignatures};
  return {...unsigned,digest:sha(Buffer.from(`${OFFLINE_FORENSIC_PUBLICATION_SCHEMA}\0${JSON.stringify(unsigned)}`))};
 }
 function ack(r,at=r.publishedAt+1000){
  const body={schema:OFFLINE_FORENSIC_ACK_SCHEMA,registryId,anchorType,publicationIndex:r.index,publicationDigest:r.digest,publicationHeadDigest:r.digest,acknowledgedAt:at};
  const witnessSignatures=wk.slice(0,2).map((k,i)=>({witnessId:witnesses[i].id,signature:signature(k,forensicPublicationAcknowledgementBytes(body))}));
  return {body,witnessSignatures};
 }
 return {directory,publicationDirectory,outboxDirectory,wk,config,store,outbox,record,ack};
}
test('31J empty pinned outbox and publication history reconcile offline',async t=>{
 const f=await fixture(t);assert.deepEqual((await f.outbox().reconcile({expectedOutboxHead:zero,expectedPublicationHead:zero})).publicationCount,0);
});
test('31J prepare is durable before local publication; ambiguous stage blocks reconciliation',async t=>{
 const f=await fixture(t),r=f.record(),o=f.outbox();
 const p=await o.prepare({record:r,expectedOutboxHead:zero,expectedPublicationHead:zero});
 assert.equal(p.count,1);assert.equal((await f.outbox().inspect()).pendingPublicationIndex,1);
 await rejects(()=>o.reconcile({expectedOutboxHead:{count:1,headDigest:p.headDigest},expectedPublicationHead:zero}),'FORENSIC_OUTBOX_UNCERTAIN_PREPARE');
});
test('31J signed local publication without independent acknowledgement remains blocked',async t=>{
 const f=await fixture(t),r=f.record(),o=f.outbox();
 const p=await o.prepare({record:r,expectedOutboxHead:zero,expectedPublicationHead:zero});
 await f.store().append({record:r,expectedHead:zero});
 await rejects(()=>o.reconcile({expectedOutboxHead:{count:1,headDigest:p.headDigest},expectedPublicationHead:{count:1,headDigest:r.digest}}),'FORENSIC_OUTBOX_UNACKNOWLEDGED');
});
test('31J witness-quorum acknowledgement is durably journaled and reconciles after restart',async t=>{
 const f=await fixture(t),r=f.record(),o=f.outbox();
 const p=await o.prepare({record:r,expectedOutboxHead:zero,expectedPublicationHead:zero});
 await f.store().append({record:r,expectedHead:zero});
 const a=await o.acknowledge({acknowledgement:f.ack(r),expectedOutboxHead:{count:1,headDigest:p.headDigest},expectedPublicationHead:{count:1,headDigest:r.digest}});
 const ok=await f.outbox().reconcile({expectedOutboxHead:{count:2,headDigest:a.headDigest},expectedPublicationHead:{count:1,headDigest:r.digest}});
 assert.equal(ok.verified,true);assert.equal(ok.productionApproved,false);
});
test('31J acknowledgement before publication is rejected',async t=>{
 const f=await fixture(t),r=f.record(),o=f.outbox();
 const p=await o.prepare({record:r,expectedOutboxHead:zero,expectedPublicationHead:zero});
 await rejects(()=>o.acknowledge({acknowledgement:f.ack(r),expectedOutboxHead:{count:1,headDigest:p.headDigest},expectedPublicationHead:zero}),'FORENSIC_OUTBOX_PUBLICATION_MISMATCH');
});
test('31J forged acknowledgement signature rejected',async t=>{
 const f=await fixture(t),r=f.record(),o=f.outbox(),p=await o.prepare({record:r,expectedOutboxHead:zero,expectedPublicationHead:zero});await f.store().append({record:r,expectedHead:zero});
 const a=f.ack(r);a.witnessSignatures[0].signature='A'.repeat(86);
 await rejects(()=>o.acknowledge({acknowledgement:a,expectedOutboxHead:{count:1,headDigest:p.headDigest},expectedPublicationHead:{count:1,headDigest:r.digest}}),'FORENSIC_OUTBOX_ACK_SIGNATURE_INVALID');
});
test('31J missing acknowledgement quorum rejected',async t=>{
 const f=await fixture(t),r=f.record(),o=f.outbox(),p=await o.prepare({record:r,expectedOutboxHead:zero,expectedPublicationHead:zero});await f.store().append({record:r,expectedHead:zero});
 const a=f.ack(r);a.witnessSignatures.pop();
 await rejects(()=>o.acknowledge({acknowledgement:a,expectedOutboxHead:{count:1,headDigest:p.headDigest},expectedPublicationHead:{count:1,headDigest:r.digest}}),'FORENSIC_OUTBOX_ACK_SIGNATURE_INVALID');
});
test('31J duplicate acknowledgement signer rejected',async t=>{
 const f=await fixture(t),r=f.record(),o=f.outbox(),p=await o.prepare({record:r,expectedOutboxHead:zero,expectedPublicationHead:zero});await f.store().append({record:r,expectedHead:zero});
 const a=f.ack(r);a.witnessSignatures[1]=a.witnessSignatures[0];
 await rejects(()=>o.acknowledge({acknowledgement:a,expectedOutboxHead:{count:1,headDigest:p.headDigest},expectedPublicationHead:{count:1,headDigest:r.digest}}),'FORENSIC_OUTBOX_ACK_SIGNATURE_INVALID');
});
test('31J acknowledgement before signed publication time rejected',async t=>{
 const f=await fixture(t),r=f.record(),o=f.outbox(),p=await o.prepare({record:r,expectedOutboxHead:zero,expectedPublicationHead:zero});await f.store().append({record:r,expectedHead:zero});
 await rejects(()=>o.acknowledge({acknowledgement:f.ack(r,r.publishedAt-1),expectedOutboxHead:{count:1,headDigest:p.headDigest},expectedPublicationHead:{count:1,headDigest:r.digest}}),'FORENSIC_OUTBOX_ACK_BINDING_INVALID');
});
test('31J substituted acknowledgement publication digest rejected',async t=>{
 const f=await fixture(t),r=f.record(),o=f.outbox(),p=await o.prepare({record:r,expectedOutboxHead:zero,expectedPublicationHead:zero});await f.store().append({record:r,expectedHead:zero});
 const a=f.ack(r);a.body.publicationDigest='f'.repeat(64);a.body.publicationHeadDigest='f'.repeat(64);
 await rejects(()=>o.acknowledge({acknowledgement:a,expectedOutboxHead:{count:1,headDigest:p.headDigest},expectedPublicationHead:{count:1,headDigest:r.digest}}),'FORENSIC_OUTBOX_ACK_BINDING_INVALID');
});
test('31J cannot replay prepare while prior publication is unacknowledged',async t=>{
 const f=await fixture(t),r=f.record(),o=f.outbox(),p=await o.prepare({record:r,expectedOutboxHead:zero,expectedPublicationHead:zero});
 await rejects(()=>o.prepare({record:r,expectedOutboxHead:{count:1,headDigest:p.headDigest},expectedPublicationHead:zero}),'FORENSIC_OUTBOX_UNACKNOWLEDGED');
});
test('31J stale outbox compare-and-swap pin rejected',async t=>{
 const f=await fixture(t),r=f.record(),o=f.outbox();await o.prepare({record:r,expectedOutboxHead:zero,expectedPublicationHead:zero});
 await rejects(()=>o.prepare({record:r,expectedOutboxHead:zero,expectedPublicationHead:zero}),'FORENSIC_OUTBOX_STALE_PIN');
});
test('31J local publication without prior outbox prepare is rejected',async t=>{
 const f=await fixture(t),r=f.record();await f.store().append({record:r,expectedHead:zero});
 await rejects(()=>f.outbox().reconcile({expectedOutboxHead:zero,expectedPublicationHead:{count:1,headDigest:r.digest}}),'FORENSIC_OUTBOX_ORPHAN_PUBLICATION');
});
test('31J prepare refuses publication history already ahead of acknowledged outbox',async t=>{
 const f=await fixture(t),r=f.record();await f.store().append({record:r,expectedHead:zero});
 await rejects(()=>f.outbox().prepare({record:f.record(r),expectedOutboxHead:zero,expectedPublicationHead:{count:1,headDigest:r.digest}}),'FORENSIC_OUTBOX_ORPHAN_PUBLICATION');
});
test('31J two concurrent prepares are serialized by kernel lock',async t=>{
 const f=await fixture(t),r=f.record(),o=f.outbox();
 const x=await Promise.allSettled([o.prepare({record:r,expectedOutboxHead:zero,expectedPublicationHead:zero}),o.prepare({record:r,expectedOutboxHead:zero,expectedPublicationHead:zero})]);
 assert.equal(x.filter(v=>v.status==='fulfilled').length,1);
 assert.equal(x.filter(v=>v.status==='rejected'&&v.reason.code==='FORENSIC_OUTBOX_STALE_PIN').length,1);
});
test('31J tampered journal digest fails closed',async t=>{
 const f=await fixture(t),r=f.record(),o=f.outbox();await o.prepare({record:r,expectedOutboxHead:zero,expectedPublicationHead:zero});
 const path=join(f.outboxDirectory,'0000000001.json'),e=JSON.parse(await readFile(path,'utf8'));e.publicationDigest='f'.repeat(64);await writeFile(path,JSON.stringify(e));
 await rejects(()=>o.inspect(),'FORENSIC_OUTBOX_DIGEST_INVALID');
});
test('31J missing first journal record fails closed',async t=>{
 const f=await fixture(t),r=f.record(),o=f.outbox(),p=await o.prepare({record:r,expectedOutboxHead:zero,expectedPublicationHead:zero});await f.store().append({record:r,expectedHead:zero});
 await o.acknowledge({acknowledgement:f.ack(r),expectedOutboxHead:{count:1,headDigest:p.headDigest},expectedPublicationHead:{count:1,headDigest:r.digest}});
 await unlink(join(f.outboxDirectory,'0000000001.json'));
 await rejects(()=>o.inspect(),'FORENSIC_OUTBOX_HISTORY_GAP');
});
test('31J symlinked journal record fails closed',async t=>{
 const f=await fixture(t),r=f.record(),o=f.outbox();await o.prepare({record:r,expectedOutboxHead:zero,expectedPublicationHead:zero});
 const path=join(f.outboxDirectory,'0000000001.json'),copy=join(f.directory,'copy');await writeFile(copy,await readFile(path));await unlink(path);await symlink(copy,path);
 await rejects(()=>o.inspect(),'FORENSIC_OUTBOX_FILE_UNSAFE');
});
test('31J externally pinned outbox head rejects valid-prefix rollback',async t=>{
 const f=await fixture(t),r=f.record(),o=f.outbox(),p=await o.prepare({record:r,expectedOutboxHead:zero,expectedPublicationHead:zero});await f.store().append({record:r,expectedHead:zero});
 const a=await o.acknowledge({acknowledgement:f.ack(r),expectedOutboxHead:{count:1,headDigest:p.headDigest},expectedPublicationHead:{count:1,headDigest:r.digest}});
 await unlink(join(f.outboxDirectory,'0000000002.json'));
 await rejects(()=>o.inspect({expectedOutboxHead:{count:2,headDigest:a.headDigest}}),'FORENSIC_OUTBOX_PIN_MISMATCH');
});
test('31J next publication cannot prepare until prior acknowledgement is durable',async t=>{
 const f=await fixture(t),r=f.record(),o=f.outbox(),p=await o.prepare({record:r,expectedOutboxHead:zero,expectedPublicationHead:zero});await f.store().append({record:r,expectedHead:zero});
 const a=await o.acknowledge({acknowledgement:f.ack(r),expectedOutboxHead:{count:1,headDigest:p.headDigest},expectedPublicationHead:{count:1,headDigest:r.digest}});
 const next=f.record(r),nextPin={count:1,headDigest:r.digest};
 const prep=await o.prepare({record:next,expectedOutboxHead:{count:2,headDigest:a.headDigest},expectedPublicationHead:nextPin});
 assert.equal(prep.count,3);
});
function childScript(f,r,stage){
 const mod=fileURLToPath(new URL('../src/offline-forensic-publication-outbox.mjs',import.meta.url));
 const pub=fileURLToPath(new URL('../src/offline-forensic-head-publication.mjs',import.meta.url));
 const c={registryId,anchorType,witnessQuorum:2,witnesses:f.config.witnesses.map(w=>({id:w.id,pem:w.publicKey.export({type:'spki',format:'pem'})})),reviewerPolicies:f.config.reviewerPolicies.map(p=>({quorum:p.quorum,reviewers:p.reviewers.map(v=>({id:v.id,pem:v.publicKey.export({type:'spki',format:'pem'})}))}))};
 const script=`import {createPublicKey} from 'node:crypto';import {createOfflineForensicPublicationOutbox} from ${JSON.stringify(mod)};import {createOfflineForensicPublicationStore} from ${JSON.stringify(pub)};const c=JSON.parse(process.argv[3]);c.witnesses=c.witnesses.map(w=>({id:w.id,publicKey:createPublicKey(w.pem)}));c.reviewerPolicies=c.reviewerPolicies.map(p=>({quorum:p.quorum,reviewers:p.reviewers.map(r=>({id:r.id,publicKey:createPublicKey(r.pem),readLatest:async()=>null}))}));const pub=createOfflineForensicPublicationStore({...c,directory:process.argv[1]});const o=createOfflineForensicPublicationOutbox({...c,directory:process.argv[2],publicationStore:pub,injectFault:stage=>{if(stage===${JSON.stringify(stage)})process.exit(97)}});await o.prepare({record:JSON.parse(process.argv[4]),expectedOutboxHead:{count:0,headDigest:'0'.repeat(64)},expectedPublicationHead:{count:0,headDigest:'0'.repeat(64)}});`;
 return {script,c};
}
test('31J actual child-process crash after pending fsync requires forensic review',async t=>{
 const f=await fixture(t),r=f.record(),{script,c}=childScript(f,r,'after-pending-sync');
 const p=spawnSync(process.execPath,['--input-type=module','-e',script,f.publicationDirectory,f.outboxDirectory,JSON.stringify(c),JSON.stringify(r)],{encoding:'utf8',timeout:12000});
 assert.equal(p.status,97,p.stderr);
 await rejects(()=>f.outbox().inspect(),'FORENSIC_OUTBOX_PENDING_REVIEW_REQUIRED');
});
test('31J actual child-process crash after commit fsync retains prepared event',async t=>{
 const f=await fixture(t),r=f.record(),{script,c}=childScript(f,r,'after-commit-sync');
 const p=spawnSync(process.execPath,['--input-type=module','-e',script,f.publicationDirectory,f.outboxDirectory,JSON.stringify(c),JSON.stringify(r)],{encoding:'utf8',timeout:12000});
 assert.equal(p.status,97,p.stderr);
 const s=await f.outbox().inspect();assert.equal(s.pendingPublicationIndex,1);
 await rejects(()=>f.outbox().reconcile({expectedOutboxHead:{count:1,headDigest:s.headDigest},expectedPublicationHead:zero}),'FORENSIC_OUTBOX_UNCERTAIN_PREPARE');
});

function childPublicationScript(f,stage){
 const pub=fileURLToPath(new URL('../src/offline-forensic-head-publication.mjs',import.meta.url));
 const c={registryId,anchorType,witnessQuorum:2,witnesses:f.config.witnesses.map(w=>({id:w.id,pem:w.publicKey.export({type:'spki',format:'pem'})})),reviewerPolicies:f.config.reviewerPolicies.map(p=>({quorum:p.quorum,reviewers:p.reviewers.map(v=>({id:v.id,pem:v.publicKey.export({type:'spki',format:'pem'})}))}))};
 const script=`import {createPublicKey} from 'node:crypto';import {createOfflineForensicPublicationStore} from ${JSON.stringify(pub)};const c=JSON.parse(process.argv[2]);c.witnesses=c.witnesses.map(w=>({id:w.id,publicKey:createPublicKey(w.pem)}));c.reviewerPolicies=c.reviewerPolicies.map(p=>({quorum:p.quorum,reviewers:p.reviewers.map(r=>({id:r.id,publicKey:createPublicKey(r.pem),readLatest:async()=>null}))}));const store=createOfflineForensicPublicationStore({...c,directory:process.argv[1],injectFault:stage=>{if(stage===${JSON.stringify(stage)})process.exit(99)}});await store.append({record:JSON.parse(process.argv[3]),expectedHead:{count:0,headDigest:'0'.repeat(64)}});`;
 return {script,c};
}
test('31J real crash after publication commit before ack fails closed, then accepts independent signed ack',async t=>{
 const f=await fixture(t),r=f.record(),o=f.outbox(),p=await o.prepare({record:r,expectedOutboxHead:zero,expectedPublicationHead:zero});
 const {script,c}=childPublicationScript(f,'after-commit-sync');
 const child=spawnSync(process.execPath,['--input-type=module','-e',script,f.publicationDirectory,JSON.stringify(c),JSON.stringify(r)],{encoding:'utf8',timeout:12000});
 assert.equal(child.status,99,child.stderr);
 const pubHead={count:1,headDigest:r.digest},outHead={count:1,headDigest:p.headDigest};
 assert.equal((await f.store().inspect()).count,1);
 await rejects(()=>o.reconcile({expectedOutboxHead:outHead,expectedPublicationHead:pubHead}),'FORENSIC_OUTBOX_UNACKNOWLEDGED');
 const a=await o.acknowledge({acknowledgement:f.ack(r),expectedOutboxHead:outHead,expectedPublicationHead:pubHead});
 assert.equal((await f.outbox().reconcile({expectedOutboxHead:{count:2,headDigest:a.headDigest},expectedPublicationHead:pubHead})).verified,true);
});
test('31J real crash before publication commit blocks outbox acknowledgement and reconciliation',async t=>{
 const f=await fixture(t),r=f.record(),o=f.outbox(),p=await o.prepare({record:r,expectedOutboxHead:zero,expectedPublicationHead:zero});
 const {script,c}=childPublicationScript(f,'after-pending-sync');
 const child=spawnSync(process.execPath,['--input-type=module','-e',script,f.publicationDirectory,JSON.stringify(c),JSON.stringify(r)],{encoding:'utf8',timeout:12000});
 assert.equal(child.status,99,child.stderr);
 await rejects(()=>o.reconcile({expectedOutboxHead:{count:1,headDigest:p.headDigest},expectedPublicationHead:zero}),'FORENSIC_PUBLICATION_PENDING_REVIEW_REQUIRED');
 await rejects(()=>o.acknowledge({acknowledgement:f.ack(r),expectedOutboxHead:{count:1,headDigest:p.headDigest},expectedPublicationHead:zero}),'FORENSIC_PUBLICATION_PENDING_REVIEW_REQUIRED');
});
