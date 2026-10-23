import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,readFile,writeFile,unlink,symlink} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import {createHash,generateKeyPairSync,sign,createPublicKey} from 'node:crypto';
import {
 OFFLINE_FORENSIC_PUBLICATION_SCHEMA,forensicPublicationPolicyDigest,
 forensicPublicationRotationBytes,forensicPublicationSigningBytes,
 verifyOfflineForensicPublicationHistory,verifyOfflinePublishedForensicEvidenceBundle,createOfflineForensicPublicationStore
} from '../src/offline-forensic-head-publication.mjs';
const registryId='synthetic-publication-registry-31ib',anchorType='registry',ROOT='0'.repeat(64);
const sha=x=>createHash('sha256').update(x).digest('hex');
const fails=(fn,code)=>assert.throws(fn,e=>e?.code===code);
const rejects=(fn,code)=>assert.rejects(fn,e=>e?.code===code);
const pk=()=>generateKeyPairSync('ed25519');
const member=(k,id)=>({id,publicKey:k.publicKey});
const reviewer=(k,id)=>({...member(k,id),readLatest:async()=>{throw Error('offline only');}});
const signing=(k,b)=>sign(null,b,k.privateKey).toString('base64url');
async function fixture(t){
 const directory=await mkdtemp(join(tmpdir(),'tj-31ib-'));t.after(()=>rm(directory,{recursive:true,force:true}));
 const witnessKeys=[pk(),pk(),pk()],oldKeys=[pk(),pk()],newKeys=[pk(),pk()];
 const witnesses=witnessKeys.map((k,i)=>member(k,`synthetic-witness-31ib-${i}`));
 const reviewerPolicies=[
  {reviewers:oldKeys.map((k,i)=>reviewer(k,`synthetic-reviewer-31ib-${i}`)),quorum:2},
  {reviewers:newKeys.map((k,i)=>reviewer(k,`synthetic-reviewer-31ib-${i}`)),quorum:2}
 ];
 const cfg={directory,registryId,anchorType,witnesses,witnessQuorum:2,reviewerPolicies};
 const store=(options={})=>createOfflineForensicPublicationStore({...cfg,...options});
 const make=({previous=null,forensicCount=1,forensicHeadDigest='a'.repeat(64),policyIndex=0,publishedAt=1700000000000,witnessIds=[0,1],rotation=true}={})=>{
  const b={schema:OFFLINE_FORENSIC_PUBLICATION_SCHEMA,registryId,anchorType,index:(previous?.index??0)+1,previousDigest:previous?.digest??ROOT,forensicCount,forensicHeadDigest,policyIndex,policyDigest:forensicPublicationPolicyDigest(reviewerPolicies[policyIndex]),publishedAt};
  const rotationApprovals=previous&&policyIndex>previous.policyIndex&&rotation?oldKeys.map((k,i)=>({reviewerId:`synthetic-reviewer-31ib-${i}`,signature:signing(k,forensicPublicationRotationBytes(b))})):[];
  const witnessSignatures=witnessIds.map(i=>({witnessId:witnesses[i].id,signature:signing(witnessKeys[i],forensicPublicationSigningBytes(b,rotationApprovals))}));
  const unsigned={...b,rotationApprovals,witnessSignatures};
  return {...unsigned,digest:sha(Buffer.from(`${OFFLINE_FORENSIC_PUBLICATION_SCHEMA}\0${JSON.stringify(unsigned)}`))};
 };
 const verify=(publications,expectedHead={count:publications.length,headDigest:publications.at(-1)?.digest??ROOT},extra={})=>verifyOfflineForensicPublicationHistory({...cfg,publications,expectedHead,...extra});
 return {...cfg,store,make,verify,witnessKeys,oldKeys,newKeys};
}
test('31I-B independently signed publication and pinned forensic head verify',async t=>{
 const f=await fixture(t),a=f.make();
 assert.deepEqual(f.verify([a],{count:1,headDigest:a.digest},{expectedForensicHead:{count:1,headDigest:'a'.repeat(64)}}),{verified:true,count:1,headDigest:a.digest,forensicHead:{count:1,headDigest:'a'.repeat(64)},productionApproved:false});
});
test('31I-B durable append and restart retains canonical signed history',async t=>{
 const f=await fixture(t),a=f.make(),s=f.store();
 assert.equal((await s.append({record:a,expectedHead:{count:0,headDigest:ROOT}})).recorded,true);
 const hist=await f.store().inspectHistory({expectedHead:{count:1,headDigest:a.digest}});
 assert.deepEqual(hist.publications,[a]);
});
test('31I-B authenticated reviewer rotation requires old quorum and new pinned policy',async t=>{
 const f=await fixture(t),a=f.make(),b=f.make({previous:a,forensicCount:2,forensicHeadDigest:'b'.repeat(64),policyIndex:1,publishedAt:1700000001000});
 assert.equal(f.verify([a,b]).verified,true);
 const s=f.store();await s.append({record:a,expectedHead:{count:0,headDigest:ROOT}});
 assert.equal((await s.append({record:b,expectedHead:{count:1,headDigest:a.digest}})).count,2);
});
test('31I-B missing old reviewer rotation approval is rejected',async t=>{
 const f=await fixture(t),a=f.make(),b=f.make({previous:a,policyIndex:1,publishedAt:1700000001000,rotation:false});
 fails(()=>f.verify([a,b]),'FORENSIC_PUBLICATION_ROTATION_INVALID');
});
test('31I-B forged old reviewer approval is rejected',async t=>{
 const f=await fixture(t),a=f.make(),b=f.make({previous:a,policyIndex:1,publishedAt:1700000001000});
 b.rotationApprovals[0].signature='A'.repeat(86);
 fails(()=>f.verify([a,b]),'FORENSIC_PUBLICATION_ROTATION_INVALID');
});
test('31I-B publication cannot skip a reviewer policy transition',async t=>{
 const f=await fixture(t),a=f.make({policyIndex:1});fails(()=>f.verify([a]),'FORENSIC_PUBLICATION_POLICY_SKIP');
});
test('31I-B witness quorum cannot be forged or duplicated',async t=>{
 const f=await fixture(t),a=f.make();a.witnessSignatures[1].witnessId=a.witnessSignatures[0].witnessId;
 fails(()=>f.verify([a]),'FORENSIC_PUBLICATION_WITNESS_INVALID');
});
test('31I-B cross-domain witness substitution is rejected',async t=>{
 const f=await fixture(t),a=f.make();a.witnessSignatures[0].signature=signing(f.witnessKeys[0],Buffer.from('wrong-domain'));
 fails(()=>f.verify([a]),'FORENSIC_PUBLICATION_WITNESS_INVALID');
});
test('31I-B exact externally pinned publication head prevents valid-prefix rollback',async t=>{
 const f=await fixture(t),a=f.make(),b=f.make({previous:a,forensicCount:2,forensicHeadDigest:'b'.repeat(64),publishedAt:1700000001000});
 fails(()=>f.verify([a],{count:2,headDigest:b.digest}),'FORENSIC_PUBLICATION_PIN_MISMATCH');
});
test('31I-B same forensic count with different head is rejected',async t=>{
 const f=await fixture(t),a=f.make(),b=f.make({previous:a,forensicCount:1,forensicHeadDigest:'b'.repeat(64),publishedAt:1700000001000});
 fails(()=>f.verify([a,b]),'FORENSIC_PUBLICATION_ROLLBACK');
});
test('31I-B timestamp rollback and count rollback rejected',async t=>{
 const f=await fixture(t),a=f.make({forensicCount:2}),b=f.make({previous:a,forensicCount:1,publishedAt:1700000001000}),c=f.make({previous:a,forensicCount:3,publishedAt:1699999999999});
 fails(()=>f.verify([a,b]),'FORENSIC_PUBLICATION_ROLLBACK');fails(()=>f.verify([a,c]),'FORENSIC_PUBLICATION_ROLLBACK');
});
test('31I-B altered publication data invalidates witness signatures',async t=>{
 const f=await fixture(t),a=f.make();a.forensicHeadDigest='f'.repeat(64);
 fails(()=>f.verify([a]),'FORENSIC_PUBLICATION_WITNESS_INVALID');
});
test('31I-B stale concurrent append cannot replace or fork history',async t=>{
 const f=await fixture(t),a=f.make(),b=f.make({forensicCount:2,forensicHeadDigest:'b'.repeat(64)}),s=f.store();
 const results=await Promise.allSettled([s.append({record:a,expectedHead:{count:0,headDigest:ROOT}}),s.append({record:b,expectedHead:{count:0,headDigest:ROOT}})]);
 assert.equal(results.filter(r=>r.status==='fulfilled').length,1);
 assert.equal(results.filter(r=>r.status==='rejected'&&r.reason.code==='FORENSIC_PUBLICATION_STALE_PIN').length,1);
 assert.equal((await s.inspect()).count,1);
});
test('31I-B disk record tampering rejects inspection',async t=>{
 const f=await fixture(t),a=f.make(),s=f.store();await s.append({record:a,expectedHead:{count:0,headDigest:ROOT}});
 const path=join(f.directory,'0000000001.json'),r=JSON.parse(await readFile(path,'utf8'));r.witnessSignatures[0].signature='A'.repeat(86);await writeFile(path,JSON.stringify(r));
 await rejects(()=>s.inspect(),'FORENSIC_PUBLICATION_WITNESS_INVALID');
});
test('31I-B missing numbered record rejects gap',async t=>{
 const f=await fixture(t),a=f.make(),b=f.make({previous:a,forensicCount:2,forensicHeadDigest:'b'.repeat(64),publishedAt:1700000001000}),s=f.store();
 await s.append({record:a,expectedHead:{count:0,headDigest:ROOT}});await s.append({record:b,expectedHead:{count:1,headDigest:a.digest}});
 await unlink(join(f.directory,'0000000001.json'));await rejects(()=>s.inspect(),'FORENSIC_PUBLICATION_HISTORY_GAP');
});
test('31I-B symlink substitution of a publication is rejected',async t=>{
 const f=await fixture(t),a=f.make(),s=f.store();await s.append({record:a,expectedHead:{count:0,headDigest:ROOT}});
 const path=join(f.directory,'0000000001.json'),copy=join(f.directory,'elsewhere');await writeFile(copy,JSON.stringify(a));await unlink(path);await symlink(copy,path);
 await rejects(()=>s.inspect(),'FORENSIC_PUBLICATION_FILE_UNSAFE');
});
test('31I-B witness and reviewer key reuse is rejected',async t=>{
 const f=await fixture(t),p=f.reviewerPolicies[0],bad=[{...p,reviewers:[{...p.reviewers[0],publicKey:f.witnesses[0].publicKey},p.reviewers[1]]},f.reviewerPolicies[1]];
 fails(()=>f.verify([],{count:0,headDigest:ROOT},{reviewerPolicies:bad}),'RECOVERY_ADJUDICATION_SHARED_OR_DUPLICATE_KEY');
});
test('31I-B retired reviewer signing key cannot reactivate after rotation',async t=>{
 const f=await fixture(t),bad=[...f.reviewerPolicies,f.reviewerPolicies[0]];
 fails(()=>f.verify([],{count:0,headDigest:ROOT},{reviewerPolicies:bad}),'FORENSIC_PUBLICATION_KEY_REACTIVATED');
});
test('31I-B actual child process crash after durable pending write blocks recovery',async t=>{
 const f=await fixture(t),a=f.make();
 const env={...process.env,TJ_CFG:JSON.stringify({directory:f.directory,registryId,anchorType,witnessQuorum:2,witnesses:f.witnesses.map(w=>({id:w.id,pem:w.publicKey.export({type:'spki',format:'pem'})})),reviewerPolicies:f.reviewerPolicies.map(p=>({quorum:p.quorum,reviewers:p.reviewers.map(r=>({id:r.id,pem:r.publicKey.export({type:'spki',format:'pem'})}))})),record:a})};
 const code=`import {createPublicKey} from 'node:crypto';import {createOfflineForensicPublicationStore} from ${JSON.stringify(new URL('../src/offline-forensic-head-publication.mjs',import.meta.url).href)};const c=JSON.parse(process.env.TJ_CFG);const witnesses=c.witnesses.map(w=>({id:w.id,publicKey:createPublicKey(w.pem)}));const reviewerPolicies=c.reviewerPolicies.map(p=>({quorum:p.quorum,reviewers:p.reviewers.map(r=>({id:r.id,publicKey:createPublicKey(r.pem),readLatest:async()=>{}}))}));const store=createOfflineForensicPublicationStore({...c,witnesses,reviewerPolicies,injectFault:stage=>{if(stage==='after-pending-sync')process.kill(process.pid,'SIGKILL');}});await store.append({record:c.record,expectedHead:{count:0,headDigest:'0'.repeat(64)}});`;
 const child=spawnSync(process.execPath,['--input-type=module','-e',code],{env,timeout:12000});assert.equal(child.signal,'SIGKILL',`status=${child.status} stderr=${child.stderr?.toString()}`);
 await rejects(()=>f.store().inspect(),'FORENSIC_PUBLICATION_PENDING_REVIEW_REQUIRED');
 await rejects(()=>f.store().append({record:a,expectedHead:{count:0,headDigest:ROOT}}),'FORENSIC_PUBLICATION_PENDING_REVIEW_REQUIRED');
});
test('31I-B actual child crash after committed fsync is readable, stale replay rejected',async t=>{
 const f=await fixture(t),a=f.make();
 const env={...process.env,TJ_CFG:JSON.stringify({directory:f.directory,registryId,anchorType,witnessQuorum:2,witnesses:f.witnesses.map(w=>({id:w.id,pem:w.publicKey.export({type:'spki',format:'pem'})})),reviewerPolicies:f.reviewerPolicies.map(p=>({quorum:p.quorum,reviewers:p.reviewers.map(r=>({id:r.id,pem:r.publicKey.export({type:'spki',format:'pem'})}))})),record:a})};
 const code=`import {createPublicKey} from 'node:crypto';import {createOfflineForensicPublicationStore} from ${JSON.stringify(new URL('../src/offline-forensic-head-publication.mjs',import.meta.url).href)};const c=JSON.parse(process.env.TJ_CFG);const witnesses=c.witnesses.map(w=>({id:w.id,publicKey:createPublicKey(w.pem)}));const reviewerPolicies=c.reviewerPolicies.map(p=>({quorum:p.quorum,reviewers:p.reviewers.map(r=>({id:r.id,publicKey:createPublicKey(r.pem),readLatest:async()=>{}}))}));const store=createOfflineForensicPublicationStore({...c,witnesses,reviewerPolicies,injectFault:stage=>{if(stage==='after-commit-sync')process.kill(process.pid,'SIGKILL');}});await store.append({record:c.record,expectedHead:{count:0,headDigest:'0'.repeat(64)}});`;
 const child=spawnSync(process.execPath,['--input-type=module','-e',code],{env,timeout:12000});assert.equal(child.signal,'SIGKILL',child.stderr?.toString());
 assert.deepEqual(await f.store().inspect({expectedHead:{count:1,headDigest:a.digest}}),{count:1,headDigest:a.digest,productionApproved:false});
 await rejects(()=>f.store().append({record:a,expectedHead:{count:0,headDigest:ROOT}}),'FORENSIC_PUBLICATION_STALE_PIN');
});
test('31I-B disk valid-prefix rollback requires an external pinned head to detect',async t=>{
 const f=await fixture(t),a=f.make(),b=f.make({previous:a,forensicCount:2,forensicHeadDigest:'b'.repeat(64),publishedAt:1700000001000}),s=f.store();
 await s.append({record:a,expectedHead:{count:0,headDigest:ROOT}});await s.append({record:b,expectedHead:{count:1,headDigest:a.digest}});
 await unlink(join(f.directory,'0000000002.json'));
 assert.equal((await s.inspect()).count,1); // explicit limit: local-only inspection cannot know rollback
 await rejects(()=>s.inspect({expectedHead:{count:2,headDigest:b.digest}}),'FORENSIC_PUBLICATION_PIN_MISMATCH');
});
test('31I-B forged policy digest is rejected before publication signatures',async t=>{
 const f=await fixture(t),a=f.make();a.policyDigest='e'.repeat(64);
 fails(()=>f.verify([a]),'FORENSIC_PUBLICATION_CHAIN_INVALID');
});
test('31I-B malformed event fails closed with typed error',async t=>{
 const f=await fixture(t);fails(()=>f.verify([null],{count:1,headDigest:'a'.repeat(64)}),'FORENSIC_PUBLICATION_RECORD_INVALID');
});
test('31I-B forged external forensic head pin is rejected',async t=>{
 const f=await fixture(t),a=f.make();fails(()=>f.verify([a],{count:1,headDigest:a.digest},{expectedForensicHead:{count:1,headDigest:'f'.repeat(64)}}),'FORENSIC_PUBLICATION_FORENSIC_PIN_MISMATCH');
});

test('31I-B composite verifier binds published genesis to exact portable empty forensic chain',async t=>{
 const f=await fixture(t),a=f.make({forensicCount:0,forensicHeadDigest:ROOT});
 const reviewerEpochs=[{startIndex:1,...f.reviewerPolicies[0]}];
 const result=verifyOfflinePublishedForensicEvidenceBundle({...f,events:[],reviewerEpochs,expectedForensicHead:{count:0,headDigest:ROOT},publications:[a],expectedPublicationHead:{count:1,headDigest:a.digest}});
 assert.deepEqual(result,{verified:true,publicationHead:{count:1,headDigest:a.digest},forensicHead:{count:0,headDigest:ROOT},productionApproved:false});
});
test('31I-B composite verifier rejects mismatched pinned epoch identity',async t=>{
 const f=await fixture(t),a=f.make({forensicCount:0,forensicHeadDigest:ROOT});
 const reviewerEpochs=[{startIndex:1,...f.reviewerPolicies[1]}];
 fails(()=>verifyOfflinePublishedForensicEvidenceBundle({...f,events:[],reviewerEpochs,expectedForensicHead:{count:0,headDigest:ROOT},publications:[a],expectedPublicationHead:{count:1,headDigest:a.digest}}),'FORENSIC_PUBLICATION_EPOCH_BINDING_INVALID');
});
test('31I-B cross-process flock excludes a competing reader throughout durable append',async t=>{
 const f=await fixture(t),a=f.make();let enter,release;
 const entered=new Promise(r=>enter=r),gate=new Promise(r=>release=r);
 const s=f.store({injectFault:async stage=>{if(stage==='after-pending-sync'){enter();await gate;}}});
 const append=s.append({record:a,expectedHead:{count:0,headDigest:ROOT}});
 await entered;
 try{
  const env={...process.env,TJ_CFG:JSON.stringify({directory:f.directory,registryId,anchorType,witnessQuorum:2,witnesses:f.witnesses.map(w=>({id:w.id,pem:w.publicKey.export({type:'spki',format:'pem'})})),reviewerPolicies:f.reviewerPolicies.map(p=>({quorum:p.quorum,reviewers:p.reviewers.map(r=>({id:r.id,pem:r.publicKey.export({type:'spki',format:'pem'})}))}))})};
  const code=`import {createPublicKey} from 'node:crypto';import {createOfflineForensicPublicationStore} from ${JSON.stringify(new URL('../src/offline-forensic-head-publication.mjs',import.meta.url).href)};const c=JSON.parse(process.env.TJ_CFG);const witnesses=c.witnesses.map(w=>({id:w.id,publicKey:createPublicKey(w.pem)}));const reviewerPolicies=c.reviewerPolicies.map(p=>({quorum:p.quorum,reviewers:p.reviewers.map(r=>({id:r.id,publicKey:createPublicKey(r.pem),readLatest:async()=>{}}))}));try{await createOfflineForensicPublicationStore({...c,witnesses,reviewerPolicies,lockTimeoutMs:100}).inspect();process.exit(2);}catch(e){if(e.code!=='FORENSIC_PUBLICATION_LOCK_UNAVAILABLE'){console.error(e.code);process.exit(3);}process.exit(0);}`;
  const child=spawnSync(process.execPath,['--input-type=module','-e',code],{env,timeout:12000});
  assert.equal(child.status,0,child.stderr?.toString());
 }finally{release();}
 await append;
 assert.equal((await f.store().inspect()).count,1);
});
