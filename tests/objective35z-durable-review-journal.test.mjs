import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {randomBytes,generateKeyPairSync,createHash} from 'node:crypto';
import {spawn} from 'node:child_process';
import {LocalDesignStore} from '../src/local-store.mjs';
import {createLocalArtworkQuarantineIntent} from '../src/preview-local-artwork-quarantine-review.mjs';
import {createLocalArtworkReviewEvidence,verifyHistoricalLocalArtworkReviewSignature} from '../src/preview-local-artwork-review-evidence.mjs';
import {createLocalArtworkReviewJournal,localArtworkReviewJournalGenesisHead as genesis} from '../src/preview-local-artwork-review-journal.mjs';
const png=Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/lIgAAAAASUVORK5CYII=','base64');
const now=1800000000000;
const reviewKey=randomBytes(32),pair=generateKeyPairSync('ed25519'),other=generateKeyPairSync('ed25519');
const resolver=async id=>id==='reviewer'?pair.publicKey:null;
const rejects=(p,code)=>assert.rejects(p,e=>e?.code===code);
async function setup(t){
 const base=await fs.mkdtemp(join(tmpdir(),'tj35z-'));
 t.after(()=>fs.rm(base,{recursive:true,force:true}));
 const root=join(base,'artwork-root'),directory=join(base,'review-ledger');
 const store=new LocalDesignStore(root);await store.init();
 const a=await store.putArtwork(png,'image/png');await store.putArtwork(png,'image/png');
 await store.putDesign({productManifestId:'concept-crew-tee',layers:[{id:'one',type:'artwork',surfaceId:'front',x:.1,y:.1,width:.2,height:.2,rotationDeg:0,artworkId:a.id}],artworkGrants:{[a.id]:a.grant}});
 return {base,root,directory,store};
}
async function signed(root,{challenge=randomBytes(16).toString('hex'),nonce=randomBytes(16).toString('hex')}={}){
 const ticket=await createLocalArtworkQuarantineIntent(root,{reviewKey,now,nonce});
 const evidence=await createLocalArtworkReviewEvidence(root,ticket,{reviewKey,signingKey:pair.privateKey,keyId:'reviewer',challenge,now});
 return {ticket,evidence};
}
const opts=(v,e,expectedHead=genesis())=>({...e,reviewKey,resolvePublicKey:resolver,
 expectedChallenge:e.evidence.challenge,expectedHead,now});
const journal=v=>createLocalArtworkReviewJournal(v);
const record=(v,n)=>join(v.directory,String(n).padStart(4,'0')+'.json');
async function runWorker(fixture){
 const path=join(fixture.base,'worker-'+randomBytes(4).toString('hex')+'.json');
 const {base,...data}=fixture;await fs.writeFile(path,JSON.stringify(data));
 return new Promise((resolve,reject)=>{
  const p=spawn(process.execPath,[new URL('./support/objective35z-worker.mjs',import.meta.url).pathname,path],{stdio:['ignore','pipe','pipe']});
  let out='',err='';p.stdout.on('data',b=>out+=b);p.stderr.on('data',b=>err+=b);
  p.once('error',reject);p.once('close',(code,signal)=>resolve({code,signal,out,err}));
 });
}
function workerFixture(v,e,head=genesis(),stage){return {...v,...e,expectedHead:head,now,
 reviewKey:reviewKey.toString('hex'),publicKey:pair.publicKey.export({type:'spki',format:'pem'}),stage};}

test('35Z canonical signed transcript admitted with no mutation or commerce authority',async t=>{
 const v=await setup(t),e=await signed(v.root),j=journal(v);
 const before=await fs.readdir(join(v.root,'artworks'));
 const r=await j.admit(opts(v,e));
 assert.equal(r.head.count,1);assert.equal(r.entries.length,1);
 assert.equal(r.durableLocalTranscript,true);assert.equal(r.independentlyWitnessed,false);
 assert.equal(r.authorizesDeletion,false);assert.equal(r.authorizesQuarantine,false);
 assert.equal(r.shopifyWritesAllowed,false);assert.equal(r.authorizesProduction,false);
 assert.equal(r.liveSnapshotVerified,false);assert.equal(r.historySignaturesVerified,true);
 assert.equal(r.entries[0].challenge,e.evidence.challenge);
 assert.deepEqual(await fs.readdir(join(v.root,'artworks')),before);
 assert.deepEqual((await j.inspect({expectedHead:r.head,resolvePublicKey:resolver})).head,r.head);
 assert.equal((await fs.stat(record(v,1))).mode&0o077,0);
});
test('35Z genesis and head are deterministic and external pin is mandatory',async t=>{
 const v=await setup(t),e=await signed(v.root),j=journal(v);
 assert.deepEqual(genesis(),genesis());
 await rejects(j.admit({...opts(v,e),expectedHead:undefined}),'LOCAL_REVIEW_JOURNAL_INVALID_REQUEST');
 const r=await j.admit(opts(v,e));
 await rejects(j.inspect({resolvePublicKey:resolver}),'LOCAL_REVIEW_JOURNAL_EXTERNAL_HEAD_REQUIRED');
 await rejects(j.inspect({expectedHead:genesis(),resolvePublicKey:resolver}),'LOCAL_REVIEW_JOURNAL_STALE_OR_ROLLED_BACK_HEAD');
 await rejects(j.inspect({expectedHead:{...r.head,unexpected:1},resolvePublicKey:resolver}),'LOCAL_REVIEW_JOURNAL_EXTERNAL_HEAD_REQUIRED');
});
test('35Z append two distinct signed reviews in order with exact chain continuity',async t=>{
 const v=await setup(t),j=journal(v),a=await signed(v.root);
 const one=await j.admit(opts(v,a));const b=await signed(v.root);
 const two=await j.admit(opts(v,b,one.head));
 assert.equal(two.head.count,2);assert.notEqual(one.head.headDigest,two.head.headDigest);
 const first=JSON.parse(await fs.readFile(record(v,1),'utf8'));
 const second=JSON.parse(await fs.readFile(record(v,2),'utf8'));
 assert.equal(second.previousRecordDigest,first.recordDigest);
 assert.equal(two.head.headDigest,second.recordDigest);
 assert.deepEqual((await j.inspect({expectedHead:two.head,resolvePublicKey:resolver})).entries.map(x=>x.index),[1,2]);
});
test('35Z same evidence cannot be replayed after acceptance',async t=>{
 const v=await setup(t),e=await signed(v.root),j=journal(v),r=await j.admit(opts(v,e));
 await rejects(j.admit(opts(v,e,r.head)),'LOCAL_REVIEW_JOURNAL_REPLAY');
 assert.equal((await fs.readdir(v.directory)).filter(x=>x.endsWith('.json')).length,1);
});
test('35Z same ticket with different signed challenge is replay',async t=>{
 const v=await setup(t),e=await signed(v.root),j=journal(v),r=await j.admit(opts(v,e));
 const b={ticket:e.ticket,evidence:await createLocalArtworkReviewEvidence(v.root,e.ticket,{reviewKey,signingKey:pair.privateKey,keyId:'reviewer',challenge:randomBytes(16).toString('hex'),now})};
 await rejects(j.admit(opts(v,b,r.head)),'LOCAL_REVIEW_JOURNAL_REPLAY');
});
test('35Z reused challenge with distinct ticket and signature is replay',async t=>{
 const v=await setup(t),e=await signed(v.root),j=journal(v),r=await j.admit(opts(v,e));
 const b=await signed(v.root,{challenge:e.evidence.challenge});
 await rejects(j.admit(opts(v,b,r.head)),'LOCAL_REVIEW_JOURNAL_REPLAY');
});
test('35Z forged challenge fails before journal append',async t=>{
 const v=await setup(t),e=await signed(v.root),j=journal(v);
 await rejects(j.admit({...opts(v,e),expectedChallenge:'a'.repeat(32)}),'LOCAL_REVIEW_EVIDENCE_WRONG_CHALLENGE');
 assert.deepEqual((await fs.readdir(v.directory)).filter(x=>x.endsWith('.json')),[]);
});
test('35Z signed evidence tamper cannot be admitted',async t=>{
 const v=await setup(t),e=await signed(v.root),j=journal(v);
 await rejects(j.admit(opts(v,{...e,evidence:{...e.evidence,referencePin:'a'.repeat(64)}})),'LOCAL_REVIEW_EVIDENCE_BAD_SIGNATURE');
});
test('35Z expired signed evidence fails closed',async t=>{
 const v=await setup(t),e=await signed(v.root),j=journal(v);
 await rejects(j.admit({...opts(v,e),now:e.evidence.expiresAt}),'LOCAL_REVIEW_EVIDENCE_EXPIRED');
});
test('35Z wrong owner root cannot accept another root signed review',async t=>{
 const v=await setup(t),w=await setup(t),e=await signed(v.root),j=journal(w);
 await rejects(j.admit(opts(w,e)),'LOCAL_QUARANTINE_REVIEW_WRONG_ROOT');
});
test('35Z stale artwork bytes prevent admission',async t=>{
 const v=await setup(t),e=await signed(v.root),j=journal(v);
 const p=join(v.root,'artworks',e.evidence.candidateArtworkIds[0]+'.png');
 const b=await fs.readFile(p);b[20]^=1;await fs.writeFile(p,b);
 await assert.rejects(j.admit(opts(v,e)),x=>x?.code?.startsWith('LOCAL_'));
 assert.deepEqual((await fs.readdir(v.directory)).filter(x=>x.endsWith('.json')),[]);
});
test('35Z current trusted key rotation blocks historical signature inspection',async t=>{
 const v=await setup(t),e=await signed(v.root),j=journal(v),r=await j.admit(opts(v,e));
 await rejects(j.inspect({expectedHead:r.head,resolvePublicKey:async()=>other.publicKey}),'LOCAL_REVIEW_JOURNAL_HISTORY_INVALID');
});
test('35Z historical verifier cannot claim current freshness or authority',async t=>{
 const v=await setup(t),e=await signed(v.root);
 const r=await verifyHistoricalLocalArtworkReviewSignature(e.evidence,{resolvePublicKey:resolver});
 assert.equal(r.historicalSignatureVerified,true);assert.equal(r.liveSnapshotVerified,false);
 assert.equal(r.currentFreshnessVerified,false);assert.equal(r.authority,'NONE');
 assert.equal(r.safeToAutoDelete,false);assert.equal(r.shopifyWritesAllowed,false);
});
test('35Z historical verifier rejects forged signature, key and extra fields',async t=>{
 const v=await setup(t),e=await signed(v.root);
 await rejects(verifyHistoricalLocalArtworkReviewSignature({...e.evidence,signature:'A'.repeat(86)},{resolvePublicKey:resolver}),'LOCAL_REVIEW_EVIDENCE_BAD_SIGNATURE');
 await rejects(verifyHistoricalLocalArtworkReviewSignature(e.evidence,{resolvePublicKey:async()=>other.publicKey}),'LOCAL_REVIEW_EVIDENCE_BAD_SIGNATURE');
 await rejects(verifyHistoricalLocalArtworkReviewSignature({...e.evidence,admin:true},{resolvePublicKey:resolver}),'LOCAL_REVIEW_EVIDENCE_INVALID');
});
test('35Z historical ledger record tamper fails before returning any transcript',async t=>{
 const v=await setup(t),e=await signed(v.root),j=journal(v),r=await j.admit(opts(v,e));
 const p=record(v,1),entry=JSON.parse(await fs.readFile(p,'utf8'));
 entry.evidence.referencePin='a'.repeat(64);await fs.writeFile(p,JSON.stringify(entry));
 await rejects(j.inspect({expectedHead:r.head,resolvePublicKey:resolver}),'LOCAL_REVIEW_JOURNAL_HISTORY_INVALID');
});
test('35Z forged signed evidence within record rejected even if record digest is rehashed',async t=>{
 const v=await setup(t),e=await signed(v.root),j=journal(v),r=await j.admit(opts(v,e));
 const p=record(v,1),entry=JSON.parse(await fs.readFile(p,'utf8'));
 entry.evidence.candidateCount=2;
 const {recordDigest:_,...body}=entry;
 entry.recordDigest=createHash('sha256').update('TJ-35Z-RECORD\n'+JSON.stringify(body)).digest('hex');
 await fs.writeFile(p,JSON.stringify(entry));
 await rejects(j.inspect({expectedHead:r.head,resolvePublicKey:resolver}),'LOCAL_REVIEW_JOURNAL_HISTORY_INVALID');
});
test('35Z appended unknown fields and noncanonical JSON bytes rejected',async t=>{
 const v=await setup(t),e=await signed(v.root),j=journal(v),r=await j.admit(opts(v,e));
 const p=record(v,1);await fs.appendFile(p,'\n');
 await rejects(j.inspect({expectedHead:r.head,resolvePublicKey:resolver}),'LOCAL_REVIEW_JOURNAL_HISTORY_INVALID');
});
test('35Z truncated history fails against independent pinned head',async t=>{
 const v=await setup(t),j=journal(v),a=await signed(v.root);
 const one=await j.admit(opts(v,a)),b=await signed(v.root),two=await j.admit(opts(v,b,one.head));
 await fs.unlink(record(v,2));
 await rejects(j.inspect({expectedHead:two.head,resolvePublicKey:resolver}),'LOCAL_REVIEW_JOURNAL_STALE_OR_ROLLED_BACK_HEAD');
});
test('35Z missing middle record or reordered names fails closed',async t=>{
 const v=await setup(t),j=journal(v),a=await signed(v.root);
 const one=await j.admit(opts(v,a)),b=await signed(v.root),two=await j.admit(opts(v,b,one.head));
 await fs.rename(record(v,1),record(v,3));
 await rejects(j.inspect({expectedHead:two.head,resolvePublicKey:resolver}),'LOCAL_REVIEW_JOURNAL_HISTORY_INVALID');
});
test('35Z symlinked ledger directory is forbidden',async t=>{
 const v=await setup(t),e=await signed(v.root);
 await fs.mkdir(v.directory,{mode:0o700});const alias=join(v.base,'symlink');await fs.symlink(v.directory,alias);
 await rejects(journal({...v,directory:alias}).admit(opts(v,e)),'LOCAL_REVIEW_JOURNAL_DIRECTORY_UNSAFE');
});
test('35Z world-readable ledger directory is forbidden',async t=>{
 const v=await setup(t),e=await signed(v.root);
 await fs.mkdir(v.directory,{mode:0o755});
 await rejects(journal(v).admit(opts(v,e)),'LOCAL_REVIEW_JOURNAL_DIRECTORY_UNSAFE');
});
test('35Z symlinked record file rejected on inspection',async t=>{
 const v=await setup(t),e=await signed(v.root),j=journal(v),r=await j.admit(opts(v,e));
 const p=record(v,1),copy=join(v.base,'copy');await fs.rename(p,copy);await fs.symlink(copy,p);
 await rejects(j.inspect({expectedHead:r.head,resolvePublicKey:resolver}),'LOCAL_REVIEW_JOURNAL_RECORD_UNSAFE');
});
test('35Z unexpected file in ledger fails closed',async t=>{
 const v=await setup(t),e=await signed(v.root),j=journal(v),r=await j.admit(opts(v,e));
 await fs.writeFile(join(v.directory,'unknown.txt'),'unexpected');
 await rejects(j.inspect({expectedHead:r.head,resolvePublicKey:resolver}),'LOCAL_REVIEW_JOURNAL_HISTORY_INVALID');
});
test('35Z injected after-pending fault leaves uncertain marker and prevents retries',async t=>{
 const v=await setup(t),e=await signed(v.root);
 const j=journal({...v,injectFault:async stage=>{if(stage==='after-pending-sync')throw Error('synthetic crash');}});
 await assert.rejects(j.admit(opts(v,e)),/synthetic crash/);
 assert.ok((await fs.readdir(v.directory)).includes('.pending.json'));
 await rejects(journal(v).admit(opts(v,e)),'LOCAL_REVIEW_JOURNAL_UNCERTAIN_COMMIT');
 await rejects(journal(v).inspect({expectedHead:genesis(),resolvePublicKey:resolver}),'LOCAL_REVIEW_JOURNAL_UNCERTAIN_COMMIT');
});
test('35Z injected after-link fault blocks reads even if record appears complete',async t=>{
 const v=await setup(t),e=await signed(v.root);
 const j=journal({...v,injectFault:async stage=>{if(stage==='after-link-sync')throw Error('synthetic crash');}});
 await assert.rejects(j.admit(opts(v,e)),/synthetic crash/);
 assert.ok((await fs.readdir(v.directory)).includes('.pending.json'));
 assert.ok((await fs.readdir(v.directory)).includes('0001.json'));
 await rejects(journal(v).inspect({expectedHead:genesis(),resolvePublicKey:resolver}),'LOCAL_REVIEW_JOURNAL_UNCERTAIN_COMMIT');
});
test('35Z real SIGKILL after pending sync leaves fail-closed pending-only journal',async t=>{
 const v=await setup(t),e=await signed(v.root);
 const p=await runWorker(workerFixture(v,e,genesis(),'after-pending-sync'));
 assert.equal(p.signal,'SIGKILL');
 assert.ok((await fs.readdir(v.directory)).includes('.pending.json'));
 await rejects(journal(v).admit(opts(v,e)),'LOCAL_REVIEW_JOURNAL_UNCERTAIN_COMMIT');
});
test('35Z real SIGKILL after link sync leaves fail-closed linked-pending journal',async t=>{
 const v=await setup(t),e=await signed(v.root);
 const p=await runWorker(workerFixture(v,e,genesis(),'after-link-sync'));
 assert.equal(p.signal,'SIGKILL');
 assert.ok((await fs.readdir(v.directory)).includes('.pending.json'));
 assert.ok((await fs.readdir(v.directory)).includes('0001.json'));
 await rejects(journal(v).inspect({expectedHead:genesis(),resolvePublicKey:resolver}),'LOCAL_REVIEW_JOURNAL_UNCERTAIN_COMMIT');
});
test('35Z two independent processes serialize competing admissions, one wins',async t=>{
 const v=await setup(t),a=await signed(v.root),b=await signed(v.root);
 const [one,two]=await Promise.all([runWorker(workerFixture(v,a)),runWorker(workerFixture(v,b))]);
 assert.deepEqual([one.code,two.code].sort(),[0,2]);
 const success=[one,two].find(x=>x.code===0),failed=[one,two].find(x=>x.code===2);
 const head=JSON.parse(success.out.trim()).head;
 assert.equal(JSON.parse(failed.out.trim()).code,'LOCAL_REVIEW_JOURNAL_STALE_OR_ROLLED_BACK_HEAD');
 assert.equal((await journal(v).inspect({expectedHead:head,resolvePublicKey:resolver})).head.count,1);
});
test('35Z post-commit failure cannot silently replay an already committed review',async t=>{
 const v=await setup(t),e=await signed(v.root);
 const j=journal({...v,injectFault:async stage=>{if(stage==='after-commit-sync')throw Error('lost acknowledgment');}});
 await assert.rejects(j.admit(opts(v,e)),/lost acknowledgment/);
 const entry=JSON.parse(await fs.readFile(record(v,1),'utf8'));
 const head={count:1,headDigest:entry.recordDigest};
 assert.equal((await journal(v).inspect({expectedHead:head,resolvePublicKey:resolver})).head.count,1);
 await rejects(journal(v).admit(opts(v,e,head)),'LOCAL_REVIEW_JOURNAL_REPLAY');
});
test('35Z configuration rejects nested ledger inside artwork root',async t=>{
 const v=await setup(t);
 assert.throws(()=>journal({...v,directory:join(v.root,'review-ledger')}),e=>e.code==='LOCAL_REVIEW_JOURNAL_CONFIGURATION');
});
test('35Z hardlinked historical record cannot be accepted',async t=>{
 const v=await setup(t),e=await signed(v.root),j=journal(v),r=await j.admit(opts(v,e));
 await fs.link(record(v,1),join(v.base,'outside-hardlink'));
 await rejects(j.inspect({expectedHead:r.head,resolvePublicKey:resolver}),'LOCAL_REVIEW_JOURNAL_RECORD_UNSAFE');
});
test('35Z world-readable record cannot be accepted',async t=>{
 const v=await setup(t),e=await signed(v.root),j=journal(v),r=await j.admit(opts(v,e));
 await fs.chmod(record(v,1),0o644);
 await rejects(j.inspect({expectedHead:r.head,resolvePublicKey:resolver}),'LOCAL_REVIEW_JOURNAL_RECORD_UNSAFE');
});
test('35Z lock-path symlink substitution cannot be followed',async t=>{
 const v=await setup(t),e=await signed(v.root),j=journal(v),r=await j.admit(opts(v,e));
 const lock=join(v.directory,'.review-lock');await fs.unlink(lock);await fs.symlink(record(v,1),lock);
 await assert.rejects(j.inspect({expectedHead:r.head,resolvePublicKey:resolver}),x=>
  x?.code==='ELOOP'||x?.code==='LOCAL_REVIEW_JOURNAL_LOCK_UNSAFE');
});
