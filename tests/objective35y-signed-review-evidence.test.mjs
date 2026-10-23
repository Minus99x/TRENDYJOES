import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {randomBytes,generateKeyPairSync,createHash} from 'node:crypto';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {LocalDesignStore} from '../src/local-store.mjs';
import {createLocalArtworkQuarantineIntent,verifyLocalArtworkQuarantineIntent} from '../src/preview-local-artwork-quarantine-review.mjs';
import {createLocalArtworkReviewEvidence as create,verifyLocalArtworkReviewEvidence as verify} from '../src/preview-local-artwork-review-evidence.mjs';
const exec=promisify(execFile);
const png=Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/lIgAAAAASUVORK5CYII=','base64');
const reviewKey=randomBytes(32),challenge=randomBytes(16).toString('hex'),otherChallenge=randomBytes(16).toString('hex');
const pair=generateKeyPairSync('ed25519'),otherPair=generateKeyPairSync('ed25519');
const now=1800000000000;
const signer={reviewKey,signingKey:pair.privateKey,keyId:'operator-2026',challenge,now};
const verifier={reviewKey,resolvePublicKey:async id=>id==='operator-2026'?pair.publicKey:null,expectedChallenge:challenge,now};
const rejects=(promise,code)=>assert.rejects(promise,e=>e?.code===code);
async function setup(t){
 const root=await fs.mkdtemp(join(tmpdir(),'tj35y-'));t.after(()=>fs.rm(root,{recursive:true,force:true}));
 const store=new LocalDesignStore(root);await store.init();
 const a=await store.putArtwork(png,'image/png');const b=await store.putArtwork(png,'image/png');
 const saved=await store.putDesign({productManifestId:'concept-crew-tee',layers:[{id:'layer1',type:'artwork',surfaceId:'front',x:.1,y:.1,width:.2,height:.2,rotationDeg:0,artworkId:a.id}],artworkGrants:{[a.id]:a.grant}});
 const ticket=await createLocalArtworkQuarantineIntent(root,{reviewKey,now});
 return {root,store,a,b,saved,ticket};
}
async function signed(t){const v=await setup(t);return {...v,evidence:await create(v.root,v.ticket,signer)};}
const artpath=(root,id,ext='png')=>join(root,'artworks',id+'.'+ext);

// Core positive contract and explicit no-authority invariants.
test('35Y signs a complete content-pinned operator report without mutation authority',async t=>{
 const {root,ticket,evidence,b,a,saved}=await signed(t);
 const filesBefore=await fs.readdir(join(root,'artworks'));
 const result=await verify(root,evidence,ticket,verifier);
 assert.equal(result.verifiedReadOnly,true);assert.equal(result.safeToAutoDelete,false);
 assert.equal(result.safeToQuarantine,false);assert.equal(result.shopifyWritesAllowed,false);
 assert.equal(evidence.authority,'NONE');assert.equal(evidence.candidateCount,1);
 assert.deepEqual(evidence.candidateArtworkIds,[b.id]);assert.equal(evidence.referencePin,ticket.referencePin);
 assert.match(result.operatorReport,/Signature: VERIFIED/);assert.match(result.operatorReport,/NO DELETE\. NO QUARANTINE\. NO SHOPIFY WRITES/);
 assert.ok(result.operatorReport.includes(b.id));assert.ok(!result.operatorReport.includes(a.grant));
 assert.ok(!JSON.stringify({evidence,result}).includes(saved.ownerToken));
 assert.deepEqual(await fs.readdir(join(root,'artworks')),filesBefore);
});
test('35Y evidence digest is stable for repeated read-only verification',async t=>{
 const {root,ticket,evidence}=await signed(t);
 const one=await verify(root,evidence,ticket,verifier),two=await verify(root,evidence,ticket,verifier);
 assert.equal(one.evidenceDigest,two.evidenceDigest);assert.equal(one.operatorReport,two.operatorReport);
});
test('35Y rejects wrong reviewer challenge (cross-session replay) before scanning',async t=>{
 const {root,ticket,evidence}=await signed(t);let scans=0;
 const io={...fs,readdir:async(...args)=>{scans++;return fs.readdir(...args);}};
 await rejects(verify(root,evidence,ticket,{...verifier,expectedChallenge:otherChallenge,io}),'LOCAL_REVIEW_EVIDENCE_WRONG_CHALLENGE');
 assert.equal(scans,0);
});
test('35Y rejects forged challenge even if signature is retained',async t=>{
 const {root,ticket,evidence}=await signed(t);
 await rejects(verify(root,{...evidence,challenge:otherChallenge},ticket,{...verifier,expectedChallenge:otherChallenge}),'LOCAL_REVIEW_EVIDENCE_BAD_SIGNATURE');
});
test('35Y expiry rejects at boundary without rescanning',async t=>{
 const {root,ticket,evidence}=await signed(t);let scans=0;
 const io={...fs,readdir:async(...args)=>{scans++;return fs.readdir(...args);}};
 await rejects(verify(root,evidence,ticket,{...verifier,now:evidence.expiresAt,io}),'LOCAL_REVIEW_EVIDENCE_EXPIRED');
 assert.equal(scans,0);
});
test('35Y rejects evidence dated in the future',async t=>{
 const {root,ticket,evidence}=await signed(t);
 await rejects(verify(root,evidence,ticket,{...verifier,now:now-1}),'LOCAL_REVIEW_EVIDENCE_EXPIRED');
});
test('35Y cannot outlive underlying ticket',async t=>{
 const {root,ticket}=await setup(t);const evidence=await create(root,ticket,{...signer,ttlMs:300000});
 assert.equal(evidence.expiresAt,ticket.expiresAt);
});
test('35Y untrusted key ID fails closed before disk scan',async t=>{
 const {root,ticket,evidence}=await signed(t);let scans=0;
 const io={...fs,readdir:async(...args)=>{scans++;return fs.readdir(...args);}};
 await rejects(verify(root,evidence,ticket,{...verifier,resolvePublicKey:async()=>null,io}),'LOCAL_REVIEW_EVIDENCE_UNTRUSTED_SIGNER');
 assert.equal(scans,0);
});
test('35Y same key ID resolved to rotated public key rejects old signature',async t=>{
 const {root,ticket,evidence}=await signed(t);
 await rejects(verify(root,evidence,ticket,{...verifier,resolvePublicKey:async()=>otherPair.publicKey}),'LOCAL_REVIEW_EVIDENCE_BAD_SIGNATURE');
});
test('35Y private key cannot be used as trusted verifier key',async t=>{
 const {root,ticket,evidence}=await signed(t);
 await rejects(verify(root,evidence,ticket,{...verifier,resolvePublicKey:async()=>pair.privateKey}),'LOCAL_REVIEW_EVIDENCE_UNTRUSTED_SIGNER');
});
test('35Y forged candidate, count and authority flags rejected',async t=>{
 const {root,ticket,evidence}=await signed(t);
 for(const change of [{candidateArtworkIds:[]},{candidateCount:2},{authority:'DELETE'},
  {safeToAutoDelete:true},{safeToQuarantine:true},{shopifyWritesAllowed:true},{referenceScanComplete:false}]){
  await rejects(verify(root,{...evidence,...change},ticket,verifier),'LOCAL_REVIEW_EVIDENCE_INVALID');
 }
});
test('35Y signed metadata tampering cannot change reference pin or expiry',async t=>{
 const {root,ticket,evidence}=await signed(t);
 await rejects(verify(root,{...evidence,referencePin:'0'.repeat(64)},ticket,verifier),'LOCAL_REVIEW_EVIDENCE_BAD_SIGNATURE');
 await rejects(verify(root,{...evidence,expiresAt:evidence.expiresAt-1},ticket,verifier),'LOCAL_REVIEW_EVIDENCE_BAD_SIGNATURE');
});
test('35Y unknown signed fields and malformed signature are refused',async t=>{
 const {root,ticket,evidence}=await signed(t);
 await rejects(verify(root,{...evidence,authorization:'YES'},ticket,verifier),'LOCAL_REVIEW_EVIDENCE_INVALID');
 await rejects(verify(root,{...evidence,signature:'a'},ticket,verifier),'LOCAL_REVIEW_EVIDENCE_INVALID');
});
test('35Y signature from untrusted operator key rejected even with matching key ID',async t=>{
 const {root,ticket}=await setup(t);const evidence=await create(root,ticket,{...signer,signingKey:otherPair.privateKey});
 await rejects(verify(root,evidence,ticket,verifier),'LOCAL_REVIEW_EVIDENCE_BAD_SIGNATURE');
});
test('35Y cross-ticket replay fails even if artwork snapshot is unchanged',async t=>{
 const {root,ticket,evidence}=await signed(t);
 const second=await createLocalArtworkQuarantineIntent(root,{reviewKey,now,nonce:'a'.repeat(32)});
 assert.equal(ticket.referencePin,second.referencePin);
 await rejects(verify(root,evidence,second,verifier),'LOCAL_REVIEW_EVIDENCE_WRONG_TICKET');
});
test('35Y cross-root replay fails even when two roots contain same design shape',async t=>{
 const first=await signed(t),second=await setup(t);
 await rejects(verify(second.root,first.evidence,first.ticket,verifier),'LOCAL_QUARANTINE_REVIEW_WRONG_ROOT');
});
test('35Y new revision invalidates evidence after signature',async t=>{
 const {root,store,saved,ticket,evidence}=await signed(t);
 await store.reviseDesign(saved.reference,saved.ownerToken,{productManifestId:'concept-crew-tee',expectedRevision:1,layers:[]});
 await rejects(verify(root,evidence,ticket,verifier),'LOCAL_QUARANTINE_REVIEW_STALE');
});
test('35Y image bytes and metadata changed together invalidate signed content pin',async t=>{
 const {root,b,ticket,evidence}=await signed(t);
 const p=artpath(root,b.id),mp=artpath(root,b.id,'json');const bytes=await fs.readFile(p);bytes[20]^=1;
 await fs.writeFile(p,bytes);const meta=JSON.parse(await fs.readFile(mp,'utf8'));
 meta.sha256=createHash('sha256').update(bytes).digest('hex');await fs.writeFile(mp,JSON.stringify(meta));
 await rejects(verify(root,evidence,ticket,verifier),'LOCAL_QUARANTINE_REVIEW_STALE');
});
test('35Y cross-process same-size artwork replacement is rejected',async t=>{
 const {root,b,ticket,evidence}=await signed(t);
 const script=`const fs=require('node:fs');const p=process.argv[1];const b=fs.readFileSync(p);b[20]^=1;fs.writeFileSync(p,b);`;
 await exec(process.execPath,['-e',script,artpath(root,b.id)]);
 await rejects(verify(root,evidence,ticket,verifier),'LOCAL_RETENTION_ARTWORK_DIGEST_MISMATCH');
});
test('35Y candidate count and evidence byte budget fail closed on creation',async t=>{
 const {root,ticket}=await setup(t);
 await rejects(create(root,ticket,{...signer,maxCandidates:0}),'LOCAL_REVIEW_EVIDENCE_INVALID_OPTIONS');
 await rejects(create(root,ticket,{...signer,maxEvidenceBytes:200}),'LOCAL_REVIEW_EVIDENCE_TOO_LARGE');
});
test('35Y bounded verifier rejects small output budget before disk scan',async t=>{
 const {root,ticket,evidence}=await signed(t);let scans=0;
 const io={...fs,readdir:async(...args)=>{scans++;return fs.readdir(...args);}};
 await rejects(verify(root,evidence,ticket,{...verifier,maxEvidenceBytes:200,io}),'LOCAL_REVIEW_EVIDENCE_TOO_LARGE');
 assert.equal(scans,0);
});
test('35Y rejects invalid key material, signer IDs, and missing challenge',async t=>{
 const {root,ticket}=await setup(t);
 await rejects(create(root,ticket,{...signer,signingKey:pair.publicKey}),'LOCAL_REVIEW_EVIDENCE_INVALID_OPTIONS');
 await rejects(create(root,ticket,{...signer,keyId:'../../operator'}),'LOCAL_REVIEW_EVIDENCE_INVALID_OPTIONS');
 await rejects(create(root,ticket,{...signer,challenge:undefined}),'LOCAL_REVIEW_EVIDENCE_INVALID_OPTIONS');
});
test('35Y rejects missing trusted key resolver and invalid expected challenge',async t=>{
 const {root,ticket,evidence}=await signed(t);
 await rejects(verify(root,evidence,ticket,{...verifier,resolvePublicKey:undefined}),'LOCAL_REVIEW_EVIDENCE_INVALID_OPTIONS');
 await rejects(verify(root,evidence,ticket,{...verifier,expectedChallenge:'no'}),'LOCAL_REVIEW_EVIDENCE_INVALID_OPTIONS');
});
test('35Y incomplete artwork pair fails closed before evidence signing',async t=>{
 const {root,ticket,b}=await setup(t);await fs.unlink(artpath(root,b.id,'json'));
 await rejects(create(root,ticket,signer),'LOCAL_QUARANTINE_REVIEW_UNCERTAIN_INVENTORY');
});
test('35Y failed lease never creates review evidence',async t=>{
 const {root,ticket}=await setup(t);await fs.mkdir(join(root,'.artwork-retention-lease'));
 await rejects(create(root,ticket,signer),'LOCAL_ARTWORK_LEASE_BUSY');
});
test('35Y strict candidate limit rejects valid larger signed candidate set',async t=>{
 const {root,ticket}=await setup(t);
 const extra=await new LocalDesignStore(root).putArtwork(png,'image/png');
 // A fresh ticket is needed after the extra artwork changes the snapshot.
 const fresh=await createLocalArtworkQuarantineIntent(root,{reviewKey,now});
 const evidence=await create(root,fresh,signer);
 assert.equal(evidence.candidateCount,2);
 await rejects(create(root,fresh,{...signer,maxCandidates:1}),'LOCAL_REVIEW_EVIDENCE_TOO_MANY_CANDIDATES');
 await rejects(verify(root,evidence,fresh,{...verifier,maxCandidates:1}),'LOCAL_REVIEW_EVIDENCE_INVALID');
 assert.ok(extra.id);
});
test('35Y sparse or decorated candidate arrays cannot bypass exact signed schema',async t=>{
 const {root,ticket,evidence}=await signed(t);
 const sparse=[...evidence.candidateArtworkIds];delete sparse[0];
 await rejects(verify(root,{...evidence,candidateArtworkIds:sparse},ticket,verifier),'LOCAL_REVIEW_EVIDENCE_INVALID');
 const decorated=[...evidence.candidateArtworkIds];decorated.untrusted='yes';
 await rejects(verify(root,{...evidence,candidateArtworkIds:decorated},ticket,verifier),'LOCAL_REVIEW_EVIDENCE_INVALID');
});
