import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {randomBytes} from 'node:crypto';
import {LocalDesignStore} from '../src/local-store.mjs';
import {withLocalArtworkLease} from '../src/preview-local-artwork-coordination.mjs';
import {inspectLocalArtworkRetention} from '../src/preview-local-artwork-retention.mjs';
import {createLocalArtworkQuarantineIntent as create,verifyLocalArtworkQuarantineIntent as verify} from '../src/preview-local-artwork-quarantine-review.mjs';
const png=Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/lIgAAAAASUVORK5CYII=','base64');
const key=randomBytes(32),otherKey=randomBytes(32),now=1800000000000;
const rejects=(promise,code)=>assert.rejects(promise,e=>e?.code===code);
async function setup(t){const root=await fs.mkdtemp(join(tmpdir(),'tj35w-'));t.after(()=>fs.rm(root,{recursive:true,force:true}));
 const store=new LocalDesignStore(root);await store.init();return {root,store};}
const options={reviewKey:key,now};
const artworkLayer=(id)=>({id:'layer1',type:'artwork',surfaceId:'front',x:0.1,y:0.1,width:0.2,height:0.2,rotationDeg:0,artworkId:id});
async function seed(t){const {root,store}=await setup(t);const a=await store.putArtwork(png,'image/png');
 const b=await store.putArtwork(png,'image/png');const saved=await store.putDesign({productManifestId:'concept-crew-tee',layers:[artworkLayer(a.id)],artworkGrants:{[a.id]:a.grant}});
 return {root,store,a,b,saved};}
test('35W read-only ticket pins referenced and unreferenced artwork and never grants mutation',async t=>{
 const {root,a,b}=await seed(t);const ticket=await create(root,options);const check=await verify(root,ticket,options);
 assert.deepEqual(ticket.candidateArtworkIds,[b.id]);assert.equal(check.safeToQuarantine,false);
 assert.equal(check.safeToAutoDelete,false);assert.equal(ticket.safeToAutoDelete,false);
 assert.equal(ticket.candidateArtworkIds.includes(a.id),false);
 assert.equal(ticket.referencePin,(await inspectLocalArtworkRetention(root)).referencePin);
 assert.equal(JSON.stringify(ticket).includes('ownerToken'),false);
 assert.deepEqual((await fs.readdir(join(root,'artworks'))).length,4);
});
test('35W ticket signature detects substituted candidate IDs',async t=>{
 const {root,a}=await seed(t);const ticket=await create(root,options);
 await rejects(verify(root,{...ticket,candidateArtworkIds:[a.id]},options),'LOCAL_QUARANTINE_REVIEW_TAMPERED');
});
test('35W ticket signature detects altered reference pin and expiry',async t=>{
 const {root}=await seed(t);const ticket=await create(root,options);
 await rejects(verify(root,{...ticket,referencePin:'0'.repeat(64)},options),'LOCAL_QUARANTINE_REVIEW_TAMPERED');
 await rejects(verify(root,{...ticket,expiresAt:ticket.expiresAt+1},options),'LOCAL_QUARANTINE_REVIEW_TAMPERED');
});
test('35W wrong review key rejects without scanning',async t=>{
 const {root}=await seed(t);const ticket=await create(root,options);
 await rejects(verify(root,ticket,{reviewKey:otherKey,now}),'LOCAL_QUARANTINE_REVIEW_TAMPERED');
});
test('35W root pin prevents cross-directory ticket substitution',async t=>{
 const {root}=await seed(t),other=await seed(t);const ticket=await create(root,options);
 await rejects(verify(other.root,ticket,options),'LOCAL_QUARANTINE_REVIEW_WRONG_ROOT');
});
test('35W expiry and future-issued ticket fail closed',async t=>{
 const {root}=await seed(t);const ticket=await create(root,{...options,ttlMs:100});
 await rejects(verify(root,ticket,{...options,now:now+100}),'LOCAL_QUARANTINE_REVIEW_EXPIRED');
 await rejects(verify(root,ticket,{...options,now:now-1}),'LOCAL_QUARANTINE_REVIEW_EXPIRED');
});
test('35W new revision after ticket creation invalidates pin',async t=>{
 const {root,store,saved}=await seed(t);const ticket=await create(root,options);
 await store.reviseDesign(saved.reference,saved.ownerToken,{productManifestId:'concept-crew-tee',expectedRevision:1,layers:[]});
 await rejects(verify(root,ticket,options),'LOCAL_QUARANTINE_REVIEW_STALE');
});
test('35W new artwork after ticket creation invalidates pin',async t=>{
 const {root,store}=await seed(t);const ticket=await create(root,options);await store.putArtwork(png,'image/png');
 await rejects(verify(root,ticket,options),'LOCAL_QUARANTINE_REVIEW_STALE');
});
test('35W incomplete image pair is not a quarantine candidate',async t=>{
 const {root,b}=await seed(t);await fs.unlink(join(root,'artworks',b.id+'.json'));
 await rejects(create(root,options),'LOCAL_QUARANTINE_REVIEW_UNCERTAIN_INVENTORY');
});
test('35W pending metadata stage prevents a review ticket',async t=>{
 const {root}=await seed(t);await fs.writeFile(join(root,'artworks','.art_'+'a'.repeat(32)+'.pending-'+'b'.repeat(24)+'.json'),'{}');
 await rejects(create(root,options),'LOCAL_QUARANTINE_REVIEW_UNCERTAIN_INVENTORY');
});
test('35W missing referenced artwork invalidates existing ticket',async t=>{
 const {root,a}=await seed(t);const ticket=await create(root,options);await fs.unlink(join(root,'artworks',a.id+'.png'));
 await rejects(verify(root,ticket,options),'LOCAL_QUARANTINE_REVIEW_UNCERTAIN_INVENTORY');
});
test('35W symlinked artwork entry fails closed and does not touch target',async t=>{
 const {root,b}=await seed(t);const ticket=await create(root,options);
 const target=join(root,'target');await fs.writeFile(target,'external');await fs.unlink(join(root,'artworks',b.id+'.png'));
 await fs.symlink(target,join(root,'artworks',b.id+'.png'));
 await rejects(verify(root,ticket,options),'LOCAL_RETENTION_UNSAFE_ENTRY');
 assert.equal(await fs.readFile(target,'utf8'),'external');
});
test('35W unknown fields, invalid keys and forged flags rejected',async t=>{
 const {root}=await seed(t);const ticket=await create(root,options);
 await rejects(verify(root,{...ticket,authorized:true},options),'LOCAL_QUARANTINE_REVIEW_INVALID');
 await rejects(verify(root,{...ticket,safeToAutoDelete:true},options),'LOCAL_QUARANTINE_REVIEW_INVALID');
 await rejects(create(root,{...options,reviewKey:Buffer.alloc(1)}),'LOCAL_QUARANTINE_REVIEW_INVALID_OPTIONS');
 await rejects(create(root,{...options,ttlMs:3600001}),'LOCAL_QUARANTINE_REVIEW_INVALID_OPTIONS');
});
test('35W competing local writer lease blocks review rather than returning stale authorization',async t=>{
 const {root}=await seed(t);const ticket=await create(root,options);
 await fs.mkdir(join(root,'.artwork-retention-lease'));
 await rejects(verify(root,ticket,options),'LOCAL_ARTWORK_LEASE_BUSY');
 assert.equal((await fs.stat(join(root,'.artwork-retention-lease'))).isDirectory(),true);
});
test('35W review does not bypass a cooperative lease held by an active writer',async t=>{
 const {root}=await seed(t);const ticket=await create(root,options);let release;const held=new Promise(r=>release=r);
 const first=withLocalArtworkLease(root,()=>held);let found=false;
 for(let i=0;i<100;i++){if(await fs.stat(join(root,'.artwork-retention-lease')).then(()=>true,()=>false)){found=true;break;}await new Promise(r=>setTimeout(r,5));}
 assert.equal(found,true);let verified=false;const second=verify(root,ticket,options).then(()=>{verified=true;});
 await new Promise(r=>setTimeout(r,40));assert.equal(verified,false);release();await first;await second;assert.equal(verified,true);
});
test('35W ticket can be reverified read-only but never consumed as a deletion grant',async t=>{
 const {root}=await seed(t);const ticket=await create(root,options);
 assert.equal((await verify(root,ticket,options)).safeToAutoDelete,false);
 assert.equal((await verify(root,ticket,options)).safeToQuarantine,false);
});
