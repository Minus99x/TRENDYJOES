import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,readFile,writeFile,symlink,unlink,chmod} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createHash,randomBytes} from 'node:crypto';
import {deflateSync} from 'node:zlib';
import {createOfflinePrivateRevisionRegistry} from '../src/offline-private-revision-registry.mjs';
import {computeArtworkDesignSha256} from '../src/manufacturing-artwork-evidence.mjs';

const hash=x=>createHash('sha256').update(x).digest('hex');
const shop='gucgmp-bc.myshopify.com';
const layer=(id='layer-A',artworkId='art-A')=>({id,type:'artwork',artworkId,surfaceId:'front',x:.2,y:.2,width:.3,height:.3,rotationDeg:0,sourceWidthPx:100,sourceHeightPx:100});
function record(revision=1,changes={}){
 const design={layers:[layer()]};
 return {schema:'TJ-CURRENT-IMMUTABLE-DESIGN-1',shop,productGid:'gid://shopify/Product/123',variantGid:'gid://shopify/ProductVariant/456',manifestId:'concept-crew-tee',ownerId:'owner-1',designId:'design-1',revision,designSha256:computeArtworkDesignSha256(design),status:'CURRENT_IMMUTABLE',design,...changes};
}
const identity=r=>Object.fromEntries(['shop','productGid','variantGid','ownerId','designId','revision'].map(k=>[k,r[k]]));
let id=0;const op=()=>`operation-${++id}-${randomBytes(6).toString('hex')}`;
const asset=(storageKey='PrivateArtwork0001',bytes=png())=>({storageKey,artworkId:'art-A',layerId:'layer-A',bytes});
const readArgs=(r=record(),storageKey='PrivateArtwork0001')=>({storageKey,ownerId:r.ownerId,designId:r.designId,revision:r.revision,artworkId:'art-A'});
const rejects=(promise,code)=>assert.rejects(promise,e=>e?.code===code);
const crcTable=Array.from({length:256},(_,i)=>{let c=i;for(let j=0;j<8;j++)c=c&1?0xedb88320^(c>>>1):c>>>1;return c>>>0;});
function crc32(b){let c=0xffffffff;for(const x of b)c=crcTable[(c^x)&255]^(c>>>8);return (c^0xffffffff)>>>0;}
function chunk(type,data){const t=Buffer.from(type),b=Buffer.alloc(12+data.length);b.writeUInt32BE(data.length,0);t.copy(b,4);data.copy(b,8);b.writeUInt32BE(crc32(Buffer.concat([t,data])),8+data.length);return b;}
function png(w=12,h=12){const head=Buffer.alloc(13);head.writeUInt32BE(w,0);head.writeUInt32BE(h,4);head[8]=8;head[9]=2;const scan=Buffer.alloc(h*(w*3+1));return Buffer.concat([Buffer.from('89504e470d0a1a0a','hex'),chunk('IHDR',head),chunk('IDAT',deflateSync(scan)),chunk('IEND',Buffer.alloc(0))]);}
async function fixture(t,{injectFault,secret=randomBytes(32)}={}){
 const directory=await mkdtemp(join(tmpdir(),'tj-private23-'));t.after(()=>rm(directory,{recursive:true,force:true}));
 let trusted=null,failRead=false,failWrite=false,delayWrite=null;
 const anchors={readAnchor:async()=>{if(failRead)throw Error('offline');return trusted?structuredClone(trusted):null;},
  compareAndSetAnchor:async(previous,next)=>{if(delayWrite)await delayWrite();if(failWrite)throw Error('offline');if(JSON.stringify(previous)!==JSON.stringify(trusted))return false;trusted=structuredClone(next);return true;}};
 const open=(extra={})=>createOfflinePrivateRevisionRegistry({directory,secret,...anchors,injectFault,...extra});
 const file=join(directory,'private-registry.json');
 const commit=(r=record(),a=[asset()],extra={})=>open().commitRevision({record:r,artworks:a,expectedRevision:r.revision===1?null:r.revision-1,opId:op(),...extra});
 return {directory,file,open,commit,anchors,getAnchor:()=>structuredClone(trusted),setAnchor:x=>{trusted=x;},setReadFailure:x=>{failRead=x;},setWriteFailure:x=>{failWrite=x;},setDelayWrite:x=>{delayWrite=x;}};
}

test('durable immutable revision and private PNG bytes survive reopen; no production approval',async t=>{const f=await fixture(t),r=record(),b=png();const out=await f.commit(r,[asset('PrivateArtwork0001',b)]);assert.equal(out.productionApproved,false);assert.equal(out.artworkCount,1);assert.deepEqual(await f.open().loadCurrentRevision(identity(r)),r);assert.deepEqual(await f.open().readPrivateArtwork(readArgs(r)),b);});
test('storage state includes exact authenticated PNG bytes and no signing secret',async t=>{const f=await fixture(t);await f.commit();const s=JSON.parse(await readFile(f.file,'utf8'));assert.equal(s.assets[0].sha256,hash(png()));assert.equal(s.assets[0].base64, png().toString('base64'));assert.equal(s.sequence,1);assert.deepEqual(f.getAnchor(),{sequence:1,mac:s.mac});});
test('caller mutation after commit cannot mutate durable snapshot or bytes',async t=>{const f=await fixture(t),r=record(),b=png(),a=asset('PrivateArtwork0001',b);await f.commit(r,[a]);r.design.layers[0].x=.9;b[0]=0;a.storageKey='EvilStorage0001';assert.equal((await f.open().loadCurrentRevision(identity(record()))).design.layers[0].x,.2);assert.deepEqual(await f.open().readPrivateArtwork(readArgs()),png());});
test('returned revision and artwork bytes are detached copies',async t=>{const f=await fixture(t);await f.commit();const r=await f.open().loadCurrentRevision(identity(record()));r.design.layers[0].x=.9;const b=await f.open().readPrivateArtwork(readArgs());b[0]=0;assert.equal((await f.open().loadCurrentRevision(identity(record()))).design.layers[0].x,.2);assert.deepEqual(await f.open().readPrivateArtwork(readArgs()),png());});
test('cross-owner, cross-design, cross-revision artwork read fails closed',async t=>{const f=await fixture(t);await f.commit();for(const change of [{ownerId:'other'},{designId:'other'},{revision:2},{artworkId:'other'},{storageKey:'UnknownStorage0001'}])await rejects(f.open().readPrivateArtwork({...readArgs(),...change}),'REGISTRY_ARTWORK_UNAVAILABLE');});
test('wrong tenant, product, variant, owner or revision cannot load current revision',async t=>{const f=await fixture(t);await f.commit();for(const change of [{shop:'other.myshopify.com'},{productGid:'gid://shopify/Product/999'},{variantGid:'gid://shopify/ProductVariant/999'},{ownerId:'other'},{designId:'other'},{revision:2}])assert.equal(await f.open().loadCurrentRevision({...identity(record()),...change}),null);});
test('revision two supersedes revision one and old private bytes become unavailable',async t=>{const f=await fixture(t);await f.commit();const next=record(2);await f.commit(next,[asset('PrivateArtwork0002')]);assert.equal(await f.open().loadCurrentRevision(identity(record())),null);assert.deepEqual(await f.open().loadCurrentRevision(identity(next)),next);await rejects(f.open().readPrivateArtwork(readArgs()),'REGISTRY_ARTWORK_UNAVAILABLE');assert.deepEqual(await f.open().readPrivateArtwork(readArgs(next,'PrivateArtwork0002')),png());});
test('stale expected revision fails without consuming operation ID',async t=>{const f=await fixture(t);await f.commit();const operation=op();await rejects(f.commit(record(2),[asset('PrivateArtwork0002')],{expectedRevision:null,opId:operation}),'REGISTRY_STALE_REVISION');await f.commit(record(2),[asset('PrivateArtwork0002')],{opId:operation});});
test('cannot skip, repeat or regress revisions',async t=>{const f=await fixture(t);await f.commit();for(const n of [1,3])await rejects(f.commit(record(n),[asset(`PrivateArtwork000${n}`)]),'REGISTRY_STALE_REVISION');});
test('replay of operation ID is rejected across reopen, even with different payload',async t=>{const f=await fixture(t),operation=op();await f.commit(record(),[asset()],{opId:operation});await rejects(f.commit(record(2),[asset('PrivateArtwork0002')],{opId:operation}),'REGISTRY_REPLAY');});
test('storage keys cannot be reused in later revisions',async t=>{const f=await fixture(t);await f.commit();await rejects(f.commit(record(2),[asset()]),'REGISTRY_STORAGE_KEY_REUSED');});
test('duplicate storage keys across layers rejected before write',async t=>{const f=await fixture(t),r=record();r.design.layers.push(layer('layer-B','art-B'));r.designSha256=computeArtworkDesignSha256(r.design);await rejects(f.commit(r,[asset(),{storageKey:'PrivateArtwork0001',artworkId:'art-B',layerId:'layer-B',bytes:png()}]),'REGISTRY_ASSETS_INVALID');assert.equal(await f.open().loadCurrentRevision(identity(r)),null);});
test('missing artwork layer and unexpected layer rejected',async t=>{const f=await fixture(t);for(const assets of [[],[asset(),{storageKey:'PrivateArtwork0002',artworkId:'other',layerId:'other',bytes:png()}]])await rejects(f.commit(record(),assets),'REGISTRY_ASSETS_INVALID');});
test('invalid PNG bytes rejected before any state is written',async t=>{const f=await fixture(t);await rejects(f.commit(record(),[asset('PrivateArtwork0001',Buffer.alloc(100))]),'REGISTRY_ASSETS_INVALID');assert.equal(f.getAnchor(),null);});
test('forged composition digest rejected before write',async t=>{const f=await fixture(t);await rejects(f.commit(record(1,{designSha256:'f'.repeat(64)})),'REGISTRY_DIGEST_MISMATCH');});
test('caller verified/productionApproved fields are rejected',async t=>{const f=await fixture(t);await rejects(f.commit(record(1,{productionApproved:true})),'REGISTRY_REVISION_INVALID');});
test('artwork revocation persists, cannot be undone by replay or repeated revoke',async t=>{const f=await fixture(t);await f.commit();const operation=op();await f.open().revokeArtwork({...readArgs(),opId:operation});await rejects(f.open().readPrivateArtwork(readArgs()),'REGISTRY_ARTWORK_UNAVAILABLE');await rejects(f.open().revokeArtwork({...readArgs(),opId:operation}),'REGISTRY_REPLAY');await rejects(f.open().revokeArtwork({...readArgs(),opId:op()}),'REGISTRY_ALREADY_REVOKED');});
test('foreign owner cannot revoke another owner artwork',async t=>{const f=await fixture(t);await f.commit();await rejects(f.open().revokeArtwork({...readArgs(),ownerId:'intruder',opId:op()}),'REGISTRY_ARTWORK_UNAVAILABLE');assert.deepEqual(await f.open().readPrivateArtwork(readArgs()),png());});
test('revoked revision cannot load or read artwork; later revision can advance',async t=>{const f=await fixture(t);await f.commit();await f.open().revokeRevision({identity:identity(record()),opId:op()});assert.equal(await f.open().loadCurrentRevision(identity(record())),null);await rejects(f.open().readPrivateArtwork(readArgs()),'REGISTRY_ARTWORK_UNAVAILABLE');await f.commit(record(2),[asset('PrivateArtwork0002')]);assert.deepEqual(await f.open().loadCurrentRevision(identity(record(2))),record(2));});
test('cannot revoke old revision or foreign identity',async t=>{const f=await fixture(t);await f.commit();await f.commit(record(2),[asset('PrivateArtwork0002')]);await rejects(f.open().revokeRevision({identity:identity(record()),opId:op()}),'REGISTRY_REVISION_NOT_CURRENT');await rejects(f.open().revokeRevision({identity:{...identity(record(2)),ownerId:'intruder'},opId:op()}),'REGISTRY_REVISION_NOT_CURRENT');});
test('concurrent compare-and-swap commits across two instances permit one winner',async t=>{const f=await fixture(t);await f.commit();const results=await Promise.allSettled([f.open().commitRevision({record:record(2),artworks:[asset('PrivateArtwork0002')],expectedRevision:1,opId:op()}),f.open().commitRevision({record:record(2),artworks:[asset('PrivateArtwork0003')],expectedRevision:1,opId:op()})]);assert.equal(results.filter(x=>x.status==='fulfilled').length,1);assert.equal(results.filter(x=>x.status==='rejected'&&x.reason.code==='REGISTRY_STALE_REVISION').length,1);});
test('concurrent revocation and read cannot yield half-written state',async t=>{const f=await fixture(t);await f.commit();const results=await Promise.allSettled([f.open().readPrivateArtwork(readArgs()),f.open().revokeArtwork({...readArgs(),opId:op()})]);assert.equal(results[1].status,'fulfilled');assert.ok(results[0].status==='fulfilled'||results[0].reason.code==='REGISTRY_ARTWORK_UNAVAILABLE');await rejects(f.open().readPrivateArtwork(readArgs()),'REGISTRY_ARTWORK_UNAVAILABLE');});
test('tampered persisted design fails HMAC integrity verification',async t=>{const f=await fixture(t);await f.commit();const s=JSON.parse(await readFile(f.file,'utf8'));s.revisions[0].design.layers[0].x=.7;s.revisions[0].designSha256=computeArtworkDesignSha256(s.revisions[0].design);await writeFile(f.file,JSON.stringify(s),{mode:0o600});await rejects(f.open().loadCurrentRevision(identity(record())),'REGISTRY_TAMPERED');});
test('tampered persisted PNG bytes fail closed',async t=>{const f=await fixture(t);await f.commit();const s=JSON.parse(await readFile(f.file,'utf8'));s.assets[0].base64=Buffer.alloc(80).toString('base64');await writeFile(f.file,JSON.stringify(s));await rejects(f.open().readPrivateArtwork(readArgs()),'REGISTRY_STATE_INVALID');});
test('restoring older valid HMAC snapshot is detected by independent anchor',async t=>{const f=await fixture(t);await f.commit();const old=await readFile(f.file);await f.commit(record(2),[asset('PrivateArtwork0002')]);await writeFile(f.file,old);await rejects(f.open().loadCurrentRevision(identity(record())),'REGISTRY_ROLLBACK');});
test('deleting ledger while anchor remains detects rollback',async t=>{const f=await fixture(t);await f.commit();await unlink(f.file);await rejects(f.open().loadCurrentRevision(identity(record())),'REGISTRY_ROLLBACK');});
test('missing external anchor fails closed',async t=>{const f=await fixture(t);await f.commit();f.setAnchor(null);await rejects(f.open().loadCurrentRevision(identity(record())),'REGISTRY_ROLLBACK');});
test('anchor read outage blocks both reads and writes',async t=>{const f=await fixture(t);await f.commit();f.setReadFailure(true);await rejects(f.open().loadCurrentRevision(identity(record())),'REGISTRY_ANCHOR_UNAVAILABLE');await rejects(f.commit(record(2),[asset('PrivateArtwork0002')]),'REGISTRY_ANCHOR_UNAVAILABLE');});
test('anchor write outage leaves fail-closed pending state',async t=>{const f=await fixture(t);await f.commit();f.setWriteFailure(true);await rejects(f.commit(record(2),[asset('PrivateArtwork0002')]),'REGISTRY_ANCHOR_UNAVAILABLE');f.setWriteFailure(false);await rejects(f.open().loadCurrentRevision(identity(record(2))),'REGISTRY_ROLLBACK');});
test('crash before rename preserves old revision and permits clean retry',async t=>{let fault=false;const f=await fixture(t,{injectFault:async stage=>{if(fault&&stage==='before-rename')throw Error('synthetic crash');}});await f.commit();fault=true;await assert.rejects(f.commit(record(2),[asset('PrivateArtwork0002')]));fault=false;assert.deepEqual(await f.open().loadCurrentRevision(identity(record())),record());await f.commit(record(2),[asset('PrivateArtwork0002')]);});
test('crash after rename refuses to treat unanchored revision as committed',async t=>{let fault=false;const f=await fixture(t,{injectFault:async stage=>{if(fault&&stage==='after-rename')throw Error('synthetic crash');}});await f.commit();fault=true;await assert.rejects(f.commit(record(2),[asset('PrivateArtwork0002')]));fault=false;await rejects(f.open().loadCurrentRevision(identity(record(2))),'REGISTRY_ROLLBACK');await rejects(f.commit(record(3),[asset('PrivateArtwork0003')]),'REGISTRY_ROLLBACK');});
test('symlink state file is rejected instead of followed',async t=>{const f=await fixture(t);await f.commit();await unlink(f.file);await symlink('/etc/passwd',f.file);await rejects(f.open().loadCurrentRevision(identity(record())),'REGISTRY_FILE_UNSAFE');});
test('world-readable persisted state is rejected',async t=>{const f=await fixture(t);await f.commit();await chmod(f.file,0o644);await rejects(f.open().loadCurrentRevision(identity(record())),'REGISTRY_FILE_UNSAFE');});
test('wrong HMAC secret cannot read prior state',async t=>{const f=await fixture(t);await f.commit();await rejects(f.open({secret:randomBytes(32)}).loadCurrentRevision(identity(record())),'REGISTRY_TAMPERED');});
test('invalid configuration requires independent anchor and strong secret',async t=>{const f=await fixture(t);assert.throws(()=>f.open({secret:Buffer.alloc(4)}),e=>e.code==='REGISTRY_CONFIGURATION');assert.throws(()=>f.open({readAnchor:null}),e=>e.code==='REGISTRY_CONFIGURATION');});
test('two distinct artwork layers commit atomically and remain owner-scoped',async t=>{
 const f=await fixture(t),r=record();r.design.layers.push(layer('layer-B','art-B'));r.designSha256=computeArtworkDesignSha256(r.design);
 await f.commit(r,[asset(),{storageKey:'PrivateArtwork0002',artworkId:'art-B',layerId:'layer-B',bytes:png(14,14)}]);
 assert.deepEqual(await f.open().readPrivateArtwork({...readArgs(r),storageKey:'PrivateArtwork0002',artworkId:'art-B'}),png(14,14));
 await rejects(f.open().readPrivateArtwork({...readArgs(r),storageKey:'PrivateArtwork0002',artworkId:'art-A'}),'REGISTRY_ARTWORK_UNAVAILABLE');
});
test('invalid second artwork prevents partial revision or first asset write',async t=>{
 const f=await fixture(t),r=record();r.design.layers.push(layer('layer-B','art-B'));r.designSha256=computeArtworkDesignSha256(r.design);
 await rejects(f.commit(r,[asset(),{storageKey:'PrivateArtwork0002',artworkId:'art-B',layerId:'layer-B',bytes:Buffer.alloc(80)}]),'REGISTRY_ASSETS_INVALID');
 assert.equal(f.getAnchor(),null);await rejects(f.open().readPrivateArtwork(readArgs(r)),'REGISTRY_ARTWORK_UNAVAILABLE');
});
test('duplicate artwork identity across distinct layers rejected',async t=>{
 const f=await fixture(t),r=record();r.design.layers.push(layer('layer-B','art-A'));r.designSha256=computeArtworkDesignSha256(r.design);
 await rejects(f.commit(r,[asset(),{storageKey:'PrivateArtwork0002',artworkId:'art-A',layerId:'layer-B',bytes:png()}]),'REGISTRY_REVISION_INVALID');
});
test('duplicate layer ID rejected even with different artwork identity',async t=>{
 const f=await fixture(t),r=record();r.design.layers.push(layer('layer-A','art-B'));r.designSha256=computeArtworkDesignSha256(r.design);
 await rejects(f.commit(r,[asset(),{storageKey:'PrivateArtwork0002',artworkId:'art-B',layerId:'layer-A',bytes:png()}]),'REGISTRY_REVISION_INVALID');
});
test('external anchor CAS conflict fails closed after local rename',async t=>{
 const f=await fixture(t);await f.commit();f.setAnchor({sequence:99,mac:'f'.repeat(64)});
 await rejects(f.commit(record(2),[asset('PrivateArtwork0002')]),'REGISTRY_ROLLBACK');
});
test('revoked artwork cannot be reintroduced using same storage key',async t=>{
 const f=await fixture(t);await f.commit();await f.open().revokeArtwork({...readArgs(),opId:op()});
 await rejects(f.commit(record(2),[asset()]),'REGISTRY_STORAGE_KEY_REUSED');
});
test('symlink lock path is rejected rather than followed',async t=>{
 const f=await fixture(t);await f.commit();const lock=join(f.directory,'.private-registry-lock');await unlink(lock);await symlink('/etc/passwd',lock);
 await rejects(f.open().loadCurrentRevision(identity(record())),'REGISTRY_LOCK_UNSAFE');
});
test('world-readable directory cannot hold private artwork',async t=>{
 const f=await fixture(t);await f.commit();await chmod(f.directory,0o755);
 await rejects(f.open().loadCurrentRevision(identity(record())),'REGISTRY_DIRECTORY_UNSAFE');
});
