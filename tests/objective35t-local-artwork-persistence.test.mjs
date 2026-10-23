import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {writeLocalArtworkPair,inspectLocalArtworkOrphans} from '../src/preview-local-artwork-persistence.mjs';
const id='art_'+'a'.repeat(32),nonce='b'.repeat(24);
const metadata={id,extension:'png',mediaType:'image/png',bytes:3};
const bytes=Buffer.from('png');
async function fixture(t){const dir=await fs.mkdtemp(join(tmpdir(),'tj35t-'));t.after(()=>fs.rm(dir,{recursive:true,force:true}));return dir;}
const call=(directory,extra={})=>writeLocalArtworkPair({directory,id,extension:'png',bytes,metadata,nonce,...extra});
const names=dir=>fs.readdir(dir);
test('35T publishes exclusive metadata hard link and image pair',async t=>{
 const dir=await fixture(t);assert.deepEqual(await call(dir),{published:true});
 assert.deepEqual((await names(dir)).sort(),[id+'.json',id+'.png']);
 assert.deepEqual(await fs.readFile(join(dir,id+'.png')),bytes);
 assert.equal((await inspectLocalArtworkOrphans(dir)).incomplete.length,0);
});
test('35T metadata staging failure never publishes image',async t=>{
 const dir=await fixture(t);const io={...fs,writeFile:async(path,...args)=>{if(path.includes('.pending-'))throw Error('metadata-stage-failure');return fs.writeFile(path,...args);}};
 await assert.rejects(call(dir,{io}),/metadata-stage-failure/);assert.deepEqual(await names(dir),[]);
});
test('35T image write failure removes owned staged metadata',async t=>{
 const dir=await fixture(t);const io={...fs,writeFile:async(path,...args)=>{if(path.endsWith('.png'))throw Error('image-failure');return fs.writeFile(path,...args);}};
 await assert.rejects(call(dir,{io}),/image-failure/);assert.deepEqual(await names(dir),[]);
});
test('35T publication link failure rolls back both owned files',async t=>{
 const dir=await fixture(t);const io={...fs,link:async()=>{throw Error('publish-failure');}};
 await assert.rejects(call(dir,{io}),/publish-failure/);assert.deepEqual(await names(dir),[]);
});
test('35T failed rollback remains uncertain and does not assert clean',async t=>{
 const dir=await fixture(t);const io={...fs,link:async()=>{throw Error('publish-failure');},unlink:async(path)=>{if(path.endsWith('.png'))throw Error('cleanup-failure');return fs.unlink(path);}};
 await assert.rejects(call(dir,{io}),e=>e.code==='LOCAL_ARTWORK_ROLLBACK_UNCERTAIN');
 const report=await inspectLocalArtworkOrphans(dir);assert.equal(report.incomplete.length,1);assert.equal(report.safeToAutoDelete,false);
});
test('35T postpublication staged unlink failure preserves valid pair for inspection',async t=>{
 const dir=await fixture(t);const io={...fs,unlink:async(path)=>{if(path.includes('.pending-'))throw Error('cleanup-failure');return fs.unlink(path);}};
 assert.deepEqual(await call(dir,{io}),{published:true});const report=await inspectLocalArtworkOrphans(dir);
 assert.equal(report.incomplete.length,0);assert.equal(report.pending.length,1);assert.equal(report.safeToAutoDelete,false);
});
test('35T incomplete pairs, pending records and symlinks are only reported',async t=>{
 const dir=await fixture(t);await fs.writeFile(join(dir,id+'.png'),bytes);
 await fs.writeFile(join(dir,`.${id}.pending-${nonce}.json`),'{}');
 await fs.symlink(join(dir,id+'.png'),join(dir,id+'.json'));
 const report=await inspectLocalArtworkOrphans(dir);assert.equal(report.incomplete.length,1);
 assert.equal(report.incomplete[0].unsafe.length,1);assert.equal(report.pending.length,1);
 assert.equal((await names(dir)).length,3);
});
test('35T inventory fails closed at entry limit without cleanup',async t=>{
 const dir=await fixture(t);await fs.writeFile(join(dir,'other'),'data');await fs.writeFile(join(dir,'other2'),'data');
 await assert.rejects(inspectLocalArtworkOrphans(dir,{maxEntries:1}),e=>e.code==='LOCAL_ARTWORK_INSPECTION_BOUNDED');
 assert.equal((await names(dir)).length,2);
});
test('35T rejects invalid identities and cannot overwrite an existing published pair',async t=>{
 const dir=await fixture(t);await assert.rejects(call(dir,{id:'../bad'}),e=>e.code==='LOCAL_ARTWORK_WRITE_INVALID');
 await call(dir);await assert.rejects(call(dir));assert.deepEqual((await names(dir)).sort(),[id+'.json',id+'.png']);
});
