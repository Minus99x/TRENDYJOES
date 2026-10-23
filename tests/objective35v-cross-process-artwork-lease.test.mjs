import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import {withLocalArtworkLease} from '../src/preview-local-artwork-coordination.mjs';
import {inspectLocalArtworkRetention} from '../src/preview-local-artwork-retention.mjs';
import {LocalDesignStore} from '../src/local-store.mjs';
const lock=root=>join(root,'.artwork-retention-lease');
async function setup(t){const root=await fs.mkdtemp(join(tmpdir(),'tj35v-'));t.after(()=>fs.rm(root,{recursive:true,force:true}));return root;}
const rejects=(p,code)=>assert.rejects(p,e=>e.code===code);
const pause=ms=>new Promise(r=>setTimeout(r,ms));
test('35V serialized operations cannot overlap across cooperating callers',async t=>{
 const root=await setup(t);let release;const held=new Promise(r=>release=r);let entered=0;
 const first=withLocalArtworkLease(root,async()=>{entered++;await held;});
 while(!await fs.stat(lock(root)).then(()=>true,()=>false))await pause(5);
 const second=withLocalArtworkLease(root,async()=>{entered++;return 'done';});
 await pause(30);assert.equal(entered,1);release();await first;assert.equal(await second,'done');assert.equal(entered,2);
 await rejects(fs.stat(lock(root)).then(()=>{}),'ENOENT');
});
test('35V pre-existing crash lock fails closed without reclaiming it',async t=>{
 const root=await setup(t);await fs.mkdir(lock(root));
 await rejects(withLocalArtworkLease(root,()=>{throw Error('must not run');},{waitMs:0}),'LOCAL_ARTWORK_LEASE_BUSY');
 assert.equal((await fs.stat(lock(root))).isDirectory(),true);
});
test('35V refuses symlink masquerading as lease',async t=>{
 const root=await setup(t);await fs.symlink(tmpdir(),lock(root));
 await rejects(withLocalArtworkLease(root,()=>{}),'LOCAL_ARTWORK_LEASE_UNSAFE');
});
test('35V refuses regular file masquerading as lease',async t=>{
 const root=await setup(t);await fs.writeFile(lock(root),'fake');
 await rejects(withLocalArtworkLease(root,()=>{}),'LOCAL_ARTWORK_LEASE_UNSAFE');
});
test('35V operation rejection releases its own lease',async t=>{
 const root=await setup(t);await assert.rejects(withLocalArtworkLease(root,()=>{throw Error('fault');}),/fault/);
 assert.equal(await withLocalArtworkLease(root,()=>42),42);
});
test('35V changed lease identity is never removed as though owned',async t=>{
 const root=await setup(t);const moved=join(root,'retained-old-lock');
 await rejects(withLocalArtworkLease(root,async()=>{await fs.rename(lock(root),moved);await fs.mkdir(lock(root));}),'LOCAL_ARTWORK_LEASE_RELEASE_UNCERTAIN');
 assert.equal((await fs.stat(lock(root))).isDirectory(),true);
});
test('35V rejects symlinked root and invalid wait bounds',async t=>{
 const root=await setup(t);const alias=root+'-alias';await fs.symlink(root,alias);t.after(()=>fs.unlink(alias));
 await rejects(withLocalArtworkLease(alias,()=>{}),'LOCAL_ARTWORK_LEASE_ROOT_UNSAFE');
 await rejects(withLocalArtworkLease(root,()=>{}, {waitMs:-1}),'LOCAL_ARTWORK_LEASE_INVALID');
});
test('35V retention inventory cannot run while another lease is held',async t=>{
 const root=await setup(t);await fs.mkdir(join(root,'designs'));await fs.mkdir(join(root,'artworks'));
 let release;const held=new Promise(r=>release=r);
 const first=withLocalArtworkLease(root,()=>held);
 while(!await fs.stat(lock(root)).then(()=>true,()=>false))await pause(5);
 let finished=false;const scan=inspectLocalArtworkRetention(root).then(x=>{finished=true;return x;});
 await pause(30);assert.equal(finished,false);release();await first;
 const result=await scan;assert.equal(result.safeToAutoDelete,false);assert.equal(result.referenceScanComplete,true);
});
test('35V retention scan fails closed on abandoned lease',async t=>{
 const root=await setup(t);await fs.mkdir(join(root,'designs'));await fs.mkdir(join(root,'artworks'));await fs.mkdir(lock(root));
 await rejects(inspectLocalArtworkRetention(root),'LOCAL_ARTWORK_LEASE_BUSY');
});
test('35V design writer cannot create revision under crash lock',async t=>{
 const root=await setup(t);const store=new LocalDesignStore(root);await store.init();await fs.mkdir(lock(root));
 await rejects(store.putDesign({productManifestId:'concept-crew-tee',layers:[]}), 'LOCAL_ARTWORK_LEASE_BUSY');
 assert.deepEqual(await fs.readdir(join(root,'designs')),[]);
});
test('35V local design writer releases lease after successful save',async t=>{
 const root=await setup(t);const store=new LocalDesignStore(root);await store.init();
 const record=await store.putDesign({productManifestId:'concept-crew-tee',layers:[]});
 assert.equal(record.revision,1);assert.equal((await fs.readdir(join(root,'designs'))).length,1);
 assert.equal(await fs.stat(lock(root)).then(()=>true,()=>false),false);
});
test('35V actual child process lock excludes parent until child releases',async t=>{
 const root=await setup(t),ready=join(root,'child-ready'),release=join(root,'child-release');
 const moduleURL=new URL('../src/preview-local-artwork-coordination.mjs',import.meta.url).href;
 const script=`import * as fs from 'node:fs/promises';import {withLocalArtworkLease} from ${JSON.stringify(moduleURL)};await withLocalArtworkLease(process.argv[1],async()=>{await fs.writeFile(process.argv[2],'ready');for(let i=0;i<500;i++){if(await fs.stat(process.argv[3]).then(()=>true,()=>false))return;await new Promise(r=>setTimeout(r,10));}throw Error('parent did not release');});`;
 const child=spawn(process.execPath,['--input-type=module','-e',script,root,ready,release],{stdio:['ignore','pipe','pipe']});
 const childExit=once(child,'exit');t.after(()=>{if(child.exitCode===null)child.kill();});
 let seen=false;for(let i=0;i<1000;i++){if(await fs.stat(ready).then(()=>true,()=>false)){seen=true;break;}if(child.exitCode!==null)break;await pause(10);}
 assert.equal(seen,true,'child did not acquire lease');
 let entered=false;const parent=withLocalArtworkLease(root,()=>{entered=true;return 42;});
 await pause(100);assert.equal(entered,false,'parent entered while child held lease');
 await fs.writeFile(release,'release');assert.equal(await parent,42);
 const [exitCode]=await childExit;assert.equal(exitCode,0);
});
test('35V artwork publication fails closed while crash lease is present',async t=>{
 const root=await setup(t);const store=new LocalDesignStore(root);await store.init();await fs.mkdir(lock(root));
 const png=Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/lIgAAAAASUVORK5CYII=','base64');
 await rejects(store.putArtwork(png,'image/png'),'LOCAL_ARTWORK_LEASE_BUSY');
 assert.deepEqual(await fs.readdir(join(root,'artworks')),[]);
});
test('35V saved revision cannot advance while crash lease is present',async t=>{
 const root=await setup(t);const store=new LocalDesignStore(root);await store.init();
 const saved=await store.putDesign({productManifestId:'concept-crew-tee',layers:[]});
 await fs.mkdir(lock(root));
 await rejects(store.reviseDesign(saved.reference,saved.ownerToken,{productManifestId:'concept-crew-tee',expectedRevision:1,layers:[]}), 'LOCAL_ARTWORK_LEASE_BUSY');
 assert.deepEqual((await fs.readdir(join(root,'designs',saved.reference))).sort(),['1.json','owner.sha256']);
});
