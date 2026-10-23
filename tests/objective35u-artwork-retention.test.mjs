import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {createHash} from 'node:crypto';
import {inspectLocalArtworkRetention} from '../src/preview-local-artwork-retention.mjs';
import {writeLocalArtworkPair} from '../src/preview-local-artwork-persistence.mjs';
const id=n=>'art_'+n.repeat(32);
const ref=n=>'TJ-'+n.repeat(24);
const sha='a'.repeat(64);
async function setup(t){const root=await fs.mkdtemp(join(tmpdir(),'tj35u-'));
 await fs.mkdir(join(root,'designs'));await fs.mkdir(join(root,'artworks'));
 t.after(()=>fs.rm(root,{recursive:true,force:true}));return root;}
async function design(root,r,layers,rev=1){const dir=join(root,'designs',r);
 await fs.mkdir(dir,{recursive:true});await fs.writeFile(join(dir,'owner.sha256'),sha);
 await fs.writeFile(join(dir,`${rev}.json`),JSON.stringify({reference:r,revision:rev,layers}));}
async function artwork(root,art){const bytes=Buffer.from('art');const meta={id:art,extension:'png',bytes:3,sha256:createHash('sha256').update(bytes).digest('hex')};
 await writeLocalArtworkPair({directory:join(root,'artworks'),id:art,extension:'png',bytes,metadata:meta});}
const layer=artworkId=>({type:'artwork',artworkId});
const inspect=root=>inspectLocalArtworkRetention(root);
test('35U scans every saved revision and retains artwork referenced only by history',async t=>{
 const root=await setup(t);await artwork(root,id('a'));await artwork(root,id('b'));await artwork(root,id('c'));
 await design(root,ref('A'),[layer(id('a'))]);await design(root,ref('A'),[layer(id('b'))],2);
 const r=await inspect(root);assert.equal(r.revisionCount,2);
 assert.deepEqual(r.referencedArtworkIds,[id('a'),id('b')]);
 assert.deepEqual(r.unreferencedCompleteArtworkIds,[id('c')]);assert.equal(r.safeToAutoDelete,false);
});
test('35U reports dangling references but never cleans them',async t=>{
 const root=await setup(t);await design(root,ref('A'),[layer(id('a'))]);
 const r=await inspect(root);assert.deepEqual(r.missingOrIncompleteReferencedArtworkIds,[id('a')]);
 assert.equal(r.referenceScanComplete,true);assert.equal(r.safeToAutoDelete,false);
});
test('35U flags incomplete pair as missing when a saved design references it',async t=>{
 const root=await setup(t);await design(root,ref('A'),[layer(id('a'))]);
 await fs.writeFile(join(root,'artworks',id('a')+'.png'),'art');
 const r=await inspect(root);assert.deepEqual(r.incompleteArtworkIds,[id('a')]);
 assert.deepEqual(r.missingOrIncompleteReferencedArtworkIds,[id('a')]);
});
test('35U pending stages remain visible and untouched',async t=>{
 const root=await setup(t);const name='.'+id('a')+'.pending-'+'b'.repeat(24)+'.json';
 await fs.writeFile(join(root,'artworks',name),'{}');const r=await inspect(root);
 assert.deepEqual(r.pendingStageFiles,[name]);assert.equal((await fs.readdir(join(root,'artworks'))).length,1);
});
test('35U corrupt JSON fails closed, never treats artwork as unreferenced',async t=>{
 const root=await setup(t);await design(root,ref('A'),[layer(id('a'))]);
 await fs.writeFile(join(root,'designs',ref('A'),'1.json'),'{bad');
 await assert.rejects(inspect(root),e=>e.code==='LOCAL_RETENTION_REVISION_CORRUPT');
});
test('35U noncontiguous revision chain fails closed',async t=>{
 const root=await setup(t);await design(root,ref('A'),[],1);await design(root,ref('A'),[],3);
 await assert.rejects(inspect(root),e=>e.code==='LOCAL_RETENTION_REVISION_GAP');
});
test('35U rejects symlinked revision and never follows outside content',async t=>{
 const root=await setup(t);await design(root,ref('A'),[]);
 await fs.symlink(join(root,'designs',ref('A'),'1.json'),join(root,'designs',ref('A'),'2.json'));
 await assert.rejects(inspect(root),e=>e.code==='LOCAL_RETENTION_UNSAFE_ENTRY');
});
test('35U rejects symlinked artwork and unknown artwork files',async t=>{
 const root=await setup(t);await fs.symlink('/etc/passwd',join(root,'artworks',id('a')+'.png'));
 await assert.rejects(inspect(root),e=>e.code==='LOCAL_RETENTION_UNSAFE_ENTRY');
 await fs.unlink(join(root,'artworks',id('a')+'.png'));await fs.writeFile(join(root,'artworks','unexpected.tmp'),'x');
 await assert.rejects(inspect(root),e=>e.code==='LOCAL_RETENTION_UNKNOWN_ARTWORK_ENTRY');
});
test('35U rejects malformed artwork references and ambiguous layers',async t=>{
 const root=await setup(t);await design(root,ref('A'),[layer('../bad')]);
 await assert.rejects(inspect(root),e=>e.code==='LOCAL_RETENTION_ARTWORK_REFERENCE_INVALID');
 await design(root,ref('A'),[{type:'text',artworkId:id('a')}]);
 await assert.rejects(inspect(root),e=>e.code==='LOCAL_RETENTION_AMBIGUOUS_ARTWORK_REFERENCE');
});
test('35U refuses inventory if a design revision changes between scans',async t=>{
 const root=await setup(t);await design(root,ref('A'),[]);let reads=0;
 const io={...fs,readFile:async(path,...args)=>{
  const data=await fs.readFile(path,...args);
  if(path.endsWith('1.json')&&++reads===1){await fs.writeFile(path,JSON.stringify({reference:ref('A'),revision:1,layers:[layer(id('a'))]}));}
  return data;
 }};
 await assert.rejects(inspectLocalArtworkRetention(root,{io}),e=>e.code==='LOCAL_RETENTION_CONCURRENT_CHANGE');
});
test('35U bounds design count and revision count',async t=>{
 const root=await setup(t);await design(root,ref('A'),[]);await design(root,ref('B'),[]);
 await assert.rejects(inspectLocalArtworkRetention(root,{maxDesigns:1}),e=>e.code==='LOCAL_RETENTION_DESIGN_LIMIT');
 await assert.rejects(inspectLocalArtworkRetention(root,{maxRevisions:1}),e=>e.code==='LOCAL_RETENTION_REVISION_LIMIT');
});
test('35U rejects oversized metadata and forged metadata identity',async t=>{
 const root=await setup(t);await artwork(root,id('a'));
 await assert.rejects(inspectLocalArtworkRetention(root,{maxMetadataBytes:16}),e=>e.code==='LOCAL_RETENTION_FILE_TOO_LARGE');
 const path=join(root,'artworks',id('a')+'.json');const m=JSON.parse(await fs.readFile(path,'utf8'));m.id=id('b');await fs.writeFile(path,JSON.stringify(m));
 await assert.rejects(inspect(root),e=>e.code==='LOCAL_RETENTION_METADATA_CORRUPT');
});
test('35U rejects malformed roots and preserves artwork on any rejection',async t=>{
 const root=await setup(t);await artwork(root,id('a'));
 await assert.rejects(inspectLocalArtworkRetention(root,{maxArtworkEntries:0}),e=>e.code==='LOCAL_RETENTION_INVALID_OPTIONS');
 await assert.rejects(inspectLocalArtworkRetention(root,{maxArtworkEntries:1}),e=>e.code==='LOCAL_RETENTION_ARTWORK_LIMIT');
 assert.equal((await fs.readdir(join(root,'artworks'))).length,2);
});
test('35U rejects symlinked design directory',async t=>{
 const root=await setup(t);await fs.symlink('/tmp',join(root,'designs',ref('A')));
 await assert.rejects(inspect(root),e=>e.code==='LOCAL_RETENTION_UNKNOWN_DESIGN_ENTRY');
});
test('35U reads actual LocalDesignStore records without exposing grants or owner tokens',async t=>{
 const {LocalDesignStore}=await import('../src/local-store.mjs');
 const root=await fs.mkdtemp(join(tmpdir(),'tj35u-real-'));t.after(()=>fs.rm(root,{recursive:true,force:true}));
 const store=new LocalDesignStore(root);await store.init();
 const png=Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/lIgAAAAASUVORK5CYII=','base64');
 const art=await store.putArtwork(png,'image/png');
 const saved=await store.putDesign({productManifestId:'concept-crew-tee',layers:[{id:'layer1',type:'artwork',surfaceId:'front',x:0.1,y:0.1,width:0.2,height:0.2,rotationDeg:0,artworkId:art.id}],artworkGrants:{[art.id]:art.grant}});
 const r=await inspect(root);
 assert.deepEqual(r.referencedArtworkIds,[art.id]);assert.deepEqual(r.unreferencedCompleteArtworkIds,[]);
 assert.equal(JSON.stringify(r).includes(art.grant),false);assert.equal(JSON.stringify(r).includes(saved.ownerToken),false);
});
test('35U detects a newly added revision between complete snapshots',async t=>{
 const root=await setup(t);await design(root,ref('A'),[]);let listings=0;
 const io={...fs,readdir:async(path,...args)=>{
  if(path===join(root,'designs')&&++listings===2)
   await fs.writeFile(join(root,'designs',ref('A'),'2.json'),JSON.stringify({reference:ref('A'),revision:2,layers:[layer(id('b'))]}));
  return fs.readdir(path,...args);
 }};
 await assert.rejects(inspectLocalArtworkRetention(root,{io}),e=>e.code==='LOCAL_RETENTION_CONCURRENT_CHANGE');
});
test('35U rejects a symlinked artwork directory',async t=>{
 const root=await setup(t);await fs.rmdir(join(root,'artworks'));await fs.symlink('/tmp',join(root,'artworks'));
 await assert.rejects(inspect(root),e=>e.code==='LOCAL_RETENTION_UNSAFE_DIRECTORY');
});
