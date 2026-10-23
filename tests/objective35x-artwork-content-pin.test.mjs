import test from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs/promises';
import {join} from 'node:path';
import {tmpdir} from 'node:os';
import {createHash,randomBytes} from 'node:crypto';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {LocalDesignStore} from '../src/local-store.mjs';
import {inspectLocalArtworkRetention as inspect} from '../src/preview-local-artwork-retention.mjs';
import {createLocalArtworkQuarantineIntent as create,verifyLocalArtworkQuarantineIntent as verify} from '../src/preview-local-artwork-quarantine-review.mjs';
const exec=promisify(execFile);
const png=Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/lIgAAAAASUVORK5CYII=','base64');
const options={reviewKey:randomBytes(32),now:1800000000000};
const rejects=(promise,code)=>assert.rejects(promise,e=>e?.code===code);
async function setup(t){
 const root=await fs.mkdtemp(join(tmpdir(),'tj35x-'));t.after(()=>fs.rm(root,{recursive:true,force:true}));
 const store=new LocalDesignStore(root);await store.init();
 const a=await store.putArtwork(png,'image/png'),b=await store.putArtwork(png,'image/png');
 const saved=await store.putDesign({productManifestId:'concept-crew-tee',layers:[{id:'layer1',type:'artwork',surfaceId:'front',x:.1,y:.1,width:.2,height:.2,rotationDeg:0,artworkId:a.id}],artworkGrants:{[a.id]:a.grant}});
 return {root,store,a,b,saved};
}
const path=(root,id,ext='png')=>join(root,'artworks',id+'.'+ext);
const changed=bytes=>{const out=Buffer.from(bytes);out[20]^=1;return out;};
async function replaceImage(root,id){const file=path(root,id);await fs.writeFile(file,changed(await fs.readFile(file)));}
async function repairMetadata(root,id){const image=await fs.readFile(path(root,id));const file=path(root,id,'json');const meta=JSON.parse(await fs.readFile(file,'utf8'));meta.sha256=createHash('sha256').update(image).digest('hex');await fs.writeFile(file,JSON.stringify(meta));}

test('35X valid content-digested inventory retains the 35W read-only boundaries',async t=>{
 const {root,a,b}=await setup(t);const scan=await inspect(root);const ticket=await create(root,options);const result=await verify(root,ticket,options);
 assert.deepEqual(scan.referencedArtworkIds,[a.id]);assert.deepEqual(scan.unreferencedCompleteArtworkIds,[b.id]);
 assert.equal(ticket.referencePin,scan.referencePin);assert.equal(result.safeToAutoDelete,false);assert.equal(result.safeToQuarantine,false);
});
test('35X same-length unreferenced image tampering rejects review creation',async t=>{
 const {root,b}=await setup(t);await replaceImage(root,b.id);
 await rejects(create(root,options),'LOCAL_RETENTION_ARTWORK_DIGEST_MISMATCH');
});
test('35X same-length referenced image tampering rejects review creation',async t=>{
 const {root,a}=await setup(t);await replaceImage(root,a.id);
 await rejects(create(root,options),'LOCAL_RETENTION_ARTWORK_DIGEST_MISMATCH');
});
test('35X image tampering after a signed ticket invalidates verification',async t=>{
 const {root,b}=await setup(t);const ticket=await create(root,options);await replaceImage(root,b.id);
 await rejects(verify(root,ticket,options),'LOCAL_RETENTION_ARTWORK_DIGEST_MISMATCH');
});
test('35X coordinated image and metadata digest substitution changes reference pin',async t=>{
 const {root,b}=await setup(t);const ticket=await create(root,options);
 await replaceImage(root,b.id);await repairMetadata(root,b.id);
 const scan=await inspect(root);assert.notEqual(scan.referencePin,ticket.referencePin);
 await rejects(verify(root,ticket,options),'LOCAL_QUARANTINE_REVIEW_STALE');
});
test('35X metadata-only digest forgery is rejected even when byte size is valid',async t=>{
 const {root,b}=await setup(t);const file=path(root,b.id,'json');const meta=JSON.parse(await fs.readFile(file,'utf8'));
 meta.sha256='0'.repeat(64);await fs.writeFile(file,JSON.stringify(meta));
 await rejects(inspect(root),'LOCAL_RETENTION_ARTWORK_DIGEST_MISMATCH');
});
test('35X image size is bounded before reading image bytes',async t=>{
 const {root,b}=await setup(t);let imageReads=0;const io={...fs,readFile:async(p,...args)=>{
  if(String(p)===path(root,b.id))imageReads++;return fs.readFile(p,...args);
 }};
 await rejects(inspect(root,{io,maxArtworkBytes:png.length-1}),'LOCAL_RETENTION_FILE_TOO_LARGE');
 assert.equal(imageReads,0);
});
test('35X invalid image-byte limit fails closed',async t=>{
 const {root}=await setup(t);await rejects(inspect(root,{maxArtworkBytes:0}),'LOCAL_RETENTION_INVALID_OPTIONS');
});
test('35X uncooperative image write during read is rejected by stable-file guard',async t=>{
 const {root,b}=await setup(t);let injected=false;const io={...fs,readFile:async(p,...args)=>{
  const bytes=await fs.readFile(p,...args);
  if(!injected&&String(p)===path(root,b.id)){injected=true;await replaceImage(root,b.id);}
  return bytes;
 }};
 await rejects(inspect(root,{io}),'LOCAL_RETENTION_CONCURRENT_CHANGE');assert.equal(injected,true);
});
test('35X a separate process can invalidate an issued ticket without any deletion',async t=>{
 const {root,b}=await setup(t);const ticket=await create(root,options);const before=await fs.readdir(join(root,'artworks'));
 const script=`const fs=require('node:fs');const p=process.argv[1];const b=fs.readFileSync(p);b[20]^=1;fs.writeFileSync(p,b);`;
 await exec(process.execPath,['-e',script,path(root,b.id)]);
 await rejects(verify(root,ticket,options),'LOCAL_RETENTION_ARTWORK_DIGEST_MISMATCH');
 assert.deepEqual(await fs.readdir(join(root,'artworks')),before);
});
test('35X a separate process updating both bytes and digest cannot reuse old ticket',async t=>{
 const {root,b}=await setup(t);const ticket=await create(root,options);
 const script=`const fs=require('node:fs');const crypto=require('node:crypto');const p=process.argv[1];const m=process.argv[2];const b=fs.readFileSync(p);b[20]^=1;fs.writeFileSync(p,b);const meta=JSON.parse(fs.readFileSync(m));meta.sha256=crypto.createHash('sha256').update(b).digest('hex');fs.writeFileSync(m,JSON.stringify(meta));`;
 await exec(process.execPath,['-e',script,path(root,b.id),path(root,b.id,'json')]);
 await rejects(verify(root,ticket,options),'LOCAL_QUARANTINE_REVIEW_STALE');
});
test('35X content pin never exposes artwork grant or design owner token',async t=>{
 const {root,a,saved}=await setup(t);const scan=await inspect(root);const ticket=await create(root,options);
 const output=JSON.stringify({scan,ticket});assert.equal(output.includes(a.grant),false);assert.equal(output.includes(saved.ownerToken),false);
 assert.equal(scan.safeToAutoDelete,false);assert.equal(ticket.safeToAutoDelete,false);
});
