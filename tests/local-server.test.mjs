import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,readFile,readdir,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createLocalServer} from '../src/local-server.mjs';
import {inspectRaster} from '../src/image-inspection.mjs';
const PNG=Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+/lIgAAAAASUVORK5CYII=','base64');
const layer={id:'layer-1',type:'text',surfaceId:'front',x:.25,y:.25,width:.3,height:.2,rotationDeg:0,value:'Hello'};
async function withServer(fn){const dir=await mkdtemp(join(tmpdir(),'tj-secure-local-test-'));
 const inst=await createLocalServer({dataDir:dir});const addr=await inst.listen(0);
 const url=`http://127.0.0.1:${addr.port}`;
 try{await fn({url,dir,inst});}finally{await new Promise(resolve=>inst.server.close(resolve));await rm(dir,{recursive:true,force:true});}
}
async function json(url,path,body,auth){const r=await fetch(url+path,{method:'POST',headers:{'Content-Type':'application/json',...(auth?{Authorization:`Bearer ${auth}`}:{})},body:JSON.stringify(body)});return {status:r.status,body:await r.json()};}
test('PNG magic and dimensions inspected, MIME spoofing blocked',()=>{
 assert.deepEqual(inspectRaster(PNG,'image/png'),{width:1,height:1,mediaType:'image/png',extension:'png'});
 assert.throws(()=>inspectRaster(PNG,'application/pdf'),/mismatch/);
 assert.throws(()=>inspectRaster(Buffer.from('<svg onload=alert(1)>'),'image/svg+xml'),/Only raster|small/);
 const corrupted=Buffer.from(PNG);corrupted[20]=255;assert.throws(()=>inspectRaster(corrupted,'image/png'),/dimensions|checksum/);
});
test('local server has health and actual demo reachable, no hidden local data folder',async()=>withServer(async({url})=>{
 const health=await (await fetch(url+'/api/health')).json();assert.equal(health.checkoutEnabled,false);
 const demo=await fetch(url+'/demo/');assert.equal(demo.status,200);assert.match(await demo.text(),/Universal Custom Design Studio/);
 assert.equal((await fetch(url+'/src/local-server.mjs')).status,200);
 assert.equal((await fetch(url+'/.tj-local-data/designs')).status,404);
 assert.equal((await fetch(url+'/package.json')).status,404);
}));
test('files require raster type; oversized, mismatched, PDF files rejected',async()=>withServer(async({url})=>{
 let r=await fetch(url+'/api/artworks',{method:'POST',headers:{'Content-Type':'application/pdf'},body:PNG});assert.equal(r.status,400);
 r=await fetch(url+'/api/artworks',{method:'POST',headers:{'Content-Type':'application/pdf'},body:Buffer.from('%PDF-1.5 fake')});assert.equal(r.status,400);
 r=await fetch(url+'/api/artworks',{method:'POST',headers:{'Content-Type':'image/png'},body:Buffer.alloc(5*1024*1024+1)});assert.equal(r.status,413);
}));
test('artwork upload is stored privately, requires grant to read',async()=>withServer(async({url,dir})=>{
 const r=await fetch(url+'/api/artworks',{method:'POST',headers:{'Content-Type':'image/png'},body:PNG});assert.equal(r.status,201);
 const a=await r.json();assert.match(a.id,/^art_[a-f0-9]{32}$/);assert.equal(a.width,1);
 assert.equal((await fetch(url+`/api/artworks/${a.id}`)).status,403);
 assert.equal((await fetch(url+`/api/artworks/${a.id}`,{headers:{Authorization:'Bearer invalid'}})).status,403);
 const granted=await fetch(url+`/api/artworks/${a.id}`,{headers:{Authorization:`Bearer ${a.grant}`}});
 assert.equal(granted.status,200);assert.deepEqual(Buffer.from(await granted.arrayBuffer()),PNG);
 const metadata=JSON.parse(await readFile(join(dir,'artworks',a.id+'.json'),'utf8'));
 assert.ok(!JSON.stringify(metadata).includes(a.grant));assert.deepEqual((await readdir(join(dir,'artworks'))).length,2);
}));
test('new private draft is immutable with conflict-controlled revisions; checkout stays disabled',async()=>withServer(async({url,dir})=>{
 const payload={productManifestId:'concept-v-tee',layers:[layer]};
 const created=await json(url,'/api/designs',{...payload,layers:[{...layer,surfaceId:'front'}]});assert.equal(created.status,201);
 const {reference,ownerToken}=created.body;assert.match(reference,/^TJ-[A-F0-9]{24}$/);
 assert.equal((await fetch(url+`/api/designs/${reference}`)).status,403);
 const read=await fetch(url+`/api/designs/${reference}`,{headers:{Authorization:`Bearer ${ownerToken}`}});assert.equal(read.status,200);
 const draft=await read.json();assert.equal(draft.revision,1);assert.equal(draft.checkoutEnabled,false);assert.equal(draft.productionApproved,false);
 const next=await json(url,`/api/designs/${reference}/revisions`,{...payload,expectedRevision:1},ownerToken);
 assert.equal(next.status,201);assert.equal(next.body.revision,2);
 const conflict=await json(url,`/api/designs/${reference}/revisions`,{...payload,expectedRevision:1},ownerToken);assert.equal(conflict.status,409);
 const v1=await fetch(url+`/api/designs/${reference}/revisions/1`,{headers:{Authorization:`Bearer ${ownerToken}`}});
 assert.equal((await v1.json()).revision,1);
 const v2=JSON.parse(await readFile(join(dir,'designs',reference,'2.json'),'utf8'));
 assert.equal(v2.revision,2);assert.ok(!JSON.stringify(v2).includes(ownerToken));
}));
test('asset design reference requires asset grant; credentials never get serialized with design',async()=>withServer(async({url,dir})=>{
 const r=await fetch(url+'/api/artworks',{method:'POST',headers:{'Content-Type':'image/png'},body:PNG});const art=await r.json();
 const artworkLayer={...layer,type:'artwork',artworkId:art.id};delete artworkLayer.value;
 const payload={productManifestId:'concept-crew-tee',layers:[artworkLayer]};
 const ungranted=await json(url,'/api/designs',payload);assert.equal(ungranted.status,403);
 const created=await json(url,'/api/designs',{...payload,artworkGrants:{[art.id]:art.grant}});assert.equal(created.status,201);
 const saved=await readFile(join(dir,'designs',created.body.reference,'1.json'),'utf8');
 assert.ok(!saved.includes(art.grant));assert.equal(JSON.parse(saved).layers[0].artworkId,art.id);
}));
test('invalid design transforms, unknown products and forged references rejected',async()=>withServer(async({url})=>{
 assert.equal((await json(url,'/api/designs',{productManifestId:'omv-wallet',layers:[]})).status,400);
 assert.equal((await json(url,'/api/designs',{productManifestId:'concept-crew-tee',layers:[{...layer,x:.9}]})).status,400);
 assert.equal((await fetch(url+'/api/designs/TJ-AAAAAAAAAAAAAAAAAAAAAAAA',{headers:{Authorization:'Bearer fake'}})).status,404);
}));
test('server refuses network-accessible listen interfaces',async()=>{
 await assert.rejects(()=>createLocalServer({host:'0.0.0.0'}),/loopback/);
});
