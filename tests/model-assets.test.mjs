import test from 'node:test';
import assert from 'node:assert/strict';
import {PRODUCT_MANIFESTS} from '../src/catalog.mjs';
import {inspectGlb} from '../src/model-assets.mjs';
import {validateLocalModelInspection} from '../src/preview-model-receipt.mjs';
const product=PRODUCT_MANIFESTS[0];
function fixture({surface='front',external=false,extension=false,uv=[0,0,1,0,0,1],indices=[0,1,2],translation=[0,0,0]}={}){
 const bin=Buffer.alloc(68),view=new DataView(bin.buffer,bin.byteOffset,bin.byteLength);
 const pos=[-.5,0,0,.5,0,0,0,1,0];pos.forEach((v,i)=>view.setFloat32(i*4,v,true));
 uv.forEach((v,i)=>view.setFloat32(36+i*4,v,true));indices.forEach((v,i)=>view.setUint16(60+i*2,v,true));
 const doc={asset:{version:'2.0'},buffers:[{byteLength:68,...(external?{uri:'evil.bin'}:{})}],bufferViews:[{buffer:0,byteOffset:0,byteLength:36},{buffer:0,byteOffset:36,byteLength:24},{buffer:0,byteOffset:60,byteLength:6}],accessors:[{bufferView:0,componentType:5126,count:3,type:'VEC3'},{bufferView:1,componentType:5126,count:3,type:'VEC2'},{bufferView:2,componentType:5123,count:3,type:'SCALAR'}],meshes:[{primitives:[{attributes:{POSITION:0,TEXCOORD_0:1},indices:2}]}],nodes:[{mesh:0,translation,extras:{tjSurfaceId:surface}}],scenes:[{nodes:[0]}],scene:0};
 if(extension)doc.extensionsRequired=['KHR_draco_mesh_compression'];
 let js=Buffer.from(JSON.stringify(doc));js=Buffer.concat([js,Buffer.alloc((4-js.length%4)%4,32)]);
 const output=Buffer.alloc(12+8+js.length+8+bin.length);output.writeUInt32LE(0x46546c67,0);output.writeUInt32LE(2,4);output.writeUInt32LE(output.length,8);output.writeUInt32LE(js.length,12);output.writeUInt32LE(0x4e4f534a,16);js.copy(output,20);
 const start=20+js.length;output.writeUInt32LE(bin.length,start);output.writeUInt32LE(0x004e4942,start+4);bin.copy(output,start+8);return output;
}
async function rejects(bytes,code){await assert.rejects(inspectGlb(bytes,product),e=>e.code===code);}
test('imports embedded GLB, hashes bytes, and binds print UV to selected manifest',async()=>{
 const g=await inspectGlb(fixture(),product);
 assert.equal(g.triangleCount,1);assert.equal(g.vertexCount,3);
 assert.deepEqual(g.mappedSurfaces,['front']);assert.deepEqual(g.missingSurfaces,['back','sleeve-left']);
 assert.equal(g.sha256.length,64);assert.equal(g.approval,'UNVERIFIED_LOCAL_PREVIEW_ONLY');
 assert.equal(g.asset.triangles[0].surfaceId,'front');assert.deepEqual(g.asset.triangles[0].uv,[[0,0],[1,0],[0,1]]);
 assert.ok(g.asset.triangles[0].a.every(Number.isFinite));
});
test('GLB header rejects non-GLB, truncated assets, fake length',async()=>{
 await rejects(Buffer.from('not a model'),'FILE_SIZE');
 const b=fixture();b[0]=0;await rejects(b,'HEADER');
 const c=fixture();c.writeUInt32LE(c.length+12,8);await rejects(c,'HEADER');
 const d=fixture().subarray(0,40);await rejects(d,'HEADER');
});
test('GLB rejects referenced outside buffers and required compressed extensions',async()=>{
 await rejects(fixture({external:true}),'BUFFER');
 await rejects(fixture({extension:true}),'EXTENSIONS');
});
test('surface mappings cannot reference undeclared product surfaces',async()=>await rejects(fixture({surface:'footwear-sole'}),'SURFACE'));
test('printable surface UVs must be normalized, finite coordinates',async()=>{
 await rejects(fixture({uv:[0,0,1.1,0,0,1]}),'UV');
 await rejects(fixture({uv:[0,0,NaN,0,0,1]}),'NONFINITE');
});
test('triangle indices must stay within allocated vertex data',async()=>await rejects(fixture({indices:[0,1,8]}),'INDICES'));
test('scene graph transforms are applied, then normalized for stable camera view',async()=>{
 const g=await inspectGlb(fixture({translation:[12,5,-3]}),product);
 assert.deepEqual(g.assetBoundsMeters.min,[11.5,5,-3]);
 assert.deepEqual(g.assetBoundsMeters.extent,[1,1,0]);
 const ext=g.asset.triangles[0].a;
 assert.ok(ext.every(v=>Math.abs(v)<2));
});
test('same GLB has stable SHA digest across repeated imports',async()=>{
 const input=fixture();const a=await inspectGlb(input,product),b=await inspectGlb(input,product);
 assert.equal(a.sha256,b.sha256);
});
test('browser UI has explicit model import and preserves disabled checkout',async()=>{
 const fs=await import('node:fs/promises');const text=await fs.readFile(new URL('../demo/index.html',import.meta.url),'utf8');
 for(const id of ['model-file','model-import-summary','clear-model','validate-calibration','export-calibration'])assert.ok(text.includes(`id="${id}"`));
 assert.match(text,/Checkout unavailable/);assert.match(text,/disabled class="disabled-checkout"/);
});

test('actual inspected embedded GLB passes strict preview receipt and cannot authorize production',async()=>{
 const m=await inspectGlb(fixture(),product);const r=validateLocalModelInspection(m,product);
 assert.equal(r.sha256,m.sha256);assert.equal(r.triangleCount,1);
 assert.equal(r.manufacturingApproved,false);assert.equal(r.checkoutEnabled,false);
});
test('GLB WebCrypto unavailable rejects with explicit secure-origin error',async()=>{
 const original=Object.getOwnPropertyDescriptor(globalThis,'crypto');
 try{
  Object.defineProperty(globalThis,'crypto',{value:undefined,configurable:true,writable:true});
  await assert.rejects(inspectGlb(fixture(),product),e=>e.code==='GLB_SECURE_CONTEXT_REQUIRED');
 }finally{if(original)Object.defineProperty(globalThis,'crypto',original);else delete globalThis.crypto;}
});
