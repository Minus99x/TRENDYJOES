import test from 'node:test';import assert from 'node:assert/strict';import {readBoundedLocalGlb} from '../src/preview-glb-file-read.mjs';
const header=(n=24)=>{const b=new ArrayBuffer(n),v=new DataView(b);v.setUint32(0,0x46546c67,true);v.setUint32(4,2,true);v.setUint32(8,n,true);v.setUint32(12,4,true);v.setUint32(16,0x4e4f534a,true);return b;};
const file=(size=24,name='model.glb',actual=size)=>({size,name,arrayBuffer:async()=>actual>=24?header(actual):new ArrayBuffer(actual)});
test('bounded exact-length local GLB input accepted',async()=>{assert.equal((await readBoundedLocalGlb(file())).byteLength,24);});
test('truncated/overlong/oversized/fake extension fail closed',async()=>{for(const f of [file(24,'evil.bin'),file(24,'model.glb',23),file(24,'model.glb',30),file(17),file(16*1024*1024+1),file(24,'model.glb'.repeat(100))])await assert.rejects(readBoundedLocalGlb(f));});
test('invalid byte return and inconsistent read fail closed',async()=>{await assert.rejects(readBoundedLocalGlb({size:24,name:'test.glb',arrayBuffer:async()=>new Uint8Array(24)}),/GLB_FILE_READ_INCONSISTENT/);});
