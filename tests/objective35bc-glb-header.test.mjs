import test from 'node:test';import assert from 'node:assert/strict';
import {readBoundedLocalGlb,validateLocalGlbHeader} from '../src/preview-glb-file-read.mjs';
function glb(){const b=new ArrayBuffer(24),v=new DataView(b);for(const [i,n] of [[0,0x46546c67],[4,2],[8,24],[12,4],[16,0x4e4f534a]])v.setUint32(i,n,true);return b;}
test('35BC GLB v2 minimal header accepted as structure only',async()=>{const b=glb();assert.equal(validateLocalGlbHeader(b).previewOnly,true);assert.equal((await readBoundedLocalGlb({size:24,name:'toy.glb',arrayBuffer:async()=>b})).byteLength,24);});
for(const [name,at,value] of [['magic',0,0],['version',4,3],['declared size',8,25],['json length',12,12],['JSON tag',16,0x004e4942]])test(`35BC rejects forged ${name}`,()=>{const b=glb();new DataView(b).setUint32(at,value,true);assert.throws(()=>validateLocalGlbHeader(b),/GLB_HEADER_/);});
test('35BC rejects partial and trailing chunks',()=>{assert.throws(()=>validateLocalGlbHeader(new ArrayBuffer(22)),/GLB_HEADER_/);const b=new ArrayBuffer(28);new Uint8Array(b).set(new Uint8Array(glb()));new DataView(b).setUint32(8,28,true);assert.throws(()=>validateLocalGlbHeader(b),/GLB_HEADER_BIN_CHUNK/);});
