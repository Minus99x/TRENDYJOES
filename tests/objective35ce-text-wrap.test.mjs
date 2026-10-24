import test from 'node:test';import assert from 'node:assert/strict';
import {wrapPreviewText} from '../src/preview-text-wrap.mjs';
test('35CE respects explicit paragraph breaks and limits',()=>{const r=wrapPreviewText({text:'ABCD\nEFG',maxColumns:2,maxLines:3});assert.deepEqual(r.lines,['AB','CD','EF']);assert.equal(r.truncated,true);assert.equal(r.manufacturingApproved,false);});
test('35CE avoids breaking surrogate pairs',()=>{const r=wrapPreviewText({text:'😀😁',maxColumns:1});assert.deepEqual(r.lines,['😀','😁']);});
test('35CE non text or control payload rejected',()=>{for(const t of [null,9,'x\u0000y','x'.repeat(1501)])assert.throws(()=>wrapPreviewText({text:t}));assert.throws(()=>wrapPreviewText({text:'x',maxColumns:0}));});
