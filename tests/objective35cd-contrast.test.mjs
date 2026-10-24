import test from 'node:test';import assert from 'node:assert/strict';
import {reviewPreviewContrast} from '../src/preview-color-contrast.mjs';
test('35CD white on black has maximum screen contrast',()=>{const r=reviewPreviewContrast({foreground:'#ffffff',background:'#000000'});assert.equal(r.ratio,21);assert.equal(r.passesAA,true);assert.equal(r.manufacturingApproved,false);});
test('35CD identical colors fail even for large text',()=>{assert.equal(reviewPreviewContrast({foreground:'#aaaaaa',background:'#aaaaaa',largeText:true}).passesAA,false);});
test('35CD require exact hex RGB without alpha',()=>{for(const foreground of ['#abc','red','#ffffffff','var(--red)','   #ffffff',null])assert.throws(()=>reviewPreviewContrast({foreground,background:'#000000'}));assert.throws(()=>reviewPreviewContrast({foreground:'#ffffff',background:'#000000',largeText:'false'}));});
