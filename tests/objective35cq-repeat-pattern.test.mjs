import test from 'node:test';import assert from 'node:assert/strict';import {tilePreviewPattern as run} from '../src/preview-repeat-pattern.mjs';
test('35CQ pattern tiling counts cells with clipping',()=>{const o=run({zoneWidth:23,zoneHeight:20,tileWidth:10,tileHeight:10});assert.equal(o.tileCount,6);assert.equal(o.cells[2].visibleWidth,3);assert.equal(o.cells[5].y,10);});
test('35CQ staggered rows are offset in preview',()=>{const o=run({zoneWidth:30,zoneHeight:20,tileWidth:10,tileHeight:10,stagger:true});assert.equal(o.cells[3].x,5);});
test('35CQ denies explosive tiling and nonboolean stagger',()=>{assert.throws(()=>run({zoneWidth:10000,zoneHeight:10000,tileWidth:1,tileHeight:1}));assert.throws(()=>run({zoneWidth:10,zoneHeight:10,tileWidth:1,tileHeight:1,stagger:'yes'}));});
