import test from 'node:test';import assert from 'node:assert/strict';import {measurePreviewCoverage as run} from '../src/preview-coverage-map.mjs';
test('35CP exact union does not count overlap twice',()=>{const o=run({zoneWidth:10,zoneHeight:10,rectangles:[{x:0,y:0,width:5,height:10},{x:4,y:0,width:4,height:10}]});assert.equal(o.coveredAreaMm2,80);assert.equal(o.coveragePercent,80);});
test('35CP clips off-zone rectangles and flags',()=>{const o=run({zoneWidth:10,zoneHeight:10,rectangles:[{x:-5,y:2,width:10,height:2}]});assert.equal(o.coveredAreaMm2,10);assert.equal(o.clipped,true);});
test('35CP rejects nonfinite or zero geometry',()=>{assert.throws(()=>run({zoneWidth:NaN,zoneHeight:10}));assert.throws(()=>run({zoneWidth:10,zoneHeight:10,rectangles:[{x:0,y:0,width:0,height:1}]}));});
