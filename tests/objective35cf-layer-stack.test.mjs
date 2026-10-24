import test from 'node:test';import assert from 'node:assert/strict';
import {movePreviewLayer} from '../src/preview-layer-stack.mjs';
const layers=[{id:'a',surfaceId:'front'},{id:'b',surfaceId:'back'},{id:'c',surfaceId:'front'},{id:'d',surfaceId:'front'}];
test('35CF reorder only within surface positions',()=>{const r=movePreviewLayer({layers,surfaceId:'front',layerId:'a',direction:'front'});assert.deepEqual(r.map(l=>l.id),['c','b','d','a']);assert.deepEqual(layers.map(l=>l.id),['a','b','c','d']);assert.ok(Object.isFrozen(r));});
test('35CF no-op at edge',()=>{const r=movePreviewLayer({layers,surfaceId:'front',layerId:'a',direction:'backward'});assert.deepEqual(r,layers);});
test('35CF duplicate/cross-surface/ref injection refused',()=>{assert.throws(()=>movePreviewLayer({layers,surfaceId:'back',layerId:'a',direction:'front'}));assert.throws(()=>movePreviewLayer({layers:[layers[0],layers[0]],surfaceId:'front',layerId:'a',direction:'front'}));assert.throws(()=>movePreviewLayer({layers,surfaceId:'front',layerId:'a',direction:'delete'}));});
