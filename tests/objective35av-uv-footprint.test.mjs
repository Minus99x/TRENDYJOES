import test from 'node:test';import assert from 'node:assert/strict';import {checkPreviewArtworkUvFootprint as check} from '../src/preview-uv-footprint.mjs';
const inspection={asset:{triangles:[{surfaceId:'front',uv:[[0,0],[1,0],[1,1]]},{surfaceId:'front',uv:[[0,0],[1,1],[0,1]]}]}};
const layer={surfaceId:'front',x:.2,y:.2,width:.3,height:.4,rotationDeg:15};
test('mapped square supports rotated preview only, not approval',()=>{const r=check(layer,inspection);assert.equal(r.covered,true);assert.equal(r.manufacturingApproved,false);assert.equal(r.sampleCount,25);});
test('rejects gaps, unknown surfaces, bounds excursions and bad grid',()=>{assert.equal(check({...layer,surfaceId:'side'},inspection).covered,false);assert.equal(check({...layer,x:.95},inspection).reason,'OUTSIDE_PREVIEW_ZONE');assert.equal(check(layer,{asset:{triangles:[{surfaceId:'front',uv:[[0,0],[.1,0],[0,.1]]}]}}).reason,'UV_PREVIEW_GAP');assert.equal(check(layer,inspection,{grid:500}).covered,false);});
