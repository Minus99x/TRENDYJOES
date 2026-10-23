import test from 'node:test';import assert from 'node:assert/strict';

import {checkPreviewArtworkUvFootprint} from '../src/preview-uv-footprint.mjs';
const layer={surfaceId:'front',x:.1,y:.1,width:.2,height:.2,rotationDeg:0};
test('35BR degenerate UV polygon blocks sampled concept coverage',()=>{const inspection={asset:{triangles:[{surfaceId:'front',uv:[[0,0],[.5,.5],[1,1]]}]}};assert.equal(checkPreviewArtworkUvFootprint(layer,inspection).reason,'DEGENERATE_MAPPED_UV');inspection.asset.triangles[0].uv=[[0,0],[1,0],[0,1]];assert.equal(checkPreviewArtworkUvFootprint(layer,inspection).sampleCount,25);});
