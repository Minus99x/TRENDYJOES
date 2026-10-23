import test from 'node:test';import assert from 'node:assert/strict';import {uvPointInTriangle as hit} from '../src/preview-uv-triangle.mjs';
const tri=[[0,0],[1,0],[0,1]];
test('barycentric hit and boundary handling',()=>{for(const p of [[0,0],[.2,.2],[1,0],[.5,.5],[0,1]])assert.equal(hit(p,tri),true);for(const p of [[.8,.8],[-.1,.3],[.5,2],[NaN,0]])assert.equal(hit(p,tri),false);});
test('degenerate, malicious and out-of-atlas triangles are never accepted',()=>{for(const t of [[[0,0],[0,0],[0,0]],[[0,0],[2,0],[0,1]],[[0,0],[NaN,0],[0,1]],[[0,0],[1,0],[0,0]]])assert.equal(hit([.1,.1],t),false);assert.equal(hit([.1,.1],tri,{epsilon:1}),false);});
