import test from 'node:test';import assert from 'node:assert/strict';

import {uvPointInTriangle} from '../src/preview-uv-triangle.mjs';
const tri=[[0,0],[1,0],[0,1]];
test('35BQ epsilon must be finite numeric and bounded, not coercible string',()=>{assert.equal(uvPointInTriangle([.2,.2],tri),true);for(const epsilon of ['0',null,{},NaN,Infinity,-1,.001])assert.equal(uvPointInTriangle([.2,.2],tri,{epsilon}),false,String(epsilon));});
