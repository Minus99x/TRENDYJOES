import test from 'node:test';import assert from 'node:assert/strict';

import {PRODUCT_MANIFESTS} from '../src/catalog.mjs';import {buildConceptUvReport} from '../src/preview-uv-report.mjs';
const product=PRODUCT_MANIFESTS[0],layer={id:'x',type:'text',value:'A',surfaceId:'front',x:.1,y:.1,width:.2,height:.2};
const inspection=()=>({sha256:'a'.repeat(64),mappedSurfaces:['front'],asset:{triangles:[{surfaceId:'front',uv:[[0,0],[1,0],[0,1]]}]}});
test('35BS rogue triangle surface cannot hide behind valid mapped UV',()=>{assert.equal(buildConceptUvReport({product,layers:[layer],inspection:inspection()}).previewChecked,true);for(const surfaceId of ['admin','back',undefined]){const m=inspection();m.asset.triangles.push({surfaceId,uv:[[0,0],[1,0],[0,1]]});const r=buildConceptUvReport({product,layers:[layer],inspection:m});assert.equal(r.previewChecked,false);assert.deepEqual(r.issues,['INVALID_TRIANGLE_SURFACE']);}});
