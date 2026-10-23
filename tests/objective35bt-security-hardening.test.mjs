import test from 'node:test';import assert from 'node:assert/strict';

import {PRODUCT_MANIFESTS} from '../src/catalog.mjs';import {buildConceptUvReport} from '../src/preview-uv-report.mjs';
const p=PRODUCT_MANIFESTS[0],layers=[{id:'x',type:'text',value:'A',surfaceId:'front',x:.1,y:.1,width:.2,height:.2}];
test('35BT declared mapped UV surface must actually exist in triangle inventory',()=>{const inspection={sha256:'a'.repeat(64),mappedSurfaces:['front'],asset:{triangles:[]}};const r=buildConceptUvReport({product:p,layers,inspection});assert.equal(r.previewChecked,false);assert.deepEqual(r.issues,['MAPPED_SURFACE_WITHOUT_UV_GEOMETRY']);inspection.asset.triangles=[{surfaceId:'front',uv:[[0,0],[1,0],[0,1]]}];assert.equal(buildConceptUvReport({product:p,layers,inspection}).previewChecked,true);});
