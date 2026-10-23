import test from 'node:test';import assert from 'node:assert/strict';import {buildConceptUvReport} from '../src/preview-uv-report.mjs';import {PRODUCT_MANIFESTS} from '../src/catalog.mjs';
const p=PRODUCT_MANIFESTS[0];
const model={sha256:'a'.repeat(64),mappedSurfaces:['front'],asset:{triangles:[{surfaceId:'front',uv:[[0,0],[1,0],[1,1]]},{surfaceId:'front',uv:[[0,0],[1,1],[0,1]]}]}};
const l={id:'L',type:'text',value:'A',surfaceId:'front',x:.2,y:.3,width:.3,height:.1,rotationDeg:0,scaleFactor:1};
test('surface gaps are reported with strict nonproduction boundary',()=>{const r=buildConceptUvReport({product:p,layers:[l],inspection:model});assert.equal(r.previewChecked,true);assert.equal(r.allSamplePointsCovered,false);assert.equal(r.details[0].covered,true);assert.ok(r.issues.includes('MISSING_MODEL_MAPPING:back'));assert.equal(r.productionApproved,false);assert.equal(r.checkoutEnabled,false);});
test('invalid composition rejected before UV checks',()=>{const r=buildConceptUvReport({product:p,layers:[{...l,x:1.2}],inspection:model});assert.equal(r.previewChecked,false);assert.deepEqual(r.issues,['INVALID_COMPOSITION_OR_MODEL']);});
