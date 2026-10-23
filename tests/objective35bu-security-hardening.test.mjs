import test from 'node:test';import assert from 'node:assert/strict';

import {estimateLayerPhysicalPlacement,createCalibrationWorksheet} from '../src/calibration.mjs';import {PRODUCT_MANIFESTS} from '../src/catalog.mjs';
const p=PRODUCT_MANIFESTS[0],l={surfaceId:'front',x:.15,y:.15,width:.15,height:.15};
const draft=createCalibrationWorksheet(p,[{surfaceId:'front',widthMm:100,heightMm:100,blankWidthMm:120,blankHeightMm:120,processCode:'DTF-TEXTILE',fixtureReference:'Jig'}],{blankSku:'SKU',measuredBy:'Operator',sourceDocument:'Doc',measuredAt:'2026-10-01'});
test('35BU direct placement estimator rejects forged status and missing issue evidence',()=>{assert.equal(estimateLayerPhysicalPlacement(draft,l).ok,true);for(const mutate of [w=>w.checkoutEnabled=true,w=>w.manufacturingApproved=true,w=>delete w.schema,w=>delete w.issues]){const w=structuredClone(draft);mutate(w);assert.equal(estimateLayerPhysicalPlacement(w,l).ok,false);}});
