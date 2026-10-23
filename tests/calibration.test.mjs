import test from 'node:test';
import assert from 'node:assert/strict';
import {PRODUCT_MANIFESTS} from '../src/catalog.mjs';
import {createCalibrationWorksheet,estimateLayerPhysicalPlacement} from '../src/calibration.mjs';
const product=PRODUCT_MANIFESTS[0];
const evidence={blankSku:'BENCH-RECORD-ONLY',measuredBy:'QA tech',sourceDocument:'mock bench measurement 2026-10-14 (tests only)',measuredAt:'2026-10-14'};
const zone={surfaceId:'front',widthMm:230,heightMm:280,blankWidthMm:300,blankHeightMm:360,processCode:'DTF-TEXTILE',fixtureReference:'Test jig record',safetyInsetMm:4};
const layer={surfaceId:'front',x:.20,y:.20,width:.40,height:.30,rotationDeg:0};
const draft=()=>createCalibrationWorksheet(product,[zone],evidence);
test('physical measurements yield only DRAFT — never product or production approval',()=>{
 const original=structuredClone(product),out=draft();assert.deepEqual(out.issues,[]);assert.equal(out.status,'DRAFT_REQUIRES_PHYSICAL_VERIFICATION');
 assert.equal(out.manufacturingApproved,false);assert.equal(out.checkoutEnabled,false);assert.deepEqual(product,original);
});
test('fails closed on missing traceability or dimensions',()=>{
 assert.ok(createCalibrationWorksheet(product,[zone],{...evidence,sourceDocument:''}).issues.some(x=>x.code==='SOURCE'));
 assert.ok(createCalibrationWorksheet(product,[{...zone,widthMm:NaN}],evidence).issues.some(x=>x.code==='SIZE'));
 assert.ok(createCalibrationWorksheet(product,[{...zone,blankWidthMm:200}],evidence).issues.some(x=>x.code==='BLANK_FIT'));
});
test('fails closed on unsupported manufacturing method and unverified surface',()=>{
 assert.ok(createCalibrationWorksheet(product,[{...zone,processCode:'UV-ROTARY'}],evidence).issues.some(x=>x.code==='PROCESS'));
 assert.ok(createCalibrationWorksheet(product,[{...zone,surfaceId:'unknown'}],evidence).issues.some(x=>x.code==='SURFACE'));
});
test('requires actual wrap circumference for optional curved fit checks',()=>{
 const tumbler=PRODUCT_MANIFESTS.find(p=>p.id==='concept-tumbler');
 const e={...zone,surfaceId:'wrap',widthMm:280,heightMm:100,blankWidthMm:300,blankHeightMm:120,processCode:'UV-ROTARY',curveCircumferenceMm:250};
 const bad=createCalibrationWorksheet(tumbler,[e],evidence);assert.ok(bad.issues.some(x=>x.code==='CURVATURE'));
});
test('calculates printable physical placement and measured DPI, not invented numbers',()=>{
 const out=estimateLayerPhysicalPlacement(draft(),layer,{sourceWidthPx:2300,sourceHeightPx:2800});
 assert.equal(out.ok,true);assert.equal(out.previewOnly,true);
 assert.equal(out.printableWidthMm,92);assert.equal(out.printableHeightMm,84);
 assert.ok(out.dpi>600);assert.equal(out.originMm.x,46);
});
test('rotated oversized designs are rejected by safety inset',()=>{
 const out=estimateLayerPhysicalPlacement(draft(),{...layer,x:.8,width:.25,rotationDeg:45});
 assert.equal(out.ok,false);assert.ok(out.issues.some(x=>x.code==='OUTSIDE_SAFE_ZONE'));
});
test('rejects incomplete measurements and missing surface',()=>{
 assert.equal(estimateLayerPhysicalPlacement(createCalibrationWorksheet(product,[],evidence),layer).ok,false);
 assert.equal(estimateLayerPhysicalPlacement(draft(),{...layer,surfaceId:'sleeve-left'}).ok,false);
});
