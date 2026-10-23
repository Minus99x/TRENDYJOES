import test from 'node:test';import assert from 'node:assert/strict';
import {PRODUCT_MANIFESTS} from '../src/catalog.mjs';
import {createCalibrationWorksheet} from '../src/calibration.mjs';
import {reviewConceptCalibration} from '../src/preview-calibration-review.mjs';
const p=PRODUCT_MANIFESTS[0],base={blankSku:'TEST-BLANK',measuredBy:'Test technician',sourceDocument:'Synthetic only',measuredAt:'2026-10-14',modelSha256:'a'.repeat(64)},zone={surfaceId:'front',widthMm:100,heightMm:140,blankWidthMm:180,blankHeightMm:200,processCode:'DTF-TEXTILE',fixtureReference:'Synthetic test jig',safetyInsetMm:4,bleedMm:2};
const draft=()=>createCalibrationWorksheet(p,[zone],base);
test('35BF verified-context draft remains nonproduction',()=>{const r=reviewConceptCalibration({worksheet:draft(),product:p,surfaceId:'front',modelSha256:base.modelSha256});assert.equal(r.canEstimatePlacement,true);assert.equal(r.manufacturingApproved,false);assert.equal(r.physicalVerificationRequired,true);});
test('35BF rejects stale product / surface / model',()=>{for(const args of [{product:{...p,id:'other'}},{surfaceId:'back'},{modelSha256:'b'.repeat(64)}]){const r=reviewConceptCalibration({worksheet:draft(),product:p,surfaceId:'front',modelSha256:base.modelSha256,...args});assert.equal(r.canEstimatePlacement,false);}});
test('35BF cannot silently turn a forged worksheet into approval',()=>{const w=draft();w.manufacturingApproved=true;assert.equal(reviewConceptCalibration({worksheet:w,product:p,surfaceId:'front'}).canEstimatePlacement,false);});
test('35BF blocks unreasonably tiny measurements and unsafe combined margin',()=>{assert(draft().issues.length===0);assert(createCalibrationWorksheet(p,[{...zone,widthMm:.001}],base).issues.some(i=>i.code==='SIZE'));assert(createCalibrationWorksheet(p,[{...zone,widthMm:10,safetyInsetMm:4,bleedMm:2}],base).issues.some(i=>i.code==='MARGIN_FIT'));});

test('35BF refuses forged draft without measurement evidence, methods or physical blank sizes',()=>{
 for(const corrupt of [w=>w.blankSku='',w=>w.sourceDocument='',w=>w.measuredBy='',
  w=>w.zones[0].blankWidthMm=0,w=>w.zones[0].processCode='SYNTHETIC-APPROVED',
  w=>w.zones[0].fixtureReference='',w=>w.zones[0].bleedMm=NaN]){
  const w=draft();corrupt(w);assert.equal(reviewConceptCalibration({worksheet:w,product:p,surfaceId:'front'}).canEstimatePlacement,false);
 }
});
