import test from 'node:test';import assert from 'node:assert/strict';

import {PRODUCT_MANIFESTS} from '../src/catalog.mjs';
import {createCalibrationWorksheet} from '../src/calibration.mjs';
import {reviewConceptCalibration} from '../src/preview-calibration-review.mjs';
const p=PRODUCT_MANIFESTS[0], zone={surfaceId:'front',widthMm:100,heightMm:100,blankWidthMm:150,blankHeightMm:150,processCode:'DTF-TEXTILE',fixtureReference:'Fixture'};
const w=()=>createCalibrationWorksheet(p,[zone],{blankSku:'SKU',measuredBy:'Operator',sourceDocument:'Document',measuredAt:'2024-02-29'});
test('35BK valid leap day remains reviewable; impossible forged date cannot pass',()=>{
 const worksheet=w();assert.equal(reviewConceptCalibration({worksheet,product:p,surfaceId:'front'}).canEstimatePlacement,true);
 for(const date of ['2025-02-29','2026-02-30','2026-13-01','2000-00-10','2024-04-31']){worksheet.measuredAt=date;assert.equal(reviewConceptCalibration({worksheet,product:p,surfaceId:'front'}).canEstimatePlacement,false,date);}
});
