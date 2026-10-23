import test from 'node:test';import assert from 'node:assert/strict';

import {PRODUCT_MANIFESTS} from '../src/catalog.mjs';
import {createCalibrationWorksheet} from '../src/calibration.mjs';
import {reviewConceptCalibration} from '../src/preview-calibration-review.mjs';
const p=PRODUCT_MANIFESTS[0];const z={surfaceId:'front',widthMm:100,heightMm:120,blankWidthMm:160,blankHeightMm:200,processCode:'DTF-TEXTILE',fixtureReference:'Jig'};
const w=createCalibrationWorksheet(p,[z],{blankSku:'A',measuredBy:'B',sourceDocument:'C',measuredAt:'2026-10-01'});
test('35BL forged 100-kilometer print zone is not a valid physical draft',()=>{assert.equal(reviewConceptCalibration({worksheet:w,product:p,surfaceId:'front'}).canEstimatePlacement,true);for(const field of ['printableWidthMm','printableHeightMm','blankWidthMm','blankHeightMm']){const v=w.zones[0][field];w.zones[0][field]=100000;assert.equal(reviewConceptCalibration({worksheet:w,product:p,surfaceId:'front'}).canEstimatePlacement,false,field);w.zones[0][field]=v;}});
