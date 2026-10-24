import test from 'node:test';import assert from 'node:assert/strict';
import {reviewRasterResolution} from '../src/preview-artwork-resolution.mjs';
test('35CB flags low effective DPI',()=>{const r=reviewRasterResolution({widthPx:600,heightPx:600,printWidthMm:152.4,printHeightMm:152.4});assert.equal(r.effectiveDpi,100);assert.equal(r.status,'LOW_RESOLUTION_WARNING');assert.equal(r.manufacturingApproved,false);});
test('35CB uses lower axis for nonuniform scaling',()=>{const r=reviewRasterResolution({widthPx:3000,heightPx:500,printWidthMm:100,printHeightMm:100});assert.equal(r.meetsPreviewTarget,false);assert.equal(r.effectiveDpi,127);});
test('35CB acceptable concept target is not manufacturing approval',()=>{const r=reviewRasterResolution({widthPx:3000,heightPx:3000,printWidthMm:100,printHeightMm:100});assert.equal(r.meetsPreviewTarget,true);assert.equal(r.manufacturingApproved,false);});
test('35CB rejects untrusted dimensions',()=>{for(const b of [{widthPx:'300'},{heightPx:0},{printWidthMm:-1},{referenceDpi:'300'},{widthPx:10000,heightPx:10000}])assert.throws(()=>reviewRasterResolution({widthPx:100,heightPx:100,printWidthMm:50,printHeightMm:50,...b}));});
