import test from 'node:test';import assert from 'node:assert/strict';
import {collectPreviewReviewBlockers} from '../src/preview-review-blockers.mjs';
import {reviewRasterResolution} from '../src/preview-artwork-resolution.mjs';
test('35CG empty review remains concept-only',()=>{const b=collectPreviewReviewBlockers();assert.deepEqual(b.warnings,[]);assert.equal(b.manufacturingApproved,false);assert.equal(b.priceApproved,false);});
test('35CG low raster and imported model explicitly called out',()=>{const raster=reviewRasterResolution({widthPx:100,heightPx:100,printWidthMm:100,printHeightMm:100});const b=collectPreviewReviewBlockers({raster,importedModelPresent:true});assert.deepEqual(b.warnings,['LOW_RASTER_DPI','IMPORTED_MODEL_UNVERIFIED']);});
test('35CG forged approval rejected',()=>{assert.throws(()=>collectPreviewReviewBlockers({raster:{schema:'TJ-PREVIEW-RASTER-RESOLUTION-1',manufacturingApproved:true,meetsPreviewTarget:true}}));assert.throws(()=>collectPreviewReviewBlockers({importedModelPresent:'false'}));});
