/** One safe, immutable local preview worksheet combining prior approved review utilities. */
import {buildPreviewDesignReviewSheet} from './preview-design-review-sheet.mjs';
import {reviewRotatedPreview} from './preview-rotation-footprint.mjs';
import {measurePreviewCoverage} from './preview-coverage-map.mjs';
import {analyzePreviewOverlaps} from './preview-surface-overlap.mjs';
import {inspectPreviewArtworkMetadata} from './preview-upload-preflight.mjs';
const exact=(o,names)=>o&&typeof o==='object'&&!Array.isArray(o)&&Object.keys(o).every(k=>names.includes(k));
export function buildPreviewQualityWorkbook({review,rotation=null,coverage=null,overlap=null,upload=null}={}){
 if(!exact(review,['productLabel','surfaceLabel','artwork','raster','rectangle','text','contrast','importedModelPresent']))throw new TypeError('PREVIEW_WORKBOOK_REVIEW');
 const categories=[['rotation',rotation,['centerX','centerY','width','height','angleDegrees','zoneWidth','zoneHeight','margin']],['coverage',coverage,['zoneWidth','zoneHeight','rectangles']],['overlap',overlap,['surfaceId','rectangles']],['upload',upload,['name','mimeType','sizeBytes','widthPx','heightPx']]];
 for(const [key,part,allowed] of categories)if(part!==null&&!exact(part,allowed))throw new TypeError('PREVIEW_WORKBOOK_'+key.toUpperCase());
 const base=buildPreviewDesignReviewSheet(review),rot=rotation===null?null:reviewRotatedPreview(rotation),cov=coverage===null?null:measurePreviewCoverage(coverage),over=overlap===null?null:analyzePreviewOverlaps(overlap),pre=upload===null?null:inspectPreviewArtworkMetadata(upload);
 const warnings=[...base.warnings];if(rot&&rot.warning!=='NONE')warnings.push(rot.warning);if(cov?.clipped)warnings.push('CLIPPED_COVERAGE');if(over?.overlapCount)warnings.push('OVERLAPPING_ARTWORK');if(pre)warnings.push(...pre.warnings);
 return Object.freeze({schema:'TJ-PREVIEW-QUALITY-WORKBOOK-1',productLabel:base.productLabel,surfaceLabel:base.surfaceLabel,coveragePercent:cov?.coveragePercent??null,overlapCount:over?.overlapCount??null,rotationWarning:rot?.warning??null,uploadMetadataWarnings:Object.freeze(pre?.warnings??[]),warnings:Object.freeze([...new Set(warnings)]),localOnly:true,manufacturingApproved:false,priceApproved:false,checkoutEnabled:false});
}
