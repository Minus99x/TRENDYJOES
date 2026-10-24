/** Whitelisted, local-only printable concept review. No private media, identity, price or authorization. */
import {fitPreviewArtwork} from './preview-layout-fit.mjs';
import {reviewRasterResolution} from './preview-artwork-resolution.mjs';
import {reviewPreviewSafeArea} from './preview-safe-area.mjs';
import {reviewPreviewContrast} from './preview-color-contrast.mjs';
import {wrapPreviewText} from './preview-text-wrap.mjs';
import {collectPreviewReviewBlockers} from './preview-review-blockers.mjs';
const safeLabel=(text)=>typeof text==='string'&&text.length<100&&text.trim()&&
 !/[\u0000-\u001f\u007f<>]/u.test(text)?text.trim():null;
const keyset=(obj,keys)=>obj&&typeof obj==='object'&&!Array.isArray(obj)&&Object.keys(obj).every(k=>keys.includes(k));
export function buildPreviewDesignReviewSheet({productLabel,surfaceLabel,artwork=null,raster=null,rectangle=null,text=null,contrast=null,importedModelPresent=false}={}){
 if(!safeLabel(productLabel)||!safeLabel(surfaceLabel)||typeof importedModelPresent!=='boolean')throw new TypeError('PREVIEW_REVIEW_LABEL');
 if(artwork!==null&&!keyset(artwork,['sourceWidth','sourceHeight','zoneWidth','zoneHeight','mode']))throw new TypeError('PREVIEW_REVIEW_ARTWORK');
 if(raster!==null&&!keyset(raster,['widthPx','heightPx','printWidthMm','printHeightMm','referenceDpi']))throw new TypeError('PREVIEW_REVIEW_RASTER');
 if(rectangle!==null&&!keyset(rectangle,['zoneWidth','zoneHeight','x','y','width','height','margin']))throw new TypeError('PREVIEW_REVIEW_RECTANGLE');
 if(text!==null&&!keyset(text,['text','maxColumns','maxLines']))throw new TypeError('PREVIEW_REVIEW_TEXT');
 if(contrast!==null&&!keyset(contrast,['foreground','background','largeText']))throw new TypeError('PREVIEW_REVIEW_CONTRAST');
 const layout=artwork===null?null:fitPreviewArtwork(artwork),resolution=raster===null?null:reviewRasterResolution(raster),
       area=rectangle===null?null:reviewPreviewSafeArea(rectangle),lineWrap=text===null?null:wrapPreviewText(text),
       legibility=contrast===null?null:reviewPreviewContrast(contrast);
 const blockers=collectPreviewReviewBlockers({raster:resolution,safeArea:area,contrast:legibility,text:lineWrap,importedModelPresent});
 // Never serialize input objects. In particular, design layer IDs, customer data and artwork media must not leak.
 return Object.freeze({schema:'TJ-PREVIEW-DESIGN-REVIEW-SHEET-1',productLabel:productLabel.trim(),surfaceLabel:surfaceLabel.trim(),
   artworkPlacement:layout===null?null:Object.freeze({mode:layout.mode,cropped:layout.cropped}),
   rasterDpi:resolution?.effectiveDpi??null,safeAreaWarning:area?.warning??null,
   screenContrastRatio:legibility?.ratio??null,estimatedTextLines:lineWrap?.lines.length??null,
   warnings:blockers.warnings,localOnly:true,manufacturingApproved:false,priceApproved:false,
   customerAuthenticated:false,checkoutEnabled:false,cartLine:null,orderId:null});
}
