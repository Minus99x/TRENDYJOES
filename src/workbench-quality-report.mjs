import {assertWorkbenchDraft} from './workbench-draft-state.mjs';import {reviewWorkbenchSafeZone} from './workbench-safe-zone.mjs';import {reviewWorkbenchOverlaps} from './workbench-overlap-review.mjs';import {reviewPreviewContrast} from './preview-color-contrast.mjs';
/** Per-surface visual QA; warnings require review but cannot grant manufacturing or checkout rights. */
export function inspectWorkbenchQuality(d,{surfaceId=d?.activeSurface,zoneWidth=100,zoneHeight=100,margin=2,background='#ffffff'}={}){
 assertWorkbenchDraft(d);if(typeof background!=='string'||!/^#[0-9a-fA-F]{6}$/.test(background))throw new TypeError('WORKBENCH_BACKGROUND');const safe=reviewWorkbenchSafeZone(d,{surfaceId,zoneWidth,zoneHeight,margin}),overlap=reviewWorkbenchOverlaps(d,{surfaceId}),warnings=safe.warnings.map(w=>w.warning);
 if(overlap.overlapCount)warnings.push('OVERLAPPING_LAYERS');
 for(const l of d.layers.filter(l=>l.surfaceId===surfaceId&&l.visible&&l.kind==='text'))if(!reviewPreviewContrast({foreground:l.color,background}).passesAA)warnings.push('LOW_SCREEN_CONTRAST');
 return Object.freeze({schema:'TJ-WORKBENCH-QUALITY-1',surfaceId,layerCount:safe.inspectedLayers,overlapCount:overlap.overlapCount,warnings:Object.freeze([...new Set(warnings)]),requiresHumanReview:warnings.length>0,localOnly:true,manufacturingApproved:false,priceApproved:false,checkoutEnabled:false});
}
