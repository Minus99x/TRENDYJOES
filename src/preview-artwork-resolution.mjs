/** Estimate rendered raster DPI using explicit physical dimensions, never a manufacturing approval. */
const validPixels=(n)=>Number.isSafeInteger(n)&&n>0&&n<=10000;
const validMm=(n)=>typeof n==='number'&&Number.isFinite(n)&&n>0&&n<=10000;
export function reviewRasterResolution({widthPx,heightPx,printWidthMm,printHeightMm,referenceDpi=300}={}) {
 if(!validPixels(widthPx)||!validPixels(heightPx)||!validMm(printWidthMm)||!validMm(printHeightMm)||
   !Number.isInteger(referenceDpi)||referenceDpi<72||referenceDpi>1200)throw new RangeError('PREVIEW_RASTER_DIMENSIONS');
 if(widthPx*heightPx>48_000_000)throw new RangeError('PREVIEW_RASTER_AREA');
 const dpiX=widthPx*25.4/printWidthMm,dpiY=heightPx*25.4/printHeightMm;
 const dpi=Math.min(dpiX,dpiY);
 return Object.freeze({schema:'TJ-PREVIEW-RASTER-RESOLUTION-1',effectiveDpi:Math.round(dpi*10)/10,
   meetsPreviewTarget:dpi>=referenceDpi,status:dpi>=referenceDpi?'PREVIEW_TARGET_MET':'LOW_RESOLUTION_WARNING',
   referenceDpi,manufacturingApproved:false,localOnly:true});
}
