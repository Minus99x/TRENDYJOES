/** Height-only text layout estimate; never claims exact rendered font metrics. */
import {wrapPreviewText} from './preview-text-wrap.mjs';
const finite=n=>typeof n==='number'&&Number.isFinite(n)&&n>0&&n<=100000;
export function reviewPreviewTextHeight({text,maxColumns,maxLines,fontSizeMm,lineHeightFactor=1.2,zoneHeightMm}={}){
 if(!finite(fontSizeMm)||!finite(lineHeightFactor)||lineHeightFactor<0.8||lineHeightFactor>3||!finite(zoneHeightMm))throw new RangeError('PREVIEW_TEXT_HEIGHT_INPUT');
 const lines=wrapPreviewText({text,maxColumns,maxLines});const estimatedHeightMm=lines.lines.length*fontSizeMm*lineHeightFactor;
 return Object.freeze({schema:'TJ-PREVIEW-TEXT-HEIGHT-1',estimatedHeightMm,lineCount:lines.lines.length,fitsHeight:estimatedHeightMm<=zoneHeightMm,warning:estimatedHeightMm>zoneHeightMm?'TEXT_HEIGHT_OVERFLOW':lines.truncated?'TEXT_LINE_OVERFLOW':'NONE',approximate:true,localOnly:true});
}
