/** Local file-metadata preflight. This does NOT inspect bytes, scan files or authorize upload. */
const goodSize=n=>Number.isSafeInteger(n)&&n>0&&n<=512*1024*1024;
const goodPixels=n=>Number.isSafeInteger(n)&&n>0&&n<=20000;
const formats=Object.freeze({'image/png':['.png'],'image/jpeg':['.jpg','.jpeg'],'image/webp':['.webp'],'image/svg+xml':['.svg']});
export function inspectPreviewArtworkMetadata({name,mimeType,sizeBytes,widthPx=null,heightPx=null}={}){
 if(typeof name!=='string'||name.length>128||!/^[- a-zA-Z0-9_.()]+$/.test(name)||name.startsWith('.')||name.includes('..')||typeof mimeType!=='string'||!Object.hasOwn(formats,mimeType)||!goodSize(sizeBytes))throw new TypeError('PREVIEW_UPLOAD_METADATA');
 if(!formats[mimeType].some(ext=>name.toLowerCase().endsWith(ext)))throw new TypeError('PREVIEW_UPLOAD_MIME_EXTENSION');
 if((widthPx===null)!==(heightPx===null))throw new TypeError('PREVIEW_UPLOAD_PIXEL_PAIR');
 if(widthPx!==null&&(!goodPixels(widthPx)||!goodPixels(heightPx)||widthPx*heightPx>48_000_000))throw new RangeError('PREVIEW_UPLOAD_PIXELS');
 const warnings=[];if(sizeBytes>25*1024*1024)warnings.push('LARGE_LOCAL_FILE');if(mimeType==='image/svg+xml')warnings.push('SVG_REQUIRES_SANITIZATION');if(widthPx===null)warnings.push('PIXEL_DIMENSIONS_NOT_CHECKED');
 return Object.freeze({schema:'TJ-PREVIEW-UPLOAD-PREFLIGHT-1',format:mimeType,declaredSizeBytes:sizeBytes,warnings:Object.freeze(warnings),bytesInspected:false,virusScanned:false,uploadAuthorized:false,localOnly:true});
}
