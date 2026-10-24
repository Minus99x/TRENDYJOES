/** WCAG relative luminance for concept preview legibility; visual aid, not a print color proof. */
function rgb(hex){if(typeof hex!=='string'||!/^#[\da-fA-F]{6}$/.test(hex))throw new TypeError('PREVIEW_COLOR_HEX');return [1,3,5].map(i=>parseInt(hex.slice(i,i+2),16)/255);}
const luminance=(hex)=>rgb(hex).map(n=>n<=0.04045?n/12.92:((n+0.055)/1.055)**2.4).reduce((sum,n,i)=>sum+n*[0.2126,0.7152,0.0722][i],0);
export function reviewPreviewContrast({foreground,background,largeText=false}={}) {
 if(typeof largeText!=='boolean')throw new TypeError('PREVIEW_TEXT_SIZE');
 const a=luminance(foreground),b=luminance(background),ratio=(Math.max(a,b)+0.05)/(Math.min(a,b)+0.05);
 return Object.freeze({schema:'TJ-PREVIEW-CONTRAST-1',ratio:Math.round(ratio*100)/100,
   minimum:largeText?3:4.5,passesAA:ratio>=(largeText?3:4.5),scope:'SCREEN_PREVIEW_ONLY',manufacturingApproved:false});
}
