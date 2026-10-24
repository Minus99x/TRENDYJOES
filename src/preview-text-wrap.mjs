/** Predict local concept line breaks; text measuring/rendering remains a browser responsibility. */
const CONTROL=/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u;
export function wrapPreviewText({text,maxColumns=28,maxLines=12}={}){
 if(typeof text!=='string'||text.length>1500||CONTROL.test(text)||!Number.isInteger(maxColumns)||maxColumns<1||maxColumns>120||
    !Number.isInteger(maxLines)||maxLines<1||maxLines>60)throw new TypeError('PREVIEW_TEXT_WRAP_INPUT');
 const lines=[];
 for(const paragraph of text.replace(/\r\n?/g,'\n').split('\n')){
   const units=Array.from(paragraph);
   if(!units.length){lines.push('');continue;}
   for(let i=0;i<units.length;i+=maxColumns)lines.push(units.slice(i,i+maxColumns).join(''));
 }
 const truncated=lines.length>maxLines;
 return Object.freeze({schema:'TJ-PREVIEW-TEXT-WRAP-1',lines:Object.freeze(lines.slice(0,maxLines)),
   truncated,estimatedOnly:true,manufacturingApproved:false});
}
