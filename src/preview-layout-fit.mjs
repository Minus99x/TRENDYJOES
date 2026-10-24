/** Pure offline canvas framing. Coordinates are millimeters, never inferred printer authorization. */
const positive=(n)=>typeof n==='number'&&Number.isFinite(n)&&n>0&&n<=100000;
const fail=()=>{throw new RangeError('PREVIEW_FIT_DIMENSIONS');};
export function fitPreviewArtwork({sourceWidth,sourceHeight,zoneWidth,zoneHeight,mode='contain'}={}) {
 if (![sourceWidth,sourceHeight,zoneWidth,zoneHeight].every(positive)||!['contain','cover'].includes(mode))fail();
 const ratio=Math[mode==='contain'?'min':'max'](zoneWidth/sourceWidth,zoneHeight/sourceHeight);
 const width=sourceWidth*ratio,height=sourceHeight*ratio;
 if(![width,height].every(Number.isFinite))fail();
 return Object.freeze({schema:'TJ-PREVIEW-FIT-1',mode,x:(zoneWidth-width)/2,y:(zoneHeight-height)/2,
   width,height,scale:ratio,cropped:mode==='cover'&&(width>zoneWidth||height>zoneHeight),
   manufacturingApproved:false});
}
