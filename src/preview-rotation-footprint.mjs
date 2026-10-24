/** Rotated-artwork axis-aligned footprint for local concept previews; no printer calibration. */
const num=n=>typeof n==='number'&&Number.isFinite(n)&&Math.abs(n)<=100000;
export function reviewRotatedPreview({centerX,centerY,width,height,angleDegrees,zoneWidth,zoneHeight,margin=0}={}){
 if(![centerX,centerY,width,height,angleDegrees,zoneWidth,zoneHeight,margin].every(num)||width<=0||height<=0||zoneWidth<=0||zoneHeight<=0||margin<0||margin*2>=Math.min(zoneWidth,zoneHeight)||Math.abs(angleDegrees)>36000)throw new RangeError('PREVIEW_ROTATION_INPUT');
 const radians=(angleDegrees%360)*Math.PI/180;
 const boundingWidth=Math.abs(width*Math.cos(radians))+Math.abs(height*Math.sin(radians));
 const boundingHeight=Math.abs(width*Math.sin(radians))+Math.abs(height*Math.cos(radians));
 const epsilon=1e-9;
 const fitsZone=centerX-boundingWidth/2>=-epsilon&&centerY-boundingHeight/2>=-epsilon&&centerX+boundingWidth/2<=zoneWidth+epsilon&&centerY+boundingHeight/2<=zoneHeight+epsilon;
 const fitsMargin=centerX-boundingWidth/2>=margin-epsilon&&centerY-boundingHeight/2>=margin-epsilon&&centerX+boundingWidth/2<=zoneWidth-margin+epsilon&&centerY+boundingHeight/2<=zoneHeight-margin+epsilon;
 return Object.freeze({schema:'TJ-PREVIEW-ROTATION-1',boundingWidth,boundingHeight,fitsZone,fitsMargin,warning:!fitsZone?'OUTSIDE_ZONE':!fitsMargin?'INSIDE_MARGIN':'NONE',localOnly:true,manufacturingApproved:false});
}
