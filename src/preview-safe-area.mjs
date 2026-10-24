/** Review a proposed rectangular artwork footprint against an explicitly measured zone. */
const finite=(n)=>typeof n==='number'&&Number.isFinite(n)&&Math.abs(n)<=100000;
export function reviewPreviewSafeArea({zoneWidth,zoneHeight,x,y,width,height,margin=0}={}) {
 if(![zoneWidth,zoneHeight,x,y,width,height,margin].every(finite)||zoneWidth<=0||zoneHeight<=0||
    width<=0||height<=0||margin<0||margin*2>=Math.min(zoneWidth,zoneHeight))throw new RangeError('PREVIEW_SAFE_AREA_GEOMETRY');
 const outside=x<0||y<0||x+width>zoneWidth||y+height>zoneHeight;
 const violatesMargin=x<margin||y<margin||x+width>zoneWidth-margin||y+height>zoneHeight-margin;
 return Object.freeze({schema:'TJ-PREVIEW-SAFE-AREA-1',fitsZone:!outside,
   fitsSafeArea:!violatesMargin,warning:outside?'OUTSIDE_ZONE':(violatesMargin?'INSIDE_MARGIN':'NONE'),
   manufacturingApproved:false});
}
