/** Exact planar union of axis-aligned preview rectangles, excluding overlap double count. */
const finite=n=>typeof n==='number'&&Number.isFinite(n)&&Math.abs(n)<=100000;
export function measurePreviewCoverage({zoneWidth,zoneHeight,rectangles=[]}={}){
 if(!finite(zoneWidth)||!finite(zoneHeight)||zoneWidth<=0||zoneHeight<=0||!Array.isArray(rectangles)||rectangles.length>40||rectangles.some(r=>!r||![r.x,r.y,r.width,r.height].every(finite)||r.width<=0||r.height<=0))throw new TypeError('PREVIEW_COVERAGE_INPUT');
 const rects=rectangles.map(r=>({x1:Math.max(0,r.x),x2:Math.min(zoneWidth,r.x+r.width),y1:Math.max(0,r.y),y2:Math.min(zoneHeight,r.y+r.height)})).filter(r=>r.x2>r.x1&&r.y2>r.y1);
 const xs=[0,zoneWidth,...rects.flatMap(r=>[r.x1,r.x2])].sort((a,b)=>a-b);let area=0;
 for(let i=1;i<xs.length;i++){const x1=xs[i-1],x2=xs[i];if(x2<=x1)continue;const spans=rects.filter(r=>r.x1<x2&&r.x2>x1).map(r=>[r.y1,r.y2]).sort((a,b)=>a[0]-b[0]);let length=0,start=null,end=null;for(const [a,b] of spans){if(start===null){start=a;end=b;}else if(a>end){length+=end-start;start=a;end=b;}else end=Math.max(end,b);}if(start!==null)length+=end-start;area+=(x2-x1)*length;}
 const zoneAreaMm2=zoneWidth*zoneHeight,coveredAreaMm2=Math.max(0,Math.min(area,zoneAreaMm2));return Object.freeze({schema:'TJ-PREVIEW-COVERAGE-1',coveredAreaMm2,coveragePercent:Number((coveredAreaMm2/zoneAreaMm2*100).toFixed(3)),clipped:rectangles.some(r=>r.x<0||r.y<0||r.x+r.width>zoneWidth||r.y+r.height>zoneHeight),localOnly:true,manufacturingApproved:false});
}
