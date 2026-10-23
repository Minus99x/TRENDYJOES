/** Strict mathematical UV point containment for unverified imported meshes. */
export function uvPointInTriangle(point,tri,{epsilon=1e-9}={}){
 if(!Array.isArray(point)||point.length!==2||!Array.isArray(tri)||tri.length!==3||
  ![...point,...tri.flat()].every(x=>typeof x==='number'&&Number.isFinite(x))||
  !tri.every(p=>Array.isArray(p)&&p.length===2)||
  [epsilon,...point,...tri.flat()].some(x=>!Number.isFinite(x)))return false;
 if(typeof epsilon!=='number'||!Number.isFinite(epsilon)||epsilon<0||epsilon>1e-6||point.some(x=>x<0||x>1)||tri.flat().some(x=>x<0||x>1))return false;
 const [a,b,c]=tri;
 const den=(b[1]-c[1])*(a[0]-c[0])+(c[0]-b[0])*(a[1]-c[1]);
 if(Math.abs(den)<1e-12)return false;
 const u=((b[1]-c[1])*(point[0]-c[0])+(c[0]-b[0])*(point[1]-c[1]))/den;
 const v=((c[1]-a[1])*(point[0]-c[0])+(a[0]-c[0])*(point[1]-c[1]))/den;
 return u>=-epsilon&&v>=-epsilon&&u+v<=1+epsilon;
}
