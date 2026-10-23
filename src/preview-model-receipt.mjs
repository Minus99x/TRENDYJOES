/** Strict, fail-closed receipt for local GLB preview geometry, never production approval.
 * The inspector output is untrusted until every triangle and declared surface
 * mapping is checked. This validates shape/consistency, not a signature or
 * cryptographic binding to the model bytes; verify the inspector SHA separately.
 */
const fail=code=>{throw Object.assign(new Error(code),{code});};
const finite=x=>typeof x==='number'&&Number.isFinite(x);
const boundedInt=(v,min,max)=>Number.isSafeInteger(v)&&v>=min&&v<=max;
const vec=(v,n,bound)=>Array.isArray(v)&&v.length===n&&v.every(x=>finite(x)&&Math.abs(x)<=bound);
const surfaceArray=(a,allowed)=>Array.isArray(a)&&a.every(s=>typeof s==='string'&&allowed.has(s))&&new Set(a).size===a.length;
function verifyTriangle(t,allowed,mapped){
 if(!t||typeof t!=='object'||Array.isArray(t)||!vec(t.a,3,4)||!vec(t.b,3,4)||!vec(t.c,3,4)||
  t.material!=='fabric'||t.side!=='asset'||!Object.hasOwn(t,'surfaceId'))fail('MODEL_TRIANGLE_INVALID');
 const keys=['a','b','c','material','side','surfaceId',...(t.surfaceId===null?[]:['uv'])];
 if(Object.keys(t).length!==keys.length||keys.some(k=>!Object.hasOwn(t,k)))fail('MODEL_TRIANGLE_INVALID');
 const ab=t.b.map((x,i)=>x-t.a[i]),ac=t.c.map((x,i)=>x-t.a[i]);
 const cross=[ab[1]*ac[2]-ab[2]*ac[1],ab[2]*ac[0]-ab[0]*ac[2],ab[0]*ac[1]-ab[1]*ac[0]];
 if(Math.hypot(...cross)<=1e-12)fail('MODEL_TRIANGLE_DEGENERATE');
 if(t.surfaceId===null)return;
 if(typeof t.surfaceId!=='string'||!allowed.has(t.surfaceId)||!mapped.has(t.surfaceId))fail('MODEL_TRIANGLE_SURFACE');
 if(!Array.isArray(t.uv)||t.uv.length!==3||!t.uv.every(v=>vec(v,2,1)&&v.every(x=>x>=0)))fail('MODEL_TRIANGLE_UV');
 const [a,b,c]=t.uv;
 if(Math.abs((b[0]-a[0])*(c[1]-a[1])-(b[1]-a[1])*(c[0]-a[0]))<=1e-12)fail('MODEL_TRIANGLE_UV_DEGENERATE');
}
export function validateLocalModelInspection(result,product){
 if(!result||typeof result!=='object'||Array.isArray(result)||!product||!Array.isArray(product.surfaces))fail('MODEL_RESULT_INVALID');
 if(result.manufacturingApproved===true||result.checkoutEnabled===true||result.customerAuthenticated===true||
  result.asset?.manufacturingApproved===true||result.asset?.checkoutEnabled===true||result.asset?.productionReady===true)fail('MODEL_AUTHORITY_FORGED');
 const sha=result.sha256;
 if(typeof sha!=='string'||!(/^[a-f0-9]{64}$/.test(sha))||!boundedInt(result.byteLength,20,16*1024*1024)||
  !boundedInt(result.triangleCount,1,45000)||!boundedInt(result.nodeCount,1,250)||
  !boundedInt(result.vertexCount,3,140000)||!Array.isArray(result.mappedSurfaces)||!Array.isArray(result.missingSurfaces))fail('MODEL_RESULT_INVALID');
 const allowed=new Set(product.surfaces.map(s=>s.id));
 if(!allowed.size||allowed.size!==product.surfaces.length||[...allowed].some(x=>typeof x!=='string'||!x))fail('MODEL_SURFACE_FORGED');
 if(!surfaceArray(result.mappedSurfaces,allowed)||!surfaceArray(result.missingSurfaces,allowed))fail('MODEL_SURFACE_FORGED');
 const mapped=new Set(result.mappedSurfaces),missing=new Set(result.missingSurfaces);
 if([...allowed].some(id=>mapped.has(id)===missing.has(id)))fail('MODEL_SURFACE_INCOMPLETE');
 const asset=result.asset;
 if(result.approval!=='UNVERIFIED_LOCAL_PREVIEW_ONLY'||!asset||asset.status!=='IMPORTED_UNVERIFIED'||
  asset.modelId!==`imported-${sha.slice(0,14)}`||asset.sha256!==sha||
  !Array.isArray(asset.triangles)||asset.triangles.length!==result.triangleCount||
  !surfaceArray(asset.surfaceIds,allowed)||asset.surfaceIds.length!==mapped.size||
  asset.surfaceIds.some(s=>!mapped.has(s)))fail('MODEL_APPROVAL_FORGED');
 for(const t of asset.triangles)verifyTriangle(t,allowed,mapped);
 const represented=new Set(asset.triangles.map(t=>t.surfaceId).filter(s=>s!==null));
 if([...mapped].some(id=>!represented.has(id)))fail('MODEL_MAPPING_WITHOUT_TRIANGLES');
 const bounds=result.assetBoundsMeters;
 if(!bounds||!vec(bounds.min,3,10000)||!vec(bounds.max,3,10000)||!vec(bounds.extent,3,20000)||
  bounds.extent.some((v,i)=>v<0||Math.abs(v-(bounds.max[i]-bounds.min[i]))>1e-5)||
  Math.max(...bounds.extent)<=0)fail('MODEL_BOUNDS_INVALID');
 return Object.freeze({sha256:sha,byteLength:result.byteLength,triangleCount:result.triangleCount,
  mappedSurfaces:Object.freeze([...mapped]),missingSurfaces:Object.freeze([...missing]),
  status:'IMPORTED_UNVERIFIED',checkoutEnabled:false,manufacturingApproved:false});
}
