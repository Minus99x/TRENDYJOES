import test from 'node:test';
import assert from 'node:assert/strict';
import {validateLocalModelInspection as validate} from '../src/preview-model-receipt.mjs';
const p={surfaces:[{id:'front'},{id:'back'}]},sha='c'.repeat(64);
const triangle=()=>({a:[-1,0,0],b:[1,0,0],c:[0,1,0],material:'fabric',side:'asset',surfaceId:'front',uv:[[0,0],[1,0],[0,1]]});
const valid=()=>({sha256:sha,byteLength:1024,nodeCount:1,vertexCount:3,triangleCount:1,
 mappedSurfaces:['front'],missingSurfaces:['back'],approval:'UNVERIFIED_LOCAL_PREVIEW_ONLY',
 assetBoundsMeters:{min:[0,0,0],max:[1,1,0],extent:[1,1,0]},
 asset:{status:'IMPORTED_UNVERIFIED',modelId:`imported-${sha.slice(0,14)}`,sha256:sha,surfaceIds:['front'],triangles:[triangle()]}});
test('valid preview mesh passes without commerce or production authority',()=>{
 const o=validate(valid(),p);assert.equal(o.manufacturingApproved,false);assert.equal(o.checkoutEnabled,false);
 assert.deepEqual(o.mappedSurfaces,['front']);assert(Object.isFrozen(o));
});
const mutations=[
 ['NaN coordinate',r=>r.asset.triangles[0].a[0]=NaN],
 ['infinite coordinate',r=>r.asset.triangles[0].b[1]=Infinity],
 ['massive coordinate',r=>r.asset.triangles[0].c[0]=99999],
 ['missing coordinate',r=>r.asset.triangles[0].a.pop()],
 ['no triangle vertices',r=>r.asset.triangles[0]={}],
 ['unexpected authority',r=>r.asset.triangles[0].approved=true],
 ['invalid material',r=>r.asset.triangles[0].material='signed'],
 ['invalid side',r=>r.asset.triangles[0].side='checkout'],
 ['unmapped surface',r=>r.asset.triangles[0].surfaceId='back'],
 ['unknown surface',r=>r.asset.triangles[0].surfaceId='other'],
 ['missing UV',r=>delete r.asset.triangles[0].uv],
 ['bad UV',r=>r.asset.triangles[0].uv[2][0]=-1],
 ['UV beyond atlas',r=>r.asset.triangles[0].uv[1][1]=2],
 ['forged asset hash',r=>r.asset.sha256='f'.repeat(64)],
 ['missing asset mappings',r=>r.asset.surfaceIds=[]],
 ['duplicate asset mappings',r=>r.asset.surfaceIds=['front','front']],
 ['absent nodes',r=>delete r.nodeCount],
 ['excessive vertices',r=>r.vertexCount=140001],
 ['forged extent',r=>r.assetBoundsMeters.extent[0]=500],
 ['infinite bounds',r=>r.assetBoundsMeters.max[0]=Infinity],
 ['missing bounds',r=>delete r.assetBoundsMeters]
];
for(const [label,change] of mutations)test(`reject ${label}`,()=>{const r=valid();change(r);assert.throws(()=>validate(r,p),/MODEL_/);});
test('plain nonprinting triangle allowed only alongside actually mapped printable geometry',()=>{const r=valid();r.asset.triangles[0].surfaceId=null;delete r.asset.triangles[0].uv;assert.throws(()=>validate(r,p),/MODEL_MAPPING_WITHOUT_TRIANGLES/);r.asset.triangles.push(triangle());r.triangleCount=2;assert.equal(validate(r,p).status,'IMPORTED_UNVERIFIED');});
