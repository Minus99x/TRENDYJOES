import test from 'node:test';import assert from 'node:assert/strict';

import {validateLocalModelInspection} from '../src/preview-model-receipt.mjs';
const sha='b'.repeat(64),p={surfaces:[{id:'front'},{id:'back'}]};
const t=()=>({a:[0,0,0],b:[1,0,0],c:[0,1,0],material:'fabric',side:'asset',surfaceId:'front',uv:[[0,0],[1,0],[0,1]]});
const good=()=>({sha256:sha,byteLength:200,nodeCount:1,vertexCount:3,triangleCount:1,mappedSurfaces:['front'],missingSurfaces:['back'],approval:'UNVERIFIED_LOCAL_PREVIEW_ONLY',assetBoundsMeters:{min:[0,0,0],max:[1,1,0],extent:[1,1,0]},asset:{status:'IMPORTED_UNVERIFIED',sha256:sha,modelId:`imported-${sha.slice(0,14)}`,surfaceIds:['front'],triangles:[t()]}});
test('35BP falsely declared mapped surface with no geometry rejected',()=>{assert.equal(validateLocalModelInspection(good(),p).status,'IMPORTED_UNVERIFIED');const r=good();r.mappedSurfaces=['front','back'];r.missingSurfaces=[];r.asset.surfaceIds=['front','back'];assert.throws(()=>validateLocalModelInspection(r,p),/MODEL_MAPPING_WITHOUT_TRIANGLES/);});
