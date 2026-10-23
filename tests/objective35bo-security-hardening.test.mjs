import test from 'node:test';import assert from 'node:assert/strict';

import {validateLocalModelInspection} from '../src/preview-model-receipt.mjs';
const sha='a'.repeat(64),p={surfaces:[{id:'front'}]};
const good=()=>({sha256:sha,byteLength:200,nodeCount:1,vertexCount:3,triangleCount:1,mappedSurfaces:['front'],missingSurfaces:[],approval:'UNVERIFIED_LOCAL_PREVIEW_ONLY',assetBoundsMeters:{min:[0,0,0],max:[1,1,0],extent:[1,1,0]},asset:{status:'IMPORTED_UNVERIFIED',sha256:sha,modelId:`imported-${sha.slice(0,14)}`,surfaceIds:['front'],triangles:[{a:[0,0,0],b:[1,0,0],c:[0,1,0],material:'fabric',side:'asset',surfaceId:'front',uv:[[0,0],[1,0],[0,1]]}]}});
test('35BO injected model and asset authority flags rejected',()=>{assert.equal(validateLocalModelInspection(good(),p).checkoutEnabled,false);for(const mutate of [x=>x.manufacturingApproved=true,x=>x.checkoutEnabled=true,x=>x.customerAuthenticated=true,x=>x.asset.productionReady=true,x=>x.asset.checkoutEnabled=true,x=>x.asset.manufacturingApproved=true]){const r=good();mutate(r);assert.throws(()=>validateLocalModelInspection(r,p),/MODEL_AUTHORITY_FORGED/);}});
