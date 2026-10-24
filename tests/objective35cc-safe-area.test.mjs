import test from 'node:test';import assert from 'node:assert/strict';
import {reviewPreviewSafeArea} from '../src/preview-safe-area.mjs';
const z={zoneWidth:100,zoneHeight:80,margin:5};
test('35CC safe layout',()=>{const r=reviewPreviewSafeArea({...z,x:10,y:10,width:60,height:50});assert.deepEqual([r.fitsZone,r.fitsSafeArea,r.warning],[true,true,'NONE']);assert.equal(r.manufacturingApproved,false);});
test('35CC distinguishes crossing margin vs zone',()=>{assert.equal(reviewPreviewSafeArea({...z,x:0,y:5,width:80,height:60}).warning,'INSIDE_MARGIN');assert.equal(reviewPreviewSafeArea({...z,x:-1,y:5,width:80,height:60}).warning,'OUTSIDE_ZONE');});
test('35CC reject impossible geometry',()=>{for(const b of [{width:-1},{margin:50},{x:NaN},{zoneWidth:'100'},{margin:-1}])assert.throws(()=>reviewPreviewSafeArea({...z,x:10,y:10,width:60,height:50,...b}));});
