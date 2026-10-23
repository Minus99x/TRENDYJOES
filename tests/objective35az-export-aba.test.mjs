import test from 'node:test';
import assert from 'node:assert/strict';
import {preparePrivateConceptExport as exportPacket} from '../src/preview-private-export-gate.mjs';
const packet=()=>({schema:'TJ-LOCAL-CONCEPT-DESIGN-EVIDENCE-1',scope:'PRIVATE_OFFLINE_EXPLICIT_EXPORT',privateContentIncluded:false,manufacturingApproved:false,checkoutEnabled:false,layers:[{id:'layer-1',contentKind:'TEXT_REDACTED'}]});
function paused(){let resume;const digest=new Promise(resolve=>resume=resolve);return {resume,fn:async p=>{await digest;return {schema:'TJ-LOCAL-CONCEPT-FINGERPRINT-1',digestSha256:'0'.repeat(64),bytes:JSON.stringify(p).length,localOnly:true,manufacturingApproved:false,checkoutEnabled:false}}};}
test('monotonic revision rejects edit-and-revert ABA during digest',async()=>{
 let revision=10,content=packet();const {resume,fn}=paused();
 const pending=exportPacket({readSnapshot:()=>content,readRevision:()=>revision,fingerprint:fn});
 content={...content,layers:[]};revision++;
 content=packet();revision++;resume();
 await assert.rejects(pending,/EXPORT_STALE_EDITOR/);
});
test('monotonic revision rejects invalidation even with byte-identical snapshot',async()=>{
 let rev=1;const {resume,fn}=paused();const pending=exportPacket({readSnapshot:packet,readRevision:()=>rev,fingerprint:fn});
 rev++;resume();await assert.rejects(pending,/EXPORT_STALE_EDITOR/);
});
test('stable revision allows redacted no-commerce packet',async()=>{
 const result=await exportPacket({readSnapshot:packet,readRevision:()=>0});
 assert.equal(result.checkoutEnabled,false);assert.equal(result.manufacturingApproved,false);
 assert.match(result.integrity.digestSha256,/^[a-f0-9]{64}$/);
});
test('revision source must be valid and monotonic nonnegative integer',async()=>{
 for(const readRevision of [null,3,()=>-1,()=>Infinity,()=>NaN,()=>1.2])
  await assert.rejects(exportPacket({readSnapshot:packet,readRevision}),/EXPORT_REVISION/);
});
test('revision callback exception refuses local export',async()=>{
 await assert.rejects(exportPacket({readSnapshot:packet,readRevision:()=>{throw Error('revocation');}}),/revocation/);
});
