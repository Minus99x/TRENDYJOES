import test from 'node:test';import assert from 'node:assert/strict';
import {fingerprintConceptEvidence} from '../src/preview-design-fingerprint.mjs';
const p=()=>({schema:'TJ-LOCAL-CONCEPT-DESIGN-EVIDENCE-1',manufacturingApproved:false,checkoutEnabled:false,privateContentIncluded:false});
test('insecure origin without WebCrypto rejects private evidence instead of emitting an unverified digest',async()=>{
 const original=Object.getOwnPropertyDescriptor(globalThis,'crypto');
 try{
  Object.defineProperty(globalThis,'crypto',{value:undefined,configurable:true,writable:true});
  await assert.rejects(fingerprintConceptEvidence(p()),e=>e.code==='CONCEPT_EVIDENCE_SECURE_CONTEXT_REQUIRED');
 }finally{if(original)Object.defineProperty(globalThis,'crypto',original);else delete globalThis.crypto;}
});
test('secure digest succeeds and remains non-authorizing',async()=>{
 const r=await fingerprintConceptEvidence(p());assert.match(r.digestSha256,/^[0-9a-f]{64}$/);
 assert.equal(r.manufacturingApproved,false);assert.equal(r.checkoutEnabled,false);
});
test('test digest injection must still return an exact 32-byte array buffer',async()=>{
 await assert.rejects(fingerprintConceptEvidence(p(),{digest:async()=>new Uint8Array(32)}),/CONCEPT_EVIDENCE_DIGEST/);
});
