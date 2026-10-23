import test from 'node:test';import assert from 'node:assert/strict';

import {preparePrivateConceptExport} from '../src/preview-private-export-gate.mjs';
const p=()=>({schema:'TJ-LOCAL-CONCEPT-DESIGN-EVIDENCE-1',manufacturingApproved:false,checkoutEnabled:false,privateContentIncluded:false,layers:[]});
test('35BX forged fingerprints never create a private export',async()=>{const good=await preparePrivateConceptExport({readSnapshot:p});assert.match(good.integrity.digestSha256,/^[a-f0-9]{64}$/);for(const signature of [{digestSha256:'0'.repeat(64)},{schema:'TJ-LOCAL-CONCEPT-FINGERPRINT-1',digestSha256:'0'.repeat(64),bytes:1,localOnly:true,checkoutEnabled:true,manufacturingApproved:false}])await assert.rejects(preparePrivateConceptExport({readSnapshot:p,fingerprint:async()=>signature}),/EXPORT_INTEGRITY_INVALID/);});
