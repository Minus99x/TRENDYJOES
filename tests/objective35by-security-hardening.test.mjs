import test from 'node:test';import assert from 'node:assert/strict';

import {preparePrivateConceptExport} from '../src/preview-private-export-gate.mjs';
const raw={schema:'TJ-LOCAL-CONCEPT-DESIGN-EVIDENCE-1',manufacturingApproved:false,checkoutEnabled:false,privateContentIncluded:false,layers:[{id:'A',contentKind:'TEXT_REDACTED'}]};
test('35BY completed export is detached from mutable editor state, even nested values',async()=>{const r=await preparePrivateConceptExport({readSnapshot:()=>raw});raw.layers[0].id='MUTATED AFTER EXPORT';raw.layers.push({id:'NEW'});assert.equal(r.evidence.layers.length,1);assert.equal(r.evidence.layers[0].id,'A');assert(Object.isFrozen(r.evidence.layers));assert(Object.isFrozen(r.evidence.layers[0]));assert(Object.isFrozen(r.integrity));});
