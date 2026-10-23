import test from 'node:test';import assert from 'node:assert/strict';

import {fingerprintConceptEvidence} from '../src/preview-design-fingerprint.mjs';
const p=()=>({schema:'TJ-LOCAL-CONCEPT-DESIGN-EVIDENCE-1',manufacturingApproved:false,checkoutEnabled:false,privateContentIncluded:false,customerAuthenticated:false,pricingVerified:false,cartLine:null,orderId:null});
test('35BW concept-only fingerprints refuse hidden checkout/order elevation',async()=>{assert.match((await fingerprintConceptEvidence(p())).digestSha256,/^[a-f0-9]{64}$/);for(const mutation of [x=>x.customerAuthenticated=true,x=>x.pricingVerified=true,x=>x.cartLine={},x=>x.orderId='ORDER-123']){const o=p();mutation(o);await assert.rejects(fingerprintConceptEvidence(o),/CONCEPT_EVIDENCE_SCHEMA/);}});
