import test from 'node:test';import assert from 'node:assert/strict';import {preparePrivateConceptExport as prepare} from '../src/preview-private-export-gate.mjs';
const p=()=>({schema:'TJ-LOCAL-CONCEPT-DESIGN-EVIDENCE-1',privateContentIncluded:false,manufacturingApproved:false,checkoutEnabled:false,layers:[]});
test('stable snapshot permits only offline redacted export',async()=>{const v=await prepare({readSnapshot:p});assert.equal(v.checkoutEnabled,false);assert.equal(v.integrity.digestSha256.length,64);assert.equal(v.scope,'LOCAL_REDACTED_ONLY');});
test('editor changes while digesting invalidate pending export',async()=>{let n=0;const f=()=>({...p(),layers:[++n]});await assert.rejects(prepare({readSnapshot:f}),/EXPORT_STALE_EDITOR/);});
test('async digester fails closed on invalid result',async()=>{await assert.rejects(prepare({readSnapshot:p,fingerprint:async()=>{throw Error('bad');}}),/bad/);});
