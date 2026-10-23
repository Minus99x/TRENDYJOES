import test from 'node:test';import assert from 'node:assert/strict';import {readFileSync} from 'node:fs';
const html=readFileSync(new URL('../demo/index.html',import.meta.url),'utf8');
const js=readFileSync(new URL('../demo/studio.mjs',import.meta.url),'utf8');
test('35BH current-layout UV status is accessible and atomic',()=>{assert.match(html,/id="uv-diagnostic-live"[^>]*role="status"[^>]*aria-live="polite"[^>]*aria-atomic="true"/);assert.match(js,/const uvInfo=state\.imported\?buildConceptUvReport\(\{product:state\.product,layers:state\.layers,inspection:state\.imported\}\)/);assert.match(js,/Sampled coverage is NOT production approval/);});
test('35BH measured draft review is context-bound before enabling export',()=>{assert.match(js,/reviewConceptCalibration\(\{worksheet:draft,product:state\.product/);assert.match(js,/modelSha256:state\.imported\?\.sha256\?\?null/);assert.match(js,/!reviewed\.canEstimatePlacement/);});
test('35BH release UI does not enable checkout or invent pricing',()=>{assert.match(html,/disabled-checkout/);assert.match(js,/checkout remains disabled/);});

test('35BH user-initiated redacted review refuses asynchronous stale edits and worksheet changes',()=>{
 assert.match(html,/id="download-concept-review"/);assert.match(html,/id="concept-review-status"[^>]*role="status"[^>]*aria-live="polite"/);
 assert.match(js,/revision!==conceptExportRevision\|\|calibrationSignature!==calibrationFingerprint\(\)/);
 assert.match(js,/state\.calibration!==worksheet/);
 assert.match(js,/buildConceptReviewPacket\(\{product:state\.product,surfaceId:state\.surface/);
 assert.match(js,/No manufacturing approval or order/);
});
