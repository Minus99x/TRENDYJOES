import test from 'node:test';import assert from 'node:assert/strict';import {readFileSync} from 'node:fs';
const html=readFileSync(new URL('../demo/index.html',import.meta.url),'utf8'),js=readFileSync(new URL('../demo/studio.mjs',import.meta.url),'utf8');
test('local model import uses accessible atomic live status',()=>{assert.match(html,/id="model-import-summary"[^>]*role="status"[^>]*aria-live="polite"[^>]*aria-atomic="true"/);});
test('active-surface accessibility description updated at every render',()=>{assert.match(js,/\$\('surface-edit-context'\)\.textContent=describeActivePreview\(/);});
