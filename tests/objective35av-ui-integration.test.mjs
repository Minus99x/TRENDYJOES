import test from 'node:test';import assert from 'node:assert/strict';import {readFileSync} from 'node:fs';
const src=readFileSync(new URL('../demo/studio.mjs',import.meta.url),'utf8');
test('actual imported model produces explicit sampled UV warning, no approval',()=>{assert.match(src,/buildConceptUvReport\(\{product,layers:state\.layers,inspection:model\}\)/);assert.match(src,/sampled only, NOT production approval/);});
