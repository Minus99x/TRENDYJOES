import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {join,resolve} from 'node:path';
import {createStaticPreviewState,updateStaticPreview,reviewStaticPreview,staticPreviewReviewAvailability,staticPreviewAccessibilitySummary} from '../src/static-preview-contract.mjs';
const root=resolve(fileURLToPath(new URL('..',import.meta.url)));
const fresh=()=>createStaticPreviewState('?product=concept-crew');
const add=(state,value)=>updateStaticPreview(state,{type:'ADD_TEXT',value});
const rejected=[
 ['bidi override','\u202eRIGHT-TO-LEFT SPOOF'],
 ['bidi embedding','\u202aLEFT-TO-RIGHT SPOOF'],
 ['bidi isolate','\u2067ISOLATED SPOOF'],
 ['bidi mark','a\u200fb'],
 ['Arabic letter mark','a\u061cb'],
 ['zero width space','\u200b'],
 ['word joiner','a\u2060b'],
 ['byte order mark','\ufeff'],
 ['C1 control','a\u0085b'],
 ['DEL control','a\u007fb'],
 ['lone high surrogate','\ud800'],
 ['lone low surrogate','\udc00'],
 ['high surrogate followed by ASCII','a\ud800b'],
 ['combining mark only','\u0301'],
 ['zero width joiner only','\u200d'],
 ['variation selector only','\ufe0f'],
];
for(const [name,value] of rejected){
 test(`34T ADD_TEXT rejects ${name} without mutating customer state`,()=>{
  const before=fresh();const snapshot=structuredClone(before);
  assert.throws(()=>add(before,value),/INVALID_TEXT/);
  assert.deepEqual(before,snapshot);
 });
}
const accepted=[
 ['English punctuation','Hello, world!'],
 ['Arabic text','مرحبا بالعالم'],
 ['Hebrew text','שלום עולם'],
 ['Persian ZWNJ inside words','می\u200cخواهم'],
 ['accented combining sequence','Cafe\u0301'],
 ['emoji ZWJ family','👩‍👩‍👧‍👦'],
 ['Japanese text','こんにちは世界'],
];
for(const [name,value] of accepted){
 test(`34T legitimate ${name} remains editable and reviewable`,()=>{
  const state=add(fresh(),value);
  assert.equal(state.layers.length,1);
  assert.equal(reviewStaticPreview(state).layerCount,1);
  assert.equal(staticPreviewReviewAvailability(state).ready,true);
  assert.equal(staticPreviewAccessibilitySummary(state).valid,true);
 });
}
test('34T forged invisible layer cannot bypass ADD_TEXT through review or readiness',()=>{
 const state=add(fresh(),'NORMAL TEXT');state.layers[0].value='\u202eSPOOF';
 assert.throws(()=>reviewStaticPreview(state),/INVALID_TEXT/);
 assert.equal(staticPreviewReviewAvailability(state).ready,false);
 assert.equal(staticPreviewAccessibilitySummary(state).valid,false);
});
test('34T forged unpaired surrogate fails review and neutral accessibility projection',()=>{
 const state=add(fresh(),'NORMAL TEXT');state.layers[0].value='\ud800';
 assert.throws(()=>reviewStaticPreview(state),/INVALID_TEXT/);
 assert.deepEqual(staticPreviewAccessibilitySummary(state),{valid:false,description:'Concept status unavailable. No changes were saved.'});
});
test('34T rejected second layer leaves existing private wording intact',()=>{
 const state=add(fresh(),'CUSTOMER SECRET');const snapshot=structuredClone(state);
 assert.throws(()=>add(state,'\u2066FORGED'),/INVALID_TEXT/);
 assert.deepEqual(state,snapshot);
 assert.equal(reviewStaticPreview(state).layerCount,1);
 assert.doesNotMatch(JSON.stringify(reviewStaticPreview(state)),/CUSTOMER SECRET/);
});
test('34T existing 200-code-unit limit still rejects oversized wording',()=>{
 assert.throws(()=>add(fresh(),'a'.repeat(201)),/INVALID_TEXT/);
 assert.equal(add(fresh(),'a'.repeat(200)).layers[0].value.length,200);
});
test('34T protected staging browser contract retains Unicode guard without commerce capability',async()=>{
 const code=await readFile(join(root,'integrations/shopify/staging-static-preview/assets/tj34i-src-static-preview-contract.js'),'utf8');
 assert.match(code,/UNSAFE_STATIC_TEXT/);
 assert.ok(code.includes('p{L}'));
 const manifest=JSON.parse(await readFile(join(root,'integrations/shopify/staging-static-preview/staging-static-preview-bundle-manifest.json'),'utf8'));
 const sourceVersion=JSON.parse(await readFile(join(root,'package.json'),'utf8')).version;
 // A protected staging candidate may lag new offline source until manually reconciled.
 assert.ok(manifest.sourceVersion.localeCompare(sourceVersion,undefined,{numeric:true})<=0);
 assert.equal(manifest.requiresMainEngineeringAcceptance,true);assert.equal(manifest.shopifyThemeInstalled,false);
});
