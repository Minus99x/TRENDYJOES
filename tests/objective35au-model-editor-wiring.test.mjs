import test from 'node:test';import assert from 'node:assert/strict';import {readFileSync} from 'node:fs';
const src=readFileSync(new URL('../demo/studio.mjs',import.meta.url),'utf8');
test('GLB inspection is lifecycle-bound and validated before editor mutation',()=>{
 const i=src.indexOf('const model=await inspectGlb');const j=src.indexOf('state.imported=model;',i);assert.ok(i>0&&j>i);const between=src.slice(i,j);
 assert.match(between,/modelImportLifecycle\.current\(ticket\)/);assert.match(between,/validateLocalModelInspection\(model,product\)/);assert.match(between,/modelImportLifecycle\.commit\(ticket/);
});
test('clear/surface/product changes invalidate pending import',()=>{assert.match(src,/clear-model'\)\.addEventListener\('click',\(\)=>\{modelImportLifecycle\.invalidate\(\)/);assert.match(src,/newProduct\(/);assert.match(src,/modelImportLifecycle\.invalidate\(\);editorAsyncGate\.invalidate\(\);/);});
