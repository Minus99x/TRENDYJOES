import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {resolve,join} from 'node:path';
import {createHash} from 'node:crypto';
import {buildStagingStaticBundle} from '../src/staging-static-package.mjs';
const root=resolve(new URL('..',import.meta.url).pathname);
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
const protectedTrees=[
 ['staging-static-preview','staging-static-preview-bundle-manifest.json'],
 ['main-staging-reconciliation-candidate','main-night-reconciliation-manifest.json']
];
test('35AR both protected 13-file staging candidate trees remain byte-pinned and write-blocked',async()=>{
 for(const [directory,manifestName] of protectedTrees){
  const folder=join(root,'integrations/shopify',directory);
  const manifest=JSON.parse(await readFile(join(folder,manifestName),'utf8'));
  assert.equal(manifest.entries.length,13,directory);
  assert.equal(manifest.checkoutEnabled,false);
  for(const item of manifest.entries){
   assert.match(item.path,/^(?:assets|sections)\/tj/);
   const bytes=await readFile(join(folder,item.path));
   assert.equal(sha(bytes),item.sha256,item.path);
   assert.equal(bytes.length,item.bytes,item.path);
  }
 }
});
test('35AR new local footwear source requires manual staging reconciliation; no silent regeneration',async()=>{
 const generated=await buildStagingStaticBundle({root});
 const protectedDir=join(root,'integrations/shopify/staging-static-preview');
 const existing=JSON.parse(await readFile(join(protectedDir,'staging-static-preview-bundle-manifest.json'),'utf8'));
 assert.equal(generated.files.size,13);
 assert.equal(existing.sourceVersion,'0.30.139');
 assert.equal(generated.manifest.sourceVersion,JSON.parse(await readFile(join(root,'package.json'),'utf8')).version);
 const drift=[];
 for(const [name,contents] of generated.files){
  if(contents!==await readFile(join(protectedDir,name),'utf8'))drift.push(name);
 }
 assert.ok(drift.includes('assets/tj34i-demo-static-preview.js'));
 assert.ok(drift.includes('assets/tj34i-src-catalog.js'));
 assert.ok(drift.includes('assets/tj34i-src-static-preview-contract.js'));
 assert.equal(generated.manifest.checkoutEnabled,false);
 assert.equal(generated.manifest.shopifyThemeInstalled,false);
 assert.equal(generated.manifest.requiresMainEngineeringAcceptance,true);
});
