import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,mkdir,cp,writeFile,readFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {buildStagingStaticBundle} from '../src/staging-static-package.mjs';
const source=resolve(new URL('..',import.meta.url).pathname);
async function withVersion(version,fn){
 const root=await mkdtemp(join(tmpdir(),'tj35aq-version-'));
 try{
  for(const name of ['src','demo'])await cp(join(source,name),join(root,name),{recursive:true});
  await mkdir(join(root,'integrations/shopify'),{recursive:true});
  await cp(join(source,'integrations/shopify/static-preview-asset-manifest.json'),join(root,'integrations/shopify/static-preview-asset-manifest.json'));
  await writeFile(join(root,'package.json'),JSON.stringify({version}));
  return await fn(root);
 }finally{await rm(root,{recursive:true,force:true});}
}
test('35AQ staging candidate version derives from source package, not stale literal',async()=>{
 const {files,manifest}=await buildStagingStaticBundle({root:source});
 assert.equal(manifest.sourceVersion,JSON.parse(await readFile(join(source,'package.json'),'utf8')).version);
 assert.equal(manifest.entries.length,13);
 assert.equal(manifest.checkoutEnabled,false);
 for(const [name,content] of files){
  assert.equal(content,await readFile(join(source,'integrations/shopify/staging-static-preview',name),'utf8'),name);
 }
});
test('35AQ version update changes only metadata, never protected generated assets',async()=>{
 const old=await buildStagingStaticBundle({root:source});
 await withVersion('7.8.9',async root=>{
  const next=await buildStagingStaticBundle({root});
  assert.equal(next.manifest.sourceVersion,'7.8.9');
  assert.deepEqual([...next.files],[...old.files]);
  assert.deepEqual(next.manifest.entries,old.manifest.entries);
 });
});
for(const invalid of ['v1.2.3','1.2','1.2.3;checkout',null,3]){
 test('35AQ rejects invalid source metadata '+String(invalid),async()=>{
  await withVersion(invalid,async root=>assert.rejects(buildStagingStaticBundle({root}),/INVALID_SOURCE_VERSION/));
 });
}
