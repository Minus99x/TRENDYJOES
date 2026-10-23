import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile,writeFile,mkdtemp,mkdir,symlink,rm} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {tmpdir} from 'node:os';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {createLocalServer} from '../src/local-server.mjs';
import {collectPreviewAssetManifest,verifyPreviewAssetManifest} from '../src/preview-asset-manifest.mjs';
import {PRODUCT_MANIFESTS} from '../src/catalog.mjs';
const root=resolve(fileURLToPath(new URL('..',import.meta.url)));
const expectedPath=join(root,'integrations/shopify/preview-asset-manifest.json');
const readExpected=async()=>JSON.parse(await readFile(expectedPath,'utf8'));
async function withTemp(fn){const dir=await mkdtemp(join(tmpdir(),'tj34g-'));try{return await fn(dir);}finally{await rm(dir,{recursive:true,force:true});}}
async function withServer(fn){return withTemp(async dir=>{const app=await createLocalServer({dataDir:dir});const {port}=await app.listen(0);try{return await fn(`http://127.0.0.1:${port}`);}finally{await new Promise((ok,bad)=>app.server.close(e=>e?bad(e):ok()));}});}
test('34G real editor browser graph is fully local, bounded, and deterministic',async()=>{
 const manifest=await collectPreviewAssetManifest({root});
 assert.equal(manifest.schema,'TJ-OFFLINE-BROWSER-ASSET-INVENTORY-1');
 assert.ok(manifest.assets.length>=15);
 assert.equal(new Set(manifest.assets.map(x=>x.path)).size,manifest.assets.length);
 assert.ok(manifest.assets.some(x=>x.path==='demo/browser-acceptance.mjs'));
 assert.ok(manifest.assets.some(x=>x.path==='src/viewer3d.mjs'));
 assert.ok(manifest.assets.some(x=>x.path==='src/preview-design-summary.mjs'));
 assert.deepEqual(manifest.assets.map(x=>x.path),[...manifest.assets.map(x=>x.path)].sort((a,b)=>a.localeCompare(b,'en')));
});
test('34G inventory explicitly refuses hosted/commerce readiness even when every asset exists',async()=>{
 const manifest=await collectPreviewAssetManifest({root});
 assert.equal(manifest.hostedPreviewReady,false);assert.equal(manifest.shopifyThemeInstalled,false);
 assert.equal(manifest.shopifyAccepted,false);assert.equal(manifest.checkoutEnabled,false);
 assert.equal(manifest.backendRequirement,'LOOPBACK_API_NOT_HOSTABLE_AS_THEME_ASSET');
 for(const feature of ['PRIVATE_DRAFT_SAVE','PRIVATE_ARTWORK_UPLOAD','AUTHENTICATED_REVISIONS','CART_AND_CHECKOUT'])assert.ok(manifest.blockedHostedFeatures.includes(feature));
});
test('34G generated integration manifest matches current exact source and fails on tampering',async()=>{
 const expected=await readExpected(),current=await collectPreviewAssetManifest({root});
 assert.equal(verifyPreviewAssetManifest(expected,current),true);
 assert.throws(()=>verifyPreviewAssetManifest({...expected,hostedPreviewReady:true},current),/ASSET_MANIFEST_MISMATCH/);
 assert.throws(()=>verifyPreviewAssetManifest({...expected,assets:expected.assets.slice(1)},current),/ASSET_MANIFEST_MISMATCH/);
 assert.throws(()=>verifyPreviewAssetManifest(null,current),/INVALID_ASSET_MANIFEST/);
});
test('34G every source SHA256 and MIME entry matches actual bytes',async()=>{
 const manifest=await readExpected();
 for(const item of manifest.assets){
  const bytes=await readFile(join(root,item.path));
  assert.equal(createHash('sha256').update(bytes).digest('hex'),item.sha256,item.path);
  assert.equal(bytes.length,item.bytes,item.path);
  assert.equal(item.url,'/'+item.path,item.path);
  assert.match(item.contentType,/^(text\/html|text\/css|text\/javascript)$/);
 }
});
test('34G browser inventory rejects parent traversal and absolute entry paths',async()=>withTemp(async dir=>{
 await writeFile(join(dir,'entry.mjs'),'export const ok=true;');
 for(const entry of ['../outside.mjs','/etc/passwd','./entry.mjs','a//b.mjs'])await assert.rejects(()=>collectPreviewAssetManifest({root:dir,entryFiles:[entry]}),/UNSAFE_ASSET_PATH/);
}));
test('34G browser inventory rejects nonlocal bare imports and external scripts',async()=>withTemp(async dir=>{
 for(const code of ["import {x} from 'node:fs';","import 'https://outside.invalid/module.mjs';","export {x} from 'package-name';"]){
  await writeFile(join(dir,'entry.mjs'),code);
  await assert.rejects(()=>collectPreviewAssetManifest({root:dir,entryFiles:['entry.mjs']}),/NONLOCAL_BROWSER_IMPORT/);
 }
}));
test('34G browser inventory rejects unbounded dynamic imports',async()=>withTemp(async dir=>{
 await writeFile(join(dir,'entry.mjs'),'const path="./other.mjs"; import(path);');
 await assert.rejects(()=>collectPreviewAssetManifest({root:dir,entryFiles:['entry.mjs']}),/UNRESOLVED_DYNAMIC_IMPORT/);
}));
test('34G browser inventory rejects symlinks, missing dependencies and unsupported asset types',async()=>withTemp(async dir=>{
 await writeFile(join(dir,'source.mjs'),'export const x=1;');
 await symlink('source.mjs',join(dir,'entry.mjs'));
 await assert.rejects(()=>collectPreviewAssetManifest({root:dir,entryFiles:['entry.mjs']}),/UNSAFE_ASSET/);
 await rm(join(dir,'entry.mjs'));
 await writeFile(join(dir,'entry.mjs'),"import './missing.mjs';");
 await assert.rejects(()=>collectPreviewAssetManifest({root:dir,entryFiles:['entry.mjs']}),/ENOENT/);
 await writeFile(join(dir,'binary.png'),'not an approved browser module');
 await assert.rejects(()=>collectPreviewAssetManifest({root:dir,entryFiles:['binary.png']}),/UNSUPPORTED_ASSET/);
}));
test('34G actual loopback HTTP serves every manifest asset byte-for-byte with expected MIME and security headers',async()=>withServer(async base=>{
 const manifest=await readExpected();
 for(const item of manifest.assets){
  const response=await fetch(base+item.url);assert.equal(response.status,200,item.url);
  assert.ok(response.headers.get('content-type')?.startsWith(item.contentType),item.url);
  assert.equal(response.headers.get('x-frame-options'),'DENY',item.url);
  assert.equal(response.headers.get('cache-control'),'no-store',item.url);
  const bytes=Buffer.from(await response.arrayBuffer());
  assert.equal(createHash('sha256').update(bytes).digest('hex'),item.sha256,item.url);
 }
}));
test('34G browser acceptance is explicit local opt-in and never claims Shopify/browser proof in Node',async()=>{
 const studio=await readFile(join(root,'demo/studio.mjs'),'utf8');
 const acceptance=await readFile(join(root,'demo/browser-acceptance.mjs'),'utf8');
 assert.match(studio,/window\.location\.protocol==='http:'/);
 assert.match(studio,/window\.location\.hostname/);
 assert.match(studio,/get\('tj_acceptance'\)==='1'/);
 assert.match(studio,/import\('\.\/browser-acceptance\.mjs'\)/);
 assert.match(acceptance,/runBrowserAcceptance/);
 assert.match(acceptance,/LOOPBACK_EXPLICIT_OPT_IN_REQUIRED/);
 assert.match(acceptance,/shopifyAccepted:false/);
 assert.match(acceptance,/checkoutEnabled:false/);
 assert.doesNotMatch(acceptance,/(?:fetch\(|XMLHttpRequest|navigator\.sendBeacon|\/cart\/add|\/checkout)/);
});
test('34G actual eight-family gateway and editor contain complete preview-only controls',async()=>withServer(async base=>{
 const page=await fetch(base+'/demo/start.html');assert.equal(page.status,200);
 const html=await page.text();
 const ids=[...html.matchAll(/href="\/demo\/\?product=([a-z0-9-]+)"/g)].map(x=>x[1]);
 assert.deepEqual(ids,PRODUCT_MANIFESTS.map(x=>x.id));
 const editor=await fetch(base+'/demo/?tj_acceptance=1');assert.equal(editor.status,200);
 const body=await editor.text();
 for(const id of ['product','add-text','mode-2d','mode-3d','review-preview','preview-summary-panel','reset'])assert.match(body,new RegExp(`id="${id}"`));
 assert.match(body,/Checkout unavailable/);assert.match(body,/script type="module" src="\.\/studio\.mjs"/);
 assert.equal((await fetch(base+'/api/checkout')).status,404);
 assert.equal((await fetch(base+'/api/orders')).status,404);
}));
