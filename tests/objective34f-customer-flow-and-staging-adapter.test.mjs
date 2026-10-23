import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,readFile} from 'node:fs/promises';
import {join,resolve,dirname} from 'node:path';
import {tmpdir} from 'node:os';
import {fileURLToPath} from 'node:url';
import {createLocalServer} from '../src/local-server.mjs';
import {PRODUCT_MANIFESTS} from '../src/catalog.mjs';
import {buildPreviewDesignSummary} from '../src/preview-design-summary.mjs';
import {editorSnapshot} from '../src/preview-editor-state.mjs';
import {buildStagingPreviewNavigation,resolveStagingPreviewNavigation,STAGING_PREVIEW_PAGE} from '../src/staging-preview-adapter.mjs';
const root=resolve(fileURLToPath(new URL('..',import.meta.url)));
const p=PRODUCT_MANIFESTS[0];
const layers=[{id:'letter-1',type:'text',surfaceId:p.surfaces[0].id,x:.2,y:.2,width:.4,height:.2,rotationDeg:0,scaleFactor:1,value:'PRIVATE DESIGN WORDS'}];
const previewSelection={colorId:p.previewOptions.colors[0]?.id??null,sizeId:p.previewOptions.sizes[0]?.id??null};
const draft={productManifestId:p.id,layers,previewSelection};
async function withServer(fn){
 const dir=await mkdtemp(join(tmpdir(),'tj-34f-'));const app=await createLocalServer({dataDir:dir});const {port}=await app.listen(0);
 const base=`http://127.0.0.1:${port}`;
 try{await fn(base);}finally{await new Promise((ok,bad)=>app.server.close(e=>e?bad(e):ok()));await rm(dir,{recursive:true,force:true});}
}
async function post(base,path,body,token,origin){return fetch(base+path,{method:'POST',headers:{'Content-Type':'application/json',...(token?{Authorization:`Bearer ${token}`}:{ }),...(origin?{Origin:origin}:{})},body:JSON.stringify(body)});}
const json=async response=>({status:response.status,body:await response.json()});
test('34F default Shopify staging navigation is inert until Main verifies actual editor page',()=>{
 const nav=buildStagingPreviewNavigation();assert.equal(nav.previewPageVerified,false);assert.equal(nav.entries.length,8);
 for(const e of nav.entries){assert.equal(e.href,null);assert.equal(e.status,'NOT_CONNECTED');}
 assert.equal(nav.checkoutEnabled,false);assert.equal(nav.commerceEnabled,false);
 assert.equal(resolveStagingPreviewNavigation(STAGING_PREVIEW_PAGE+'?product=concept-rug').status,'NOT_CONNECTED');
 assert.throws(()=>buildStagingPreviewNavigation({previewPageVerified:'true'}),/INVALID_PREVIEW_GATE/);
});
test('34F verified-route contract allows only the eight concept IDs and one query key',()=>{
 const nav=buildStagingPreviewNavigation({previewPageVerified:true});
 assert.deepEqual(nav.entries.map(e=>e.manifestId),PRODUCT_MANIFESTS.map(p=>p.id));
 for(const e of nav.entries){assert.deepEqual(resolveStagingPreviewNavigation(e.href,{previewPageVerified:true}),{status:'SELECTED',manifestId:e.manifestId});}
});
test('34F staging adapter refuses credentials, cross-origin, commerce, forged and duplicate links',()=>{
 const bad=['https://evil.example/pages/design-works-preview?product=concept-rug','//evil.example/pages/design-works-preview?product=concept-rug',
  '/cart?product=concept-rug','/checkout?product=concept-rug','/pages/design-works-preview?product=concept-rug&ownerToken=secret',
  '/pages/design-works-preview?product=concept-rug&price=1','/pages/design-works-preview?product=concept-rug&variantGid=123',
  '/pages/design-works-preview?product=concept-rug&product=concept-tumbler','/pages/design-works-preview?product=__proto__',
  '/pages/design-works-preview?product=unknown','/pages/design-works-preview?product=concept-rug#secret',
  '/pages/design-works-preview?product=concept-rug%ZZ','/pages/design-works-preview?product=concept-rug%26checkout%3Dtrue'];
 for(const url of bad)assert.equal(resolveStagingPreviewNavigation(url,{previewPageVerified:true}).status,'INVALID_LINK',url);
});
test('34F merge-ready Shopify snippet is disabled by default, has exact concept family IDs and no commerce links',async()=>{
 const liquid=await readFile(join(root,'integrations/shopify/snippets/tj-studio-preview-entry.liquid'),'utf8');
 const css=await readFile(join(root,'integrations/shopify/assets/tj-studio-preview-entry.css'),'utf8');
 assert.match(liquid,/assign tj_preview_ready = false/);assert.match(liquid,/preview_route_verified == true/);
 assert.match(liquid,/if tj_preview_ready/);assert.match(liquid,/url_encode/);assert.match(liquid,/Studio preview integration pending/);
 const line=liquid.match(/assign tj_concept_ids = '([^']+)'/);assert.ok(line);
 assert.deepEqual(line[1].split('|'),PRODUCT_MANIFESTS.map(m=>m.id));
 assert.match(css,/:focus-visible/);assert.match(css,/@media\(max-width:480px\)/);
 assert.doesNotMatch(liquid,/(?:https?:\/\/|\/cart\b|\/checkout\b|ownerToken|variantGid|shopify\.com)/);
});
test('34F real HTTP serves all eight concept links and editor module entry without commerce',async()=>withServer(async base=>{
 const gateway=await fetch(base+'/demo/start.html');assert.equal(gateway.status,200);const html=await gateway.text();
 const links=[...html.matchAll(/href="(\/demo\/\?product=[a-z0-9-]+)"/g)].map(x=>x[1]);assert.equal(links.length,8);
 for(const href of links){const r=await fetch(base+href);assert.equal(r.status,200,href);assert.match(await r.text(),/id="review-preview"/);}
 for(const path of ['/demo/studio.mjs','/src/preview-design-summary.mjs','/src/preview-entry.mjs','/demo/studio.css']){
  const r=await fetch(base+path);assert.equal(r.status,200,path);assert.equal(r.headers.get('x-frame-options'),'DENY');
 }
 const health=await json(await fetch(base+'/api/health'));assert.equal(health.body.checkoutEnabled,false);
 for(const path of ['/api/cart','/api/orders','/api/checkout','/api/shopify/cart/add'])assert.equal((await fetch(base+path)).status,404,path);
}));
test('34F real HTTP customer flow saves a private local design and validates review without leaking credentials',async()=>withServer(async base=>{
 const created=await json(await post(base,'/api/designs',draft,null,base));assert.equal(created.status,201);
 const {reference,ownerToken,revision}=created.body;assert.equal(revision,1);assert.equal(created.body.checkoutEnabled,false);
 const noOwner=await fetch(base+`/api/designs/${reference}`);assert.equal(noOwner.status,403);
 const forged=await fetch(base+`/api/designs/${reference}`,{headers:{Authorization:'Bearer forged'}});assert.equal(forged.status,403);
 const saved=await json(await fetch(base+`/api/designs/${reference}`,{headers:{Authorization:`Bearer ${ownerToken}`}}));
 assert.equal(saved.status,200);assert.equal(saved.body.productManifestId,p.id);assert.equal(saved.body.revision,1);
 const summary=buildPreviewDesignSummary({productManifestId:p.id,surfaceId:p.surfaces[0].id,layers:saved.body.layers,previewSelection:saved.body.previewSelection,
  saved:{reference,ownerToken,revision},savedSnapshot:editorSnapshot(p.id,saved.body.layers,saved.body.previewSelection)});
 assert.equal(summary.draftState,'LOCAL_REVISION_CURRENT');assert.equal(summary.checkoutEnabled,false);assert.equal(summary.cartLine,null);
 const serialized=JSON.stringify(summary);for(const secret of [ownerToken,reference,'PRIVATE DESIGN WORDS'])assert.equal(serialized.includes(secret),false);
}));
test('34F real HTTP stale revision is rejected, changed design invalidates prior review',async()=>withServer(async base=>{
 const created=(await json(await post(base,'/api/designs',draft))).body;
 const old={reference:created.reference,ownerToken:created.ownerToken,revision:1};
 const changed=[{...layers[0],value:'REVISED PRIVATE TEXT'}];
 const updated=await json(await post(base,`/api/designs/${created.reference}/revisions`,{...draft,layers:changed,expectedRevision:1},created.ownerToken,base));
 assert.equal(updated.status,201);assert.equal(updated.body.revision,2);
 const conflict=await json(await post(base,`/api/designs/${created.reference}/revisions`,{...draft,expectedRevision:1},created.ownerToken,base));
 assert.equal(conflict.status,409);
 const newDesign=await json(await fetch(base+`/api/designs/${created.reference}`,{headers:{Authorization:`Bearer ${created.ownerToken}`}}));
 assert.equal(newDesign.body.revision,2);
 const summary=buildPreviewDesignSummary({productManifestId:p.id,surfaceId:p.surfaces[0].id,layers:newDesign.body.layers,previewSelection:newDesign.body.previewSelection,
  saved:old,savedSnapshot:editorSnapshot(p.id,layers,previewSelection)});
 assert.equal(summary.draftState,'UNSAVED_PREVIEW');assert.equal(summary.revision,null);
}));
test('34F HTTP rejects cross-origin writes and never issues cart/order even when client supplies forged flags',async()=>withServer(async base=>{
 const denied=await json(await post(base,'/api/designs',{...draft,checkoutEnabled:true,productionApproved:true},null,'https://outside.invalid'));
 assert.equal(denied.status,403);
 const saved=await json(await post(base,'/api/designs',{...draft,checkoutEnabled:true,productionApproved:true},null,base));
 assert.equal(saved.status,201);assert.equal(saved.body.checkoutEnabled,false);assert.equal(saved.body.productionApproved,false);
 const record=await json(await fetch(base+`/api/designs/${saved.body.reference}`,{headers:{Authorization:`Bearer ${saved.body.ownerToken}`}}));
 assert.equal(record.body.checkoutEnabled,false);assert.equal(record.body.productionApproved,false);
 assert.equal((await post(base,'/api/shopify/cart/add',{cartLine:{price:0},checkoutEnabled:true})).status,404);
}));
test('34F browser entry module graph is complete and served as JavaScript over real loopback HTTP',async()=>withServer(async base=>{
 const seen=new Set();async function visit(file){
  const absolute=resolve(root,file);if(seen.has(absolute))return;seen.add(absolute);
  const code=await readFile(absolute,'utf8');const served=await fetch(base+'/'+file);assert.equal(served.status,200,file);assert.match(served.headers.get('content-type'),/text\/javascript/,file);assert.equal(await served.text(),code);const matches=[...code.matchAll(/(?:^|\n)\s*(?:import|export)\s+(?:[^'"\n]*?\sfrom\s*)?['"](\.[^'"]+)['"]/g)];
  for(const [,spec] of matches){const next=resolve(dirname(absolute),spec);assert.ok(next.startsWith(root+'/'),'import escaped source');await visit(next.slice(root.length+1));}
 }
 await visit('demo/studio.mjs');assert.ok(seen.size>=10,`only ${seen.size} modules reached`);
}));
