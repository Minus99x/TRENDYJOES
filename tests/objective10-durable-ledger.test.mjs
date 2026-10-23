import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,readFile,writeFile,mkdir,rm,symlink} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {createOfflineDurableLedger} from '../src/offline-durable-ledger.mjs';
import {authenticateOfflineOrderWebhook,reconcileOfflineOrder} from '../src/order-reconciliation.mjs';
import {signOrderMetadata} from '../src/shopify-intents.mjs';
import {createHmac,randomBytes} from 'node:crypto';
const shop='gucgmp-bc.myshopify.com',reference='TJ-'+'A'.repeat(24),sha='a'.repeat(64);
const productGid='gid://shopify/Product/12345',variantGid='gid://shopify/ProductVariant/67890';
const orderGid='gid://shopify/Order/99999',eventId='123e4567-e89b-42d3-a456-426614174000';
const design=(revision=1,extra={})=>({shop,ownerSubject:'gid://shopify/Customer/45678',reference,revision,productGid,variantGid,compositionSha256:sha,status:'CURRENT',...extra});
const match=(revision=1,extra={})=>({reference,revision,productGid,variantGid,compositionSha256:sha,...extra});
const claim=(id=eventId,extra={})=>({eventKey:`${shop}:orders/create:${id}`,bodySha256:'b'.repeat(64),orderGid,matchedLines:[match()],...extra});
async function fixture(fn){const directory=await mkdtemp(join(tmpdir(),'tj-ledger-'));try{return await fn(directory);}finally{await rm(directory,{recursive:true,force:true});}}
const rejects=(p,code)=>assert.rejects(p,e=>e?.code===code);
const moduleUrl=new URL('../src/offline-durable-ledger.mjs',import.meta.url).href;
function child(directory,args){return new Promise((resolve,reject)=>{
 const source=`import {createOfflineDurableLedger} from ${JSON.stringify(moduleUrl)};const l=createOfflineDurableLedger({directory:process.argv[1],lockTimeoutMs:5000});try{console.log(await l.claimOnce(JSON.parse(process.argv[2])));}catch(e){console.error(e.code||e.message);process.exitCode=1;}`;
 const p=spawn(process.execPath,['--input-type=module','-e',source,directory,JSON.stringify(args)],{stdio:['ignore','pipe','pipe']});
 let stdout='',stderr='';p.stdout.on('data',x=>stdout+=x);p.stderr.on('data',x=>stderr+=x);
 p.on('error',reject);p.on('close',code=>resolve({code,stdout:stdout.trim(),stderr:stderr.trim()}));
 });}

test('persisted revisions survive a fresh adapter and CAS rejects stale and skipped updates',()=>fixture(async dir=>{
 const a=createOfflineDurableLedger({directory:dir});await a.putDesignCAS({design:design()});
 const b=createOfflineDurableLedger({directory:dir});assert.deepEqual(await b.lookupDesign({shop,reference}),design());
 await rejects(b.putDesignCAS({design:design(2),expectedRevision:null}),'LEDGER_REVISION_CAS');
 await rejects(b.putDesignCAS({design:design(3),expectedRevision:1}),'LEDGER_REVISION_CAS');
 await b.putDesignCAS({design:design(2),expectedRevision:1});
 await rejects(a.putDesignCAS({design:design(2),expectedRevision:1}),'LEDGER_REVISION_CAS');
 assert.equal((await a.lookupDesign({shop,reference})).revision,2);
}));
test('owner cannot be substituted during CAS; variant/digest revisions are atomic',()=>fixture(async dir=>{
 const l=createOfflineDurableLedger({directory:dir});await l.putDesignCAS({design:design()});
 await rejects(l.putDesignCAS({design:design(2,{ownerSubject:'gid://shopify/Customer/9'}),expectedRevision:1}),'LEDGER_OWNER_IMMUTABLE');
 await l.putDesignCAS({design:design(2,{variantGid:'gid://shopify/ProductVariant/11111',compositionSha256:'c'.repeat(64)}),expectedRevision:1});
 assert.equal((await l.lookupDesign({shop,reference})).variantGid,'gid://shopify/ProductVariant/11111');
 await rejects(l.claimOnce(claim()),'LEDGER_REVISION_CAS');
}));
test('first order claim is durable, replay is duplicate, conflicting body/event rejects',()=>fixture(async dir=>{
 const l=createOfflineDurableLedger({directory:dir});await l.putDesignCAS({design:design()});
 assert.equal(await l.claimOnce(claim()),'acquired');
 const fresh=createOfflineDurableLedger({directory:dir});assert.equal(await fresh.claimOnce(claim()),'duplicate');
 assert.equal(await fresh.claimOnce(claim(eventId,{bodySha256:'c'.repeat(64)})),'conflict');
 assert.equal(await fresh.claimOnce(claim('123e4567-e89b-42d3-a456-426614174001')),'duplicate');
 assert.equal(await fresh.claimOnce(claim('123e4567-e89b-42d3-a456-426614174002',{bodySha256:'d'.repeat(64)})),'conflict');
}));
test('one design revision cannot be claimed by two different orders',()=>fixture(async dir=>{
 const l=createOfflineDurableLedger({directory:dir});await l.putDesignCAS({design:design()});await l.claimOnce(claim());
 await rejects(l.claimOnce(claim('123e4567-e89b-42d3-a456-426614174003',{orderGid:'gid://shopify/Order/11111'})),'LEDGER_DESIGN_ALREADY_CLAIMED');
}));
test('stale design lookup cannot race a revision CAS before atomic claim',()=>fixture(async dir=>{
 const l=createOfflineDurableLedger({directory:dir});await l.putDesignCAS({design:design()});
 const old=await l.lookupDesign({shop,reference});assert.equal(old.revision,1);
 await l.putDesignCAS({design:design(2),expectedRevision:1});
 await rejects(l.claimOnce(claim()),'LEDGER_REVISION_CAS');
 const data=JSON.parse(await readFile(join(dir,'ledger.json'),'utf8'));assert.equal(data.events.length,0);
}));
test('parallel separate processes: exactly one acquired and all others duplicate',()=>fixture(async dir=>{
 const l=createOfflineDurableLedger({directory:dir});await l.putDesignCAS({design:design()});
 const results=await Promise.all(Array.from({length:9},()=>child(dir,claim())));
 assert.equal(results.filter(r=>r.code===0&&r.stdout==='acquired').length,1,JSON.stringify(results));
 assert.equal(results.filter(r=>r.code===0&&r.stdout==='duplicate').length,8,JSON.stringify(results));
}));
test('concurrent revision writers across processes cannot both win CAS',()=>fixture(async dir=>{
 const l=createOfflineDurableLedger({directory:dir});await l.putDesignCAS({design:design()});
 const source=`import {createOfflineDurableLedger} from ${JSON.stringify(moduleUrl)};const l=createOfflineDurableLedger({directory:process.argv[1],lockTimeoutMs:5000});try{await l.putDesignCAS({design:JSON.parse(process.argv[2]),expectedRevision:1});console.log('ok')}catch(e){console.error(e.code);process.exitCode=1}`;
 const run=d=>new Promise((resolve,reject)=>{const p=spawn(process.execPath,['--input-type=module','-e',source,dir,JSON.stringify(d)]);let out='',err='';p.stdout.on('data',b=>out+=b);p.stderr.on('data',b=>err+=b);p.on('error',reject);p.on('close',code=>resolve({code,out,err}));});
 const results=await Promise.all([run(design(2,{compositionSha256:'c'.repeat(64)})),run(design(2,{compositionSha256:'d'.repeat(64)}))]);
 assert.equal(results.filter(x=>x.code===0).length,1);assert.equal(results.filter(x=>x.err.includes('LEDGER_REVISION_CAS')).length,1);
}));
test('fault before atomic rename leaves old state; retry succeeds',()=>fixture(async dir=>{
 const l=createOfflineDurableLedger({directory:dir});await l.putDesignCAS({design:design()});
 const bad=createOfflineDurableLedger({directory:dir,injectFault:stage=>{if(stage==='before-rename')throw Error('simulated power loss');}});
 await assert.rejects(bad.claimOnce(claim()),/simulated power loss/);
 assert.equal((await readFile(join(dir,'ledger.json'),'utf8')).includes('"events":[]'),true);
 assert.equal(await l.claimOnce(claim()),'acquired');
}));
test('fault after rename is ambiguous but retry is idempotently duplicate',()=>fixture(async dir=>{
 const l=createOfflineDurableLedger({directory:dir});await l.putDesignCAS({design:design()});
 const bad=createOfflineDurableLedger({directory:dir,injectFault:stage=>{if(stage==='after-rename')throw Error('lost ack');}});
 await assert.rejects(bad.claimOnce(claim()),/lost ack/);
 assert.equal(await l.claimOnce(claim()),'duplicate');
}));
test('orphan lock never auto-evicts; operator recovery is required',()=>fixture(async dir=>{
 const l=createOfflineDurableLedger({directory:dir,lockTimeoutMs:30});await mkdir(join(dir,'.atomic-lock'));
 await rejects(l.putDesignCAS({design:design()}),'LEDGER_LOCK_UNAVAILABLE');
 await rm(join(dir,'.atomic-lock'),{recursive:true});await l.putDesignCAS({design:design()});
}));
test('corrupted and symlinked state files fail closed',()=>fixture(async dir=>{
 const l=createOfflineDurableLedger({directory:dir});await writeFile(join(dir,'ledger.json'),'{bad json');
 await rejects(l.putDesignCAS({design:design()}),'LEDGER_STATE_CORRUPT');
 await rm(join(dir,'ledger.json'));const target=join(dir,'other.json');await writeFile(target,'{}');await symlink(target,join(dir,'ledger.json'));
 await rejects(l.putDesignCAS({design:design()}),'LEDGER_FILE_UNSAFE');
}));
test('malformed state with duplicate identities rejects instead of silently overwriting',()=>fixture(async dir=>{
 const l=createOfflineDurableLedger({directory:dir});await l.putDesignCAS({design:design()});
 const path=join(dir,'ledger.json'),s=JSON.parse(await readFile(path,'utf8'));s.designs.push({...s.designs[0]});await writeFile(path,JSON.stringify(s));
 await rejects(l.claimOnce(claim()),'LEDGER_STATE_DUPLICATE');
}));
test('invalid claim payloads, cross-shop design, duplicate references and revision reject',()=>fixture(async dir=>{
 const l=createOfflineDurableLedger({directory:dir});await l.putDesignCAS({design:design()});
 await rejects(l.claimOnce(claim(eventId,{matchedLines:[match(),match()]})),'LEDGER_DUPLICATE_DESIGN');
 await rejects(l.claimOnce(claim(eventId,{matchedLines:[match(2)]})),'LEDGER_REVISION_CAS');
 await rejects(l.claimOnce(claim(eventId,{eventKey:'other.myshopify.com:orders/create:'+eventId})),'LEDGER_REVISION_CAS');
 await rejects(l.claimOnce(claim(eventId,{bodySha256:'not-hex'})),'LEDGER_CLAIM_INVALID');
}));
test('synthetic HMAC webhook reconciles through persisted revision-CAS ledger; flags remain disabled',()=>fixture(async dir=>{
 const l=createOfflineDurableLedger({directory:dir});await l.putDesignCAS({design:design()});
 const metadataSecret=randomBytes(32),webhookSecret=randomBytes(32);
 const binding={schema:'TJ-SHOPIFY-AUTHORIZED-CHECKOUT-1',checkoutEnabled:true,productionReady:true,reference,revision:1,productGid,variantGid,compositionSha256:sha};
 const properties=Object.entries(signOrderMetadata(binding,metadataSecret)).map(([name,value])=>({name,value}));
 const body={id:99999,admin_graphql_api_id:orderGid,customer:{id:45678},line_items:[{id:111,product_id:12345,variant_id:67890,quantity:1,properties}]};
 const rawBody=Buffer.from(JSON.stringify(body));
 const headers={'x-shopify-hmac-sha256':createHmac('sha256',webhookSecret).update(rawBody).digest('base64'),'x-shopify-shop-domain':shop,'x-shopify-topic':'orders/create','x-shopify-webhook-id':eventId};
 const verifiedWebhook=authenticateOfflineOrderWebhook({rawBody,headers,webhookSecret,expectedShop:shop});
 const input={verifiedWebhook,metadataSecret,lookupDesign:l.lookupDesign,claimOnce:l.claimOnce};
 const result=await reconcileOfflineOrder(input);assert.equal(result.idempotency,'acquired');
 assert.equal((await reconcileOfflineOrder(input)).idempotency,'duplicate');
 assert.equal(result.checkoutEnabled,false);assert.equal(result.paymentVerified,false);
 assert.equal(result.fulfillmentAuthorized,false);assert.deepEqual(result.manufacturingJobs,[]);
}));
