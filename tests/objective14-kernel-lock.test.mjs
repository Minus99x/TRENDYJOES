import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,readFile,writeFile,mkdir,rm,symlink,link,stat,chmod} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawn} from 'node:child_process';
import {createOfflineDurableLedger} from '../src/offline-durable-ledger.mjs';

const moduleUrl=new URL('../src/offline-durable-ledger.mjs',import.meta.url).href;
const shop='gucgmp-bc.myshopify.com',reference='TJ-'+'A'.repeat(24);
const design={shop,ownerSubject:'gid://shopify/Customer/45678',reference,revision:1,
 productGid:'gid://shopify/Product/12345',variantGid:'gid://shopify/ProductVariant/67890',
 compositionSha256:'a'.repeat(64),status:'CURRENT'};
const eventId='123e4567-e89b-42d3-a456-426614174000';
const claim={eventKey:`${shop}:orders/create:${eventId}`,bodySha256:'b'.repeat(64),
 orderGid:'gid://shopify/Order/99999',matchedLines:[{
 reference,revision:1,productGid:design.productGid,variantGid:design.variantGid,
 compositionSha256:design.compositionSha256}]};
const ledger=(directory,extra={})=>createOfflineDurableLedger({directory,lockMode:'kernel',lockTimeoutMs:500,...extra});
async function fixture(t){const directory=await mkdtemp(join(tmpdir(),'tj-kernel-lock-'));
 t.after(()=>rm(directory,{recursive:true,force:true}));return directory;}
const rejects=(p,code)=>assert.rejects(p,e=>e?.code===code);
const childSource=`import {createOfflineDurableLedger} from ${JSON.stringify(moduleUrl)};
 const x=JSON.parse(process.argv[1]);const l=createOfflineDurableLedger({directory:x.directory,
 lockMode:'kernel',lockTimeoutMs:5000,injectFault:async stage=>{
 if(stage===x.holdStage){console.log('HOLD');await new Promise(()=>{setInterval(()=>{},1000);});}}});
 try{const outcome=await l.claimOnce(x.claim);console.log(outcome)}catch(e){console.error(e.code||e.message);process.exitCode=1;}`;
function startChild(directory,holdStage){
 const p=spawn(process.execPath,['--input-type=module','-e',childSource,
  JSON.stringify({directory,holdStage,claim})],{stdio:['ignore','pipe','pipe']});
 let output='',err='',closed=false;
 const closedPromise=new Promise((resolve,reject)=>{
  p.on('error',reject);p.on('close',(code,signal)=>{closed=true;resolve({code,signal,output,err});});});
 p.stdout.on('data',b=>output+=b.toString());p.stderr.on('data',b=>err+=b.toString());
 const ready=new Promise((resolve,reject)=>{
  const timer=setTimeout(()=>reject(Error(`child never reached lock: ${output} ${err}`)),4000);
  const check=()=>{if(output.includes('HOLD')){clearTimeout(timer);resolve();}};
  p.stdout.on('data',check);check();closedPromise.then(()=>{if(!output.includes('HOLD')){clearTimeout(timer);reject(Error(`child exited: ${output} ${err}`));}});
 });
 return {p,ready,closedPromise,kill:async()=>{if(!closed)p.kill('SIGKILL');return closedPromise;}};
}

test('opt-in Linux kernel lock retains durable state and persistent restrictive inode',async t=>{
 const directory=await fixture(t),l=ledger(directory);
 await l.putDesignCAS({design});
 assert.deepEqual(await ledger(directory).lookupDesign({shop,reference}),design);
 const st=await stat(join(directory,'.atomic-lock'));
 assert.equal(st.isFile(),true);assert.equal(st.mode&0o077,0);assert.equal(st.nlink,1);
});
test('kernel lock excludes legacy mkdir-lock adapter instead of silently racing',async t=>{
 const directory=await fixture(t);await ledger(directory).putDesignCAS({design});
 const old=createOfflineDurableLedger({directory,lockTimeoutMs:30});
 await rejects(old.claimOnce(claim),'LEDGER_LOCK_UNAVAILABLE');
 assert.equal(await ledger(directory).claimOnce(claim),'acquired');
});
test('SIGKILL before rename automatically releases kernel lock and preserves old state',async t=>{
 const directory=await fixture(t),l=ledger(directory);await l.putDesignCAS({design});
 const child=startChild(directory,'before-rename');t.after(()=>child.kill());
 await child.ready;assert.equal((await ledger(directory).lookupDesign({shop,reference})).revision,1);
 const death=await child.kill();assert.equal(death.signal,'SIGKILL');
 const before=JSON.parse(await readFile(join(directory,'ledger.json'),'utf8'));
 assert.equal(before.events.length,0);assert.equal(before.claims.length,0);
 assert.equal(await ledger(directory).claimOnce(claim),'acquired');
});
test('SIGKILL after rename releases lock and persisted event replays idempotently',async t=>{
 const directory=await fixture(t),l=ledger(directory);await l.putDesignCAS({design});
 const child=startChild(directory,'after-rename');t.after(()=>child.kill());
 await child.ready;const death=await child.kill();assert.equal(death.signal,'SIGKILL');
 assert.equal(await ledger(directory).claimOnce(claim),'duplicate');
 const state=JSON.parse(await readFile(join(directory,'ledger.json'),'utf8'));
 assert.equal(state.events.length,1);assert.equal(state.claims.length,1);
});
test('live lock holder is never stolen: concurrent writer times out, then recovers after death',async t=>{
 const directory=await fixture(t);await ledger(directory).putDesignCAS({design});
 const child=startChild(directory,'before-rename');t.after(()=>child.kill());await child.ready;
 await rejects(ledger(directory,{lockTimeoutMs:80}).claimOnce(claim),'LEDGER_LOCK_UNAVAILABLE');
 await child.kill();assert.equal(await ledger(directory).claimOnce(claim),'acquired');
});
test('nine cross-process kernel-lock writers yield exactly one claim',async t=>{
 const directory=await fixture(t);await ledger(directory).putDesignCAS({design});
 const src=`import {createOfflineDurableLedger} from ${JSON.stringify(moduleUrl)};
 const x=JSON.parse(process.argv[1]);try{console.log(await createOfflineDurableLedger({directory:x.directory,
 lockMode:'kernel',lockTimeoutMs:5000}).claimOnce(x.claim))}catch(e){console.error(e.code);process.exitCode=1}`;
 const run=()=>new Promise((resolve,reject)=>{
  const p=spawn(process.execPath,['--input-type=module','-e',src,JSON.stringify({directory,claim})]);
  let out='',err='';p.stdout.on('data',b=>out+=b);p.stderr.on('data',b=>err+=b);
  p.on('error',reject);p.on('close',code=>resolve({code,out:out.trim(),err:err.trim()}));});
 const results=await Promise.all(Array.from({length:9},run));
 assert.equal(results.filter(r=>r.code===0&&r.out==='acquired').length,1,JSON.stringify(results));
 assert.equal(results.filter(r=>r.code===0&&r.out==='duplicate').length,8,JSON.stringify(results));
});
test('legacy orphan directory fails closed in kernel mode; no automatic theft',async t=>{
 const directory=await fixture(t);await mkdir(join(directory,'.atomic-lock'));
 await rejects(ledger(directory).putDesignCAS({design}),'LEDGER_KERNEL_LOCK_UNSAFE');
 assert.equal((await stat(join(directory,'.atomic-lock'))).isDirectory(),true);
});
test('symlinked kernel lock path is rejected without modifying target',async t=>{
 const directory=await fixture(t),target=join(directory,'target');await writeFile(target,'untouched');
 await symlink(target,join(directory,'.atomic-lock'));
 await rejects(ledger(directory).putDesignCAS({design}),'LEDGER_KERNEL_LOCK_UNSAFE');
 assert.equal(await readFile(target,'utf8'),'untouched');
});
test('hardlinked kernel lock path is rejected to prevent alternate-inode coordination',async t=>{
 const directory=await fixture(t),target=join(directory,'target');await writeFile(target,'lock',{mode:0o600});
 await link(target,join(directory,'.atomic-lock'));
 await rejects(ledger(directory).putDesignCAS({design}),'LEDGER_KERNEL_LOCK_UNSAFE');
});
test('permissive kernel lock inode is rejected rather than silently trusted',async t=>{
 const directory=await fixture(t),target=join(directory,'.atomic-lock');await writeFile(target,'',{mode:0o600});
 await chmod(target,0o666);
 await rejects(ledger(directory).putDesignCAS({design}),'LEDGER_KERNEL_LOCK_UNSAFE');
});
test('corrupt ledger after recovered SIGKILL remains fail closed',async t=>{
 const directory=await fixture(t);await ledger(directory).putDesignCAS({design});
 const child=startChild(directory,'before-rename');t.after(()=>child.kill());await child.ready;await child.kill();
 await writeFile(join(directory,'ledger.json'),'{broken');
 await rejects(ledger(directory).claimOnce(claim),'LEDGER_STATE_CORRUPT');
});
test('group-writable scratch directory is rejected before kernel lock',async t=>{
 const directory=await fixture(t);await chmod(directory,0o770);
 await rejects(ledger(directory).putDesignCAS({design}),'LEDGER_KERNEL_LOCK_UNSAFE');
});
test('invalid lock mode rejected at configuration boundary',()=>{
 assert.throws(()=>createOfflineDurableLedger({directory:'/tmp/example',lockMode:'auto-steal'}),
  {code:'LEDGER_CONFIGURATION'});
});
