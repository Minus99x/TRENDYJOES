import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,readFile,writeFile,unlink,symlink,chmod,link} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {generateKeyPairSync,randomBytes,createHash,sign} from 'node:crypto';
import {spawnSync,spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {createOfflineDurableAnchorAdapter} from '../src/offline-durable-anchor-adapter.mjs';

const schema='TJ-OFFLINE-DURABLE-ANCHOR-RECOVERY-1';
const fields=['schema','registryId','anchorType','action','authorizationId','issuedAt','expiresAt','expectedAnchor','targetAnchor','pendingDigest','reason'];
const registryId='objective31d-test-registry';
const id=()=>`recovery-${randomBytes(12).toString('hex')}`;
const hash=x=>createHash('sha256').update(x).digest('hex');
const a=(n,hex)=>({sequence:n,mac:hex.repeat(64)});
const j=(n,hex)=>({index:n,digest:hex.repeat(64)});
const rejects=(p,code)=>assert.rejects(p,e=>e?.code===code);
async function fixture(t,anchorType='registry',injectFault){
 const base=await mkdtemp(join(tmpdir(),'tj-31d-'));t.after(()=>rm(base,{recursive:true,force:true}));
 const directory=join(base,'independent-anchor'),{publicKey,privateKey}=generateKeyPairSync('ed25519');
 const options={directory,registryId,anchorType,recovery:{publicKey},lockTimeoutMs:5000,injectFault};
 const adapter=()=>createOfflineDurableAnchorAdapter(options);
 const permit=(action,expectedAnchor,targetAnchor,pendingDigest,overrides={})=>{
  const now=Date.now(),body={schema,registryId,anchorType,action,authorizationId:id(),issuedAt:now-1000,expiresAt:now+60000,expectedAnchor,targetAnchor,pendingDigest,reason:'Independent forensic approval after inspection',...overrides};
  const signature=sign(null,Buffer.from(`${schema}\0${JSON.stringify(Object.fromEntries(fields.map(k=>[k,body[k]])))}`),privateKey).toString('base64url');
  return {...body,signature};
 };
 return {base,directory,options,adapter,permit,pending:join(directory,'.pending.json'),file:n=>join(directory,`${String(n).padStart(10,'0')}.json`)};
}
test('31D registry adapter durably commits strict CAS and survives reconstructed instances',async t=>{
 const f=await fixture(t),x=f.adapter();assert.equal(await x.read(),null);
 assert.equal(await x.compareAndSet(null,a(1,'a')),true);
 assert.deepEqual(await f.adapter().read(),a(1,'a'));
 assert.equal(await x.compareAndSet(a(1,'a'),a(2,'b')),true);
 const state=await f.adapter().inspect();assert.deepEqual(state.anchor,a(2,'b'));assert.equal(state.eventCount,2);assert.equal(state.productionApproved,false);
 assert.match(state.historyDigest,/^[a-f0-9]{64}$/);
 assert.deepEqual(await f.adapter().readPinned(a(2,'b')),a(2,'b'));
});
test('31D stale CAS fails without modifying head, invalid increments fail closed',async t=>{
 const f=await fixture(t),x=f.adapter();await x.compareAndSet(null,a(1,'a'));
 assert.equal(await x.compareAndSet(null,a(1,'c')),false);
 await rejects(x.compareAndSet(a(1,'a'),a(3,'c')),'DURABLE_ANCHOR_CAS_INVALID');
 await rejects(x.compareAndSet(a(1,'a'),{sequence:2,mac:'Z'.repeat(64)}),'DURABLE_ANCHOR_CAS_INVALID');
 await rejects(x.readPinned(a(1,'c')),'DURABLE_ANCHOR_STALE_READ');
 assert.deepEqual(await x.read(),a(1,'a'));
});
test('31D journal adapter validates journal index and digest independently',async t=>{
 const f=await fixture(t,'journal'),x=f.adapter();assert.equal(await x.compareAndSet(null,j(1,'a')),true);
 assert.equal(await x.compareAndSet(j(1,'a'),j(2,'b')),true);
 assert.deepEqual(await x.read(),j(2,'b'));
 await rejects(x.compareAndSet(j(2,'b'),a(3,'c')),'DURABLE_ANCHOR_CAS_INVALID');
});
test('31D committed history rejects modified bytes and missing predecessor',async t=>{
 const f=await fixture(t),x=f.adapter();await x.compareAndSet(null,a(1,'a'));await x.compareAndSet(a(1,'a'),a(2,'b'));
 const path=f.file(1),raw=await readFile(path,'utf8');await writeFile(path,raw.replace('a'.repeat(64),'c'.repeat(64)));
 await assert.rejects(x.read(),e=>e.code?.startsWith('DURABLE_ANCHOR_'));
 await writeFile(path,raw);await unlink(path);
 await rejects(x.read(),'DURABLE_ANCHOR_HISTORY_GAP');
});
test('31D rejects symlink event, hardlinked event, unsafe event mode',async t=>{
 const f=await fixture(t),x=f.adapter();await x.compareAndSet(null,a(1,'a'));
 const path=f.file(1),raw=await readFile(path);await unlink(path);await symlink('/etc/hosts',path);
 await rejects(x.read(),'DURABLE_ANCHOR_FILE_UNSAFE');await unlink(path);await writeFile(path,raw,{mode:0o600});
 await chmod(path,0o644);await rejects(x.read(),'DURABLE_ANCHOR_FILE_UNSAFE');
});
test('31D pending after injected crash blocks reads and further CAS until signed commit recovery',async t=>{
 const f=await fixture(t,'registry',stage=>{if(stage==='after-pending-sync')throw Error('synthetic-crash');});
 const x=f.adapter();await assert.rejects(x.compareAndSet(null,a(1,'a')),/synthetic-crash/);
 await rejects(x.read(),'DURABLE_ANCHOR_PENDING_RECOVERY_REQUIRED');
 await rejects(x.compareAndSet(null,a(1,'b')),'DURABLE_ANCHOR_PENDING_RECOVERY_REQUIRED');
 const digest=hash(await readFile(f.pending)),p=f.permit('commit-pending',null,a(1,'a'),digest);
 await rejects(x.recoverInterruptedCommit({authorization:{...p,signature:'a'.repeat(86)}}),'DURABLE_ANCHOR_RECOVERY_DENIED');
 assert.equal((await x.recoverInterruptedCommit({authorization:p})).recovered,true);
 assert.deepEqual(await f.adapter().read(),a(1,'a'));
 await rejects(x.recoverInterruptedCommit({authorization:p}),'DURABLE_ANCHOR_RECOVERY_STATE_MISMATCH');
});
test('31D signed recovery rejects altered target, expired permit, pending digest substitution',async t=>{
 const f=await fixture(t,'registry',stage=>{if(stage==='after-pending-sync')throw Error('synthetic-crash');});
 const x=f.adapter();await assert.rejects(x.compareAndSet(null,a(1,'a')));
 const digest=hash(await readFile(f.pending));
 await rejects(x.recoverInterruptedCommit({authorization:f.permit('commit-pending',null,a(1,'b'),digest)}),'DURABLE_ANCHOR_RECOVERY_INVALID_PENDING');
 await rejects(x.recoverInterruptedCommit({authorization:f.permit('commit-pending',null,a(1,'a'),'f'.repeat(64))}),'DURABLE_ANCHOR_RECOVERY_STATE_MISMATCH');
 const now=Date.now();await rejects(x.recoverInterruptedCommit({authorization:f.permit('commit-pending',null,a(1,'a'),digest,{issuedAt:now-2000000,expiresAt:now-1000000})}),'DURABLE_ANCHOR_RECOVERY_DENIED');
 await rejects(x.read(),'DURABLE_ANCHOR_PENDING_RECOVERY_REQUIRED');
});
test('31D zero-byte torn proposal requires signed exact-byte abort; does not advance head',async t=>{
 const f=await fixture(t),x=f.adapter();await x.compareAndSet(null,a(1,'a'));
 await writeFile(f.pending,Buffer.alloc(0),{mode:0o600});
 await rejects(x.read(),'DURABLE_ANCHOR_PENDING_RECOVERY_REQUIRED');
 await rejects(x.recoverInterruptedCommit({authorization:f.permit('commit-pending',a(1,'a'),a(2,'b'),hash(Buffer.alloc(0)))}),'DURABLE_ANCHOR_RECOVERY_INVALID_PENDING');
 const p=f.permit('abort-pending',a(1,'a'),null,hash(Buffer.alloc(0)));
 assert.equal((await x.recoverInterruptedCommit({authorization:p})).action,'abort-pending');
 assert.deepEqual(await x.read(),a(1,'a'));
 await rejects(x.recoverInterruptedCommit({authorization:p}),'DURABLE_ANCHOR_RECOVERY_STATE_MISMATCH');
});
test('31D abort rejects unexpected non-null target and forged permit',async t=>{
 const f=await fixture(t),x=f.adapter();await x.compareAndSet(null,a(1,'a'));
 await writeFile(f.pending,'{truncated',{mode:0o600});const digest=hash(Buffer.from('{truncated'));
 await rejects(x.recoverInterruptedCommit({authorization:f.permit('abort-pending',a(1,'a'),a(2,'b'),digest)}),'DURABLE_ANCHOR_RECOVERY_STATE_MISMATCH');
 const p=f.permit('abort-pending',a(1,'a'),null,digest);
 await rejects(x.recoverInterruptedCommit({authorization:{...p,reason:'I forged this reason'}}),'DURABLE_ANCHOR_RECOVERY_DENIED');
 assert.equal((await x.recoverInterruptedCommit({authorization:p})).recovered,true);
});
test('31D after-commit crash has committed head; stale retry cannot append duplicate',async t=>{
 const f=await fixture(t,'registry',stage=>{if(stage==='after-commit-sync')throw Error('post-commit-crash');});
 const x=f.adapter();await assert.rejects(x.compareAndSet(null,a(1,'a')),/post-commit-crash/);
 assert.deepEqual(await x.read(),a(1,'a'));
 assert.equal(await x.compareAndSet(null,a(1,'b')),false);
 assert.equal((await x.inspect()).eventCount,1);
});
test('31D real separate-process crash leaves recoverable durable pending record',async t=>{
 const f=await fixture(t),{publicKey,privateKey}=generateKeyPairSync('ed25519');
 // Use a real child with its own adapter key; sign recovery using the same child public key.
 const options={...f.options,recovery:{publicKey}};
 const script=`import {createOfflineDurableAnchorAdapter} from ${JSON.stringify(fileURLToPath(new URL('../src/offline-durable-anchor-adapter.mjs',import.meta.url)))};\nimport {createPublicKey} from 'node:crypto';\nconst opts={directory:process.argv[1],registryId:process.argv[2],anchorType:'registry',recovery:{publicKey:createPublicKey(process.argv[3])},injectFault:stage=>{if(stage==='after-pending-sync')process.exit(91)}};await createOfflineDurableAnchorAdapter(opts).compareAndSet(null,{sequence:1,mac:'a'.repeat(64)});`;
 const pem=publicKey.export({type:'spki',format:'pem'});
 const child=spawnSync(process.execPath,['--input-type=module','-e',script,f.directory,registryId,pem],{encoding:'utf8',timeout:10000});
 assert.equal(child.status,91,child.stderr);
 const adapter=createOfflineDurableAnchorAdapter(options);
 await rejects(adapter.read(),'DURABLE_ANCHOR_PENDING_RECOVERY_REQUIRED');
 const now=Date.now(),body={schema,registryId,anchorType:'registry',action:'commit-pending',authorizationId:id(),issuedAt:now-1000,expiresAt:now+60000,expectedAnchor:null,targetAnchor:a(1,'a'),pendingDigest:hash(await readFile(f.pending)),reason:'Independent forensic approval after child crash'};
 const p={...body,signature:sign(null,Buffer.from(`${schema}\0${JSON.stringify(Object.fromEntries(fields.map(k=>[k,body[k]])))}`),privateKey).toString('base64url')};
 await adapter.recoverInterruptedCommit({authorization:p});assert.deepEqual(await adapter.read(),a(1,'a'));
});
test('31D two separate processes race CAS; exactly one commits and loser gets false',async t=>{
 const f=await fixture(t),{publicKey}=generateKeyPairSync('ed25519'),pem=publicKey.export({type:'spki',format:'pem'});
 const source=fileURLToPath(new URL('../src/offline-durable-anchor-adapter.mjs',import.meta.url));
 const script=`import {createOfflineDurableAnchorAdapter} from ${JSON.stringify(source)};import {createPublicKey} from 'node:crypto';\nconst x=createOfflineDurableAnchorAdapter({directory:process.argv[1],registryId:process.argv[2],anchorType:'registry',recovery:{publicKey:createPublicKey(process.argv[3])},lockTimeoutMs:5000});\nconsole.log(await x.compareAndSet(null,{sequence:1,mac:process.argv[4].repeat(64)}));`;
 const run=char=>new Promise((ok,no)=>{
  const child=spawn(process.execPath,['--input-type=module','-e',script,f.directory,registryId,pem,char],{stdio:['ignore','pipe','pipe'],env:{...process.env,FORCE_COLOR:'0',NODE_DISABLE_COLORS:'1'}});
  let out='',err='';child.stdout.on('data',d=>out+=d);child.stderr.on('data',d=>err+=d);
  child.once('error',no);child.once('close',code=>code===0?ok(out.trim()):no(Error(err||`exit ${code}`)));
 });
 const results=await Promise.all([run('a'),run('b')]);assert.deepEqual(results.sort(),['false','true']);
 const x=createOfflineDurableAnchorAdapter({...f.options,recovery:{publicKey}});
 assert.equal((await x.inspect()).eventCount,1);
 assert.ok([a(1,'a').mac,a(1,'b').mac].includes((await x.read()).mac));
});


test('31D hardlinked committed record is refused rather than trusted',async t=>{
 const f=await fixture(t),x=f.adapter();await x.compareAndSet(null,a(1,'a'));
 await link(f.file(1),join(f.base,'outside-link'));
 await rejects(x.read(),'DURABLE_ANCHOR_FILE_UNSAFE');
});
test('31D externally pinned head catches complete valid-prefix rollback',async t=>{
 const f=await fixture(t),x=f.adapter();await x.compareAndSet(null,a(1,'a'));await x.compareAndSet(a(1,'a'),a(2,'b'));
 const trustedHead=await x.read();await unlink(f.file(2));
 // A valid local prefix alone cannot establish freshness. Independent pin does.
 assert.deepEqual(await x.read(),a(1,'a'));
 await rejects(x.readPinned(trustedHead),'DURABLE_ANCHOR_STALE_READ');
});
test('31D unknown or substituted history filename blocks reads, writes and recovery',async t=>{
 const f=await fixture(t),x=f.adapter();await x.compareAndSet(null,a(1,'a'));
 await writeFile(join(f.directory,'0000000003.json'),'{}',{mode:0o600});
 await rejects(x.read(),'DURABLE_ANCHOR_HISTORY_GAP');
 await rejects(x.compareAndSet(a(1,'a'),a(2,'b')),'DURABLE_ANCHOR_HISTORY_GAP');
});
test('31D signed commit recovery refuses corrupt pending even when its raw bytes are authorized',async t=>{
 const f=await fixture(t),x=f.adapter();await x.compareAndSet(null,a(1,'a'));
 const corrupt=Buffer.from('{"schema":"forged"}');await writeFile(f.pending,corrupt,{mode:0o600});
 await rejects(x.recoverInterruptedCommit({authorization:f.permit('commit-pending',a(1,'a'),a(2,'b'),hash(corrupt))}),'DURABLE_ANCHOR_RECOVERY_INVALID_PENDING');
 assert.deepEqual((await x.inspect().catch(e=>e)).code,'DURABLE_ANCHOR_PENDING_RECOVERY_REQUIRED');
});
