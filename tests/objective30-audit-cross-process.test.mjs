import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,readFile,writeFile,symlink,open,rename,mkdir} from 'node:fs/promises';
import {spawn} from 'node:child_process';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {randomBytes,generateKeyPairSync,sign,createHash} from 'node:crypto';
import {deflateSync} from 'node:zlib';
import {createOfflinePrivateRevisionRegistry,computePrivateRegistryBackupDigest} from '../src/offline-private-revision-registry.mjs';
import {computeArtworkDesignSha256} from '../src/manufacturing-artwork-evidence.mjs';

const schema='TJ-OFFLINE-PRIVATE-REGISTRY-ADMIN-1',fields=['schema','registryId','action','opId','operatorId','requestSha256','issuedAt','expiresAt'];
const recoverySchema='TJ-OFFLINE-PRIVATE-REGISTRY-RECOVERY-1',recoveryFields=['schema','registryId','authorizationId','issuedAt','expiresAt','expectedAnchor','targetAnchor','reason'];
const keyA='backup29-key-alpha',keyB='backup29-key-bravo',token='synthetic-operator-backup-29',shop='gucgmp-bc.myshopify.com';
const id=()=>`backup29-${randomBytes(10).toString('hex')}`;
const reject=(p,code)=>assert.rejects(p,e=>e?.code===code);
const sha=b=>createHash('sha256').update(b).digest('hex');
const crcTable=Array.from({length:256},(_,i)=>{let c=i;for(let j=0;j<8;j++)c=c&1?0xedb88320^(c>>>1):c>>>1;return c>>>0;});
function chunk(type,data){const t=Buffer.from(type),b=Buffer.alloc(12+data.length);b.writeUInt32BE(data.length,0);t.copy(b,4);data.copy(b,8);let c=0xffffffff;for(const x of Buffer.concat([t,data]))c=crcTable[(c^x)&255]^(c>>>8);b.writeUInt32BE((c^0xffffffff)>>>0,8+data.length);return b;}
function png(){const head=Buffer.alloc(13);head.writeUInt32BE(12,0);head.writeUInt32BE(12,4);head[8]=8;head[9]=2;return Buffer.concat([Buffer.from('89504e470d0a1a0a','hex'),chunk('IHDR',head),chunk('IDAT',deflateSync(Buffer.alloc(12*(12*3+1)))),chunk('IEND',Buffer.alloc(0))]);}
function record(revision=1){const design={layers:[{id:'layer-A',type:'artwork',artworkId:'art-A',surfaceId:'front',x:.2,y:.2,width:.3,height:.3,rotationDeg:0,sourceWidthPx:100,sourceHeightPx:100}]};return{schema:'TJ-CURRENT-IMMUTABLE-DESIGN-1',shop,productGid:'gid://shopify/Product/123',variantGid:'gid://shopify/ProductVariant/456',manifestId:'concept-custom-item',ownerId:'owner-1',designId:'design-1',revision,designSha256:computeArtworkDesignSha256(design),status:'CURRENT_IMMUTABLE',design};}
const principal=(changes={})=>({operatorId:'trusted-admin-backup-29',issuedAt:Date.now()-1000,expiresAt:Date.now()+60000,...changes});
async function fixture(t){
 const directory=await mkdtemp(join(tmpdir(),'tj-backup29-'));t.after(()=>rm(directory,{recursive:true,force:true}));
 const secret=randomBytes(32),keys=new Map([[keyA,randomBytes(32)],[keyB,randomBytes(32)]]);
 const {publicKey,privateKey}=generateKeyPairSync('ed25519'),{publicKey:recoveryPublic,privateKey:recoveryPrivate}=generateKeyPairSync('ed25519');
 const registryId='objective-29-backup-registry',recoveryId='objective-29-recovery-registry';
 let anchor=null,fault,down=false,verifier=(v,action)=>v===token&&['export-backup','restore-backup','export-audit'].includes(action)?principal():null;
 const adapters={readAnchor:async()=>{if(down)throw Error('anchor down');return structuredClone(anchor);},compareAndSetAnchor:async(expected,next)=>{if(JSON.stringify(anchor)!==JSON.stringify(expected))return false;anchor=structuredClone(next);return true;}};
 const encryption=(activeKeyId=keyA)=>({activeKeyId,resolveKey:k=>keys.get(k)});
 const adminAuthorization=()=>({registryId,publicKey,verifyOperator:(v,action)=>verifier(v,action)});
 const recovery={registryId:recoveryId,publicKey:recoveryPublic};
 const open=(options={})=>createOfflinePrivateRevisionRegistry({directory,secret,...adapters,injectFault:fault,encryption:encryption(),...options});
 const secure=(options={})=>open({adminAuthorization:adminAuthorization(),...options});
 const commit=async(revision=1,plaintext=false)=>createOfflinePrivateRevisionRegistry({directory,secret,...adapters,...(plaintext?{}:{encryption:encryption()})}).commitRevision({record:record(revision),artworks:[{storageKey:revision===1?'PrivateArtwork0001':'PrivateArtwork0002',artworkId:'art-A',layerId:'layer-A',bytes:png()}],expectedRevision:revision===1?null:revision-1,opId:id()});
 const state=async()=>JSON.parse(await readFile(join(directory,'private-registry.json'),'utf8'));
 const grant=(action,q,changes={},signer=privateKey)=>{const now=Date.now(),body={schema,registryId,action,opId:q.opId,operatorId:'trusted-admin-backup-29',requestSha256:computePrivateRegistryBackupDigest(action,q),issuedAt:now-1000,expiresAt:now+60000,...changes};const canonical=Object.fromEntries(fields.map(k=>[k,body[k]]));return {...body,signature:sign(null,Buffer.from(`${schema}\0${JSON.stringify(canonical)}`),signer).toString('base64url')};};
 const envelope=(action,q,backup,changes={})=>({operatorToken:token,permit:grant(action,q,changes),request:q,...(action==='restore-backup'?{backup}:{})});
 const exportRequest=()=>({opId:id(),expectedAnchor:structuredClone(anchor)});
 const restoreRequest=b=>({opId:id(),expectedAnchor:structuredClone(b.anchor),backupSha256:b.sha256});
 const exportBackup=async()=>{const q=exportRequest();return secure().exportAuthenticatedBackup(envelope('export-backup',q));};
 const removeLocal=()=>rm(join(directory,'private-registry.json'));
 const restore=(b,q=restoreRequest(b),e)=>secure().restoreAuthenticatedBackup(e||envelope('restore-backup',q,b));
 const audit=async(q=exportRequest(),e)=>secure().exportAuthenticatedAudit(e||envelope('export-audit',q));
 const recoveryPermit=(expectedAnchor,targetAnchor,changes={})=>{const now=Date.now(),body={schema:recoverySchema,registryId:recoveryId,authorizationId:id(),issuedAt:now-1000,expiresAt:now+60000,expectedAnchor,targetAnchor,reason:'Operator independently inspected interrupted restore',...changes};const canonical=Object.fromEntries(recoveryFields.map(k=>[k,body[k]]));return {...body,signature:sign(null,Buffer.from(`${recoverySchema}\0${JSON.stringify(canonical)}`),recoveryPrivate).toString('base64url')};};
 return {directory,secret,keys,open,secure,commit,state,grant,envelope,exportRequest,restoreRequest,exportBackup,removeLocal,restore,audit,getAnchor:()=>structuredClone(anchor),setAnchor:a=>{anchor=structuredClone(a);},setDown:x=>{down=x;},setFault:x=>{fault=x;},setVerifier:x=>{verifier=x;},recovery,recoveryPermit};
}
const altered=(b,changes)=>({...structuredClone(b),...changes});


const lockPath=f=>join(f.directory,'.private-registry-lock');
async function lockHolder(f,t,holdMs=350){
 const path=lockPath(f);try{const h=await open(path,'wx',0o600);await h.close();}catch(e){if(e.code!=='EEXIST')throw e;}
 const child=spawn('/usr/bin/flock',['-x','-w','3',path,'/bin/sh','-c',`printf 'READY\\n'; sleep ${holdMs/1000}`],{stdio:['ignore','pipe','pipe']});
 t.after(()=>{if(child.exitCode===null)child.kill('SIGKILL');});
 await new Promise((resolve,reject)=>{
  let output='';const timeout=setTimeout(()=>reject(Error('external lock timeout')),2000);
  child.stdout.on('data',chunk=>{output+=chunk;if(output.includes('READY')){clearTimeout(timeout);resolve();}});
  child.on('error',reject);child.on('exit',code=>{if(!output.includes('READY')){clearTimeout(timeout);reject(Error(`external lock exit ${code}`));}});
 });
 return child;
}
const waitExit=child=>new Promise((resolve,reject)=>{if(child.exitCode!==null)return resolve(child.exitCode);child.once('exit',resolve);child.once('error',reject);});

test('signed audit snapshot binds exact external anchor and state digest',async t=>{
 const f=await fixture(t);await f.commit();const a=await f.audit(),s=await f.state();
 assert.equal(a.schema,'TJ-OFFLINE-PRIVATE-REGISTRY-AUDIT-SNAPSHOT-1');assert.deepEqual(a.anchor,f.getAnchor());
 assert.equal(a.stateSha256,sha(Buffer.from(JSON.stringify(s))));assert.equal(a.previousMac,s.previousMac);
 assert.equal(a.revisionSha256,sha(Buffer.from(JSON.stringify(s.revisions))));
 assert.equal(a.artworkSha256,sha(Buffer.from(JSON.stringify(s.assets))));
 assert.equal(a.revocationSha256,sha(Buffer.from(JSON.stringify(s.revocations))));
 assert.equal(a.operationSha256,sha(Buffer.from(JSON.stringify(s.opIds))));
 assert.equal(a.historicalCoverage,'CURRENT_SNAPSHOT_ONLY');assert.equal(a.productionApproved,false);
});
test('audit discloses neither artwork bytes nor operation IDs nor operator token',async t=>{
 const f=await fixture(t);await f.commit();const s=await f.state(),a=await f.audit(),raw=JSON.stringify(a);
 assert.ok(!raw.includes(token));assert.ok(!raw.includes(s.opIds[0]));
 assert.ok(!raw.includes(s.assets[0].encryption.ciphertext));assert.ok(!raw.includes('owner-1'));
 assert.equal(a.operationCount,s.opIds.length);assert.equal(a.artworkCount,1);
});
test('audit export is read-only, repeatable and does not consume replay IDs',async t=>{
 const f=await fixture(t);await f.commit();const q=f.exportRequest(),e=f.envelope('export-audit',q),before=await f.state();
 assert.deepEqual(await f.audit(q,e),await f.audit(q,e));assert.deepEqual(await f.state(),before);
});
test('audit after restoration proves next anchor and previous backup MAC',async t=>{
 const f=await fixture(t);await f.commit();const b=await f.exportBackup();await f.removeLocal();await f.restore(b);
 const a=await f.audit();assert.equal(a.previousMac,b.anchor.mac);assert.equal(a.anchor.sequence,b.anchor.sequence+1);
 assert.equal(a.operationCount,b.opIdCount+1);assert.notEqual(a.stateSha256,b.sha256);
});
test('audit changes after artwork revocation and operation is consumed',async t=>{
 const f=await fixture(t);await f.commit();const a=await f.audit();
 await f.open().revokeArtwork({storageKey:'PrivateArtwork0001',ownerId:'owner-1',designId:'design-1',revision:1,opId:id()});
 const b=await f.audit();assert.equal(b.revocationCount,1);assert.equal(b.operationCount,a.operationCount+1);
 assert.notEqual(b.revocationSha256,a.revocationSha256);assert.notEqual(b.operationSha256,a.operationSha256);
});
test('audit changes after a new revision without erasing historical commitments',async t=>{
 const f=await fixture(t);await f.commit();const a=await f.audit();await f.commit(2);const b=await f.audit();
 assert.equal(b.revisionCount,2);assert.equal(b.artworkCount,2);assert.equal(b.operationCount,a.operationCount+1);
 assert.notEqual(a.revisionSha256,b.revisionSha256);assert.equal(a.revocationSha256,b.revocationSha256);
});
test('audit refuses unsigned operator requests',async t=>{
 const f=await fixture(t);await f.commit();await reject(f.secure().exportAuthenticatedAudit({operatorToken:token,request:f.exportRequest()}),'REGISTRY_AUDIT_DENIED');
});
test('audit rejects forged operator signature',async t=>{
 const f=await fixture(t);await f.commit();const q=f.exportRequest(),e=f.envelope('export-audit',q);e.permit.signature='a'.repeat(86);
 await reject(f.audit(q,e),'REGISTRY_ADMIN_DENIED');
});
test('audit rejects backup export permit reused for audit action',async t=>{
 const f=await fixture(t);await f.commit();const q=f.exportRequest(),e=f.envelope('export-backup',q);
 await reject(f.audit(q,e),'REGISTRY_ADMIN_DENIED');
});
test('audit rejects wrong registry identity',async t=>{
 const f=await fixture(t);await f.commit();const q=f.exportRequest(),e=f.envelope('export-audit',q);e.permit.registryId='forged-registry-id';
 await reject(f.audit(q,e),'REGISTRY_ADMIN_DENIED');
});
test('audit rejects expired operator permit',async t=>{
 const f=await fixture(t);await f.commit();const q=f.exportRequest(),e=f.envelope('export-audit',q,undefined,{issuedAt:Date.now()-60000,expiresAt:Date.now()-1});
 await reject(f.audit(q,e),'REGISTRY_ADMIN_DENIED');
});
test('audit rejects unauthorized operator session',async t=>{
 const f=await fixture(t);await f.commit();f.setVerifier(()=>null);await reject(f.audit(),'REGISTRY_ADMIN_DENIED');
});
test('audit refuses stale independent anchor',async t=>{
 const f=await fixture(t);await f.commit();const q=f.exportRequest();await f.commit(2);
 await reject(f.audit(q),'REGISTRY_BACKUP_ANCHOR_MISMATCH');
});
test('audit fails closed when external anchor is unavailable',async t=>{
 const f=await fixture(t);await f.commit();f.setDown(true);await reject(f.audit(),'REGISTRY_ANCHOR_UNAVAILABLE');
});
test('audit requires admin configuration',async t=>{
 const f=await fixture(t);await f.commit();const q=f.exportRequest();
 await reject(f.open().exportAuthenticatedAudit(f.envelope('export-audit',q)),'REGISTRY_AUTH_REQUIRED');
});
test('audit refuses plaintext legacy registry',async t=>{
 const f=await fixture(t);await f.commit(1,true);await reject(f.audit(),'REGISTRY_ENCRYPTION_REQUIRED');
});
test('audit refuses corrupted ciphertext even if HMAC recomputation not possible',async t=>{
 const f=await fixture(t);await f.commit();f.keys.set(keyA,randomBytes(32));await reject(f.audit(),'REGISTRY_ARTWORK_AUTH_FAILED');
});
test('audit request digest rejects forged extra fields and missing anchor',()=>{
 const a={sequence:1,mac:'a'.repeat(64)};
 assert.throws(()=>computePrivateRegistryBackupDigest('export-audit',{opId:id(),expectedAnchor:a,bypass:true}),e=>e.code==='REGISTRY_BACKUP_REQUEST');
 assert.throws(()=>computePrivateRegistryBackupDigest('export-audit',{opId:id(),expectedAnchor:null}),e=>e.code==='REGISTRY_BACKUP_REQUEST');
});
test('audit request digest is domain-separated from backup and restore',()=>{
 const q={opId:id(),expectedAnchor:{sequence:1,mac:'a'.repeat(64)}};
 assert.notEqual(computePrivateRegistryBackupDigest('export-audit',q),computePrivateRegistryBackupDigest('export-backup',q));
});
test('external process lock blocks authenticated audit until released',async t=>{
 const f=await fixture(t);await f.commit();const child=await lockHolder(f,t,450);
 await reject(f.secure({lockTimeoutMs:70}).exportAuthenticatedAudit(f.envelope('export-audit',f.exportRequest())),'REGISTRY_LOCK_UNAVAILABLE');
 assert.equal(await waitExit(child),0);assert.equal((await f.audit()).artworkCount,1);
});
test('external process lock prevents restore destination creation, then permits retry',async t=>{
 const f=await fixture(t);await f.commit();const b=await f.exportBackup();await f.removeLocal();
 const q=f.restoreRequest(b),e=f.envelope('restore-backup',q,b),child=await lockHolder(f,t,450);
 await reject(f.secure({lockTimeoutMs:70}).restoreAuthenticatedBackup(e),'REGISTRY_LOCK_UNAVAILABLE');
 await assert.rejects(readFile(join(f.directory,'private-registry.json')));
 assert.equal(await waitExit(child),0);await f.restore(b,q,e);assert.equal(f.getAnchor().sequence,b.anchor.sequence+1);
});
test('lock pathname substitution during restore is rejected before destination creation',async t=>{
 const f=await fixture(t);await f.commit();const b=await f.exportBackup();await f.removeLocal();
 f.setFault(async stage=>{if(stage==='before-rename'){await rename(lockPath(f),lockPath(f)+'.old');await writeFile(lockPath(f),'',{mode:0o600});}});
 await reject(f.restore(b),'REGISTRY_LOCK_UNSAFE');f.setFault(undefined);
 await assert.rejects(readFile(join(f.directory,'private-registry.json')));assert.deepEqual(f.getAnchor(),b.anchor);
});
test('directory pathname substitution during restore is rejected before destination creation',async t=>{
 const f=await fixture(t);await f.commit();const b=await f.exportBackup();await f.removeLocal();
 const moved=f.directory+'-moved';t.after(()=>rm(moved,{recursive:true,force:true}));
 f.setFault(async stage=>{if(stage==='before-rename'){await rename(f.directory,moved);await mkdir(f.directory,{mode:0o700});}});
 await reject(f.restore(b),'REGISTRY_LOCK_UNSAFE');f.setFault(undefined);
 await assert.rejects(readFile(join(f.directory,'private-registry.json')));assert.deepEqual(f.getAnchor(),b.anchor);
});
test('lock pathname substitution during a normal revision commit does not advance anchor',async t=>{
 const f=await fixture(t);await f.commit();const before=f.getAnchor();
 f.setFault(async stage=>{if(stage==='before-rename'){await rename(lockPath(f),lockPath(f)+'.old');await writeFile(lockPath(f),'',{mode:0o600});}});
 const r=f.open();await reject(r.commitRevision({record:record(2),artworks:[{storageKey:'PrivateArtwork0002',artworkId:'art-A',layerId:'layer-A',bytes:png()}],expectedRevision:1,opId:id()}),'REGISTRY_LOCK_UNSAFE');
 assert.deepEqual(f.getAnchor(),before);assert.equal((await f.state()).sequence,before.sequence);
});
test('audit lock timeout leaves registry and external anchor unchanged',async t=>{
 const f=await fixture(t);await f.commit();const before=await f.state(),anchor=f.getAnchor(),child=await lockHolder(f,t,450);
 await reject(f.secure({lockTimeoutMs:60}).exportAuthenticatedAudit(f.envelope('export-audit',f.exportRequest())),'REGISTRY_LOCK_UNAVAILABLE');
 assert.equal(await waitExit(child),0);assert.deepEqual(await f.state(),before);assert.deepEqual(f.getAnchor(),anchor);
});
test('same-instance concurrent lock timeout cannot poison the active writer context',async t=>{
 const f=await fixture(t);await f.commit();let entered;const started=new Promise(resolve=>entered=resolve);
 f.setFault(async stage=>{if(stage==='before-rename'){entered();await new Promise(resolve=>setTimeout(resolve,230));}});
 const r=f.open({lockTimeoutMs:65});
 const first=r.commitRevision({record:record(2),artworks:[{storageKey:'PrivateArtwork0002',artworkId:'art-A',layerId:'layer-A',bytes:png()}],expectedRevision:1,opId:id()});
 await started;
 await reject(r.loadCurrentRevision({...record(2)}),'REGISTRY_LOCK_UNAVAILABLE');
 const result=await first;assert.ok(result);f.setFault(undefined);
 assert.equal((await f.state()).sequence,2);assert.equal(f.getAnchor().sequence,2);
});
