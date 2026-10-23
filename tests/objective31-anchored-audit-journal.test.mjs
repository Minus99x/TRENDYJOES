import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,readFile,writeFile,unlink,chmod} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {randomBytes,generateKeyPairSync,sign} from 'node:crypto';
import {deflateSync} from 'node:zlib';
import {createOfflinePrivateRevisionRegistry,computePrivateRegistryBackupDigest} from '../src/offline-private-revision-registry.mjs';
import {createOfflineAnchoredAuditJournal} from '../src/offline-anchored-audit-journal.mjs';
import {computeArtworkDesignSha256} from '../src/manufacturing-artwork-evidence.mjs';

const adminSchema='TJ-OFFLINE-PRIVATE-REGISTRY-ADMIN-1';
const adminFields=['schema','registryId','action','opId','operatorId','requestSha256','issuedAt','expiresAt'];
const recoverySchema='TJ-OFFLINE-AUDIT-JOURNAL-RECOVERY-1';
const recoveryFields=['schema','registryId','authorizationId','issuedAt','expiresAt','expectedJournalAnchor','targetJournalAnchor','reason'];
const token='synthetic-journal-operator-token-31',registryId='objective-31-registry',shop='gucgmp-bc.myshopify.com';
const id=()=>`obj31-${randomBytes(12).toString('hex')}`;
const reject=(p,code)=>assert.rejects(p,e=>e?.code===code);
const table=Array.from({length:256},(_,i)=>{let c=i;for(let j=0;j<8;j++)c=c&1?0xedb88320^(c>>>1):c>>>1;return c>>>0;});
function chunk(type,data){const t=Buffer.from(type),b=Buffer.alloc(12+data.length);b.writeUInt32BE(data.length,0);t.copy(b,4);data.copy(b,8);let c=0xffffffff;for(const v of Buffer.concat([t,data]))c=table[(c^v)&255]^(c>>>8);b.writeUInt32BE((c^0xffffffff)>>>0,8+data.length);return b;}
function png(){const head=Buffer.alloc(13);head.writeUInt32BE(12,0);head.writeUInt32BE(12,4);head[8]=8;head[9]=2;return Buffer.concat([Buffer.from('89504e470d0a1a0a','hex'),chunk('IHDR',head),chunk('IDAT',deflateSync(Buffer.alloc(12*(12*3+1)))),chunk('IEND',Buffer.alloc(0))]);}
function record(revision=1){const design={layers:[{id:'layer-A',type:'artwork',artworkId:'art-A',surfaceId:'front',x:.2,y:.2,width:.3,height:.3,rotationDeg:0,sourceWidthPx:100,sourceHeightPx:100}]};return{schema:'TJ-CURRENT-IMMUTABLE-DESIGN-1',shop,productGid:'gid://shopify/Product/123',variantGid:'gid://shopify/ProductVariant/456',manifestId:'concept-universal-item',ownerId:'owner-1',designId:'design-1',revision,designSha256:computeArtworkDesignSha256(design),status:'CURRENT_IMMUTABLE',design};}
async function fixture(t){
 const base=await mkdtemp(join(tmpdir(),'tj-obj31-')),directory=join(base,'registry'),journalDir=join(base,'journal');t.after(()=>rm(base,{recursive:true,force:true}));
 const secret=randomBytes(32),assetKey=randomBytes(32),{publicKey,privateKey}=generateKeyPairSync('ed25519'),{publicKey:recoveryPublic,privateKey:recoveryPrivate}=generateKeyPairSync('ed25519');
 let registryAnchor=null,journalAnchor=null,fault,casEnabled=true;
 const readAnchor=async()=>structuredClone(registryAnchor),compareAndSetAnchor=async(expected,next)=>{if(JSON.stringify(registryAnchor)!==JSON.stringify(expected))return false;registryAnchor=structuredClone(next);return true;};
 const registry=createOfflinePrivateRevisionRegistry({directory,secret,readAnchor,compareAndSetAnchor,encryption:{activeKeyId:'objective31-main-key',resolveKey:()=>assetKey},adminAuthorization:{registryId,publicKey,verifyOperator:(t,action)=>t===token&&['export-audit','export-backup','restore-backup'].includes(action)?{operatorId:'operator-31',issuedAt:Date.now()-1000,expiresAt:Date.now()+60_000}:null}});
 const commit=(revision=1)=>registry.commitRevision({record:record(revision),artworks:[{storageKey:`ArtworkObj31${revision}000`,artworkId:'art-A',layerId:'layer-A',bytes:png()}],expectedRevision:revision===1?null:revision-1,opId:id()});
 const revoke=()=>registry.revokeArtwork({storageKey:'ArtworkObj311000',ownerId:'owner-1',designId:'design-1',revision:1,opId:id()});
 const envelope=(action='export-audit',request={opId:id(),expectedAnchor:structuredClone(registryAnchor)})=>{const now=Date.now(),body={schema:adminSchema,registryId,action,opId:request.opId,operatorId:'operator-31',requestSha256:computePrivateRegistryBackupDigest(action,request),issuedAt:now-1000,expiresAt:now+60_000};const permit={...body,signature:sign(null,Buffer.from(`${adminSchema}\0${JSON.stringify(Object.fromEntries(adminFields.map(k=>[k,body[k]])))}`),privateKey).toString('base64url')};return {operatorToken:token,permit,request};};
 const journal=(extra={})=>createOfflineAnchoredAuditJournal({directory:journalDir,registry,registryId,readJournalAnchor:async()=>structuredClone(journalAnchor),compareAndSetJournalAnchor:async(prev,next)=>{if(!casEnabled||JSON.stringify(journalAnchor)!==JSON.stringify(prev))return false;journalAnchor=structuredClone(next);return true;},readRegistryAnchor:readAnchor,recovery:{registryId,publicKey:recoveryPublic},injectFault:fault,...extra});
 const append=()=>journal().appendAuthenticatedSnapshot(envelope());
 const permit=(expected,target,changes={})=>{const now=Date.now(),body={schema:recoverySchema,registryId,authorizationId:id(),issuedAt:now-1000,expiresAt:now+60_000,expectedJournalAnchor:expected,targetJournalAnchor:target,reason:'Independently inspected committed registry event',...changes};return {...body,signature:sign(null,Buffer.from(`${recoverySchema}\0${JSON.stringify(Object.fromEntries(recoveryFields.map(k=>[k,body[k]])))}`),recoveryPrivate).toString('base64url')};};
 return {base,directory,journalDir,registry,commit,revoke,envelope,journal,append,permit,getRegistryAnchor:()=>structuredClone(registryAnchor),getJournalAnchor:()=>structuredClone(journalAnchor),setJournalAnchor:a=>{journalAnchor=structuredClone(a);},setFault:f=>{fault=f;},setCasEnabled:v=>{casEnabled=v;},file:n=>join(journalDir,`${String(n).padStart(10,'0')}.json`)};
}

test('objective31 initial bootstrap creates independently anchored event with explicit historical uncertainty',async t=>{
 const f=await fixture(t);await f.commit();const result=await f.append();assert.equal(result.coverage,'BOOTSTRAP_UNPROVEN_PRIOR_HISTORY');
 const inspection=await f.journal().verify();assert.equal(inspection.eventCount,1);assert.equal(inspection.firstObservedRegistrySequence,1);assert.equal(inspection.historyBeforeBootstrapProven,false);
 assert.deepEqual(result.journalAnchor,f.getJournalAnchor());assert.deepEqual(result.registryAnchor,f.getRegistryAnchor());
});
test('objective31 contiguous registry revocation observation advances independent anchor and hash chain',async t=>{
 const f=await fixture(t);await f.commit();await f.append();await f.revoke();const newEvent=await f.append(),events=[JSON.parse(await readFile(f.file(1))),JSON.parse(await readFile(f.file(2)))];
 assert.equal(events[1].previousDigest,events[0].digest);assert.equal(events[1].registryPreviousMac,events[0].registryAnchor.mac);
 assert.equal(events[1].registryAnchor.sequence,events[0].registryAnchor.sequence+1);assert.equal(events[1].coverage,'CONTIGUOUS_OBSERVATION');
 assert.equal((await f.journal().verify()).eventCount,2);assert.equal(newEvent.journalAnchor.index,2);
});
test('objective31 legacy v0.29/v0.30 state is bootstrapped without invented earlier events',async t=>{
 const f=await fixture(t);await f.commit();await f.revoke();const a=await f.append();assert.equal(a.registryAnchor.sequence,2);
 assert.equal(a.coverage,'BOOTSTRAP_UNPROVEN_PRIOR_HISTORY');assert.equal((await f.journal().verify()).firstObservedRegistrySequence,2);
});
test('objective31 skipped registry revisions refuse to forge a continuous chain',async t=>{
 const f=await fixture(t);await f.commit();await f.append();await f.revoke();await f.registry.revokeRevision({identity:{shop,productGid:'gid://shopify/Product/123',variantGid:'gid://shopify/ProductVariant/456',ownerId:'owner-1',designId:'design-1',revision:1},opId:id()});
 await reject(f.append(),'AUDIT_HISTORY_GAP');assert.equal((await f.journal().verify()).eventCount,1);
});
test('objective31 replay of a previously journaled registry state cannot add duplicate event',async t=>{const f=await fixture(t);await f.commit();await f.append();await reject(f.append(),'AUDIT_HISTORY_GAP');assert.equal((await f.journal().verify()).eventCount,1);});
test('objective31 reject unsigned operator-snapshot export',async t=>{const f=await fixture(t);await f.commit();await reject(f.journal().appendAuthenticatedSnapshot({}), 'REGISTRY_AUDIT_DENIED');assert.equal((await f.journal().verify()).eventCount,0);});
test('objective31 anchored journal does not store identifiers, operation IDs, tokens, or artwork ciphertext',async t=>{const f=await fixture(t);await f.commit();await f.append();const body=await readFile(f.file(1),'utf8'),state=await readFile(join(f.directory,'private-registry.json'),'utf8');assert.ok(!body.includes(token));assert.ok(!body.includes('owner-1'));assert.ok(!body.includes(JSON.parse(state).opIds[0]));assert.ok(!body.includes(JSON.parse(state).assets[0].encryption.ciphertext));assert.ok(!body.includes('gid://shopify'));});
test('objective31 tampered event is detected even with unchanged external anchor',async t=>{const f=await fixture(t);await f.commit();await f.append();const e=JSON.parse(await readFile(f.file(1)));e.revisionCount=777;await writeFile(f.file(1),JSON.stringify(e));await reject(f.journal().verify(),'AUDIT_EVENT_TAMPERED');});
test('objective31 missing anchored journal event refuses verification and new appends',async t=>{const f=await fixture(t);await f.commit();await f.append();await unlink(f.file(1));await reject(f.journal().verify(),'AUDIT_ANCHOR_MISMATCH');await reject(f.append(),'AUDIT_ANCHOR_MISMATCH');});
test('objective31 extra unanchored journal event refuses subsequent commits until signed recovery',async t=>{
 const f=await fixture(t);await f.commit();f.setFault(stage=>{if(stage==='after-event-file')throw Error('injected process crash');});await assert.rejects(f.append());
 f.setFault(undefined);await reject(f.journal().verify(),'AUDIT_ANCHOR_MISMATCH');await reject(f.append(),'AUDIT_ANCHOR_MISMATCH');
 const event=JSON.parse(await readFile(f.file(1)));const target={index:1,digest:event.digest};assert.equal(await f.journal().recoverInterruptedAppend({authorization:f.permit(null,target)}),'recovered');
 assert.equal((await f.journal().verify()).eventCount,1);await reject(f.journal().recoverInterruptedAppend({authorization:f.permit(null,target)}),'AUDIT_RECOVERY_ANCHOR_MISMATCH');
});
test('objective31 recovery forbids forged operator permit, wrong signed target, and tampered justification',async t=>{
 const f=await fixture(t);await f.commit();f.setFault(()=>{throw Error('crash');});await assert.rejects(f.append());f.setFault(undefined);
 const e=JSON.parse(await readFile(f.file(1)));const target={index:1,digest:e.digest};
 const wrong=f.permit(null,{index:1,digest:'a'.repeat(64)});await reject(f.journal().recoverInterruptedAppend({authorization:wrong}),'AUDIT_RECOVERY_CHAIN');
 const forged=f.permit(null,target);forged.reason='substituted reason';await reject(f.journal().recoverInterruptedAppend({authorization:forged}),'AUDIT_RECOVERY_DENIED');
 const expired=f.permit(null,target,{expiresAt:Date.now()-1});await reject(f.journal().recoverInterruptedAppend({authorization:expired}),'AUDIT_RECOVERY_DENIED');
});
test('objective31 independent anchor outage/conflict fails closed and preserves event evidence',async t=>{
 const f=await fixture(t);await f.commit();f.setCasEnabled(false);await reject(f.append(),'AUDIT_ANCHOR_CONFLICT');await reject(f.journal().verify(),'AUDIT_ANCHOR_MISMATCH');
 assert.equal(JSON.parse(await readFile(f.file(1))).index,1);
});
test('objective31 changed registry anchor prevents recovering stale pending event',async t=>{
 const f=await fixture(t);await f.commit();f.setFault(()=>{throw Error('crash');});await assert.rejects(f.append());f.setFault(undefined);await f.revoke();
 const e=JSON.parse(await readFile(f.file(1)));await reject(f.journal().recoverInterruptedAppend({authorization:f.permit(null,{index:1,digest:e.digest})}),'AUDIT_REGISTRY_CHANGED');
});
test('objective31 journal file with loose permissions fails closed',async t=>{const f=await fixture(t);await f.commit();await f.append();await chmod(f.file(1),0o644);await reject(f.journal().verify(),'AUDIT_FILE_UNSAFE');});
test('objective31 strict constructor refuses missing external independent anchor',async t=>{const f=await fixture(t);assert.throws(()=>f.journal({readJournalAnchor:undefined}),e=>e.code==='AUDIT_CONFIGURATION');assert.throws(()=>f.journal({readRegistryAnchor:undefined}),e=>e.code==='AUDIT_CONFIGURATION');});

test('objective31 exact signed backup restoration is observed as next contiguous registry event',async t=>{
 const f=await fixture(t);await f.commit();await f.append();
 const backup=await f.registry.exportAuthenticatedBackup(f.envelope('export-backup'));
 await unlink(join(f.directory,'private-registry.json'));
 const restoreRequest={opId:id(),expectedAnchor:backup.anchor,backupSha256:backup.sha256};
 await f.registry.restoreAuthenticatedBackup({...f.envelope('restore-backup',restoreRequest),backup});
 const next=await f.append();const events=[JSON.parse(await readFile(f.file(1))),JSON.parse(await readFile(f.file(2)))];
 assert.equal(events[1].registryAnchor.sequence,events[0].registryAnchor.sequence+1);
 assert.equal(events[1].registryPreviousMac,events[0].registryAnchor.mac);
 assert.equal(events[1].operationCount,events[0].operationCount+1);
 assert.equal(next.coverage,'CONTIGUOUS_OBSERVATION');
});
test('objective31 full journal can be reopened without trusting cached in-process state',async t=>{
 const f=await fixture(t);await f.commit();await f.append();await f.revoke();await f.append();
 const restarted=f.journal();assert.equal((await restarted.verify()).eventCount,2);
});
test('objective31 premature unverified extraneous event filename fails closed',async t=>{
 const f=await fixture(t);await f.commit();await f.append();await writeFile(join(f.journalDir,'unauthorized.json'),'{}');await reject(f.journal().verify(),'AUDIT_MISSING_EVENT');
});
