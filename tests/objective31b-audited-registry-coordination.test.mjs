import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,readFile,writeFile,unlink,chmod} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {randomBytes,generateKeyPairSync,sign} from 'node:crypto';
import {deflateSync} from 'node:zlib';
import {spawn} from 'node:child_process';
import {createOfflinePrivateRevisionRegistry,computePrivateRegistryMutationDigest,computePrivateRegistryBackupDigest} from '../src/offline-private-revision-registry.mjs';
import {createOfflineAnchoredAuditJournal} from '../src/offline-anchored-audit-journal.mjs';
import {createOfflineAuditedRegistryCoordinator} from '../src/offline-audited-registry-coordinator.mjs';
import {computeArtworkDesignSha256} from '../src/manufacturing-artwork-evidence.mjs';

const registryId='objective-31b-registry',shop='gucgmp-bc.myshopify.com',pid='gid://shopify/Product/123',vid='gid://shopify/ProductVariant/456';
const session='synthetic-verified-session-31b',operator='synthetic-verified-operator-31b';
const mutationSchema='TJ-OFFLINE-PRIVATE-REGISTRY-MUTATION-1',adminSchema='TJ-OFFLINE-PRIVATE-REGISTRY-ADMIN-1';
const coordinatorSchema='TJ-OFFLINE-AUDITED-REGISTRY-COORDINATOR-RECOVERY-1';
const journalRecoverySchema='TJ-OFFLINE-AUDIT-JOURNAL-RECOVERY-1';
const registryRecoverySchema='TJ-OFFLINE-PRIVATE-REGISTRY-RECOVERY-1';
const mutationFields=['schema','registryId','action','opId','shop','ownerId','requestSha256','issuedAt','expiresAt'];
const adminFields=['schema','registryId','action','opId','operatorId','requestSha256','issuedAt','expiresAt'];
const coordinatorFields=['schema','registryId','action','authorizationId','issuedAt','expiresAt','expectedJournalAnchor','expectedRegistryAnchor','targetRegistryAnchor','reason'];
const journalFields=['schema','registryId','authorizationId','issuedAt','expiresAt','expectedJournalAnchor','targetJournalAnchor','reason'];
const registryRecoveryFields=['schema','registryId','authorizationId','issuedAt','expiresAt','expectedAnchor','targetAnchor','reason'];
const id=()=>`obj31b-${randomBytes(10).toString('hex')}`;
const rejects=(promise,code)=>assert.rejects(promise,e=>e?.code===code);
const signBody=(schema,fields,body,key)=>({...body,signature:sign(null,Buffer.from(`${schema}\0${JSON.stringify(Object.fromEntries(fields.map(k=>[k,body[k]])))}`),key).toString('base64url')});
const crc=Array.from({length:256},(_,i)=>{let c=i;for(let j=0;j<8;j++)c=c&1?0xedb88320^(c>>>1):c>>>1;return c>>>0;});
function chunk(type,data){const t=Buffer.from(type),b=Buffer.alloc(12+data.length);b.writeUInt32BE(data.length,0);t.copy(b,4);data.copy(b,8);let c=0xffffffff;for(const x of Buffer.concat([t,data]))c=crc[(c^x)&255]^(c>>>8);b.writeUInt32BE((c^0xffffffff)>>>0,8+data.length);return b;}
function png(){const h=Buffer.alloc(13);h.writeUInt32BE(12,0);h.writeUInt32BE(12,4);h[8]=8;h[9]=2;return Buffer.concat([Buffer.from('89504e470d0a1a0a','hex'),chunk('IHDR',h),chunk('IDAT',deflateSync(Buffer.alloc(12*37))),chunk('IEND',Buffer.alloc(0))]);}
function record(revision=1){const design={layers:[{id:'layer-A',type:'artwork',artworkId:'art-A',surfaceId:'front',x:.2,y:.2,width:.3,height:.3,rotationDeg:0,sourceWidthPx:100,sourceHeightPx:100}]};return{schema:'TJ-CURRENT-IMMUTABLE-DESIGN-1',shop,productGid:pid,variantGid:vid,manifestId:'universal-manufacturing-fixture',ownerId:'owner-1',designId:'design-1',revision,designSha256:computeArtworkDesignSha256(design),status:'CURRENT_IMMUTABLE',design};}
function commitRequest(revision=1){return{record:record(revision),artworks:[{storageKey:`PrivateArtwork31b${revision}000`,artworkId:'art-A',layerId:'layer-A',bytes:png()}],expectedRevision:revision===1?null:revision-1,opId:id()};}
function revokeRequest(){return{shop,productGid:pid,variantGid:vid,ownerId:'owner-1',designId:'design-1',revision:1,storageKey:'PrivateArtwork31b1000',artworkId:'art-A',layerId:'layer-A',opId:id()};}
async function fixture(t){
 const base=await mkdtemp(join(tmpdir(),'tj-31b-'));t.after(()=>rm(base,{recursive:true,force:true}));
 const directory=join(base,'registry'),journalDir=join(base,'journal'),coordDir=join(base,'coord');
 const secret=randomBytes(32),assetKey=randomBytes(32),{publicKey,privateKey}=generateKeyPairSync('ed25519');
 const {publicKey:independentPublic,privateKey:independentPrivate}=generateKeyPairSync('ed25519');
 let registryAnchor=null,journalAnchor=null,coordFault,journalFault,registryFault,registryCas=true,journalCas=true;
 const readRegistryAnchor=async()=>structuredClone(registryAnchor),readJournalAnchor=async()=>structuredClone(journalAnchor);
 const registry=createOfflinePrivateRevisionRegistry({directory,secret,readAnchor:readRegistryAnchor,
  recovery:{registryId,publicKey:independentPublic},injectFault:async stage=>{if(registryFault)await registryFault(stage);},
  compareAndSetAnchor:async(old,next)=>{if(!registryCas||JSON.stringify(registryAnchor)!==JSON.stringify(old))return false;registryAnchor=structuredClone(next);return true;},
  encryption:{activeKeyId:'objective31b-encryption-key',resolveKey:()=>assetKey},
  verifyArtworkAccess:async token=>token===session?{shop,ownerId:'owner-1',issuedAt:Date.now()-1000,expiresAt:Date.now()+60000}:null,
  mutationAuthorization:{registryId,publicKey},
  adminAuthorization:{registryId,publicKey,verifyOperator:async(token,action)=>token===operator&&['export-audit','export-backup','restore-backup'].includes(action)?{operatorId:'operator-31b',issuedAt:Date.now()-1000,expiresAt:Date.now()+60000}:null}
 });
 const mutation=(action,request)=>{const now=Date.now(),body={schema:mutationSchema,registryId,action,opId:request.opId,shop,ownerId:'owner-1',requestSha256:computePrivateRegistryMutationDigest(action,request),issuedAt:now-1000,expiresAt:now+60000};return{sessionToken:session,permit:signBody(mutationSchema,mutationFields,body,privateKey),request};};
 const admin=(action,request)=>{const now=Date.now(),body={schema:adminSchema,registryId,action,opId:request.opId,operatorId:'operator-31b',requestSha256:computePrivateRegistryBackupDigest(action,request),issuedAt:now-1000,expiresAt:now+60000};return{operatorToken:operator,permit:signBody(adminSchema,adminFields,body,privateKey),request};};
 const auditEnvelope=async expectedAnchor=>admin('export-audit',{opId:id(),expectedAnchor});
 const journal=()=>createOfflineAnchoredAuditJournal({directory:journalDir,registry,registryId,readJournalAnchor,
  compareAndSetJournalAnchor:async(old,next)=>{if(!journalCas||JSON.stringify(journalAnchor)!==JSON.stringify(old))return false;journalAnchor=structuredClone(next);return true;},
  readRegistryAnchor,recovery:{registryId,publicKey:independentPublic},injectFault:journalFault});
 const coordinator=()=>createOfflineAuditedRegistryCoordinator({directory:coordDir,registry,journal:journal(),registryId,readRegistryAnchor,readJournalAnchor,
  recovery:{publicKey:independentPublic},injectFault:coordFault});
 const permit=(action,expectedJournalAnchor,expectedRegistryAnchor,targetRegistryAnchor,changes={})=>{const now=Date.now(),body={schema:coordinatorSchema,registryId,action,authorizationId:id(),issuedAt:now-1000,expiresAt:now+60000,expectedJournalAnchor,expectedRegistryAnchor,targetRegistryAnchor,reason:'Independently inspected exact offline registry transition',...changes};return signBody(coordinatorSchema,coordinatorFields,body,independentPrivate);};
 const registryPermit=(expected,target,changes={})=>{const now=Date.now(),body={schema:registryRecoverySchema,registryId,authorizationId:id(),issuedAt:now-1000,expiresAt:now+60000,expectedAnchor:expected,targetAnchor:target,reason:'Independent inspection of registry state and predecessor',...changes};return signBody(registryRecoverySchema,registryRecoveryFields,body,independentPrivate);};
 const journalPermit=(expected,target,changes={})=>{const now=Date.now(),body={schema:journalRecoverySchema,registryId,authorizationId:id(),issuedAt:now-1000,expiresAt:now+60000,expectedJournalAnchor:expected,targetJournalAnchor:target,reason:'Independently inspected pending audit journal event',...changes};return signBody(journalRecoverySchema,journalFields,body,independentPrivate);};
 const execute=(action,request)=>coordinator().execute({action,envelope:mutation(action==='commitAuthenticatedRevision'?'commit-revision':action==='revokeAuthenticatedArtwork'?'revoke-artwork':'revoke-revision',request),auditEnvelope});
 const commit=(revision=1)=>execute('commitAuthenticatedRevision',commitRequest(revision));
 const revoke=()=>execute('revokeAuthenticatedArtwork',revokeRequest());
 return {base,directory,journalDir,coordDir,registry,journal,coordinator,permit,journalPermit,registryPermit,auditEnvelope,admin,mutation,commit,revoke,execute,
  getR:()=>structuredClone(registryAnchor),getJ:()=>structuredClone(journalAnchor),setCoordFault:x=>{coordFault=x;},setJournalFault:x=>{journalFault=x;},setRegistryFault:x=>{registryFault=x;},setRegistryCas:x=>{registryCas=x;},setJournalCas:x=>{journalCas=x;},file:n=>join(journalDir,`${String(n).padStart(10,'0')}.json`)};
}

test('31B signed authenticated initial commit atomically observed in normal path',async t=>{const f=await fixture(t);const result=await f.commit();assert.equal(result.result.revision,1);assert.equal((await f.coordinator().inspect()).eventCount,1);assert.deepEqual(result.registryAnchor,f.getR());assert.deepEqual(result.journalAnchor,f.getJ());});
test('31B sequential signed revision and artwork revocation preserve chain',async t=>{const f=await fixture(t);await f.commit();await f.commit(2);await f.revoke();const x=await f.coordinator().inspect();assert.equal(x.eventCount,3);assert.equal(x.registryAnchor.sequence,3);const e=JSON.parse(await readFile(f.file(3)));assert.equal(e.revocationCount,1);assert.equal(e.coverage,'CONTIGUOUS_OBSERVATION');});
test('31B concurrent authenticated writers serialize across separate coordinator instances',async t=>{const f=await fixture(t);await f.commit();const a=commitRequest(2),b=commitRequest(2);const settled=await Promise.allSettled([f.execute('commitAuthenticatedRevision',a),f.execute('commitAuthenticatedRevision',b)]);assert.equal(settled.filter(x=>x.status==='fulfilled').length,1);assert.equal(settled.filter(x=>x.reason?.code==='REGISTRY_STALE_REVISION').length,1);assert.equal((await f.coordinator().inspect()).eventCount,2);});
test('31B invalid action and missing signed audit provider never mutate',async t=>{const f=await fixture(t);await rejects(f.coordinator().execute({action:'commitRevision',envelope:{},auditEnvelope:f.auditEnvelope}),'COORDINATOR_ACTION_DENIED');await rejects(f.coordinator().execute({action:'commitAuthenticatedRevision',envelope:f.mutation('commit-revision',commitRequest())}),'COORDINATOR_ACTION_DENIED');assert.equal(f.getR(),null);});
test('31B unsigned authenticated registry mutation is rejected without audit event',async t=>{const f=await fixture(t);await rejects(f.coordinator().execute({action:'commitAuthenticatedRevision',envelope:{},auditEnvelope:f.auditEnvelope}),'REGISTRY_MUTATION_DENIED');assert.equal(f.getR(),null);assert.equal((await f.coordinator().inspect()).eventCount,0);});
test('31B after registry commit crash blocks further writes until independent signed reconciliation',async t=>{const f=await fixture(t);f.setCoordFault(stage=>{if(stage==='after-registry-commit')throw Error('crash-after-registry-commit');});await assert.rejects(f.commit(),/crash-after-registry-commit/);f.setCoordFault(undefined);await rejects(f.commit(2),'COORDINATOR_BOOTSTRAP_REQUIRED');const target=f.getR();const p=f.permit('reconcile-registry-gap',null,null,target);assert.equal((await f.coordinator().reconcile({authorization:p,auditEnvelope:f.auditEnvelope})).reconciled,true);assert.equal((await f.coordinator().inspect()).eventCount,1);await f.commit(2);assert.equal((await f.coordinator().inspect()).eventCount,2);});
test('31B signed reconciliation is one-time and cannot replay',async t=>{const f=await fixture(t);f.setCoordFault(()=>{throw Error('crash');});await assert.rejects(f.commit());f.setCoordFault(undefined);const p=f.permit('reconcile-registry-gap',null,null,f.getR());await f.coordinator().reconcile({authorization:p,auditEnvelope:f.auditEnvelope});await rejects(f.coordinator().reconcile({authorization:p,auditEnvelope:f.auditEnvelope}),'COORDINATOR_RECOVERY_STATE_MISMATCH');});
test('31B forged recovery signature rejected, no journal advancement',async t=>{const f=await fixture(t);f.setCoordFault(()=>{throw Error('crash');});await assert.rejects(f.commit());f.setCoordFault(undefined);const p=f.permit('reconcile-registry-gap',null,null,f.getR());p.reason='tampered justification';await rejects(f.coordinator().reconcile({authorization:p,auditEnvelope:f.auditEnvelope}),'COORDINATOR_RECOVERY_DENIED');assert.equal(f.getJ(),null);});
test('31B expired independent recovery permit rejected',async t=>{const f=await fixture(t);f.setCoordFault(()=>{throw Error('crash');});await assert.rejects(f.commit());f.setCoordFault(undefined);const p=f.permit('reconcile-registry-gap',null,null,f.getR(),{expiresAt:Date.now()-1});await rejects(f.coordinator().reconcile({authorization:p,auditEnvelope:f.auditEnvelope}),'COORDINATOR_RECOVERY_DENIED');});
test('31B substituted signed recovery target rejected against current independent anchor',async t=>{const f=await fixture(t);f.setCoordFault(()=>{throw Error('crash');});await assert.rejects(f.commit());f.setCoordFault(undefined);const p=f.permit('reconcile-registry-gap',null,null,{sequence:1,mac:'a'.repeat(64)});await rejects(f.coordinator().reconcile({authorization:p,auditEnvelope:f.auditEnvelope}),'COORDINATOR_RECOVERY_STATE_MISMATCH');});
test('31B registry mutation skipped outside coordinator is detected and next coordinated write blocked',async t=>{const f=await fixture(t);await f.commit();await f.registry.revokeAuthenticatedArtwork(f.mutation('revoke-artwork',revokeRequest()));await rejects(f.commit(2),'COORDINATOR_REGISTRY_GAP');assert.equal((await f.journal().verify()).eventCount,1);});
test('31B external registry mutation can only be reconciled with independently signed one-step permit',async t=>{const f=await fixture(t);await f.commit();const prior=f.getR(),priorJ=f.getJ();await f.registry.revokeAuthenticatedArtwork(f.mutation('revoke-artwork',revokeRequest()));await rejects(f.coordinator().inspect(),'COORDINATOR_REGISTRY_GAP');await f.coordinator().reconcile({authorization:f.permit('reconcile-registry-gap',priorJ,prior,f.getR()),auditEnvelope:f.auditEnvelope});assert.equal((await f.coordinator().inspect()).eventCount,2);});
test('31B two skipped registry mutations cannot be falsely reconciled as contiguous',async t=>{const f=await fixture(t);await f.commit();const prior=f.getR(),priorJ=f.getJ();await f.registry.revokeAuthenticatedArtwork(f.mutation('revoke-artwork',revokeRequest()));const r=record(1);await f.registry.revokeAuthenticatedRevision(f.mutation('revoke-revision',{identity:Object.fromEntries(['shop','productGid','variantGid','ownerId','designId','revision'].map(k=>[k,r[k]])),opId:id()}));await rejects(f.coordinator().reconcile({authorization:f.permit('reconcile-registry-gap',priorJ,prior,f.getR()),auditEnvelope:f.auditEnvelope}),'COORDINATOR_RECOVERY_STATE_MISMATCH');});
test('31B interrupted journal file write blocks further coordinated mutations',async t=>{const f=await fixture(t);f.setJournalFault(stage=>{if(stage==='after-event-file')throw Error('journal-crash');});await assert.rejects(f.commit(),/journal-crash/);f.setJournalFault(undefined);await rejects(f.commit(2),'AUDIT_ANCHOR_MISMATCH');assert.equal(f.getJ(),null);});
test('31B independently signed pending journal recovery restores two-anchor continuity',async t=>{const f=await fixture(t);f.setJournalFault(()=>{throw Error('journal-crash');});await assert.rejects(f.commit());f.setJournalFault(undefined);const e=JSON.parse(await readFile(f.file(1)));const target={index:1,digest:e.digest};const result=await f.coordinator().recoverJournal({authorization:f.journalPermit(null,target)});assert.equal(result.result,'recovered');await f.commit(2);assert.equal((await f.coordinator().inspect()).eventCount,2);});
test('31B tampered pending journal event cannot be independently recovered',async t=>{const f=await fixture(t);f.setJournalFault(()=>{throw Error('journal-crash');});await assert.rejects(f.commit());f.setJournalFault(undefined);const e=JSON.parse(await readFile(f.file(1)));const target={index:1,digest:e.digest};e.operationCount+=2;await writeFile(f.file(1),JSON.stringify(e));await rejects(f.coordinator().recoverJournal({authorization:f.journalPermit(null,target)}),'AUDIT_EVENT_TAMPERED');});
test('31B crash after fully anchored audit returns error but state remains synced on restart',async t=>{const f=await fixture(t);f.setCoordFault(stage=>{if(stage==='after-journal-append')throw Error('post-audit-crash');});await assert.rejects(f.commit(),/post-audit-crash/);f.setCoordFault(undefined);assert.equal((await f.coordinator().inspect()).eventCount,1);await f.commit(2);assert.equal((await f.coordinator().inspect()).eventCount,2);});
test('31B legacy existing registry requires explicit independently signed bootstrap',async t=>{const f=await fixture(t);await f.registry.commitAuthenticatedRevision(f.mutation('commit-revision',commitRequest()));await rejects(f.coordinator().inspect(),'COORDINATOR_BOOTSTRAP_REQUIRED');await rejects(f.commit(2),'COORDINATOR_BOOTSTRAP_REQUIRED');const p=f.permit('bootstrap-unproven-history',null,null,f.getR());const result=await f.coordinator().bootstrap({authorization:p,auditEnvelope:f.auditEnvelope});assert.equal(result.historyBeforeBootstrapProven,false);assert.equal((await f.coordinator().inspect()).eventCount,1);await f.commit(2);});
test('31B bootstrap cannot be repeated or claim earlier history',async t=>{const f=await fixture(t);await f.registry.commitAuthenticatedRevision(f.mutation('commit-revision',commitRequest()));const p=f.permit('bootstrap-unproven-history',null,null,f.getR());await f.coordinator().bootstrap({authorization:p,auditEnvelope:f.auditEnvelope});await rejects(f.coordinator().bootstrap({authorization:p,auditEnvelope:f.auditEnvelope}),'COORDINATOR_BOOTSTRAP_DENIED');const e=JSON.parse(await readFile(f.file(1)));assert.equal(e.coverage,'BOOTSTRAP_UNPROVEN_PRIOR_HISTORY');});
test('31B journal anchor CAS conflict requires signed pending-event recovery',async t=>{const f=await fixture(t);f.setJournalCas(false);await rejects(f.commit(),'AUDIT_ANCHOR_CONFLICT');f.setJournalCas(true);const e=JSON.parse(await readFile(f.file(1)));await f.coordinator().recoverJournal({authorization:f.journalPermit(null,{index:1,digest:e.digest})});assert.equal((await f.coordinator().inspect()).eventCount,1);});
test('31B registry anchor CAS conflict never produces falsely anchored journal',async t=>{const f=await fixture(t);f.setRegistryCas(false);await rejects(f.commit(),'REGISTRY_ANCHOR_CONFLICT');assert.equal(f.getJ(),null);assert.equal((await f.journal().verify()).eventCount,0);});
test('31B wrong independent public key cannot authorize reconciliation',async t=>{const f=await fixture(t);f.setCoordFault(()=>{throw Error('crash');});await assert.rejects(f.commit());f.setCoordFault(undefined);const {publicKey}=generateKeyPairSync('ed25519');const wrong=createOfflineAuditedRegistryCoordinator({directory:f.coordDir,registry:f.registry,journal:f.journal(),registryId,readRegistryAnchor:async()=>f.getR(),readJournalAnchor:async()=>f.getJ(),recovery:{publicKey}});await rejects(wrong.reconcile({authorization:f.permit('reconcile-registry-gap',null,null,f.getR()),auditEnvelope:f.auditEnvelope}),'COORDINATOR_RECOVERY_DENIED');});
test('31B lock file with unsafe permissions is refused before mutation',async t=>{const f=await fixture(t);await f.coordinator().inspect();await chmod(join(f.coordDir,'.audited-registry-coordinator-lock'),0o644);await rejects(f.commit(),'COORDINATOR_LOCK_UNSAFE');assert.equal(f.getR(),null);});
test('31B cross-process held coordinator flock prevents concurrent mutation',async t=>{
 const f=await fixture(t);await f.coordinator().inspect();const path=join(f.coordDir,'.audited-registry-coordinator-lock');
 const child=spawn('/usr/bin/flock',['-x',path,'sleep','2'],{stdio:['ignore','ignore','ignore']});
 try{await new Promise(r=>setTimeout(r,250));await rejects(f.commit(),'COORDINATOR_LOCK_UNAVAILABLE');assert.equal(f.getR(),null);}finally{child.kill();await new Promise(r=>child.once('close',r));}
});
test('31B authenticated backup restore is coordinated as contiguous registry audit event',async t=>{
 const f=await fixture(t);await f.commit();const backup=await f.registry.exportAuthenticatedBackup(f.admin('export-backup',{opId:id(),expectedAnchor:f.getR()}));
 await unlink(join(f.directory,'private-registry.json'));
 const request={opId:id(),expectedAnchor:backup.anchor,backupSha256:backup.sha256};
 const out=await f.coordinator().execute({action:'restoreAuthenticatedBackup',envelope:{...f.admin('restore-backup',request),backup},auditEnvelope:f.auditEnvelope});
 assert.equal(out.result.restored,true);assert.equal((await f.coordinator().inspect()).eventCount,2);
});
test('31B recovery request without audit authority fails closed and leaves one-step gap',async t=>{const f=await fixture(t);f.setCoordFault(()=>{throw Error('crash');});await assert.rejects(f.commit());f.setCoordFault(undefined);const p=f.permit('reconcile-registry-gap',null,null,f.getR());await rejects(f.coordinator().reconcile({authorization:p,auditEnvelope:async()=>({})}),'REGISTRY_AUDIT_DENIED');assert.equal(f.getJ(),null);});

test('31B signed registry recovery after rename-before-anchor crash is journaled without inventing intermediate state',async t=>{
 const f=await fixture(t);await f.commit();const prior=f.getR();
 f.setRegistryFault(stage=>{if(stage==='after-rename')throw Error('registry-rename-crash');});
 await assert.rejects(f.revoke(),/registry-rename-crash/);f.setRegistryFault(undefined);
 assert.deepEqual(f.getR(),prior);assert.equal((await f.coordinator().inspect()).eventCount,1);
 await rejects(f.commit(2),'REGISTRY_ROLLBACK');
 const pending=JSON.parse(await readFile(join(f.directory,'private-registry.json')));
 const target={sequence:pending.sequence,mac:pending.mac};
 const result=await f.coordinator().execute({action:'recoverInterruptedRegistry',envelope:{authorization:f.registryPermit(prior,target)},auditEnvelope:f.auditEnvelope});
 assert.equal(result.result,'recovered');assert.equal((await f.coordinator().inspect()).eventCount,2);
 assert.equal(JSON.parse(await readFile(f.file(2))).revocationCount,1);
});
test('31B forged registry recovery signature cannot create a journal entry',async t=>{
 const f=await fixture(t);await f.commit();const prior=f.getR();
 f.setRegistryFault(stage=>{if(stage==='after-rename')throw Error('crash');});await assert.rejects(f.revoke());f.setRegistryFault(undefined);
 const pending=JSON.parse(await readFile(join(f.directory,'private-registry.json')));
 const p=f.registryPermit(prior,{sequence:pending.sequence,mac:pending.mac});p.reason='substituted recovery evidence';
 await rejects(f.coordinator().execute({action:'recoverInterruptedRegistry',envelope:{authorization:p},auditEnvelope:f.auditEnvelope}),'REGISTRY_RECOVERY_SIGNATURE');
 assert.equal((await f.journal().verify()).eventCount,1);
});
test('31B post-recovery pre-journal crash requires independently signed second-anchor reconciliation',async t=>{
 const f=await fixture(t);await f.commit();const prior=f.getR(),priorJ=f.getJ();
 f.setRegistryFault(stage=>{if(stage==='after-rename')throw Error('crash');});await assert.rejects(f.revoke());f.setRegistryFault(undefined);
 const pending=JSON.parse(await readFile(join(f.directory,'private-registry.json')));
 const target={sequence:pending.sequence,mac:pending.mac};
 f.setCoordFault(stage=>{if(stage==='after-registry-commit')throw Error('crash-after-registry-recovery');});
 await assert.rejects(f.coordinator().execute({action:'recoverInterruptedRegistry',envelope:{authorization:f.registryPermit(prior,target)},auditEnvelope:f.auditEnvelope}));
 f.setCoordFault(undefined);await rejects(f.commit(2),'COORDINATOR_REGISTRY_GAP');
 await f.coordinator().reconcile({authorization:f.permit('reconcile-registry-gap',priorJ,prior,target),auditEnvelope:f.auditEnvelope});
 assert.equal((await f.coordinator().inspect()).eventCount,2);
});
