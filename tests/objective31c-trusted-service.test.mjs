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
import {createOfflineAuditedRegistryService} from '../src/offline-audited-registry-service.mjs';
import {createOfflineDurableAnchorAdapter} from '../src/offline-durable-anchor-adapter.mjs';

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
 const registryOptions={directory,secret,readAnchor:readRegistryAnchor,
  recovery:{registryId,publicKey:independentPublic},injectFault:async stage=>{if(registryFault)await registryFault(stage);},
  compareAndSetAnchor:async(old,next)=>{if(!registryCas||JSON.stringify(registryAnchor)!==JSON.stringify(old))return false;registryAnchor=structuredClone(next);return true;},
  encryption:{activeKeyId:'objective31b-encryption-key',resolveKey:()=>assetKey},
  verifyArtworkAccess:async token=>token===session?{shop,ownerId:'owner-1',issuedAt:Date.now()-1000,expiresAt:Date.now()+60000}:null,
  mutationAuthorization:{registryId,publicKey},
  adminAuthorization:{registryId,publicKey,verifyOperator:async(token,action)=>token===operator&&['export-audit','export-backup','restore-backup'].includes(action)?{operatorId:'operator-31b',issuedAt:Date.now()-1000,expiresAt:Date.now()+60000}:null}
 };
 const registry=createOfflinePrivateRevisionRegistry(registryOptions);
 const mutation=(action,request)=>{const now=Date.now(),body={schema:mutationSchema,registryId,action,opId:request.opId,shop,ownerId:'owner-1',requestSha256:computePrivateRegistryMutationDigest(action,request),issuedAt:now-1000,expiresAt:now+60000};return{sessionToken:session,permit:signBody(mutationSchema,mutationFields,body,privateKey),request};};
 const admin=(action,request)=>{const now=Date.now(),body={schema:adminSchema,registryId,action,opId:request.opId,operatorId:'operator-31b',requestSha256:computePrivateRegistryBackupDigest(action,request),issuedAt:now-1000,expiresAt:now+60000};return{operatorToken:operator,permit:signBody(adminSchema,adminFields,body,privateKey),request};};
 const auditEnvelope=async expectedAnchor=>admin('export-audit',{opId:id(),expectedAnchor});
 const journalOptions={directory:journalDir,registryId,readJournalAnchor,
  compareAndSetJournalAnchor:async(old,next)=>{if(!journalCas||JSON.stringify(journalAnchor)!==JSON.stringify(old))return false;journalAnchor=structuredClone(next);return true;},
  readRegistryAnchor,recovery:{registryId,publicKey:independentPublic},injectFault:undefined};
 const coordinatorOptions={directory:coordDir,registryId,readRegistryAnchor,readJournalAnchor,recovery:{publicKey:independentPublic}};
 const journal=()=>createOfflineAnchoredAuditJournal({...journalOptions,registry});
 const coordinator=()=>createOfflineAuditedRegistryCoordinator({...coordinatorOptions,registry,journal:journal()});
 const service=()=>createOfflineAuditedRegistryService({registryOptions,journalOptions,coordinatorOptions});
 const permit=(action,expectedJournalAnchor,expectedRegistryAnchor,targetRegistryAnchor,changes={})=>{const now=Date.now(),body={schema:coordinatorSchema,registryId,action,authorizationId:id(),issuedAt:now-1000,expiresAt:now+60000,expectedJournalAnchor,expectedRegistryAnchor,targetRegistryAnchor,reason:'Independently inspected exact offline registry transition',...changes};return signBody(coordinatorSchema,coordinatorFields,body,independentPrivate);};
 const registryPermit=(expected,target,changes={})=>{const now=Date.now(),body={schema:registryRecoverySchema,registryId,authorizationId:id(),issuedAt:now-1000,expiresAt:now+60000,expectedAnchor:expected,targetAnchor:target,reason:'Independent inspection of registry state and predecessor',...changes};return signBody(registryRecoverySchema,registryRecoveryFields,body,independentPrivate);};
 const journalPermit=(expected,target,changes={})=>{const now=Date.now(),body={schema:journalRecoverySchema,registryId,authorizationId:id(),issuedAt:now-1000,expiresAt:now+60000,expectedJournalAnchor:expected,targetJournalAnchor:target,reason:'Independently inspected pending audit journal event',...changes};return signBody(journalRecoverySchema,journalFields,body,independentPrivate);};
 const execute=(action,request)=>coordinator().execute({action,envelope:mutation(action==='commitAuthenticatedRevision'?'commit-revision':action==='revokeAuthenticatedArtwork'?'revoke-artwork':'revoke-revision',request),auditEnvelope});
 const commit=(revision=1)=>execute('commitAuthenticatedRevision',commitRequest(revision));
 const revoke=()=>execute('revokeAuthenticatedArtwork',revokeRequest());
 return {base,directory,journalDir,coordDir,registry,registryOptions,journalOptions,coordinatorOptions,service,journal,coordinator,permit,journalPermit,registryPermit,auditEnvelope,admin,mutation,commit,revoke,execute,
  getR:()=>structuredClone(registryAnchor),getJ:()=>structuredClone(journalAnchor),setCoordFault:x=>{coordFault=x;},setJournalFault:x=>{journalFault=x;},setRegistryFault:x=>{registryFault=x;},setRegistryCas:x=>{registryCas=x;},setJournalCas:x=>{journalCas=x;},file:n=>join(journalDir,`${String(n).padStart(10,'0')}.json`)};
}

const artRequest=()=>({shop,productGid:pid,variantGid:vid,ownerId:'owner-1',designId:'design-1',revision:1,storageKey:'PrivateArtwork31b1000',artworkId:'art-A',layerId:'layer-A'});
const commitThroughService=(f,revision=1)=>f.service().mutate({action:'commitAuthenticatedRevision',envelope:f.mutation('commit-revision',commitRequest(revision)),auditEnvelope:f.auditEnvelope});

test('31C service exposes only explicit authenticated operations and no raw registry/journal',async t=>{
 const f=await fixture(t),s=f.service();
 assert.equal(Object.isFrozen(s),true);
 assert.deepEqual(Object.keys(s).sort(),['bootstrap','exportBackup','inspect','mutate','readArtwork','reconcile','recoverJournal'].sort());
 for(const key of ['registry','journal','coordinator','commitRevision','revokeArtwork','readPrivateArtwork','exportAuthenticatedAudit'])assert.equal(s[key],undefined);
 await rejects(s.mutate({action:'commitRevision',envelope:{},auditEnvelope:f.auditEnvelope}),'AUDITED_SERVICE_ACTION_DENIED');
 assert.equal(f.getR(),null);
});
test('31C service rejects absent authentication, encryption, recovery and inconsistent anchor wiring',async t=>{
 const f=await fixture(t),opts={registryOptions:f.registryOptions,journalOptions:f.journalOptions,coordinatorOptions:f.coordinatorOptions};
 for(const bad of [
  {...opts,registryOptions:{...opts.registryOptions,mutationAuthorization:undefined}},
  {...opts,registryOptions:{...opts.registryOptions,verifyArtworkAccess:undefined}},
  {...opts,registryOptions:{...opts.registryOptions,encryption:undefined}},
  {...opts,registryOptions:{...opts.registryOptions,adminAuthorization:undefined}},
  {...opts,journalOptions:{...opts.journalOptions,registry:f.registry}},
  {...opts,coordinatorOptions:{...opts.coordinatorOptions,registry:f.registry}},
  {...opts,coordinatorOptions:{...opts.coordinatorOptions,journal:f.journal()}},
  {...opts,coordinatorOptions:{...opts.coordinatorOptions,readRegistryAnchor:async()=>null}},
  {...opts,journalOptions:{...opts.journalOptions,readJournalAnchor:async()=>null}},
  {...opts,journalOptions:{...opts.journalOptions,registryId:'another-registry'}},
  {...opts,rawRegistry:f.registry}
 ])assert.throws(()=>createOfflineAuditedRegistryService(bad),e=>e.code==='AUDITED_SERVICE_CONFIGURATION');
});
test('31C service signed commit is journaled; authenticated artwork read returns exact bytes',async t=>{
 const f=await fixture(t),s=f.service();await commitThroughService(f);
 assert.equal((await s.inspect()).eventCount,1);
 const b=await s.readArtwork({sessionToken:session,request:artRequest()});assert.deepEqual(b,png());
 b[0]^=0xff;assert.deepEqual(await s.readArtwork({sessionToken:session,request:artRequest()}),png());
});
test('31C unauthenticated artwork read cannot cross owner or expose raw storage',async t=>{
 const f=await fixture(t),s=f.service();await commitThroughService(f);
 await rejects(s.readArtwork({sessionToken:'invalid-identity-token',request:artRequest()}),'REGISTRY_ACCESS_DENIED');
 await rejects(s.readArtwork({sessionToken:session,request:{...artRequest(),ownerId:'other-owner'}}),'REGISTRY_ACCESS_DENIED');
 await rejects(s.readArtwork({sessionToken:session,request:{...artRequest(),variantGid:'gid://shopify/ProductVariant/777'}}),'REGISTRY_ARTWORK_UNAVAILABLE');
});
test('31C signed encrypted backup is read-only and requires operator authority',async t=>{
 const f=await fixture(t),s=f.service();await commitThroughService(f);
 const a=f.getR(),backup=await s.exportBackup(f.admin('export-backup',{opId:id(),expectedAnchor:a}));
 assert.equal(backup.anchor.mac,a.mac);assert.equal(backup.assetCount,1);
 await rejects(s.exportBackup({}),'REGISTRY_BACKUP_DENIED');assert.equal((await s.inspect()).eventCount,1);
});
test('31C direct raw writer bypass creates detectable gap and blocks all facade reads',async t=>{
 const f=await fixture(t),s=f.service();await commitThroughService(f);
 await f.registry.revokeAuthenticatedArtwork(f.mutation('revoke-artwork',revokeRequest()));
 await rejects(s.inspect(),'COORDINATOR_REGISTRY_GAP');
 await rejects(s.readArtwork({sessionToken:session,request:artRequest()}),'COORDINATOR_REGISTRY_GAP');
 await rejects(s.exportBackup(f.admin('export-backup',{opId:id(),expectedAnchor:f.getR()})),'COORDINATOR_REGISTRY_GAP');
 await rejects(commitThroughService(f,2),'COORDINATOR_REGISTRY_GAP');
});
test('31C one-step external writer gap requires independent exact-head signed reconciliation',async t=>{
 const f=await fixture(t),s=f.service();await commitThroughService(f);const prior=f.getR(),priorJ=f.getJ();
 await f.registry.revokeAuthenticatedArtwork(f.mutation('revoke-artwork',revokeRequest()));
 const target=f.getR();await rejects(s.reconcile({authorization:f.permit('reconcile-registry-gap',priorJ,prior,{...target,mac:'a'.repeat(64)}),auditEnvelope:f.auditEnvelope}),'COORDINATOR_RECOVERY_STATE_MISMATCH');
 const p=f.permit('reconcile-registry-gap',priorJ,prior,target);
 assert.equal((await s.reconcile({authorization:p,auditEnvelope:f.auditEnvelope})).reconciled,true);
 assert.equal((await s.inspect()).eventCount,2);
 await rejects(s.readArtwork({sessionToken:session,request:artRequest()}),'REGISTRY_ARTWORK_UNAVAILABLE');
 await rejects(s.reconcile({authorization:p,auditEnvelope:f.auditEnvelope}),'COORDINATOR_RECOVERY_STATE_MISMATCH');
});
test('31C multi-step external writer gap is not falsely reconciled',async t=>{
 const f=await fixture(t),s=f.service();await commitThroughService(f);const prior=f.getR(),priorJ=f.getJ();
 await f.registry.revokeAuthenticatedArtwork(f.mutation('revoke-artwork',revokeRequest()));
 await f.registry.commitAuthenticatedRevision(f.mutation('commit-revision',commitRequest(2)));
 await rejects(s.reconcile({authorization:f.permit('reconcile-registry-gap',priorJ,prior,f.getR()),auditEnvelope:f.auditEnvelope}),'COORDINATOR_RECOVERY_STATE_MISMATCH');
 await rejects(s.inspect(),'COORDINATOR_REGISTRY_GAP');
});
test('31C journal tampering blocks facade reads despite valid registry anchor',async t=>{
 const f=await fixture(t),s=f.service();await commitThroughService(f);
 const path=f.file(1),event=JSON.parse(await readFile(path));event.operationCount+=1;await writeFile(path,JSON.stringify(event));
 await rejects(s.readArtwork({sessionToken:session,request:artRequest()}),'AUDIT_EVENT_TAMPERED');
 await rejects(s.exportBackup(f.admin('export-backup',{opId:id(),expectedAnchor:f.getR()})),'AUDIT_EVENT_TAMPERED');
});
test('31C signed but invalid mutation leaves both anchors unchanged',async t=>{
 const f=await fixture(t),s=f.service();await rejects(s.mutate({action:'commitAuthenticatedRevision',envelope:{},auditEnvelope:f.auditEnvelope}),'REGISTRY_MUTATION_DENIED');
 assert.equal(f.getR(),null);assert.equal(f.getJ(),null);
});
test('31C service crash between registry and journal requires signed reconciliation before read',async t=>{
 const f=await fixture(t),s=f.service();f.setRegistryFault(undefined);
 const crashed=createOfflineAuditedRegistryCoordinator({...f.coordinatorOptions,registry:f.registry,journal:f.journal(),injectFault:stage=>{if(stage==='after-registry-commit')throw Error('synthetic-crash');}});
 await assert.rejects(crashed.execute({action:'commitAuthenticatedRevision',envelope:f.mutation('commit-revision',commitRequest()),auditEnvelope:f.auditEnvelope}),/synthetic-crash/);
 await rejects(s.readArtwork({sessionToken:session,request:artRequest()}),'COORDINATOR_BOOTSTRAP_REQUIRED');
 const p=f.permit('reconcile-registry-gap',null,null,f.getR());await s.reconcile({authorization:p,auditEnvelope:f.auditEnvelope});
 assert.deepEqual(await s.readArtwork({sessionToken:session,request:artRequest()}),png());
});
test('31C forged audit provider cannot silently authorize new registry mutation',async t=>{
 const f=await fixture(t),s=f.service();
 await rejects(s.mutate({action:'commitAuthenticatedRevision',envelope:f.mutation('commit-revision',commitRequest()),auditEnvelope:async()=>({})}),'REGISTRY_AUDIT_DENIED');
 assert.equal(f.getJ(),null);await rejects(s.inspect(),'COORDINATOR_BOOTSTRAP_REQUIRED');
});

// Two independent external anchor files survive reconstruction of the service.
// This is a disposable fixture, not a durable production CAS service.
async function externalAnchors(f){
 const rPath=join(f.base,'external-registry-anchor.json'),jPath=join(f.base,'external-journal-anchor.json');
 const read=path=>readFile(path,'utf8').then(JSON.parse,e=>{if(e.code==='ENOENT')return null;throw e;});
 const cas=path=>async(old,next)=>{
  if(JSON.stringify(await read(path))!==JSON.stringify(old))return false;
  const tmp=path+'.tmp-'+process.pid+'-'+randomBytes(4).toString('hex');
  await writeFile(tmp,JSON.stringify(next),{mode:0o600});
  const {rename}=await import('node:fs/promises');await rename(tmp,path);return true;
 };
 const readR=()=>read(rPath),readJ=()=>read(jPath);
 const registryOptions={...f.registryOptions,readAnchor:readR,compareAndSetAnchor:cas(rPath)};
 const journalOptions={...f.journalOptions,readRegistryAnchor:readR,readJournalAnchor:readJ,compareAndSetJournalAnchor:cas(jPath)};
 const coordinatorOptions={...f.coordinatorOptions,readRegistryAnchor:readR,readJournalAnchor:readJ};
 return {rPath,jPath,readR,readJ,registryOptions,journalOptions,coordinatorOptions,
  service:()=>createOfflineAuditedRegistryService({registryOptions,journalOptions,coordinatorOptions})};
}
test('31C independent external journal anchor rollback blocks signed reads and writes',async t=>{
 const f=await fixture(t),x=await externalAnchors(f),s=x.service();
 await s.mutate({action:'commitAuthenticatedRevision',envelope:f.mutation('commit-revision',commitRequest()),auditEnvelope:f.auditEnvelope});
 const original=await x.readJ();assert.equal((await s.inspect()).eventCount,1);
 await writeFile(x.jPath,JSON.stringify({index:1,digest:'a'.repeat(64)}));
 await assert.rejects(s.inspect());
 await assert.rejects(s.readArtwork({sessionToken:session,request:artRequest()}));
 await writeFile(x.jPath,JSON.stringify(original));
 assert.equal((await x.service().inspect()).eventCount,1);
});
test('31C real child process exit after registry commit leaves persistent one-step gap requiring signed recovery',async t=>{
 const f=await fixture(t),x=await externalAnchors(f),s=x.service();
 await s.mutate({action:'commitAuthenticatedRevision',envelope:f.mutation('commit-revision',commitRequest()),auditEnvelope:f.auditEnvelope});
 const beforeR=await x.readR(),beforeJ=await x.readJ();
 const config={base:f.base,registryId,shop,session,operator,
  secret:f.registryOptions.secret.toString('base64'),assetKey:f.registryOptions.encryption.resolveKey().toString('base64'),
  issuerPublic:f.registryOptions.mutationAuthorization.publicKey.export({type:'spki',format:'pem'}),
  independentPublic:f.registryOptions.recovery.publicKey.export({type:'spki',format:'pem'}),
  envelope:f.mutation('revoke-artwork',revokeRequest())};
 const configPath=join(f.base,'child-fixture.json');await writeFile(configPath,JSON.stringify(config),{mode:0o600});
 const {spawnSync}=await import('node:child_process');
 const child=spawnSync(process.execPath,[new URL('./fixtures/objective31c-crash-child.mjs',import.meta.url).pathname,configPath],{encoding:'utf8',timeout:10000});
 assert.equal(child.status,91,`child status=${child.status}; stderr=${child.stderr}`);
 const afterR=await x.readR(),afterJ=await x.readJ();
 assert.equal(afterR.sequence,beforeR.sequence+1);assert.deepEqual(afterJ,beforeJ);
 const restarted=x.service();
 await rejects(restarted.inspect(),'COORDINATOR_REGISTRY_GAP');
 await rejects(restarted.readArtwork({sessionToken:session,request:artRequest()}),'COORDINATOR_REGISTRY_GAP');
 const permit=f.permit('reconcile-registry-gap',beforeJ,beforeR,afterR);
 await restarted.reconcile({authorization:permit,auditEnvelope:f.auditEnvelope});
 assert.equal((await x.service().inspect()).eventCount,2);
 await rejects(x.service().readArtwork({sessionToken:session,request:artRequest()}),'REGISTRY_ARTWORK_UNAVAILABLE');
});
test('31C direct coordinator read rejects unauthorized operation even with valid audit heads',async t=>{
 const f=await fixture(t);await commitThroughService(f);
 await rejects(f.coordinator().read({action:'readPrivateArtwork',envelope:{}}),'COORDINATOR_READ_DENIED');
 await rejects(f.coordinator().read({action:'exportAuthenticatedAudit',envelope:f.admin('export-audit',{opId:id(),expectedAnchor:f.getR()})}),'COORDINATOR_READ_DENIED');
 await rejects(f.coordinator().read({action:'readAuthenticatedArtwork',envelope:null}),'COORDINATOR_READ_DENIED');
});
test('31C externally substituted registry anchor blocks all service read surfaces',async t=>{
 const f=await fixture(t),x=await externalAnchors(f),s=x.service();
 await s.mutate({action:'commitAuthenticatedRevision',envelope:f.mutation('commit-revision',commitRequest()),auditEnvelope:f.auditEnvelope});
 const prior=await x.readR();await writeFile(x.rPath,JSON.stringify({...prior,mac:'b'.repeat(64)}));
 await assert.rejects(x.service().inspect());
 await assert.rejects(x.service().readArtwork({sessionToken:session,request:artRequest()}));
 await assert.rejects(x.service().exportBackup(f.admin('export-backup',{opId:id(),expectedAnchor:prior})));
});


test('31D durable independent registry and journal adapters wire through authenticated service and detect rollback',async t=>{
 const f=await fixture(t),publicKey=f.coordinatorOptions.recovery.publicKey;
 const registryAdapter=createOfflineDurableAnchorAdapter({directory:join(f.base,'durable-registry-anchor'),registryId,anchorType:'registry',recovery:{publicKey}});
 const journalAdapter=createOfflineDurableAnchorAdapter({directory:join(f.base,'durable-journal-anchor'),registryId,anchorType:'journal',recovery:{publicKey}});
 const readR=()=>registryAdapter.read(),readJ=()=>journalAdapter.read();
 const registryOptions={...f.registryOptions,readAnchor:readR,compareAndSetAnchor:(old,next)=>registryAdapter.compareAndSet(old,next)};
 const journalOptions={...f.journalOptions,readRegistryAnchor:readR,readJournalAnchor:readJ,compareAndSetJournalAnchor:(old,next)=>journalAdapter.compareAndSet(old,next)};
 const coordinatorOptions={...f.coordinatorOptions,readRegistryAnchor:readR,readJournalAnchor:readJ};
 const service=()=>createOfflineAuditedRegistryService({registryOptions,journalOptions,coordinatorOptions});
 await service().mutate({action:'commitAuthenticatedRevision',envelope:f.mutation('commit-revision',commitRequest()),auditEnvelope:f.auditEnvelope});
 assert.deepEqual(await service().readArtwork({sessionToken:session,request:artRequest()}),png());
 assert.equal((await service().inspect()).eventCount,1);
 assert.equal((await registryAdapter.inspect()).eventCount,1);
 assert.equal((await journalAdapter.inspect()).eventCount,1);
 await service().mutate({action:'revokeAuthenticatedArtwork',envelope:f.mutation('revoke-artwork',revokeRequest()),auditEnvelope:f.auditEnvelope});
 assert.equal((await service().inspect()).eventCount,2);
 assert.equal((await registryAdapter.inspect()).eventCount,2);
 assert.equal((await journalAdapter.inspect()).eventCount,2);
 await rejects(service().readArtwork({sessionToken:session,request:artRequest()}),'REGISTRY_ARTWORK_UNAVAILABLE');
 // Delete the latest independently stored journal anchor record. The service
 // must refuse the valid-looking but stale earlier anchor (not silently heal).
 await unlink(join(f.base,'durable-journal-anchor','0000000002.json'));
 await rejects(service().inspect(),'AUDIT_ANCHOR_MISMATCH');
 await rejects(service().exportBackup(f.admin('export-backup',{opId:id(),expectedAnchor:await registryAdapter.read()})),'AUDIT_ANCHOR_MISMATCH');
});
