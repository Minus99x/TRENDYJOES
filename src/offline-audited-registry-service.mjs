/**
 * Objective 31C: opt-in trusted OFFLINE service boundary.
 * Constructs registry and journal privately; never returns either underlying
 * mutable object. This is capability isolation, NOT filesystem access control.
 * A process retaining raw secrets/directory access can still bypass this seam.
 */
import {createOfflinePrivateRevisionRegistry} from './offline-private-revision-registry.mjs';
import {createOfflineAnchoredAuditJournal} from './offline-anchored-audit-journal.mjs';
import {createOfflineAuditedRegistryCoordinator} from './offline-audited-registry-coordinator.mjs';

const fail=()=>{throw Object.assign(new Error('AUDITED_SERVICE_CONFIGURATION'),{code:'AUDITED_SERVICE_CONFIGURATION'});};
const obj=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&[Object.prototype,null].includes(Object.getPrototypeOf(x));
const exact=(x,fields)=>obj(x)&&Object.keys(x).sort().join('|')===fields.slice().sort().join('|');
const methods=Object.freeze([
 'commitAuthenticatedRevision','revokeAuthenticatedArtwork','revokeAuthenticatedRevision',
 'migrateAuthenticatedArtwork','rotateAuthenticatedArtworkKey','restoreAuthenticatedBackup',
 'recoverInterruptedRegistry'
]);

export function createOfflineAuditedRegistryService(options={}){
 if(!exact(options,['registryOptions','journalOptions','coordinatorOptions']))fail();
 const {registryOptions,journalOptions,coordinatorOptions}=options;
 if(!obj(registryOptions)||!obj(journalOptions)||!obj(coordinatorOptions))fail();
 const id=coordinatorOptions.registryId;
 // Require all authenticated/encrypted seams. No weak legacy fixture mode.
 if(typeof id!=='string'||!registryOptions.mutationAuthorization||!registryOptions.adminAuthorization||
    !registryOptions.verifyArtworkAccess||!registryOptions.encryption||!registryOptions.recovery||
    !journalOptions.recovery||!coordinatorOptions.recovery||
    registryOptions.mutationAuthorization.registryId!==id||
    registryOptions.adminAuthorization.registryId!==id||
    registryOptions.recovery.registryId!==id||journalOptions.recovery.registryId!==id||
    journalOptions.registryId!==id||
    typeof registryOptions.readAnchor!=='function'||
    registryOptions.readAnchor!==journalOptions.readRegistryAnchor||
    registryOptions.readAnchor!==coordinatorOptions.readRegistryAnchor||
    typeof journalOptions.readJournalAnchor!=='function'||
    journalOptions.readJournalAnchor!==coordinatorOptions.readJournalAnchor||
    Object.hasOwn(journalOptions,'registry')||Object.hasOwn(coordinatorOptions,'registry')||
    Object.hasOwn(coordinatorOptions,'journal'))fail();
 const registry=createOfflinePrivateRevisionRegistry(registryOptions);
 const journal=createOfflineAnchoredAuditJournal({...journalOptions,registry});
 const coordinator=createOfflineAuditedRegistryCoordinator({...coordinatorOptions,registry,journal});
 return Object.freeze({
  inspect:()=>coordinator.inspect(),
  mutate:({action,envelope,auditEnvelope}={})=>{
   if(!methods.includes(action))return Promise.reject(Object.assign(new Error('AUDITED_SERVICE_ACTION_DENIED'),{code:'AUDITED_SERVICE_ACTION_DENIED'}));
   return coordinator.execute({action,envelope,auditEnvelope});
  },
  readArtwork:envelope=>coordinator.read({action:'readAuthenticatedArtwork',envelope}),
  exportBackup:envelope=>coordinator.read({action:'exportAuthenticatedBackup',envelope}),
  reconcile:args=>coordinator.reconcile(args),
  bootstrap:args=>coordinator.bootstrap(args),
  recoverJournal:args=>coordinator.recoverJournal(args)
 });
}
