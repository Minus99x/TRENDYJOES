/**
 * Objective 31F: independent signed witness contract for the recovery-ledger
 * head and fail-closed TWO-RESOURCE reconciliation. Offline, opt-in contract:
 * independent witnesses are injected, not hosted by this library. This is NOT
 * atomic cross-resource commit or production anti-rollback infrastructure.
 */
import {createHash,randomBytes,verify as verifySignature} from 'node:crypto';
import {verifyOfflineWitnessQuorum} from './offline-recovery-witness.mjs';
import {validateOfflineRecoveryReviewers,verifyOfflineRecoveryAdjudicationQuorum,recoveryReviewKeyDigest} from './offline-recovery-adjudication.mjs';

export const OFFLINE_RECOVERY_LEDGER_WITNESS_SCHEMA='TJ-OFFLINE-RECOVERY-LEDGER-WITNESS-1';
const ROOT='0'.repeat(64);
const HEX=/^[0-9a-f]{64}$/;
const ID=/^[A-Za-z0-9_-]{12,80}$/;
const FIELDS=['schema','witnessId','registryId','anchorType','count','headDigest','challenge','issuedAt','expiresAt'];
const fail=code=>{throw Object.assign(new Error(code),{code});};
const object=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&[Object.prototype,null].includes(Object.getPrototypeOf(x));
const exact=(x,keys)=>object(x)&&Object.keys(x).sort().join('|')===keys.slice().sort().join('|');
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const sha=x=>createHash('sha256').update(x).digest('hex');
const challengeValid=x=>typeof x==='string'&&/^[A-Za-z0-9_-]{43}$/.test(x)&&Buffer.from(x,'base64url').toString('base64url')===x;
const headValid=s=>exact(s,['count','headDigest'])&&Number.isSafeInteger(s.count)&&s.count>=0&&s.count<=10000&&HEX.test(s.headDigest)&&((s.count===0)===(s.headDigest===ROOT));
const projectHead=s=>({count:s.count,headDigest:s.headDigest});
const projectAnchor=s=>({anchor:s.anchor,eventCount:s.eventCount,historyDigest:s.historyDigest});
function validateWitnesses(witnesses,quorum){
 if(!Array.isArray(witnesses)||witnesses.length<2||witnesses.length>10||!Number.isSafeInteger(quorum)||quorum<=witnesses.length/2||quorum>witnesses.length)fail('LEDGER_WITNESS_CONFIGURATION');
 const ids=new Set(),keys=new Set();
 for(const w of witnesses){
  if(!exact(w,['id','publicKey','readLatest'])||!ID.test(w.id||'')||ids.has(w.id)||w.publicKey?.type!=='public'||w.publicKey?.asymmetricKeyType!=='ed25519'||typeof w.readLatest!=='function')fail('LEDGER_WITNESS_CONFIGURATION');
  const key=sha(w.publicKey.export({type:'spki',format:'der'}));
  if(keys.has(key))fail('LEDGER_WITNESS_CONFIGURATION');
  ids.add(w.id);keys.add(key);
 }
}
/** All supplied receipts must agree, including beyond quorum: equivocation fails closed. */
export function verifyOfflineRecoveryLedgerWitnessQuorum({registryId,anchorType,witnesses,quorum,receipts,snapshot,challenge,now=Date.now()}={}){
 validateWitnesses(witnesses,quorum);
 if(!ID.test(registryId||'')||!['registry','journal'].includes(anchorType)||!headValid(snapshot)||!challengeValid(challenge)||!Number.isSafeInteger(now)||!Array.isArray(receipts)||receipts.length<quorum||receipts.length>witnesses.length)fail('LEDGER_WITNESS_SNAPSHOT_INVALID');
 const byId=new Map(witnesses.map(w=>[w.id,w])),seen=new Set();
 for(const r of receipts){
  if(!exact(r,[...FIELDS,'signature'])||r.schema!==OFFLINE_RECOVERY_LEDGER_WITNESS_SCHEMA||r.registryId!==registryId||r.anchorType!==anchorType||!byId.has(r.witnessId)||seen.has(r.witnessId)||r.count!==snapshot.count||r.headDigest!==snapshot.headDigest||r.challenge!==challenge||!Number.isSafeInteger(r.issuedAt)||!Number.isSafeInteger(r.expiresAt)||r.issuedAt>now||r.expiresAt<=now||r.expiresAt<=r.issuedAt||r.expiresAt-r.issuedAt>300000||typeof r.signature!=='string'||!/^[A-Za-z0-9_-]{86}$/.test(r.signature))fail('LEDGER_WITNESS_RECEIPT_INVALID');
  const body=Object.fromEntries(FIELDS.map(k=>[k,r[k]]));const sig=Buffer.from(r.signature,'base64url');
  if(sig.length!==64||sig.toString('base64url')!==r.signature||!verifySignature(null,Buffer.from(`${OFFLINE_RECOVERY_LEDGER_WITNESS_SCHEMA}\0${JSON.stringify(body)}`),byId.get(r.witnessId).publicKey,sig))fail('LEDGER_WITNESS_SIGNATURE_INVALID');
  seen.add(r.witnessId);
 }
 return Object.freeze({verified:true,count:seen.size,required:quorum,productionApproved:false});
}
/**
 * Reconciliation intentionally NEVER auto-repairs a prepared anchor or ledger.
 * A committed reservation is permanently burned; even a successful anchor
 * recovery requires a fresh independent witness of the new ledger and anchor
 * heads before any subsequent trusted operation.
 */
export function createOfflineRecoveryReconciliationGuard({adapter,ledger,registryId,anchorType,anchorWitnesses,anchorQuorum,ledgerWitnesses,ledgerQuorum,reviewers,reviewQuorum,forensicJournal,forensicWitnesses,forensicWitnessQuorum}={}){
 validateWitnesses(ledgerWitnesses,ledgerQuorum);
 if(!ID.test(registryId||'')||!['registry','journal'].includes(anchorType)||!adapter||!ledger||['inspectRecoveryState','validateRecoveryAuthorization','recoverInterruptedCommit'].some(k=>typeof adapter[k]!=='function')||['inspect','reserve'].some(k=>typeof ledger[k]!=='function')||!Array.isArray(anchorWitnesses))fail('RECOVERY_RECONCILIATION_CONFIGURATION');
 // Reuse the 31E anchor verification contract, including its distinct-key and
 // strict-majority checks. A malformed configuration fails at construction.
 const anchorIds=new Set(),anchorKeys=new Set();
 if(anchorWitnesses.length<2||anchorWitnesses.length>10||!Number.isSafeInteger(anchorQuorum)||anchorQuorum<=anchorWitnesses.length/2||anchorQuorum>anchorWitnesses.length)fail('RECOVERY_RECONCILIATION_CONFIGURATION');
 for(const w of anchorWitnesses){
  if(!exact(w,['id','publicKey','readLatest'])||!ID.test(w.id||'')||anchorIds.has(w.id)||w.publicKey?.type!=='public'||w.publicKey?.asymmetricKeyType!=='ed25519'||typeof w.readLatest!=='function')fail('RECOVERY_RECONCILIATION_CONFIGURATION');
  const key=sha(w.publicKey.export({type:'spki',format:'der'}));if(anchorKeys.has(key))fail('RECOVERY_RECONCILIATION_CONFIGURATION');anchorIds.add(w.id);anchorKeys.add(key);
 }
 // Witnesses for the two domains must not share signing keys: otherwise a
 // compromised anchor witness could impersonate a recovery-ledger witness.
 for(const w of ledgerWitnesses)if(anchorKeys.has(sha(w.publicKey.export({type:'spki',format:'der'}))))fail('RECOVERY_RECONCILIATION_SHARED_WITNESS_KEY');
 const hasReviewers=reviewers!==undefined||reviewQuorum!==undefined;
 const hasForensicJournal=forensicJournal!==undefined||forensicWitnesses!==undefined||forensicWitnessQuorum!==undefined;
 if(hasForensicJournal&&(!hasReviewers||!forensicJournal||typeof forensicJournal.inspectWitnessed!=='function'||typeof forensicJournal.append!=='function'||!Array.isArray(forensicWitnesses)))fail('FORENSIC_JOURNAL_INTEGRATION_CONFIGURATION');
 if(hasReviewers){
  if(typeof ledger.inspectHistory!=='function')fail('RECOVERY_ADJUDICATION_CONFIGURATION');
  validateOfflineRecoveryReviewers(reviewers,reviewQuorum,[...anchorKeys,...ledgerWitnesses.map(w=>recoveryReviewKeyDigest(w.publicKey))]);
  if(hasForensicJournal){
   const forbidden=new Set([...anchorKeys,...ledgerWitnesses.map(w=>recoveryReviewKeyDigest(w.publicKey)),...reviewers.map(w=>recoveryReviewKeyDigest(w.publicKey))]);
   if(forensicWitnesses.some(w=>!w?.publicKey||forbidden.has(recoveryReviewKeyDigest(w.publicKey))))fail('FORENSIC_JOURNAL_SHARED_WITNESS_KEY');
  }
 }
 async function verifiedSnapshot(){
  // Always inspect BOTH local resources before asking independent witnesses.
  // Pending ledger reservations throw and require human forensic review.
  const anchor=await adapter.inspectRecoveryState();const ledgerHead=projectHead(await ledger.inspect());
  const anchorChallenge=randomBytes(32).toString('base64url');
  const ledgerChallenge=randomBytes(32).toString('base64url');
  const [aReceipts,lReceipts]=await Promise.all([
   Promise.all(anchorWitnesses.map(w=>w.readLatest({challenge:anchorChallenge,registryId,anchorType}))),
   Promise.all(ledgerWitnesses.map(w=>w.readLatest({challenge:ledgerChallenge,registryId,anchorType})))
  ]);
  verifyOfflineWitnessQuorum({registryId,anchorType,witnesses:anchorWitnesses,quorum:anchorQuorum,receipts:aReceipts,snapshot:projectAnchor(anchor),challenge:anchorChallenge});
  verifyOfflineRecoveryLedgerWitnessQuorum({registryId,anchorType,witnesses:ledgerWitnesses,quorum:ledgerQuorum,receipts:lReceipts,snapshot:ledgerHead,challenge:ledgerChallenge});
  const afterAnchor=await adapter.inspectRecoveryState(),afterLedger=projectHead(await ledger.inspect());
  if(!same(anchor,afterAnchor)||!same(ledgerHead,afterLedger))fail('RECOVERY_RECONCILIATION_CONCURRENT_CHANGE');
  return {anchor,ledgerHead};
 }
 async function inspectReconciliation(){
  const s=await verifiedSnapshot();
  // Reservation history cannot prove the action outcome; never auto-clear it.
  const disposition=s.anchor.pending?'PENDING_ANCHOR_REVIEW_REQUIRED':s.ledgerHead.count>0?'RESERVATION_OUTCOME_REVIEW_REQUIRED':'NO_PENDING_RESERVATIONS';
  return Object.freeze({anchor:structuredClone(s.anchor),ledger:structuredClone(s.ledgerHead),disposition,independentlyWitnessed:true,automaticRepairAllowed:false,productionApproved:false});
 }
 async function recoverOnce({authorization,forensicReview,forensicEvidence}={}){
  // Authenticate first, before any reservation can be consumed.
  adapter.validateRecoveryAuthorization(authorization);
  const s=await verifiedSnapshot();
  if(!s.anchor.pending||!same(s.anchor.anchor,authorization.expectedAnchor)||s.anchor.pendingDigest!==authorization.pendingDigest)fail('RECOVERY_RECONCILIATION_STATE_MISMATCH');
  // Without an independently adjudicated outcome record, ANY earlier burned
  // permit means an ambiguous two-resource recovery could still be unresolved.
  // This v31F guard deliberately allows only the first reservation; subsequent
  // recoveries need a future separately authorized reconciliation protocol.
  let adjudication=null,journalHead=null;
  if(s.ledgerHead.count>0){
   if(!hasReviewers||!exact(forensicReview,['caseDigest','outcomes']))fail('RECOVERY_RECONCILIATION_REVIEW_REQUIRED');
   if(hasForensicJournal)journalHead=await forensicJournal.inspectWitnessed({witnesses:forensicWitnesses,quorum:forensicWitnessQuorum});
   const history=await ledger.inspectHistory();
   if(history.count!==s.ledgerHead.count||history.headDigest!==s.ledgerHead.headDigest)fail('RECOVERY_ADJUDICATION_CONCURRENT_CHANGE');
   // Reviewers are independently provisioned sources; no caller-provided
   // signatures are accepted. The review must bind the FULL burned-permit
   // history, current pending proposal, and fresh one-time challenge.
   const challenge=randomBytes(32).toString('base64url');
   const review=structuredClone(forensicReview);
   const authorizationDigest=sha(Buffer.from(JSON.stringify(authorization)));
   const receipts=await Promise.all(reviewers.map(r=>r.readLatest({challenge,registryId,anchorType,history:structuredClone(history),anchor:structuredClone(s.anchor),caseDigest:review.caseDigest,outcomes:structuredClone(review.outcomes),authorization:structuredClone(authorization),authorizationDigest})));
   adjudication=verifyOfflineRecoveryAdjudicationQuorum({registryId,anchorType,reviewers,quorum:reviewQuorum,receipts,history,anchor:s.anchor,caseDigest:review.caseDigest,outcomes:review.outcomes,authorizationDigest,challenge,excludedKeys:[...anchorKeys,...ledgerWitnesses.map(w=>recoveryReviewKeyDigest(w.publicKey))]});
   // The two resources can change while external reviewers are signing.
   const [againAnchor,againHistory]=await Promise.all([adapter.inspectRecoveryState(),ledger.inspectHistory()]);
   if(!same(s.anchor,againAnchor)||!same(history,againHistory))fail('RECOVERY_ADJUDICATION_CONCURRENT_CHANGE');
   if(hasForensicJournal){
    if(!forensicEvidence||Object.keys(forensicEvidence).sort().join('|')!=='caseEvidence|outcomeEvidence')fail('FORENSIC_JOURNAL_EVIDENCE_REQUIRED');
    await forensicJournal.append({review:{history,anchor:s.anchor,caseDigest:review.caseDigest,outcomes:review.outcomes,authorizationDigest,challenge,receipts},caseEvidence:forensicEvidence.caseEvidence,outcomeEvidence:forensicEvidence.outcomeEvidence,expectedHead:{count:journalHead.count,headDigest:journalHead.headDigest}});
   }
  }
  const reservation=await ledger.reserve({authorizationId:authorization.authorizationId,permitDigest:sha(Buffer.from(JSON.stringify(authorization))),pendingDigest:authorization.pendingDigest,expectedHead:s.ledgerHead});
  // A concurrent anchor mutation here may burn a permit; that is safer than
  // repeating a potentially irreversible action after an ambiguous crash.
  const result=await adapter.recoverInterruptedCommit({authorization});
  return Object.freeze({...result,reservationIndex:reservation.index,disposition:'POST_RECOVERY_INDEPENDENT_REWITNESS_REQUIRED',forensicReviewVerified:adjudication?.verified??false,adjudicationDigest:adjudication?.adjudicationDigest??null,forensicJournalRecorded:hasForensicJournal&&adjudication!==null,productionApproved:false});
 }
 return Object.freeze({inspectReconciliation,recoverOnce});
}
