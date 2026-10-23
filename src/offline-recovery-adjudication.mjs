/**
 * Objective 31G: opt-in independent forensic adjudication of previously burned
 * recovery reservations. This verifies SIGNED review assertions; it cannot
 * independently establish that a real-world outcome occurred. No auto-retry,
 * remote key custody, durable external monotonicity or production authorization.
 */
import {createHash,verify as verifySignature} from 'node:crypto';
export const OFFLINE_RECOVERY_ADJUDICATION_SCHEMA='TJ-OFFLINE-RECOVERY-ADJUDICATION-1';
const ID=/^[A-Za-z0-9_-]{12,80}$/;
const HEX=/^[0-9a-f]{64}$/;
const ROOT='0'.repeat(64);
const FIELDS=['schema','reviewerId','registryId','anchorType','ledgerCount','ledgerHeadDigest','historyDigest','anchorStateDigest','caseDigest','outcomesDigest','authorizationDigest','challenge','issuedAt','expiresAt'];
const fail=code=>{throw Object.assign(new Error(code),{code});};
const object=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&[Object.prototype,null].includes(Object.getPrototypeOf(x));
const exact=(x,keys)=>object(x)&&Object.keys(x).sort().join('|')===keys.slice().sort().join('|');
const sha=x=>createHash('sha256').update(x).digest('hex');
const challengeValid=x=>typeof x==='string'&&/^[A-Za-z0-9_-]{43}$/.test(x)&&Buffer.from(x,'base64url').toString('base64url')===x;
const keyDigest=k=>sha(k.export({type:'spki',format:'der'}));
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);

export function validateOfflineRecoveryReviewers(reviewers,quorum,excludedKeys=[]){
 if(!Array.isArray(reviewers)||reviewers.length<2||reviewers.length>10||!Number.isSafeInteger(quorum)||quorum<=reviewers.length/2||quorum>reviewers.length)fail('RECOVERY_ADJUDICATION_CONFIGURATION');
 const ids=new Set(),keys=new Set(excludedKeys);
 for(const r of reviewers){
  if(!exact(r,['id','publicKey','readLatest'])||!ID.test(r.id||'')||ids.has(r.id)||r.publicKey?.type!=='public'||r.publicKey?.asymmetricKeyType!=='ed25519'||typeof r.readLatest!=='function')fail('RECOVERY_ADJUDICATION_CONFIGURATION');
  const digest=keyDigest(r.publicKey);
  if(keys.has(digest))fail('RECOVERY_ADJUDICATION_SHARED_OR_DUPLICATE_KEY');
  ids.add(r.id);keys.add(digest);
 }
 return true;
}
export function recoveryReviewKeyDigest(publicKey){return keyDigest(publicKey);}

function validHistory(history,registryId,anchorType){
 if(!exact(history,['count','headDigest','events'])||!Number.isSafeInteger(history.count)||history.count<1||history.count>10000||!HEX.test(history.headDigest)||history.headDigest===ROOT||!Array.isArray(history.events)||history.events.length!==history.count)fail('RECOVERY_ADJUDICATION_HISTORY_INVALID');
 let previous=ROOT;const ids=new Set(),permits=new Set();
 for(let i=0;i<history.events.length;i++){
  const e=history.events[i];
  if(!exact(e,['schema','registryId','anchorType','index','previousDigest','authorizationId','permitDigest','pendingDigest','digest'])||e.schema!=='TJ-OFFLINE-RECOVERY-RESERVATION-1'||e.registryId!==registryId||e.anchorType!==anchorType||e.index!==i+1||e.previousDigest!==previous||!ID.test(e.authorizationId||'')||!HEX.test(e.permitDigest)||!HEX.test(e.pendingDigest)||!HEX.test(e.digest))fail('RECOVERY_ADJUDICATION_HISTORY_INVALID');
  const {digest,...body}=e;
  if(digest!==sha(Buffer.from(`${e.schema}\0${JSON.stringify(body)}`)))fail('RECOVERY_ADJUDICATION_HISTORY_INVALID');
  if(ids.has(e.authorizationId)||permits.has(e.permitDigest))fail('RECOVERY_ADJUDICATION_HISTORY_INVALID');
  ids.add(e.authorizationId);permits.add(e.permitDigest);previous=digest;
 }
 if(previous!==history.headDigest)fail('RECOVERY_ADJUDICATION_HISTORY_INVALID');
}
function validOutcomes(outcomes,history,anchor){
 if(!Array.isArray(outcomes)||outcomes.length!==history.count)fail('RECOVERY_ADJUDICATION_OUTCOMES_INVALID');
 for(let i=0;i<outcomes.length;i++){
  const o=outcomes[i],e=history.events[i];
  if(!exact(o,['index','authorizationId','permitDigest','pendingDigest','result','evidenceDigest'])||o.index!==e.index||o.authorizationId!==e.authorizationId||o.permitDigest!==e.permitDigest||o.pendingDigest!==e.pendingDigest||!['RESOLVED_APPLIED','RESOLVED_NOT_APPLIED'].includes(o.result)||!HEX.test(o.evidenceDigest)||o.evidenceDigest===ROOT)fail('RECOVERY_ADJUDICATION_OUTCOMES_INVALID');
  // A reservation adjudicated as already applied cannot be retried against the
  // exact same pending proposal, even with a freshly signed recovery permit.
  if(anchor.pending&&o.pendingDigest===anchor.pendingDigest&&o.result==='RESOLVED_APPLIED')fail('RECOVERY_ADJUDICATION_ALREADY_APPLIED');
 }
}
/** Pure verifier: every supplied receipt must match, including extra receipts. */
export function verifyOfflineRecoveryAdjudicationQuorum({registryId,anchorType,reviewers,quorum,receipts,history,anchor,caseDigest,outcomes,authorizationDigest,challenge,now=Date.now(),excludedKeys=[]}={}){
 validateOfflineRecoveryReviewers(reviewers,quorum,excludedKeys);
 if(!ID.test(registryId||'')||!['registry','journal'].includes(anchorType)||!Number.isSafeInteger(now)||!challengeValid(challenge)||!HEX.test(caseDigest)||caseDigest===ROOT||!HEX.test(authorizationDigest)||!exact(anchor,['anchor','eventCount','historyDigest','pending','pendingDigest','productionApproved'])||!Number.isSafeInteger(anchor.eventCount)||anchor.eventCount<0||anchor.eventCount>10000||!HEX.test(anchor.historyDigest)||typeof anchor.pending!=='boolean'||(anchor.pending?!HEX.test(anchor.pendingDigest):anchor.pendingDigest!==null)||!Array.isArray(receipts)||receipts.length<quorum||receipts.length>reviewers.length)fail('RECOVERY_ADJUDICATION_REQUEST_INVALID');
 validHistory(history,registryId,anchorType);validOutcomes(outcomes,history,anchor);
 const historyDigest=sha(Buffer.from(JSON.stringify(history.events)));
 const anchorStateDigest=sha(Buffer.from(JSON.stringify(anchor)));
 const outcomesDigest=sha(Buffer.from(JSON.stringify(outcomes)));
 const byId=new Map(reviewers.map(r=>[r.id,r]));const seen=new Set();
 for(const r of receipts){
  if(!exact(r,[...FIELDS,'signature'])||r.schema!==OFFLINE_RECOVERY_ADJUDICATION_SCHEMA||!byId.has(r.reviewerId)||seen.has(r.reviewerId)||r.registryId!==registryId||r.anchorType!==anchorType||r.ledgerCount!==history.count||r.ledgerHeadDigest!==history.headDigest||r.historyDigest!==historyDigest||r.anchorStateDigest!==anchorStateDigest||r.caseDigest!==caseDigest||r.outcomesDigest!==outcomesDigest||r.authorizationDigest!==authorizationDigest||r.challenge!==challenge||!Number.isSafeInteger(r.issuedAt)||!Number.isSafeInteger(r.expiresAt)||r.issuedAt>now||r.expiresAt<=now||r.expiresAt<=r.issuedAt||r.expiresAt-r.issuedAt>300000||typeof r.signature!=='string'||!/^[A-Za-z0-9_-]{86}$/.test(r.signature))fail('RECOVERY_ADJUDICATION_RECEIPT_INVALID');
  const body=Object.fromEntries(FIELDS.map(k=>[k,r[k]]));const sig=Buffer.from(r.signature,'base64url');
  if(sig.length!==64||sig.toString('base64url')!==r.signature||!verifySignature(null,Buffer.from(`${OFFLINE_RECOVERY_ADJUDICATION_SCHEMA}\0${JSON.stringify(body)}`),byId.get(r.reviewerId).publicKey,sig))fail('RECOVERY_ADJUDICATION_SIGNATURE_INVALID');
  seen.add(r.reviewerId);
 }
 return Object.freeze({verified:true,reviewers:seen.size,required:quorum,adjudicationDigest:sha(Buffer.from(JSON.stringify({historyDigest,anchorStateDigest,caseDigest,outcomesDigest,authorizationDigest}))),productionApproved:false});
}
