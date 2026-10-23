/**
 * Objective 32C: OFFLINE, read-only verification of externally pinned supervisory
 * review statements about 32B orphan evidence. No action authorization, state
 * mutation, network access, key custody or implicit replay consumption.
 */
import {createHash,verify as verifySignature} from 'node:crypto';
import {OFFLINE_PINNED_ORPHAN_REPORT_SCHEMA} from './offline-pinned-orphan-classifier.mjs';

export const OFFLINE_ORPHAN_SUPERVISOR_DECISION_SCHEMA='TJ-OFFLINE-ORPHAN-SUPERVISOR-DECISION-1';
export const OFFLINE_ORPHAN_REPLAY_SNAPSHOT_SCHEMA='TJ-OFFLINE-ORPHAN-SUPERVISOR-REPLAY-1';
const HEX=/^[a-f0-9]{64}$/,ID=/^[A-Za-z0-9_-]{12,80}$/;
const DISPOSITIONS=new Set(['REQUIRE_INDEPENDENT_REVIEW','REJECT_EVIDENCE','NO_ANOMALIES_REVIEWED']);
const CLASSES=new Set(['SIGNED_ARCHIVE','COORDINATOR_LOCK','PENDING_INTENT_UNVERIFIED','QUARANTINE_UNVERIFIED',
 'UNTRACKED_ARCHIVE_UNVERIFIED','UNTRACKED_ENTRY_UNVERIFIED','ENTRY_DISAPPEARED','SIGNED_ARCHIVE_UNSAFE',
 'UNSAFE_UNTRACKED_ENTRY','SIGNED_ARCHIVE_MISSING','SIGNED_ARCHIVE_TAMPERED','SIGNED_ARCHIVE_INVALID_STRUCTURE']);
const REPORT_FIELDS=['schema','registryId','manifestDigest','head','epoch','transitionDigest','recordsDigest','evidence','status','issueCount','supervisoryDisposition','readOnly','productionApproved','mayDelete','mayRepair','mayManufacture','mayAcknowledge'];
const DECISION_FIELDS=['schema','registryId','reportDigest','manifestDigest','head','epoch','transitionDigest','recordsDigest','issueDigest','issueCount','disposition','decisionId','nonce','issuedAt','expiresAt','replayDigest','reviewerPolicyDigest'];
const sha=b=>createHash('sha256').update(b).digest('hex');
const fail=code=>{throw Object.assign(new Error(code),{code});};
const plain=o=>o!==null&&typeof o==='object'&&!Array.isArray(o)&&[Object.prototype,null].includes(Object.getPrototypeOf(o));
const exact=(o,keys)=>plain(o)&&Object.keys(o).sort().join('|')===keys.slice().sort().join('|');
const same=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const cmp=(a,b)=>a<b?-1:a>b?1:0;
const validHead=h=>exact(h,['count','headDigest'])&&Number.isSafeInteger(h.count)&&h.count>=0&&h.count<=2000&&HEX.test(h.headDigest)&&((h.count===0)===(h.headDigest==='0'.repeat(64)));
function plainData(x,depth=0){
 if(depth>32)fail('SUPERVISOR_CANONICAL_INVALID');
 if(x===null||typeof x==='string'||typeof x==='boolean'||(typeof x==='number'&&Number.isFinite(x)))return;
 if(!Array.isArray(x)&&!plain(x))fail('SUPERVISOR_CANONICAL_INVALID');
 for(const d of Object.values(Object.getOwnPropertyDescriptors(x))){
  if(!Object.hasOwn(d,'value'))fail('SUPERVISOR_CANONICAL_INVALID');
  plainData(d.value,depth+1);
 }
}
const canonical=x=>{plainData(x);let s;try{s=JSON.stringify(x);}catch{fail('SUPERVISOR_CANONICAL_INVALID');}
 if(typeof s!=='string'||Buffer.byteLength(s)>4*1024*1024||!same(JSON.parse(s),x))fail('SUPERVISOR_CANONICAL_INVALID');return Buffer.from(s);};
const signatureValid=s=>typeof s==='string'&&/^[A-Za-z0-9_-]{86}$/.test(s)&&Buffer.from(s,'base64url').length===64&&Buffer.from(s,'base64url').toString('base64url')===s;

function policy(reviewers,quorum){
 if(!Array.isArray(reviewers)||reviewers.length<2||reviewers.length>12||!Number.isSafeInteger(quorum)||quorum<=reviewers.length/2||quorum>reviewers.length)fail('SUPERVISOR_POLICY_INVALID');
 const ids=new Set(),keys=new Set(),members=[];
 for(const r of reviewers){
  if(!exact(r,['id','publicKey'])||!ID.test(r.id||'')||ids.has(r.id)||r.publicKey?.type!=='public'||r.publicKey?.asymmetricKeyType!=='ed25519')fail('SUPERVISOR_POLICY_INVALID');
  const digest=sha(r.publicKey.export({format:'der',type:'spki'}));
  if(keys.has(digest))fail('SUPERVISOR_POLICY_DUPLICATE_KEY');
  ids.add(r.id);keys.add(digest);members.push({id:r.id,keyDigest:digest,publicKey:r.publicKey});
 }
 const sorted=members.slice().sort((a,b)=>cmp(a.id,b.id));
 const digest=sha(Buffer.from(`${OFFLINE_ORPHAN_SUPERVISOR_DECISION_SCHEMA}-POLICY\0${JSON.stringify({quorum,reviewers:sorted.map(({id,keyDigest})=>({id,keyDigest}))})}`));
 return {digest,quorum,members:new Map(members.map(r=>[r.id,r.publicKey]))};
}
export function offlineOrphanSupervisorPolicyDigest({reviewers,quorum}={}){return policy(reviewers,quorum).digest;}

function issues(report){
 if(!Array.isArray(report.evidence)||report.evidence.length>4096)fail('SUPERVISOR_REPORT_INVALID');
 const seen=new Set(),out=[];
 for(const e of report.evidence){
  if(!plain(e)||!Number.isSafeInteger(e.directoryIndex)||e.directoryIndex<0||e.directoryIndex>=64||!HEX.test(e.nameDigest||'')||
   !CLASSES.has(e.classification)||
   (e.name!==null&&(typeof e.name!=='string'||e.name.length>160||sha(Buffer.from(e.name))!==e.nameDigest)))fail('SUPERVISOR_REPORT_INVALID');
  const key=`${e.directoryIndex}:${e.nameDigest}`;
  if(seen.has(key))fail('SUPERVISOR_REPORT_DUPLICATE_ENTRY');seen.add(key);
  if(!['SIGNED_ARCHIVE','COORDINATOR_LOCK'].includes(e.classification))out.push({directoryIndex:e.directoryIndex,nameDigest:e.nameDigest,
   classification:e.classification,evidenceDigest:sha(canonical(e))});
 }
 out.sort((a,b)=>a.directoryIndex-b.directoryIndex||cmp(a.nameDigest,b.nameDigest));
 return out;
}
export function offlineOrphanReportIssueDigest(report){
 if(!plain(report))fail('SUPERVISOR_REPORT_INVALID');
 return sha(Buffer.from(`${OFFLINE_ORPHAN_SUPERVISOR_DECISION_SCHEMA}-ISSUES\0${JSON.stringify(issues(report))}`));
}
function checkedReport(report,pins){
 if(!exact(pins,['reportDigest','manifestDigest','head','epoch','transitionDigest','recordsDigest'])||
  ![pins.reportDigest,pins.manifestDigest,pins.transitionDigest,pins.recordsDigest].every(x=>HEX.test(x||''))||
  !validHead(pins.head)||!Number.isSafeInteger(pins.epoch)||pins.epoch<0||pins.epoch>20)fail('SUPERVISOR_EXTERNAL_PINS_REQUIRED');
 if(!exact(report,[...REPORT_FIELDS,'reportDigest'])||report.schema!==OFFLINE_PINNED_ORPHAN_REPORT_SCHEMA||!ID.test(report.registryId||'')||
  ![report.reportDigest,report.manifestDigest,report.transitionDigest,report.recordsDigest].every(x=>HEX.test(x||''))||
  !validHead(report.head)||!Number.isSafeInteger(report.epoch)||report.epoch<0||report.epoch>20||
  !Number.isSafeInteger(report.issueCount)||report.issueCount<0||report.issueCount>4096||
  report.supervisoryDisposition!=='EXTERNAL_DECISION_REQUIRED_FOR_ANY_REMEDIATION'||report.readOnly!==true||
  [report.productionApproved,report.mayDelete,report.mayRepair,report.mayManufacture,report.mayAcknowledge].some(x=>x!==false))fail('SUPERVISOR_REPORT_INVALID');
 const {reportDigest,...body}=report;
 if(sha(Buffer.from(`${OFFLINE_PINNED_ORPHAN_REPORT_SCHEMA}\0${canonical(body)}`))!==reportDigest||
  reportDigest!==pins.reportDigest||report.manifestDigest!==pins.manifestDigest||!same(report.head,pins.head)||
  report.epoch!==pins.epoch||report.transitionDigest!==pins.transitionDigest||report.recordsDigest!==pins.recordsDigest)
  fail('SUPERVISOR_REPORT_PIN_MISMATCH');
 const entries=issues(report);
 if(report.issueCount!==entries.length||report.status!==(entries.length?'SUPERVISORY_REVIEW_REQUIRED':'NO_ANOMALIES_OBSERVED'))fail('SUPERVISOR_REPORT_INVALID');
 return {issueDigest:offlineOrphanReportIssueDigest(report),issueCount:entries.length};
}
function checkedDecisionBody(b){
 if(!exact(b,DECISION_FIELDS)||b.schema!==OFFLINE_ORPHAN_SUPERVISOR_DECISION_SCHEMA||!ID.test(b.registryId||'')||
  ![b.reportDigest,b.manifestDigest,b.transitionDigest,b.recordsDigest,b.issueDigest,b.replayDigest,b.reviewerPolicyDigest].every(x=>HEX.test(x||''))||
  !validHead(b.head)||!Number.isSafeInteger(b.epoch)||b.epoch<0||b.epoch>20||
  !Number.isSafeInteger(b.issueCount)||b.issueCount<0||b.issueCount>4096||!DISPOSITIONS.has(b.disposition)||
  !ID.test(b.decisionId||'')||!ID.test(b.nonce||'')||!Number.isSafeInteger(b.issuedAt)||b.issuedAt<0||
  !Number.isSafeInteger(b.expiresAt)||b.expiresAt<=b.issuedAt||b.expiresAt-b.issuedAt>300000)fail('SUPERVISOR_DECISION_INVALID');
}
export function offlineOrphanSupervisorDecisionSigningBytes(body){checkedDecisionBody(body);return Buffer.from(`${OFFLINE_ORPHAN_SUPERVISOR_DECISION_SCHEMA}\0${JSON.stringify(body)}`);}

export function encodeOfflineOrphanReplaySnapshot({registryId,consumed}={}){
 if(!ID.test(registryId||'')||!Array.isArray(consumed)||consumed.length>4096)fail('SUPERVISOR_REPLAY_SNAPSHOT_INVALID');
 let last='',nonces=new Set();
 for(const c of consumed){
  if(!exact(c,['decisionId','nonce'])||!ID.test(c.decisionId||'')||!ID.test(c.nonce||'')||c.decisionId<=last||nonces.has(c.nonce))fail('SUPERVISOR_REPLAY_SNAPSHOT_INVALID');
  last=c.decisionId;nonces.add(c.nonce);
 }
 return Buffer.from(JSON.stringify({schema:OFFLINE_ORPHAN_REPLAY_SNAPSHOT_SCHEMA,registryId,consumed}));
}
function replayState(bytes,expectedDigest,registryId){
 if(!Buffer.isBuffer(bytes)||bytes.length>1024*1024||!HEX.test(expectedDigest||'')||sha(bytes)!==expectedDigest)fail('SUPERVISOR_REPLAY_PIN_MISMATCH');
 let r;try{r=JSON.parse(bytes.toString('utf8'));}catch{fail('SUPERVISOR_REPLAY_SNAPSHOT_INVALID');}
 if(!exact(r,['schema','registryId','consumed'])||r.schema!==OFFLINE_ORPHAN_REPLAY_SNAPSHOT_SCHEMA||r.registryId!==registryId||
  !encodeOfflineOrphanReplaySnapshot(r).equals(bytes))fail('SUPERVISOR_REPLAY_SNAPSHOT_INVALID');
 return r;
}
/**
 * Verification-only: no durable nonce reservation. The caller MUST atomically
 * advance independently pinned replay state before any external use. This
 * function intentionally NEVER authorizes remediation or checkout.
 */
export function verifyOfflineOrphanSupervisorDecision({report,expectedPins,decision,reviewers,quorum,expectedReviewerPolicyDigest,replayBytes,expectedReplayDigest,nowMs}={}){
 if(!Number.isSafeInteger(nowMs)||nowMs<0)fail('SUPERVISOR_TRUSTED_TIME_REQUIRED');
 const {issueDigest,issueCount}=checkedReport(report,expectedPins),p=policy(reviewers,quorum);
 if(!exact(decision,['body','signatures']))fail('SUPERVISOR_DECISION_INVALID');
 const b=decision.body,bytes=offlineOrphanSupervisorDecisionSigningBytes(b);
 if(b.registryId!==report.registryId||b.reportDigest!==report.reportDigest||b.manifestDigest!==report.manifestDigest||
  !same(b.head,report.head)||b.epoch!==report.epoch||b.transitionDigest!==report.transitionDigest||
  b.recordsDigest!==report.recordsDigest||b.issueDigest!==issueDigest||b.issueCount!==issueCount)
  fail('SUPERVISOR_DECISION_REPORT_MISMATCH');
 if(!HEX.test(expectedReviewerPolicyDigest||'')||p.digest!==expectedReviewerPolicyDigest)fail('SUPERVISOR_EXTERNAL_REVIEWER_POLICY_PIN_REQUIRED');
 if(b.reviewerPolicyDigest!==p.digest)fail('SUPERVISOR_DECISION_POLICY_MISMATCH');
 if(nowMs<b.issuedAt||nowMs>=b.expiresAt)fail('SUPERVISOR_DECISION_EXPIRED_OR_FUTURE');
 if((b.disposition==='NO_ANOMALIES_REVIEWED')!==(issueCount===0))fail('SUPERVISOR_DISPOSITION_INVALID');
 if(b.replayDigest!==expectedReplayDigest)fail('SUPERVISOR_REPLAY_PIN_MISMATCH');
 const replay=replayState(replayBytes,expectedReplayDigest,report.registryId);
 if(replay.consumed.some(x=>x.decisionId===b.decisionId||x.nonce===b.nonce))fail('SUPERVISOR_DECISION_REPLAY');
 if(!Array.isArray(decision.signatures)||decision.signatures.length<p.quorum||decision.signatures.length>p.members.size)fail('SUPERVISOR_DECISION_QUORUM_INVALID');
 let last='';for(const s of decision.signatures){
  if(!exact(s,['reviewerId','signature'])||typeof s.reviewerId!=='string'||s.reviewerId<=last||!p.members.has(s.reviewerId)||
   !signatureValid(s.signature)||!verifySignature(null,bytes,p.members.get(s.reviewerId),Buffer.from(s.signature,'base64url')))
   fail('SUPERVISOR_DECISION_SIGNATURE_INVALID');
  last=s.reviewerId;
 }
 return Object.freeze({signatureVerified:true,decisionDigest:sha(bytes),reportDigest:b.reportDigest,issueDigest,issueCount,
  disposition:b.disposition,replayDigest:expectedReplayDigest,requiresIndependentAtomicReplayCommit:true,
  readOnly:true,authorizesRemediation:false,mayDelete:false,mayRepair:false,mayManufacture:false,mayAcknowledge:false,productionApproved:false});
}
