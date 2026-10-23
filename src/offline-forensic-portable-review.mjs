/**
 * Objective 31K: portable, DATA-ONLY forensic publication/outbox evidence.
 * A bundle carries NO trusted keys or trusted pins. The verifying operator
 * supplies both from an independently retained channel. This API NEVER
 * authorizes a retry, cleanup, acknowledgement, release, or production action.
 */
import {createHash} from 'node:crypto';
import {verifyOfflinePublishedForensicEvidenceWithTransitions,verifyOfflineForensicPublicationTransitions} from './offline-forensic-transition-certificate.mjs';
import {verifyOfflineForensicEvidenceBundle} from './offline-forensic-review-journal.mjs';
import {verifyOfflineForensicOutboxHistory} from './offline-forensic-publication-outbox.mjs';

export const OFFLINE_FORENSIC_PORTABLE_SCHEMA='TJ-OFFLINE-FORENSIC-PORTABLE-REVIEW-1';
const ROOT='0'.repeat(64),HEX=/^[0-9a-f]{64}$/,ID=/^[A-Za-z0-9_-]{12,80}$/;
const FIELDS=['schema','registryId','anchorType','forensicEvents','publications','transitionCertificates','outboxEvents','declaredHeads'];
const fail=code=>{throw Object.assign(Error(code),{code});};
const obj=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&[Object.prototype,null].includes(Object.getPrototypeOf(x));
const exact=(x,keys)=>obj(x)&&Object.keys(x).sort().join('|')===keys.slice().sort().join('|');
const validHead=x=>exact(x,['count','headDigest'])&&Number.isSafeInteger(x.count)&&x.count>=0&&x.count<=2000&&HEX.test(x.headDigest)&&(x.count===0)===(x.headDigest===ROOT);
const equal=(a,b)=>a.count===b.count&&a.headDigest===b.headDigest;
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
function validateShape(x){
 if(!exact(x,FIELDS)||x.schema!==OFFLINE_FORENSIC_PORTABLE_SCHEMA||!ID.test(x.registryId||'')||!['registry','journal'].includes(x.anchorType)||!Array.isArray(x.forensicEvents)||x.forensicEvents.length>1000||!Array.isArray(x.publications)||x.publications.length>1000||!Array.isArray(x.transitionCertificates)||x.transitionCertificates.length>19||!Array.isArray(x.outboxEvents)||x.outboxEvents.length>2000||!exact(x.declaredHeads,['forensic','publication','outbox'])||!Object.values(x.declaredHeads).every(validHead))fail('FORENSIC_PORTABLE_REVIEW_SCHEMA_INVALID');
}
/** Data-only assembly. The digest protects against accidental corruption,
 * not a malicious exporter. Do not use its declared heads as trust anchors. */
export function createOfflineForensicPortableReviewBundle({registryId,anchorType,forensicEvents,publications,transitionCertificates,outboxEvents,declaredHeads}={}){
 const payload={schema:OFFLINE_FORENSIC_PORTABLE_SCHEMA,registryId,anchorType,forensicEvents,publications,transitionCertificates,outboxEvents,declaredHeads};
 validateShape(payload);
 let raw;
 try{raw=JSON.stringify(payload);}catch{fail('FORENSIC_PORTABLE_REVIEW_SERIALIZATION_INVALID');}
 if(typeof raw!=='string'||Buffer.byteLength(raw)>8*1024*1024)fail('FORENSIC_PORTABLE_REVIEW_SIZE_INVALID');
 const parsed=JSON.parse(raw);validateShape(parsed);
 return Object.freeze({payload:parsed,transportDigest:sha(Buffer.from(raw)),productionApproved:false});
}
/**
 * Trust is an independent in-memory configuration with KeyObjects and
 * historical reviewer policies; independentPins MUST be provided separately
 * and MUST NOT be copied from the untrusted bundle.
 * Results are diagnostic only, including CONSISTENT_READ_ONLY.
 */
export function verifyOfflineForensicPortableReviewBundle({envelope,independentPins,trust}={}){
 if(!exact(envelope,['payload','transportDigest','productionApproved'])||envelope.productionApproved!==false||!HEX.test(envelope.transportDigest)||!obj(trust)||!exact(independentPins,['forensic','publication','outbox'])||!Object.values(independentPins).every(validHead))fail('FORENSIC_PORTABLE_REVIEW_REQUEST_INVALID');
 const b=envelope.payload;validateShape(b);
 const raw=JSON.stringify(b);
 if(Buffer.byteLength(raw)>8*1024*1024||sha(Buffer.from(raw))!==envelope.transportDigest)fail('FORENSIC_PORTABLE_REVIEW_TRANSPORT_INVALID');
 if(b.registryId!==trust.registryId||b.anchorType!==trust.anchorType||!equal(b.declaredHeads.forensic,independentPins.forensic)||!equal(b.declaredHeads.publication,independentPins.publication)||!equal(b.declaredHeads.outbox,independentPins.outbox))fail('FORENSIC_PORTABLE_REVIEW_INDEPENDENT_PIN_MISMATCH');
 const args={registryId:b.registryId,anchorType:b.anchorType,witnesses:trust.witnesses,witnessQuorum:trust.witnessQuorum,reviewerPolicies:trust.reviewerPolicies,reviewerEpochs:trust.reviewerEpochs,events:b.forensicEvents,expectedForensicHead:independentPins.forensic,publications:b.publications,expectedPublicationHead:independentPins.publication,transitionCertificates:b.transitionCertificates};
 if(b.publications.length)verifyOfflinePublishedForensicEvidenceWithTransitions(args);
 else {
  const {expectedForensicHead:unusedForensicHead,...publicationOnly}=args;
  verifyOfflineForensicPublicationTransitions({...publicationOnly,expectedHead:independentPins.publication});
  verifyOfflineForensicEvidenceBundle({registryId:b.registryId,anchorType:b.anchorType,events:b.forensicEvents,reviewerEpochs:trust.reviewerEpochs,expectedHead:independentPins.forensic});
 }
 const out=verifyOfflineForensicOutboxHistory({registryId:b.registryId,anchorType:b.anchorType,witnesses:trust.witnesses,witnessQuorum:trust.witnessQuorum,events:b.outboxEvents,expectedHead:independentPins.outbox});
 const prepared=b.outboxEvents.filter(e=>e.action==='PREPARE');
 let classification='CONSISTENT_READ_ONLY';
 if(b.publications.length>prepared.length)classification='ORPHAN_PUBLICATION_REVIEW';
 else if(b.publications.length<out.completed)classification='MISSING_PUBLISHED_HISTORY_REVIEW';
 else if(b.publications.some((r,i)=>r.digest!==prepared[i]?.publicationDigest||r.publishedAt!==prepared[i]?.publishedAt))classification='PUBLICATION_SUBSTITUTION_REVIEW';
 else if(out.openPrepare)classification=b.publications.length===prepared.length?'PUBLISHED_UNACKNOWLEDGED_REVIEW':'PREPARED_UNCERTAIN_REVIEW';
 else if(b.publications.length!==out.completed)classification='COUNT_MISMATCH_REVIEW';
 else if(b.publications.length===0)classification=b.forensicEvents.length?'UNPUBLISHED_FORENSIC_REVIEW':'EMPTY_VERIFIED_NO_AUTHORITY';
 return Object.freeze({verified:true,classification,forensicReviewRequired:classification.endsWith('_REVIEW'),publicationCount:b.publications.length,acknowledgedCount:out.completed,unacknowledgedPublicationIndex:out.openPrepare?.publicationIndex??null,readOnly:true,mayRetry:false,mayAcknowledge:false,mayDeletePending:false,productionApproved:false});
}
