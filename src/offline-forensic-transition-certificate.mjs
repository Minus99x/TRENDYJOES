/**
 * Objective 31J: opt-in, offline reviewer-policy transition certificates.
 * A certificate is signed by the outgoing quorum and all incoming reviewer
 * keys (proof of possession). It is bound to one signed publication record.
 * These are synthetic/local contracts, not a deployed PKI or trusted clock.
 */
import {createHash,verify as verifySignature} from 'node:crypto';
import {forensicPublicationPolicyDigest,verifyOfflineForensicPublicationHistory,verifyOfflinePublishedForensicEvidenceBundle} from './offline-forensic-head-publication.mjs';
import {validateOfflineRecoveryReviewers} from './offline-recovery-adjudication.mjs';

export const OFFLINE_FORENSIC_TRANSITION_SCHEMA='TJ-OFFLINE-FORENSIC-TRANSITION-CERT-1';
const ID=/^[A-Za-z0-9_-]{12,80}$/,HEX=/^[0-9a-f]{64}$/;
const BODY=['schema','registryId','anchorType','fromPolicyIndex','toPolicyIndex','fromPolicyDigest','toPolicyDigest','publicationIndex','previousPublicationDigest','publicationDigest','challenge','issuedAt','expiresAt'];
const fail=code=>{throw Object.assign(Error(code),{code});};
const obj=x=>x!==null&&typeof x==='object'&&!Array.isArray(x)&&[Object.prototype,null].includes(Object.getPrototypeOf(x));
const exact=(x,keys)=>obj(x)&&Object.keys(x).sort().join('|')===keys.slice().sort().join('|');
const canonicalSig=s=>typeof s==='string'&&/^[A-Za-z0-9_-]{86}$/.test(s)&&Buffer.from(s,'base64url').length===64&&Buffer.from(s,'base64url').toString('base64url')===s;
const signed=(key,bytes,s)=>canonicalSig(s)&&verifySignature(null,bytes,key,Buffer.from(s,'base64url'));
function checkBody(b){
 if(!exact(b,BODY)||b.schema!==OFFLINE_FORENSIC_TRANSITION_SCHEMA||!ID.test(b.registryId||'')||!['registry','journal'].includes(b.anchorType)||!Number.isSafeInteger(b.fromPolicyIndex)||b.fromPolicyIndex<0||b.fromPolicyIndex>18||b.toPolicyIndex!==b.fromPolicyIndex+1||!HEX.test(b.fromPolicyDigest)||!HEX.test(b.toPolicyDigest)||!Number.isSafeInteger(b.publicationIndex)||b.publicationIndex<2||b.publicationIndex>1000||!HEX.test(b.previousPublicationDigest)||!HEX.test(b.publicationDigest)||typeof b.challenge!=='string'||!(/^[A-Za-z0-9_-]{43}$/.test(b.challenge))||Buffer.from(b.challenge,'base64url').length!==32||Buffer.from(b.challenge,'base64url').toString('base64url')!==b.challenge||!Number.isSafeInteger(b.issuedAt)||b.issuedAt<0||!Number.isSafeInteger(b.expiresAt)||b.expiresAt<=b.issuedAt||b.expiresAt-b.issuedAt>900000)fail('FORENSIC_TRANSITION_BODY_INVALID');
}
export function forensicTransitionSigningBytes(body){
 checkBody(body);return Buffer.from(`${OFFLINE_FORENSIC_TRANSITION_SCHEMA}\0${JSON.stringify(body)}`);
}
export function forensicTransitionPossessionBytes(body,oldApprovals){
 checkBody(body);
 if(!Array.isArray(oldApprovals)||oldApprovals.length<2)fail('FORENSIC_TRANSITION_APPROVAL_INVALID');
 return Buffer.from(`${OFFLINE_FORENSIC_TRANSITION_SCHEMA}:POSSESSION\0${JSON.stringify({body,oldApprovals})}`);
}
function verifyEntries(entries,members,required,bytes,field,code,requireAll=false){
 if(!Array.isArray(entries)||entries.length<required||entries.length>members.length||(requireAll&&entries.length!==members.length))fail(code);
 const byId=new Map(members.map(m=>[m.id,m.publicKey])),seen=new Set();
 for(const r of entries){
  if(!exact(r,[field,'signature'])||!byId.has(r[field])||seen.has(r[field])||!signed(byId.get(r[field]),bytes,r.signature))fail(code);
  seen.add(r[field]);
 }
}
export function verifyOfflineForensicTransitionCertificate({certificate,registryId,anchorType,previousPublication,nextPublication,oldPolicy,newPolicy}={}){
 if(!exact(certificate,['body','oldApprovals','newKeyPossessions'])||!obj(previousPublication)||!obj(nextPublication)||!obj(oldPolicy)||!obj(newPolicy))fail('FORENSIC_TRANSITION_REQUEST_INVALID');
 const b=certificate.body;checkBody(b);
 validateOfflineRecoveryReviewers(oldPolicy.reviewers,oldPolicy.quorum);
 validateOfflineRecoveryReviewers(newPolicy.reviewers,newPolicy.quorum);
 if(b.registryId!==registryId||b.anchorType!==anchorType||b.fromPolicyIndex!==previousPublication.policyIndex||b.toPolicyIndex!==nextPublication.policyIndex||b.fromPolicyDigest!==forensicPublicationPolicyDigest(oldPolicy)||b.toPolicyDigest!==forensicPublicationPolicyDigest(newPolicy)||b.publicationIndex!==nextPublication.index||b.previousPublicationDigest!==previousPublication.digest||b.publicationDigest!==nextPublication.digest||nextPublication.previousDigest!==previousPublication.digest||b.issuedAt>nextPublication.publishedAt||b.expiresAt<nextPublication.publishedAt)fail('FORENSIC_TRANSITION_BINDING_INVALID');
 const oldBytes=forensicTransitionSigningBytes(b);
 verifyEntries(certificate.oldApprovals,oldPolicy.reviewers,oldPolicy.quorum,oldBytes,'reviewerId','FORENSIC_TRANSITION_APPROVAL_INVALID');
 // Require proof from EVERY incoming key, not just newly introduced keys.
 // A retained key cannot be silently bound to an altered policy either.
 verifyEntries(certificate.newKeyPossessions,newPolicy.reviewers,newPolicy.reviewers.length,forensicTransitionPossessionBytes(b,certificate.oldApprovals),'reviewerId','FORENSIC_TRANSITION_POSSESSION_INVALID',true);
 return Object.freeze({verified:true,publicationIndex:b.publicationIndex,fromPolicyIndex:b.fromPolicyIndex,toPolicyIndex:b.toPolicyIndex,productionApproved:false});
}
/** Stricter opt-in verifier. Existing v0.30.10 verifier remains unchanged for
 * historical archives; callers must use this method to REQUIRE certificates. */
export function verifyOfflineForensicPublicationTransitions({registryId,anchorType,witnesses,witnessQuorum,reviewerPolicies,publications,expectedHead,expectedForensicHead,transitionCertificates}={}){
 const history=verifyOfflineForensicPublicationHistory({registryId,anchorType,witnesses,witnessQuorum,reviewerPolicies,publications,expectedHead,expectedForensicHead});
 if(!Array.isArray(transitionCertificates))fail('FORENSIC_TRANSITION_CERTIFICATES_REQUIRED');
 const transitions=[];
 for(let i=1;i<publications.length;i++)if(publications[i].policyIndex!==publications[i-1].policyIndex)transitions.push([publications[i-1],publications[i]]);
 if(transitionCertificates.length!==transitions.length)fail('FORENSIC_TRANSITION_CERTIFICATE_COUNT');
 for(let i=0;i<transitions.length;i++){
  const [prev,next]=transitions[i];
  verifyOfflineForensicTransitionCertificate({certificate:transitionCertificates[i],registryId,anchorType,previousPublication:prev,nextPublication:next,oldPolicy:reviewerPolicies[prev.policyIndex],newPolicy:reviewerPolicies[next.policyIndex]});
 }
 return Object.freeze({...history,certifiedTransitions:transitions.length,productionApproved:false});
}
export function verifyOfflinePublishedForensicEvidenceWithTransitions(args={}){
 const bundle=verifyOfflinePublishedForensicEvidenceBundle(args);
 const transitions=verifyOfflineForensicPublicationTransitions({...args,expectedHead:args.expectedPublicationHead});
 return Object.freeze({...bundle,certifiedTransitions:transitions.certifiedTransitions,productionApproved:false});
}
