import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,createHash,sign} from 'node:crypto';
import {OFFLINE_FORENSIC_PUBLICATION_SCHEMA,forensicPublicationPolicyDigest,forensicPublicationRotationBytes,forensicPublicationSigningBytes} from '../src/offline-forensic-head-publication.mjs';
import {OFFLINE_FORENSIC_TRANSITION_SCHEMA,forensicTransitionSigningBytes,forensicTransitionPossessionBytes,verifyOfflineForensicTransitionCertificate,verifyOfflineForensicPublicationTransitions} from '../src/offline-forensic-transition-certificate.mjs';

const ROOT='0'.repeat(64),registryId='synthetic-transition-registry-31j',anchorType='registry';
const sha=x=>createHash('sha256').update(x).digest('hex');
const keys=()=>generateKeyPairSync('ed25519');
const signature=(k,b)=>sign(null,b,k.privateKey).toString('base64url');
const fails=(f,code)=>assert.throws(f,e=>e?.code===code);
function fixture(){
 const wks=[keys(),keys(),keys()],oks=[keys(),keys(),keys()],nks=[keys(),keys(),keys()];
 const witnesses=wks.map((k,i)=>({id:`synthetic-witness-31j-${i}`,publicKey:k.publicKey}));
 const reviewerPolicies=[oks,nks].map((ks,epoch)=>({quorum:2,reviewers:ks.map((k,i)=>({id:`synthetic-reviewer-31j-${epoch}-${i}`,publicKey:k.publicKey,readLatest:async()=>null}))}));
 const cfg={registryId,anchorType,witnesses,witnessQuorum:2,reviewerPolicies};
 function pub(previous,policyIndex,publishedAt){
  const b={schema:OFFLINE_FORENSIC_PUBLICATION_SCHEMA,registryId,anchorType,index:previous?2:1,previousDigest:previous?.digest??ROOT,forensicCount:previous?2:1,forensicHeadDigest:previous?'b'.repeat(64):'a'.repeat(64),policyIndex,policyDigest:forensicPublicationPolicyDigest(reviewerPolicies[policyIndex]),publishedAt};
  const rotationApprovals=previous?oks.slice(0,2).map((k,i)=>({reviewerId:reviewerPolicies[0].reviewers[i].id,signature:signature(k,forensicPublicationRotationBytes(b))})):[];
  const witnessSignatures=wks.slice(0,2).map((k,i)=>({witnessId:witnesses[i].id,signature:signature(k,forensicPublicationSigningBytes(b,rotationApprovals))}));
  const unsigned={...b,rotationApprovals,witnessSignatures};
  return {...unsigned,digest:sha(Buffer.from(`${OFFLINE_FORENSIC_PUBLICATION_SCHEMA}\0${JSON.stringify(unsigned)}`))};
 }
 const a=pub(null,0,1700000000000),b=pub(a,1,1700000002000);
 function certificate(next=b,prior=a,changes={}){
  const body={schema:OFFLINE_FORENSIC_TRANSITION_SCHEMA,registryId,anchorType,fromPolicyIndex:0,toPolicyIndex:1,fromPolicyDigest:forensicPublicationPolicyDigest(reviewerPolicies[0]),toPolicyDigest:forensicPublicationPolicyDigest(reviewerPolicies[1]),publicationIndex:next.index,previousPublicationDigest:prior.digest,publicationDigest:next.digest,challenge:Buffer.alloc(32,7).toString('base64url'),issuedAt:1700000001000,expiresAt:1700000005000,...changes};
  const oldApprovals=oks.slice(0,2).map((k,i)=>({reviewerId:reviewerPolicies[0].reviewers[i].id,signature:signature(k,forensicTransitionSigningBytes(body))}));
  const newKeyPossessions=nks.map((k,i)=>({reviewerId:reviewerPolicies[1].reviewers[i].id,signature:signature(k,forensicTransitionPossessionBytes(body,oldApprovals))}));
  return {body,oldApprovals,newKeyPossessions};
 }
 const cert=certificate();
 const verify=(certs=[cert],publications=[a,b],extra={})=>verifyOfflineForensicPublicationTransitions({...cfg,publications,expectedHead:{count:publications.length,headDigest:publications.at(-1)?.digest??ROOT},transitionCertificates:certs,...extra});
 return {a,b,cert,certificate,verify,cfg,oks,nks,wks};
}
test('31J certified historical reviewer rotation verifies outgoing quorum and all incoming keys',()=>{
 const f=fixture();assert.equal(f.verify().certifiedTransitions,1);
});
test('31J certificate verification directly returns offline-only status',()=>{
 const f=fixture();const r=verifyOfflineForensicTransitionCertificate({certificate:f.cert,registryId,anchorType,previousPublication:f.a,nextPublication:f.b,oldPolicy:f.cfg.reviewerPolicies[0],newPolicy:f.cfg.reviewerPolicies[1]});assert.equal(r.productionApproved,false);
});
test('31J no transition requires no certificates',()=>{
 const f=fixture();assert.equal(f.verify([],[f.a]).certifiedTransitions,0);
});
test('31J missing certificate rejected even though legacy publication signatures valid',()=>{
 const f=fixture();fails(()=>f.verify([]),'FORENSIC_TRANSITION_CERTIFICATE_COUNT');
});
test('31J surplus certificate rejected',()=>{
 const f=fixture();fails(()=>f.verify([f.cert,f.cert]),'FORENSIC_TRANSITION_CERTIFICATE_COUNT');
});
test('31J forged outgoing signature rejected',()=>{
 const f=fixture();f.cert.oldApprovals[0].signature='A'.repeat(86);fails(()=>f.verify(),'FORENSIC_TRANSITION_APPROVAL_INVALID');
});
test('31J missing outgoing quorum rejected',()=>{
 const f=fixture();f.cert.oldApprovals.pop();fails(()=>f.verify(),'FORENSIC_TRANSITION_APPROVAL_INVALID');
});
test('31J duplicate outgoing signer rejected',()=>{
 const f=fixture();f.cert.oldApprovals[1]=f.cert.oldApprovals[0];fails(()=>f.verify(),'FORENSIC_TRANSITION_APPROVAL_INVALID');
});
test('31J new key must sign proof of possession',()=>{
 const f=fixture();f.cert.newKeyPossessions[0].signature='A'.repeat(86);fails(()=>f.verify(),'FORENSIC_TRANSITION_POSSESSION_INVALID');
});
test('31J every incoming reviewer must prove possession',()=>{
 const f=fixture();f.cert.newKeyPossessions.pop();fails(()=>f.verify(),'FORENSIC_TRANSITION_POSSESSION_INVALID');
});
test('31J duplicate incoming proof rejected',()=>{
 const f=fixture();f.cert.newKeyPossessions[2]=f.cert.newKeyPossessions[0];fails(()=>f.verify(),'FORENSIC_TRANSITION_POSSESSION_INVALID');
});
test('31J certificate cannot be bound to a different publication digest',()=>{
 const f=fixture();f.cert.body.publicationDigest='f'.repeat(64);fails(()=>f.verify(),'FORENSIC_TRANSITION_BINDING_INVALID');
});
test('31J certificate cannot be moved to another previous publication',()=>{
 const f=fixture();f.cert.body.previousPublicationDigest='f'.repeat(64);fails(()=>f.verify(),'FORENSIC_TRANSITION_BINDING_INVALID');
});
test('31J certificate cannot approve an alternate incoming policy',()=>{
 const f=fixture();f.cert.body.toPolicyDigest='f'.repeat(64);fails(()=>f.verify(),'FORENSIC_TRANSITION_BINDING_INVALID');
});
test('31J certificate cannot approve an alternate outgoing policy',()=>{
 const f=fixture();f.cert.body.fromPolicyDigest='f'.repeat(64);fails(()=>f.verify(),'FORENSIC_TRANSITION_BINDING_INVALID');
});
test('31J expired certificate at publication time rejected',()=>{
 const f=fixture();f.cert.body.expiresAt=f.b.publishedAt-1;fails(()=>f.verify(),'FORENSIC_TRANSITION_BINDING_INVALID');
});
test('31J future-issued certificate at publication time rejected',()=>{
 const f=fixture();f.cert.body.issuedAt=f.b.publishedAt+1;fails(()=>f.verify(),'FORENSIC_TRANSITION_BINDING_INVALID');
});
test('31J certificate validity window bounded to 15 minutes',()=>{
 const f=fixture();f.cert.body.expiresAt=f.cert.body.issuedAt+900001;fails(()=>f.verify(),'FORENSIC_TRANSITION_BODY_INVALID');
});
test('31J malformed challenge rejected',()=>{
 const f=fixture();f.cert.body.challenge='not-a-challenge';fails(()=>f.verify(),'FORENSIC_TRANSITION_BODY_INVALID');
});
test('31J unknown fields rejected',()=>{
 const f=fixture();f.cert.body.admin=true;fails(()=>f.verify(),'FORENSIC_TRANSITION_BODY_INVALID');
});
test('31J wrong signature domain rejected',()=>{
 const f=fixture();f.cert.newKeyPossessions[0].signature=signature(f.nks[0],forensicTransitionSigningBytes(f.cert.body));fails(()=>f.verify(),'FORENSIC_TRANSITION_POSSESSION_INVALID');
});
test('31J altered old approval invalidates incoming proof even when new old approval valid',()=>{
 const f=fixture();f.cert.oldApprovals.reverse();fails(()=>f.verify(),'FORENSIC_TRANSITION_POSSESSION_INVALID');
});
test('31J old reviewer key cannot impersonate incoming proof',()=>{
 const f=fixture();f.cert.newKeyPossessions[0].signature=signature(f.oks[0],forensicTransitionPossessionBytes(f.cert.body,f.cert.oldApprovals));fails(()=>f.verify(),'FORENSIC_TRANSITION_POSSESSION_INVALID');
});
test('31J cross-shop registry substitution rejected',()=>{
 const f=fixture();fails(()=>f.verify([f.cert],[f.a,f.b],{registryId:'other-synthetic-registry-31j'}),'FORENSIC_PUBLICATION_CHAIN_INVALID');
});
test('31J publication rollback pin remains mandatory',()=>{
 const f=fixture();fails(()=>f.verify([f.cert],[f.a,f.b],{expectedHead:{count:1,headDigest:f.a.digest}}),'FORENSIC_PUBLICATION_PIN_MISMATCH');
});
