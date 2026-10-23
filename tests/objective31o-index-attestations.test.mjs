import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {
 OFFLINE_ACQUISITION_ATTESTATION_SCHEMA,
 offlineAcquisitionIndexAttestationPolicyDigest,
 offlineAcquisitionIndexAttestationSigningBytes,
 verifyOfflineAcquisitionIndexHeadAttestation,
 verifyOfflineAcquisitionIndexPortableHistory,
 reviewOfflineAcquisitionIndexBranches
} from '../src/offline-acquisition-index-attestations.mjs';
import {OFFLINE_ACQUISITION_INDEX_SCHEMA} from '../src/offline-acquisition-cross-session-index.mjs';

const ROOT='0'.repeat(64),zero={count:0,headDigest:ROOT},registryId='trendyjoes-index-31o',nowMs=1700000000000;
const hash=x=>createHash('sha256').update(x).digest('hex');
const digestRecord=b=>hash(Buffer.from(`${OFFLINE_ACQUISITION_INDEX_SCHEMA}\0${JSON.stringify(b)}`));
const keys=Array.from({length:3},(_,i)=>({...generateKeyPairSync('ed25519'),id:`witness_31o_${i+1}`}));
const witnesses=keys.map(({id,publicKey})=>({id,publicKey})),quorum=2;
const policyDigest=offlineAcquisitionIndexAttestationPolicyDigest({witnesses,quorum});
const clone=x=>structuredClone(x);
const pin=history=>history.length?{count:history.length,headDigest:history.at(-1).digest}:zero;
function makeHistory(labels){
 const entries=[];let previous=ROOT,retention=zero;
 for(const [i,label] of labels.entries()){
  const p={acquisitionId:`acquisition_${label}_0000000`,sessionHead:{count:3,headDigest:hash('session:'+label)},previousRetentionHead:retention,retentionHead:{count:2*i+2,headDigest:hash('retention:'+label)},forensicHeads:{forensic:{count:i+1,headDigest:hash('forensic:'+i)},publication:{count:i+1,headDigest:hash('publication:'+i)},outbox:{count:i+1,headDigest:hash('outbox:'+i)}},manifestDigest:hash('manifest:'+label)};
  const body={schema:OFFLINE_ACQUISITION_INDEX_SCHEMA,index:i+1,previousDigest:previous,payload:p};
  const e={...body,digest:digestRecord(body)};entries.push(e);previous=e.digest;retention=p.retentionHead;
 }
 return entries;
}
function attest(history,{signerIndices=[0,1],nonce='nonce_31o_0000001',overrides={}}={}){
 const body={schema:OFFLINE_ACQUISITION_ATTESTATION_SCHEMA,registryId,head:pin(history),previousHead:pin(history.slice(0,-1)),issuedAt:nowMs-1000,expiresAt:nowMs+60000,nonce,policyDigest,...overrides};
 const bytes=offlineAcquisitionIndexAttestationSigningBytes(body);
 const signatures=signerIndices.map(i=>({witnessId:keys[i].id,signature:sign(null,bytes,keys[i].privateKey).toString('base64url')})).sort((a,b)=>a.witnessId.localeCompare(b.witnessId,'en'));
 return {body,signatures};
}
const verify=a=>verifyOfflineAcquisitionIndexHeadAttestation({attestation:a,witnesses,quorum,registryId,nowMs});
const review=(branches,anchor=zero)=>reviewOfflineAcquisitionIndexBranches({branches,witnesses,quorum,registryId,nowMs,trustedAnchor:anchor});
const branch=(history,nonce)=>({history,attestation:attest(history,{nonce})});
const rejects=(fn,code)=>assert.throws(fn,e=>e.code===code,code);
function rehash(history){let prev=ROOT;for(let i=0;i<history.length;i++){const e=history[i];e.index=i+1;e.previousDigest=prev;const {digest,...b}=e;e.digest=digestRecord(b);prev=e.digest;}return history;}

test('31O independently pinned policy digest stable across witness order',()=>{
 assert.equal(policyDigest,offlineAcquisitionIndexAttestationPolicyDigest({witnesses:witnesses.slice().reverse(),quorum}));
});
test('31O valid majority-signed portable attestation cannot authorize operations',()=>{
 const v=verify(attest(makeHistory(['alpha'])));assert.equal(v.verified,true);assert.equal(v.productionApproved,false);assert.equal(v.mayRetry,false);assert.equal(v.mayAcknowledge,false);assert.equal(v.signerIds.length,2);
});
test('31O majority requirement cannot be reduced to a single signer',()=>rejects(()=>offlineAcquisitionIndexAttestationPolicyDigest({witnesses,quorum:1}),'INDEX_ATTESTATION_POLICY_INVALID'));
test('31O duplicate witness public keys rejected even with distinct IDs',()=>rejects(()=>offlineAcquisitionIndexAttestationPolicyDigest({witnesses:[witnesses[0],{...witnesses[0],id:'different_31o_witness'}],quorum:2}),'INDEX_ATTESTATION_DUPLICATE_KEY'));
test('31O insufficient valid signatures fail closed',()=>rejects(()=>verify(attest(makeHistory(['alpha']),{signerIndices:[0]})),'INDEX_ATTESTATION_QUORUM_INVALID'));
test('31O repeated witness signature cannot satisfy quorum',()=>{const a=attest(makeHistory(['alpha']));a.signatures[1]=clone(a.signatures[0]);rejects(()=>verify(a),'INDEX_ATTESTATION_SIGNATURE_INVALID');});
test('31O unordered signatures rejected',()=>{const a=attest(makeHistory(['alpha']));a.signatures.reverse();rejects(()=>verify(a),'INDEX_ATTESTATION_SIGNATURE_INVALID');});
test('31O forged signature rejected',()=>{const a=attest(makeHistory(['alpha']));a.signatures[0].signature=sign(null,offlineAcquisitionIndexAttestationSigningBytes(a.body),generateKeyPairSync('ed25519').privateKey).toString('base64url');rejects(()=>verify(a),'INDEX_ATTESTATION_SIGNATURE_INVALID');});
test('31O substituted independent witness key rejected',()=>{const a=attest(makeHistory(['alpha']));const bad=witnesses.map((w,i)=>i===0?{...w,publicKey:generateKeyPairSync('ed25519').publicKey}:w);rejects(()=>verifyOfflineAcquisitionIndexHeadAttestation({attestation:a,witnesses:bad,quorum,registryId,nowMs}),'INDEX_ATTESTATION_POLICY_MISMATCH');});
test('31O signer identifier substitution rejected',()=>{const a=attest(makeHistory(['alpha']));a.signatures[0].witnessId='unknown_witness_31o';rejects(()=>verify(a),'INDEX_ATTESTATION_SIGNATURE_INVALID');});
test('31O malformed signature encoding rejected',()=>{const a=attest(makeHistory(['alpha']));a.signatures[0].signature='invalid';rejects(()=>verify(a),'INDEX_ATTESTATION_SIGNATURE_INVALID');});
test('31O altered head invalidates signatures',()=>{const a=attest(makeHistory(['alpha']));a.body.head.headDigest=hash('forged');rejects(()=>verify(a),'INDEX_ATTESTATION_SIGNATURE_INVALID');});
test('31O altered predecessor invalidates signatures',()=>{const a=attest(makeHistory(['alpha','beta']));a.body.previousHead.headDigest=hash('forged');rejects(()=>verify(a),'INDEX_ATTESTATION_SIGNATURE_INVALID');});
test('31O nonce tamper invalidates signatures',()=>{const a=attest(makeHistory(['alpha']));a.body.nonce='nonce_31o_modified';rejects(()=>verify(a),'INDEX_ATTESTATION_SIGNATURE_INVALID');});
test('31O extra body fields rejected',()=>{const a=attest(makeHistory(['alpha']));a.body.permission='retry';rejects(()=>verify(a),'INDEX_ATTESTATION_BODY_INVALID');});
test('31O expired attestation rejected',()=>{const a=attest(makeHistory(['alpha']));rejects(()=>verifyOfflineAcquisitionIndexHeadAttestation({attestation:a,witnesses,quorum,registryId,nowMs:nowMs+60000}),'INDEX_ATTESTATION_EXPIRED_OR_FUTURE');});
test('31O future-dated attestation rejected',()=>{const a=attest(makeHistory(['alpha']));rejects(()=>verifyOfflineAcquisitionIndexHeadAttestation({attestation:a,witnesses,quorum,registryId,nowMs:nowMs-1001}),'INDEX_ATTESTATION_EXPIRED_OR_FUTURE');});
test('31O wrong registry rejected',()=>{const a=attest(makeHistory(['alpha']));rejects(()=>verifyOfflineAcquisitionIndexHeadAttestation({attestation:a,witnesses,quorum,registryId:'other_31o_registry',nowMs}),'INDEX_ATTESTATION_POLICY_MISMATCH');});
test('31O policy digest substitution rejected',()=>{const a=attest(makeHistory(['alpha']));a.body.policyDigest=hash('fake');rejects(()=>verify(a),'INDEX_ATTESTATION_POLICY_MISMATCH');});
test('31O valid portable index structural history matches external anchor',()=>{const h=makeHistory(['alpha','beta']);const v=verifyOfflineAcquisitionIndexPortableHistory({history:h,expectedHead:pin(h),trustedAnchor:pin(h.slice(0,1))});assert.equal(v.verifiedStructuralHistory,true);assert.equal(v.signaturesOfSessionsVerified,false);assert.equal(v.productionApproved,false);});
test('31O altered index record bytes rejected',()=>{const h=makeHistory(['alpha']);h[0].payload.manifestDigest=hash('tamper');rejects(()=>verifyOfflineAcquisitionIndexPortableHistory({history:h,expectedHead:pin(h),trustedAnchor:zero}),'INDEX_ATTESTATION_HISTORY_INVALID');});
test('31O truncated history rejected even when attacker supplies new matching pin',()=>{const h=makeHistory(['alpha','beta']);rejects(()=>verifyOfflineAcquisitionIndexPortableHistory({history:h.slice(0,1),expectedHead:pin(h),trustedAnchor:zero}),'INDEX_ATTESTATION_HISTORY_REQUEST_INVALID');});
test('31O wrong independent nonzero anchor rejects reconstructed history',()=>{const h=makeHistory(['alpha','beta']);rejects(()=>verifyOfflineAcquisitionIndexPortableHistory({history:h,expectedHead:pin(h),trustedAnchor:{count:1,headDigest:hash('wrong')} }),'INDEX_ATTESTATION_ANCHOR_MISMATCH');});
test('31O rehashed replay of acquisition identity rejected',()=>{const h=makeHistory(['alpha','beta']);h[1].payload.acquisitionId=h[0].payload.acquisitionId;rehash(h);rejects(()=>verifyOfflineAcquisitionIndexPortableHistory({history:h,expectedHead:pin(h),trustedAnchor:zero}),'INDEX_ATTESTATION_HISTORY_CONTINUITY');});
test('31O rehashed skipped retention pair rejected',()=>{const h=makeHistory(['alpha','beta']);h[1].payload.previousRetentionHead={count:2,headDigest:hash('wrong-retention')};rehash(h);rejects(()=>verifyOfflineAcquisitionIndexPortableHistory({history:h,expectedHead:pin(h),trustedAnchor:zero}),'INDEX_ATTESTATION_HISTORY_CONTINUITY');});
test('31O rehashed forensic-head rollback rejected',()=>{const h=makeHistory(['alpha','beta']);h[1].payload.forensicHeads.forensic={count:0,headDigest:ROOT};rehash(h);rejects(()=>verifyOfflineAcquisitionIndexPortableHistory({history:h,expectedHead:pin(h),trustedAnchor:zero}),'INDEX_ATTESTATION_HISTORY_CONTINUITY');});
test('31O same-branch different-height attestations share valid prefix',()=>{const h=makeHistory(['alpha','beta']);const v=review([branch(h.slice(0,1),'nonce_31o_0000001'),branch(h,'nonce_31o_0000002')]);assert.equal(v.classification,'CONSISTENT_SIGNED_PREFIXES_ONLY');assert.equal(v.productionApproved,false);});
test('31O independently signed equal-height branch fork produces equivocation evidence',()=>{const a=makeHistory(['alpha','beta']),b=makeHistory(['alpha','gamma']);const v=review([branch(a,'nonce_31o_0000001'),branch(b,'nonce_31o_0000002')],pin(a.slice(0,1)));assert.equal(v.classification,'SIGNED_BRANCH_EQUIVOCATION_EVIDENCE');assert.equal(v.conflict.firstConflictingIndex,2);assert.equal(v.conflict.commonSigners.length,2);assert.equal(v.mayRetry,false);});
test('31O cross-height divergent branch fork detected from full signed prefixes',()=>{const a=makeHistory(['alpha','beta']),b=makeHistory(['alpha','gamma','delta']);const v=review([branch(a,'nonce_31o_0000001'),branch(b,'nonce_31o_0000002')],pin(a.slice(0,1)));assert.equal(v.conflict.firstConflictingIndex,2);});
test('31O same height but no common independently pinned ancestor rejected',()=>{const a=makeHistory(['alpha','beta']),b=makeHistory(['other','gamma']);rejects(()=>review([branch(a,'nonce_31o_0000001'),branch(b,'nonce_31o_0000002')],pin(a.slice(0,1))),'INDEX_ATTESTATION_ANCHOR_MISMATCH');});
test('31O duplicate signed attestation replay rejected',()=>{const h=makeHistory(['alpha']);const b=branch(h,'nonce_31o_0000001');rejects(()=>review([b,clone(b)]),'INDEX_ATTESTATION_REPLAY');});
test('31O attested immediate predecessor must match actual historical record',()=>{const h=makeHistory(['alpha','beta']);const a=attest(h,{overrides:{previousHead:{count:1,headDigest:hash('wrong-previous')}}});rejects(()=>review([{history:h,attestation:a},branch(h,'nonce_31o_0000002')]),'INDEX_ATTESTATION_PREDECESSOR_MISMATCH');});
test('31O forged portable history cannot be legitimized by valid signature over old head',()=>{const h=makeHistory(['alpha','beta']),a=attest(h);h[1].payload.manifestDigest=hash('tampered');rehash(h);rejects(()=>review([{history:h,attestation:a},branch(makeHistory(['alpha']),'nonce_31o_0000002')]),'INDEX_ATTESTATION_ANCHOR_MISMATCH');});
