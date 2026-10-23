import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync} from 'node:crypto';
import {serializeOfflineWitnessRoster} from '../src/preview-local-artwork-review-witness-roster-ledger.mjs';
import {createOfflineWitnessRosterEpochTransition} from '../src/preview-local-artwork-review-witness-epoch.mjs';
import {OFFLINE_EPOCH_HEAD_SCHEMA,createOfflineEpochGenesis} from '../src/preview-local-artwork-review-epoch-head-registry.mjs';
import {createOfflineEpochChainEvidence,createOfflineEpochObserverReceipt}
 from '../src/preview-local-artwork-review-epoch-observer-evidence.mjs';
import {createOfflineEpochTransitionProvenance,verifyOfflineEpochTransitionProvenance,
 inspectOfflineEpochObserverViewsWithProvenance} from '../src/preview-local-artwork-review-epoch-transition-provenance.mjs';
const sha=x=>createHash('sha256').update(x).digest('hex');
const fp=k=>sha(k.export({type:'spki',format:'der'}));
const now=1700000000000,namespacePin=sha('35AK-namespace'),rootPin=sha('35AK-root');
const registryId=sha('35AK-registry'),policySignerFingerprint=sha('35AK-policy'),audience=sha('35AK-audience');
const issuer1=generateKeyPairSync('ed25519'),issuer2=generateKeyPairSync('ed25519');
const observer1=generateKeyPairSync('ed25519'),observer2=generateKeyPairSync('ed25519');
const w1=generateKeyPairSync('ed25519'),w2=generateKeyPairSync('ed25519');
const witnesses=[{witnessId:sha('35AK-w1'),publicKeyFingerprint:fp(w1.publicKey),status:'active'},
 {witnessId:sha('35AK-w2'),publicKeyFingerprint:fp(w2.publicKey),status:'active'}]
 .sort((a,b)=>a.witnessId.localeCompare(b.witnessId));
const base={rootPin,registryId,policySignerFingerprint,audience};
const r0=serializeOfflineWitnessRoster({...base,validFromMs:now-30000,validUntilMs:now-1000,witnesses});
const r1=serializeOfflineWitnessRoster({...base,validFromMs:now-15000,validUntilMs:now+1000,
 witnesses:[{...witnesses[0],status:'revoked'},witnesses[1]]});
const r2=serializeOfflineWitnessRoster({...base,validFromMs:now-4000,validUntilMs:now+15000,
 witnesses:[witnesses[0],{...witnesses[1],status:'revoked'}]});
const g=createOfflineEpochGenesis({namespacePin,rootPin,registryId,epoch:5,rosterSha256:r0.sha256});
const t1=createOfflineWitnessRosterEpochTransition({signingKey:issuer1.privateKey,...base,
 previousRosterSha256:r0.sha256,nextRosterSha256:r1.sha256,previousEpoch:5,nextEpoch:6,cutoverMs:now-10000});
const t2=createOfflineWitnessRosterEpochTransition({signingKey:issuer2.privateKey,...base,
 previousRosterSha256:r1.sha256,nextRosterSha256:r2.sha256,previousEpoch:6,nextEpoch:7,cutoverMs:now-2000});
const rec=(prior,roster,transition)=>Buffer.from(JSON.stringify({schema:OFFLINE_EPOCH_HEAD_SCHEMA,
 namespacePin,rootPin,registryId,epoch:prior.epoch+1,rosterSha256:roster.sha256,
 transitionSha256:transition.sha256,previousRecordSha256:prior.recordSha256,authority:'NONE'}));
const record1=rec(g.head,r1,t1),head1={epoch:6,rosterSha256:r1.sha256,recordSha256:sha(record1)};
const record2=rec(head1,r2,t2),head2={epoch:7,rosterSha256:r2.sha256,recordSha256:sha(record2)};
const records=[g.bytes,record1,record2];
const evidence=createOfflineEpochChainEvidence({recordBytes:records,namespacePin,rootPin,registryId,
 expectedGenesisSha256:g.head.recordSha256,expectedHead:head2});
const issuerPins=[{issuerPublicKey:issuer1.publicKey,expectedIssuerKeyFingerprint:fp(issuer1.publicKey)},
 {issuerPublicKey:issuer2.publicKey,expectedIssuerKeyFingerprint:fp(issuer2.publicKey)}];
const steps=[{transitionBytes:t1.bytes,nextRosterBytes:r1.bytes},{transitionBytes:t2.bytes,nextRosterBytes:r2.bytes}];
const provenance=createOfflineEpochTransitionProvenance({evidenceBytes:evidence.bytes,
 genesisRosterBytes:r0.bytes,transitions:steps});
const pins={expectedNamespacePin:namespacePin,expectedRootPin:rootPin,
 expectedRegistryId:registryId,expectedGenesisSha256:g.head.recordSha256,
 expectedHead:head2,expectedEvidenceSha256:evidence.sha256,
 expectedPolicySignerFingerprint:policySignerFingerprint,expectedAudience:audience,
 expectedGenesisRosterSha256:r0.sha256,trustedNowMs:now};
const verify=(overrides={})=>verifyOfflineEpochTransitionProvenance({provenanceBytes:provenance.bytes,
 expectedProvenanceSha256:provenance.sha256,expectedIssuerPins:issuerPins,...pins,...overrides});
const invalid=(args,code)=>assert.throws(()=>verify(args),{code});
const json=b=>JSON.parse(b.toString('utf8'));
const alter=(bytes,fn)=>{const obj=json(bytes);fn(obj);const changed=Buffer.from(JSON.stringify(obj));
 return {provenanceBytes:changed,expectedProvenanceSha256:sha(changed)};};
const b64=b=>b.toString('base64url');
const un64=s=>Buffer.from(s,'base64url');
test('35AK two historical issuer-signed cutovers and current roster verified',()=>{
 const v=verify();assert.equal(v.transitionCount,2);assert.equal(v.chainHashesVerified,true);
 assert.equal(v.transitionSignaturesVerified,true);assert.equal(v.rosterPoliciesVerified,true);
 assert.equal(v.latestRosterSha256,r2.sha256);assert.equal(v.independentCustodyVerified,false);
 assert.equal(v.trustedClockIndependentlyVerified,false);assert.equal(v.authorizesProduction,false);
});
test('35AK deterministic transport, does not self-certify issuer signatures',()=>{
 assert.deepEqual(createOfflineEpochTransitionProvenance({evidenceBytes:evidence.bytes,
  genesisRosterBytes:r0.bytes,transitions:steps}).bytes,provenance.bytes);
 assert.equal(provenance.transitionSignaturesVerified,false);
});
test('35AK historical first roster expired today yet signed cutover still validates',()=>{
 assert.ok(json(r0.bytes).validUntilMs<now);assert.equal(verify().transitionCount,2);
});
test('35AK genesis-only evidence validates current roster without issuer',()=>{
 const ev=createOfflineEpochChainEvidence({recordBytes:[g.bytes],namespacePin,rootPin,registryId,
  expectedGenesisSha256:g.head.recordSha256,expectedHead:g.head});
 const b=createOfflineEpochTransitionProvenance({evidenceBytes:ev.bytes,
  genesisRosterBytes:r0.bytes,transitions:[]});
 assert.equal(verifyOfflineEpochTransitionProvenance({provenanceBytes:b.bytes,
  expectedProvenanceSha256:b.sha256,expectedIssuerPins:[],...pins,
  expectedEvidenceSha256:ev.sha256,expectedHead:g.head,trustedNowMs:now-20000}).transitionCount,0);
});
for(const [label,change,code] of [
 ['missing external issuer keys',{expectedIssuerPins:undefined},'OFFLINE_EPOCH_PROVENANCE_MISSING_EXTERNAL_PINS'],
 ['wrong provenance digest',{expectedProvenanceSha256:sha('other')},'OFFLINE_EPOCH_PROVENANCE_DIGEST_MISMATCH'],
 ['wrong evidence digest',{expectedEvidenceSha256:sha('other')},'OFFLINE_EPOCH_PROVENANCE_EVIDENCE_MISMATCH'],
 ['wrong root',{expectedRootPin:sha('other')},'OFFLINE_EPOCH_EVIDENCE_PIN_MISMATCH'],
 ['wrong registry',{expectedRegistryId:sha('other')},'OFFLINE_EPOCH_EVIDENCE_PIN_MISMATCH'],
 ['wrong namespace',{expectedNamespacePin:sha('other')},'OFFLINE_EPOCH_EVIDENCE_PIN_MISMATCH'],
 ['wrong genesis pin',{expectedGenesisSha256:sha('other')},'OFFLINE_EPOCH_EVIDENCE_PIN_MISMATCH'],
 ['wrong head',{expectedHead:{...head2,recordSha256:sha('other')}},'OFFLINE_EPOCH_EVIDENCE_PIN_MISMATCH'],
 ['wrong genesis roster pin',{expectedGenesisRosterSha256:sha('other')},'OFFLINE_EPOCH_PROVENANCE_GENESIS_ROSTER_MISMATCH'],
 ['wrong policy signer',{expectedPolicySignerFingerprint:sha('other')},'OFFLINE_EPOCH_HEAD_MISMATCH'],
 ['wrong audience',{expectedAudience:sha('other')},'OFFLINE_EPOCH_HEAD_MISMATCH'],
 ['future cutover',{trustedNowMs:now-3000},'OFFLINE_EPOCH_PROVENANCE_INVALID_CUTOVER'],
 ['latest roster expired',{trustedNowMs:now+15000},'OFFLINE_ROSTER_OUTSIDE_VALIDITY'],
 ['missing head',{expectedHead:undefined},'OFFLINE_EPOCH_PROVENANCE_MISSING_EXTERNAL_PINS'],
 ['issuer key substituted',{expectedIssuerPins:[{issuerPublicKey:issuer2.publicKey,
  expectedIssuerKeyFingerprint:fp(issuer2.publicKey)},issuerPins[1]]},'OFFLINE_EPOCH_SIGNER_SUBSTITUTION'],
 ['issuer fingerprint substituted',{expectedIssuerPins:[{...issuerPins[0],
  expectedIssuerKeyFingerprint:fp(issuer2.publicKey)},issuerPins[1]]},'OFFLINE_EPOCH_MISSING_EXTERNAL_PINS'],
 ['wrong issuer count',{expectedIssuerPins:[issuerPins[0]]},'OFFLINE_EPOCH_PROVENANCE_INVALID_STEPS'],
])test(`35AK rejects ${label}`,()=>invalid(change,code));
test('35AK rejects missing middle transition even if package SHA is repinned',()=>{
 const p=alter(provenance.bytes,o=>o.transitions.splice(0,1));
 invalid(p,'OFFLINE_EPOCH_PROVENANCE_INVALID_STEPS');
});
test('35AK rejects inserted unreferenced transition',()=>{
 const p=alter(provenance.bytes,o=>o.transitions.push(o.transitions[0]));
 invalid({...p,expectedIssuerPins:[...issuerPins,issuerPins[0]]},'OFFLINE_EPOCH_PROVENANCE_INCOMPLETE_CHAIN');
});
test('35AK rejects genesis roster substitution with new transport digest',()=>{
 const p=alter(provenance.bytes,o=>o.genesisRoster=b64(r1.bytes));
 invalid(p,'OFFLINE_EPOCH_PROVENANCE_GENESIS_ROSTER_MISMATCH');
});
test('35AK rejects later roster substitution with repinned package digest',()=>{
 const p=alter(provenance.bytes,o=>o.transitions[1].nextRoster=b64(r1.bytes));
 invalid(p,'OFFLINE_EPOCH_PROVENANCE_RECORD_MISMATCH');
});
test('35AK rejects swapped transition order with repinned package digest',()=>{
 const p=alter(provenance.bytes,o=>o.transitions.reverse());
 invalid(p,'OFFLINE_EPOCH_PROVENANCE_RECORD_MISMATCH');
});
test('35AK rejects altered issuer signature even when record digest re-pinned in transport',()=>{
 const p=alter(provenance.bytes,o=>{const t=json(un64(o.transitions[0].transition));
  t.signature='A'.repeat(86);o.transitions[0].transition=b64(Buffer.from(JSON.stringify(t)));});
 invalid(p,'OFFLINE_EPOCH_PROVENANCE_RECORD_MISMATCH');
});
test('35AK forged transition and rebuilt chain fail with retained independent genesis/head',()=>{
 const fake=createOfflineWitnessRosterEpochTransition({signingKey:issuer2.privateKey,...base,
  previousRosterSha256:r0.sha256,nextRosterSha256:r1.sha256,previousEpoch:5,nextEpoch:6,cutoverMs:now-10000});
 const fakeRecord=rec(g.head,r1,fake),fakeHead={epoch:6,rosterSha256:r1.sha256,recordSha256:sha(fakeRecord)};
 const fakeEv=createOfflineEpochChainEvidence({recordBytes:[g.bytes,fakeRecord],namespacePin,rootPin,registryId,
  expectedGenesisSha256:g.head.recordSha256,expectedHead:fakeHead});
 const fakePkg=createOfflineEpochTransitionProvenance({evidenceBytes:fakeEv.bytes,
  genesisRosterBytes:r0.bytes,transitions:[{transitionBytes:fake.bytes,nextRosterBytes:r1.bytes}]});
 invalid({provenanceBytes:fakePkg.bytes,expectedProvenanceSha256:fakePkg.sha256,
  expectedEvidenceSha256:fakeEv.sha256,expectedIssuerPins:[issuerPins[0]]},
 'OFFLINE_EPOCH_EVIDENCE_PIN_MISMATCH');
});
test('35AK forged issuer signature rejected even when attacker rebuilds chain and supplies new head pins',()=>{
 const t=json(t1.bytes);t.signature='A'.repeat(86);
 const forgedBytes=Buffer.from(JSON.stringify(t));
 const forgedT={bytes:forgedBytes,sha256:sha(forgedBytes)};
 const forgedRec1=rec(g.head,r1,forgedT);
 const forgedHead1={epoch:6,rosterSha256:r1.sha256,recordSha256:sha(forgedRec1)};
 const forgedRec2=rec(forgedHead1,r2,t2);
 const forgedHead2={epoch:7,rosterSha256:r2.sha256,recordSha256:sha(forgedRec2)};
 const forgedEvidence=createOfflineEpochChainEvidence({recordBytes:[g.bytes,forgedRec1,forgedRec2],
  namespacePin,rootPin,registryId,expectedGenesisSha256:g.head.recordSha256,expectedHead:forgedHead2});
 const forgedPackage=createOfflineEpochTransitionProvenance({evidenceBytes:forgedEvidence.bytes,
  genesisRosterBytes:r0.bytes,transitions:[{transitionBytes:forgedBytes,nextRosterBytes:r1.bytes},steps[1]]});
 invalid({provenanceBytes:forgedPackage.bytes,expectedProvenanceSha256:forgedPackage.sha256,
  expectedEvidenceSha256:forgedEvidence.sha256,expectedHead:forgedHead2},'OFFLINE_EPOCH_BAD_SIGNATURE');
});
test('35AK historical roster policy substitution rejected even with rebuilt signed transition',()=>{
 const badRoster=serializeOfflineWitnessRoster({...base,policySignerFingerprint:sha('wrong-policy'),
  validFromMs:now-15000,validUntilMs:now+1000,witnesses});
 const newT1=createOfflineWitnessRosterEpochTransition({signingKey:issuer1.privateKey,...base,
  previousRosterSha256:r0.sha256,nextRosterSha256:badRoster.sha256,
  previousEpoch:5,nextEpoch:6,cutoverMs:now-10000});
 const badRec1=rec(g.head,badRoster,newT1),badHead1={epoch:6,
  rosterSha256:badRoster.sha256,recordSha256:sha(badRec1)};
 const badT2=createOfflineWitnessRosterEpochTransition({signingKey:issuer2.privateKey,...base,
  previousRosterSha256:badRoster.sha256,nextRosterSha256:r2.sha256,
  previousEpoch:6,nextEpoch:7,cutoverMs:now-2000});
 const badRec2=rec(badHead1,r2,badT2),badHead2={epoch:7,
  rosterSha256:r2.sha256,recordSha256:sha(badRec2)};
 const ev=createOfflineEpochChainEvidence({recordBytes:[g.bytes,badRec1,badRec2],
  namespacePin,rootPin,registryId,expectedGenesisSha256:g.head.recordSha256,expectedHead:badHead2});
 const pack=createOfflineEpochTransitionProvenance({evidenceBytes:ev.bytes,
  genesisRosterBytes:r0.bytes,transitions:[{transitionBytes:newT1.bytes,nextRosterBytes:badRoster.bytes},
   {transitionBytes:badT2.bytes,nextRosterBytes:r2.bytes}]});
 invalid({provenanceBytes:pack.bytes,expectedProvenanceSha256:pack.sha256,
  expectedEvidenceSha256:ev.sha256,expectedHead:badHead2},'OFFLINE_ROSTER_INVALID_POLICY');
});
test('35AK rejects noncanonical transport key order even with repinned digest',()=>{
 const o=json(provenance.bytes);const raw=Buffer.from(JSON.stringify({authority:o.authority,...o}));
 invalid({provenanceBytes:raw,expectedProvenanceSha256:sha(raw)},'OFFLINE_EPOCH_PROVENANCE_NONCANONICAL');
});
test('35AK rejects extra transport property even with repinned digest',()=>{
 const p=alter(provenance.bytes,o=>o.elevated=true);
 invalid(p,'OFFLINE_EPOCH_PROVENANCE_NONCANONICAL');
});
test('35AK rejects padded noncanonical base64 even with repinned digest',()=>{
 const p=alter(provenance.bytes,o=>o.genesisRoster+='=');
 invalid(p,'OFFLINE_EPOCH_PROVENANCE_INVALID_BYTES');
});
test('35AK rejects changed embedded evidence even if outer digest repinned',()=>{
 const p=alter(provenance.bytes,o=>o.evidence=b64(Buffer.from('bad evidence')));
 invalid(p,'OFFLINE_EPOCH_PROVENANCE_EVIDENCE_MISMATCH');
});
test('35AK rejects truncated/oversized transport',()=>{
 invalid({provenanceBytes:Buffer.from('')},'OFFLINE_EPOCH_PROVENANCE_INVALID_BYTES');
 invalid({provenanceBytes:Buffer.alloc(2_000_001)},'OFFLINE_EPOCH_PROVENANCE_INVALID_BYTES');
});
test('35AK rejects no externally supplied time',()=>invalid({trustedNowMs:undefined},'OFFLINE_EPOCH_PROVENANCE_MISSING_EXTERNAL_PINS'));
test('35AK rejects historical cutover reordering even with signed individual transitions',()=>{
 const badT2=createOfflineWitnessRosterEpochTransition({signingKey:issuer2.privateKey,...base,
  previousRosterSha256:r1.sha256,nextRosterSha256:r2.sha256,previousEpoch:6,nextEpoch:7,cutoverMs:now-12000});
 const badRec2=rec(head1,r2,badT2),badHead2={epoch:7,rosterSha256:r2.sha256,recordSha256:sha(badRec2)};
 const badEv=createOfflineEpochChainEvidence({recordBytes:[g.bytes,record1,badRec2],namespacePin,rootPin,registryId,
  expectedGenesisSha256:g.head.recordSha256,expectedHead:badHead2});
 const badPkg=createOfflineEpochTransitionProvenance({evidenceBytes:badEv.bytes,
  genesisRosterBytes:r0.bytes,transitions:[steps[0],{transitionBytes:badT2.bytes,nextRosterBytes:r2.bytes}]});
 invalid({provenanceBytes:badPkg.bytes,expectedProvenanceSha256:badPkg.sha256,
  expectedEvidenceSha256:badEv.sha256,expectedHead:badHead2},'OFFLINE_EPOCH_PROVENANCE_INVALID_CUTOVER');
});
const obs=(key,id,challenge)=>{
 const receipt=createOfflineEpochObserverReceipt({signingKey:key.privateKey,observerId:id,
  namespacePin,rootPin,registryId,audience,challenge,evidenceSha256:evidence.sha256,
  headEpoch:head2.epoch,headRecordSha256:head2.recordSha256,
  issuedAtMs:now-100,expiresAtMs:now+100});
 return {view:{evidenceBytes:evidence.bytes,receiptBytes:receipt.bytes,observerPublicKey:key.publicKey},
  pin:{observerId:id,observerKeyFingerprint:fp(key.publicKey),receiptSha256:receipt.sha256,
   challenge,expectedHead:head2}};
};
const oa=obs(observer1,sha('observer1'),sha('challenge1'));
const ob=obs(observer2,sha('observer2'),sha('challenge2'));
const views=[oa.view,ob.view],observerPins=[oa.pin,ob.pin];
const bundles=[{provenanceBytes:provenance.bytes,expectedProvenanceSha256:provenance.sha256},
 {provenanceBytes:provenance.bytes,expectedProvenanceSha256:provenance.sha256}];
const inspect=(overrides={})=>inspectOfflineEpochObserverViewsWithProvenance({views,observerPins,
 provenanceBundles:bundles,issuerPinsByView:[issuerPins,issuerPins],
 expectedNamespacePin:namespacePin,expectedRootPin:rootPin,
 expectedRegistryId:registryId,expectedGenesisSha256:g.head.recordSha256,
 expectedPolicySignerFingerprint:policySignerFingerprint,expectedAudience:audience,
 expectedGenesisRosterSha256:r0.sha256,trustedNowMs:now,...overrides});
test('35AK independently pinned observer receipts plus issuer provenance agree',()=>{
 const v=inspect();assert.equal(v.relationship,'AGREEMENT');assert.equal(v.provenanceVerifiedViews,2);
 assert.equal(v.transitionSignaturesVerified,true);assert.equal(v.authorizesProduction,false);
 assert.equal(v.crossHostConsensusVerified,false);
});
test('35AK observer adjudication refuses a missing provenance bundle',()=>{
 assert.throws(()=>inspect({provenanceBundles:[bundles[0]]}),{code:'OFFLINE_EPOCH_PROVENANCE_INVALID_VIEWS'});
});
test('35AK observer adjudication refuses one view with a forged provenance digest',()=>{
 assert.throws(()=>inspect({provenanceBundles:[bundles[0],{...bundles[1],
  expectedProvenanceSha256:sha('other')}]}),{code:'OFFLINE_EPOCH_PROVENANCE_DIGEST_MISMATCH'});
});
test('35AK observer adjudication refuses substituted second issuer key',()=>{
 assert.throws(()=>inspect({issuerPinsByView:[issuerPins,[issuerPins[0],issuerPins[0]]]}),
  {code:'OFFLINE_EPOCH_SIGNER_SUBSTITUTION'});
});
test('35AK observer adjudication rejects expired observer even with valid provenance',()=>{
 assert.throws(()=>inspect({trustedNowMs:now+100}),{code:'OFFLINE_EPOCH_OBSERVER_EXPIRED'});
});
test('35AK transport rejects sparse step array',()=>{
 const sparse=new Array(1);assert.throws(()=>createOfflineEpochTransitionProvenance({evidenceBytes:evidence.bytes,
  genesisRosterBytes:r0.bytes,transitions:sparse}),{code:'OFFLINE_EPOCH_PROVENANCE_INVALID_STEPS'});
});
