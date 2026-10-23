import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync} from 'node:crypto';
import {serializeOfflineWitnessRoster} from '../src/preview-local-artwork-review-witness-roster-ledger.mjs';
import {createOfflineWitnessRosterEpochTransition} from '../src/preview-local-artwork-review-witness-epoch.mjs';
import {OFFLINE_EPOCH_HEAD_SCHEMA,createOfflineEpochGenesis} from '../src/preview-local-artwork-review-epoch-head-registry.mjs';
import {createOfflineEpochChainEvidence} from '../src/preview-local-artwork-review-epoch-observer-evidence.mjs';
import {createOfflineEpochTransitionProvenance} from '../src/preview-local-artwork-review-epoch-transition-provenance.mjs';
import {verifyOfflineRetainedEpochContinuity,OFFLINE_RETAINED_EPOCH_CONTINUITY_SCHEMA}
 from '../src/preview-local-artwork-review-retained-epoch-continuity.mjs';
const sha=x=>createHash('sha256').update(x).digest('hex');
const fp=k=>sha(k.export({type:'spki',format:'der'}));
const now=1700000000000;
const namespacePin=sha('35AL namespace'),rootPin=sha('35AL root'),registryId=sha('35AL registry');
const policySignerFingerprint=sha('35AL policy'),audience=sha('35AL audience');
const issuer1=generateKeyPairSync('ed25519'),issuer2=generateKeyPairSync('ed25519');
const w1=generateKeyPairSync('ed25519'),w2=generateKeyPairSync('ed25519');
const witnesses=[{witnessId:sha('35AL witness1'),publicKeyFingerprint:fp(w1.publicKey),status:'active'},
 {witnessId:sha('35AL witness2'),publicKeyFingerprint:fp(w2.publicKey),status:'active'}]
 .sort((a,b)=>a.witnessId.localeCompare(b.witnessId));
const base={rootPin,registryId,policySignerFingerprint,audience};
const r0=serializeOfflineWitnessRoster({...base,validFromMs:now-30000,
 validUntilMs:now-1000,witnesses});
const r1=serializeOfflineWitnessRoster({...base,validFromMs:now-15000,
 validUntilMs:now+1000,witnesses:[{...witnesses[0],status:'revoked'},witnesses[1]]});
const r2=serializeOfflineWitnessRoster({...base,validFromMs:now-4000,
 validUntilMs:now+15000,witnesses:[witnesses[0],{...witnesses[1],status:'revoked'}]});
const g=createOfflineEpochGenesis({namespacePin,rootPin,registryId,epoch:5,rosterSha256:r0.sha256});
const makeT=(key,prior,next,from,to,cutoverMs)=>createOfflineWitnessRosterEpochTransition({
 signingKey:key.privateKey,...base,previousRosterSha256:prior.sha256,nextRosterSha256:next.sha256,
 previousEpoch:from,nextEpoch:to,cutoverMs});
const t1=makeT(issuer1,r0,r1,5,6,now-10000),t2=makeT(issuer2,r1,r2,6,7,now-2000);
const rec=(prior,roster,t)=>Buffer.from(JSON.stringify({schema:OFFLINE_EPOCH_HEAD_SCHEMA,
 namespacePin,rootPin,registryId,epoch:prior.epoch+1,rosterSha256:roster.sha256,
 transitionSha256:t.sha256,previousRecordSha256:prior.recordSha256,authority:'NONE'}));
const b1=rec(g.head,r1,t1),head1={epoch:6,rosterSha256:r1.sha256,recordSha256:sha(b1)};
const b2=rec(head1,r2,t2),head2={epoch:7,rosterSha256:r2.sha256,recordSha256:sha(b2)};
const issuerPins=[{issuerPublicKey:issuer1.publicKey,expectedIssuerKeyFingerprint:fp(issuer1.publicKey)},
 {issuerPublicKey:issuer2.publicKey,expectedIssuerKeyFingerprint:fp(issuer2.publicKey)}];
function makeSnapshot(records,head,steps,at){
 const evidence=createOfflineEpochChainEvidence({recordBytes:records,namespacePin,rootPin,registryId,
  expectedGenesisSha256:g.head.recordSha256,expectedHead:head});
 const provenance=createOfflineEpochTransitionProvenance({evidenceBytes:evidence.bytes,
  genesisRosterBytes:r0.bytes,transitions:steps});
 return {snapshot:{provenanceBytes:provenance.bytes},pin:{expectedProvenanceSha256:provenance.sha256,
  expectedEvidenceSha256:evidence.sha256,expectedHead:head,
  expectedIssuerPins:issuerPins.slice(0,steps.length),observedAtMs:at}};
}
const a=makeSnapshot([g.bytes,b1],head1,[{transitionBytes:t1.bytes,nextRosterBytes:r1.bytes}],now-5000);
const b=makeSnapshot([g.bytes,b1,b2],head2,[{transitionBytes:t1.bytes,nextRosterBytes:r1.bytes},
 {transitionBytes:t2.bytes,nextRosterBytes:r2.bytes}],now);
const common={expectedNamespacePin:namespacePin,expectedRootPin:rootPin,
 expectedRegistryId:registryId,expectedGenesisSha256:g.head.recordSha256,
 expectedGenesisRosterSha256:r0.sha256,expectedPolicySignerFingerprint:policySignerFingerprint,
 expectedAudience:audience,trustedNowMs:now};
const run=(snapshots=[a.snapshot,b.snapshot],retainedPins=[a.pin,b.pin],changes={})=>
 verifyOfflineRetainedEpochContinuity({snapshots,retainedPins,...common,...changes});
const rejects=(code,snapshots,retainedPins,changes)=>assert.throws(()=>run(snapshots,retainedPins,changes),{code});
const alt1=serializeOfflineWitnessRoster({...base,validFromMs:now-15000,
 validUntilMs:now+2000,witnesses:[witnesses[0],{...witnesses[1],status:'revoked'}]});
const alt2=serializeOfflineWitnessRoster({...base,validFromMs:now-4000,
 validUntilMs:now+15000,witnesses:[{...witnesses[0],status:'revoked'},witnesses[1]]});
const altT1=makeT(issuer1,r0,alt1,5,6,now-10000);
const altB1=rec(g.head,alt1,altT1),altHead1={epoch:6,rosterSha256:alt1.sha256,recordSha256:sha(altB1)};
const altT2=makeT(issuer2,alt1,alt2,6,7,now-2000);
const altB2=rec(altHead1,alt2,altT2),altHead2={epoch:7,rosterSha256:alt2.sha256,recordSha256:sha(altB2)};
const fork1=makeSnapshot([g.bytes,altB1],altHead1,
 [{transitionBytes:altT1.bytes,nextRosterBytes:alt1.bytes}],now-4000);
const fork2=makeSnapshot([g.bytes,altB1,altB2],altHead2,
 [{transitionBytes:altT1.bytes,nextRosterBytes:alt1.bytes},
  {transitionBytes:altT2.bytes,nextRosterBytes:alt2.bytes}],now);

test('35AL independently pinned historical snapshots preserve signed prefix',()=>{
 const r=run();assert.equal(r.schema,OFFLINE_RETAINED_EPOCH_CONTINUITY_SCHEMA);
 assert.equal(r.checkpointCount,2);assert.deepEqual(r.latestHead,head2);
 assert.equal(r.historyContinuityVerified,true);assert.equal(r.issuerSignaturesVerified,true);
 assert.equal(r.independentCustodyVerified,false);assert.equal(r.trustedClockIndependentlyVerified,false);
 assert.equal(r.crossHostConsensusVerified,false);assert.equal(r.authorizesProduction,false);
 assert.match(r.continuityDigest,/^[0-9a-f]{64}$/);
});
test('35AL deterministic digest with independently pinned same observations',()=>{
 assert.equal(run().continuityDigest,run().continuityDigest);
 assert.equal(Object.isFrozen(run().checkpoints),true);
});
test('35AL valid alternate independently pinned branch is self-consistent',()=>{
 const r=run([fork1.snapshot,fork2.snapshot],[fork1.pin,fork2.pin]);
 assert.equal(r.checkpointCount,2);
});
test('35AL rejects signed same-epoch equivocation',()=>
 rejects('OFFLINE_RETAINED_EPOCH_EQUIVOCATION',[a.snapshot,fork1.snapshot],[a.pin,fork1.pin]));
test('35AL rejects signed cross-epoch fork even if later head is externally repinned',()=>
 rejects('OFFLINE_RETAINED_EPOCH_EQUIVOCATION',[a.snapshot,fork2.snapshot],[a.pin,fork2.pin]));
test('35AL rejects rollback to an older signed checkpoint',()=>
 rejects('OFFLINE_RETAINED_EPOCH_ROLLBACK',[b.snapshot,a.snapshot],
 [{...b.pin,observedAtMs:now-1000},{...a.pin,observedAtMs:now}]));
test('35AL rejects same-epoch replay even when both snapshots are valid',()=>
 rejects('OFFLINE_RETAINED_EPOCH_REPLAY',[a.snapshot,a.snapshot],
 [a.pin,{...a.pin,observedAtMs:now-4000}]));
test('35AL rejects pruned retained observation count',()=>
 rejects('OFFLINE_RETAINED_EPOCH_MISSING_EXTERNAL_PINS',[b.snapshot],[b.pin]));
test('35AL rejects missing old observation when independent pin is retained',()=>
 rejects('OFFLINE_RETAINED_EPOCH_MISSING_EXTERNAL_PINS',[b.snapshot],[a.pin,b.pin]));
test('35AL rejects swapped transport against retained pin order',()=>
 rejects('OFFLINE_EPOCH_PROVENANCE_DIGEST_MISMATCH',[b.snapshot,a.snapshot],[a.pin,b.pin]));
test('35AL rejects attacker repinning transport only, not evidence SHA',()=>{
 const altered=Buffer.from(JSON.stringify({...JSON.parse(b.snapshot.provenanceBytes),authority:'PRODUCTION'}));
 rejects('OFFLINE_EPOCH_PROVENANCE_INVALID_STEPS',[a.snapshot,{provenanceBytes:altered}],
 [a.pin,{...b.pin,expectedProvenanceSha256:sha(altered)}]);
});
test('35AL rejects attacker repinning altered embedded evidence SHA only',()=>{
 const obj=JSON.parse(b.snapshot.provenanceBytes);obj.evidence=Buffer.from('evil').toString('base64url');
 const altered=Buffer.from(JSON.stringify(obj));
 rejects('OFFLINE_EPOCH_PROVENANCE_EVIDENCE_MISMATCH',[a.snapshot,{provenanceBytes:altered}],
 [a.pin,{...b.pin,expectedProvenanceSha256:sha(altered)}]);
});
test('35AL rejects wrong independent genesis',()=>
 rejects('OFFLINE_EPOCH_EVIDENCE_PIN_MISMATCH',undefined,undefined,
 {expectedGenesisSha256:sha('other')}));
test('35AL rejects wrong independent roster root',()=>
 rejects('OFFLINE_EPOCH_PROVENANCE_GENESIS_ROSTER_MISMATCH',undefined,undefined,
 {expectedGenesisRosterSha256:sha('other')}));
test('35AL rejects wrong namespace',()=>
 rejects('OFFLINE_EPOCH_EVIDENCE_PIN_MISMATCH',undefined,undefined,
 {expectedNamespacePin:sha('other')}));
test('35AL rejects wrong issuer key substitution',()=>{
 const replacement=generateKeyPairSync('ed25519');
 rejects('OFFLINE_EPOCH_SIGNER_SUBSTITUTION',undefined,
 [a.pin,{...b.pin,expectedIssuerPins:[{issuerPublicKey:replacement.publicKey,
  expectedIssuerKeyFingerprint:fp(replacement.publicKey)},issuerPins[1]]}]);
});
test('35AL rejects issuer pin omission',()=>
 rejects('OFFLINE_EPOCH_PROVENANCE_INVALID_STEPS',undefined,
 [a.pin,{...b.pin,expectedIssuerPins:[issuerPins[0]]}]));
test('35AL rejects untrusted current clock',()=>
 rejects('OFFLINE_RETAINED_EPOCH_MISSING_EXTERNAL_PINS',undefined,undefined,
 {trustedNowMs:undefined}));
test('35AL rejects future observation',()=>
 rejects('OFFLINE_RETAINED_EPOCH_MISSING_EXTERNAL_PINS',undefined,
 [a.pin,{...b.pin,observedAtMs:now+1}]));
test('35AL rejects non-monotonic observed times',()=>
 rejects('OFFLINE_RETAINED_EPOCH_MISSING_EXTERNAL_PINS',undefined,
 [a.pin,{...b.pin,observedAtMs:now-5000}]));
test('35AL rejects sparse snapshot array',()=>{
 const s=[a.snapshot,b.snapshot];delete s[0];
 rejects('OFFLINE_RETAINED_EPOCH_MISSING_EXTERNAL_PINS',s);
});
test('35AL rejects sparse independent pin array',()=>{
 const p=[a.pin,b.pin];delete p[0];
 rejects('OFFLINE_RETAINED_EPOCH_MISSING_EXTERNAL_PINS',undefined,p);
});
test('35AL rejects unpinned injected snapshot',()=>
 rejects('OFFLINE_RETAINED_EPOCH_MISSING_EXTERNAL_PINS',[a.snapshot,b.snapshot,b.snapshot]));
test('35AL rejects prototype-inherited snapshot fields',()=>{
 const bad=Object.create({provenanceBytes:a.snapshot.provenanceBytes});
 rejects('OFFLINE_RETAINED_EPOCH_MISSING_EXTERNAL_PINS',[bad,b.snapshot]);
});
test('35AL rejects extra authority in snapshot',()=>
 rejects('OFFLINE_RETAINED_EPOCH_MISSING_EXTERNAL_PINS',
 [{...a.snapshot,authorizesProduction:true},b.snapshot]));
test('35AL rejects extra authority in external pin',()=>
 rejects('OFFLINE_RETAINED_EPOCH_MISSING_EXTERNAL_PINS',undefined,
 [{...a.pin,authorizesProduction:true},b.pin]));
test('35AL rejects malformed provenance bytes',()=>
 rejects('OFFLINE_EPOCH_PROVENANCE_INVALID_BYTES',
 [a.snapshot,{provenanceBytes:Buffer.from('')}]));
test('35AL rejects future signed cutover with older observedAt',()=>
 rejects('OFFLINE_EPOCH_PROVENANCE_INVALID_CUTOVER',undefined,
 [a.pin,{...b.pin,observedAtMs:now-5000+1}]));
test('35AL rejects expired historical roster at alleged observation',()=>
 rejects('OFFLINE_ROSTER_OUTSIDE_VALIDITY',undefined,
 [{...a.pin,observedAtMs:now+1001},{...b.pin,observedAtMs:now+2000}],
 {trustedNowMs:now+2000}));
test('35AL rejects wrong historic head',()=>
 rejects('OFFLINE_EPOCH_EVIDENCE_PIN_MISMATCH',undefined,
 [{...a.pin,expectedHead:{...head1,recordSha256:sha('forged')}},b.pin]));
test('35AL rejects noncanonical transport even with repinned outer digest',()=>{
 const o=JSON.parse(b.snapshot.provenanceBytes);
 const altered=Buffer.from(JSON.stringify({authority:o.authority,...o}));
 rejects('OFFLINE_EPOCH_PROVENANCE_NONCANONICAL',[a.snapshot,{provenanceBytes:altered}],
 [a.pin,{...b.pin,expectedProvenanceSha256:sha(altered)}]);
});
