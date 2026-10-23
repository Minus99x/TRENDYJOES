import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync} from 'node:crypto';
import {mkdtemp,chmod,readFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {serializeOfflineWitnessRoster} from '../src/preview-local-artwork-review-witness-roster-ledger.mjs';
import {createOfflineWitnessRosterEpochTransition} from '../src/preview-local-artwork-review-witness-epoch.mjs';
import {OFFLINE_EPOCH_HEAD_SCHEMA,createOfflineEpochGenesis,initializeOfflineEpochHeadRegistry,
 advanceOfflinePinnedEpochHead} from '../src/preview-local-artwork-review-epoch-head-registry.mjs';
import {createOfflineEpochChainEvidence,verifyOfflineEpochChainEvidence,
 createOfflineEpochObserverReceipt,verifyOfflineEpochObserverReceipt,
 inspectOfflineEpochObserverViews} from '../src/preview-local-artwork-review-epoch-observer-evidence.mjs';
const sha=x=>createHash('sha256').update(x).digest('hex');
const fp=k=>sha(k.export({type:'spki',format:'der'}));
const now=1700000000000,cutover=now-500;
const namespacePin=sha('35AJ-namespace'),rootPin=sha('35AJ-root'),registryId=sha('35AJ-registry');
const policySignerFingerprint=sha('35AJ-policy'),audience=sha('35AJ-audience');
const issuer=generateKeyPairSync('ed25519'),w1=generateKeyPairSync('ed25519'),w2=generateKeyPairSync('ed25519');
const o1=generateKeyPairSync('ed25519'),o2=generateKeyPairSync('ed25519'),o3=generateKeyPairSync('ed25519');
const witnesses=[{witnessId:sha('35AJ-w1'),publicKeyFingerprint:fp(w1.publicKey),status:'active'},
 {witnessId:sha('35AJ-w2'),publicKeyFingerprint:fp(w2.publicKey),status:'active'}]
 .sort((a,b)=>a.witnessId.localeCompare(b.witnessId));
const base={rootPin,registryId,policySignerFingerprint,audience};
const oldRoster=serializeOfflineWitnessRoster({...base,validFromMs:now-10000,validUntilMs:now+1000,witnesses});
const newRoster=serializeOfflineWitnessRoster({...base,validFromMs:now-1000,validUntilMs:now+10000,
 witnesses:[{...witnesses[0],status:'revoked'},witnesses[1]]});
const genesis=createOfflineEpochGenesis({namespacePin,rootPin,registryId,epoch:2,rosterSha256:oldRoster.sha256});
const transition=createOfflineWitnessRosterEpochTransition({signingKey:issuer.privateKey,...base,
 previousRosterSha256:oldRoster.sha256,nextRosterSha256:newRoster.sha256,
 previousEpoch:2,nextEpoch:3,cutoverMs:cutover});
const transitionVerification={transitionBytes:transition.bytes,expectedTransitionSha256:transition.sha256,
 issuerPublicKey:issuer.publicKey,expectedIssuerKeyFingerprint:fp(issuer.publicKey),
 previousRosterBytes:oldRoster.bytes,nextRosterBytes:newRoster.bytes,
 expectedPreviousRosterSha256:oldRoster.sha256,expectedNextRosterSha256:newRoster.sha256,
 expectedRootPin:rootPin,expectedRegistryId:registryId,
 expectedPolicySignerFingerprint:policySignerFingerprint,expectedAudience:audience,
 expectedPreviousEpoch:2,expectedNextEpoch:3,trustedNowMs:now};
const external=h=>({epoch:h.epoch,rosterSha256:h.rosterSha256,recordSha256:h.recordSha256});
const pins={expectedNamespacePin:namespacePin,expectedRootPin:rootPin,expectedRegistryId:registryId,
 expectedGenesisSha256:genesis.head.recordSha256};
const eargs=(recordBytes,expectedHead)=>({recordBytes,namespacePin,rootPin,registryId,
 expectedGenesisSha256:genesis.head.recordSha256,expectedHead});
const readargs=(evidence,expectedHead)=>({evidenceBytes:evidence.bytes,...pins,
 expectedHead,expectedEvidenceSha256:evidence.sha256});
const record=(previous,rosterSha256,transitionSha256)=>Buffer.from(JSON.stringify({schema:OFFLINE_EPOCH_HEAD_SCHEMA,
 namespacePin,rootPin,registryId,epoch:previous.epoch+1,rosterSha256,transitionSha256,
 previousRecordSha256:previous.recordSha256,authority:'NONE'}));
const headFor=(epoch,rosterSha256,b)=>({epoch,rosterSha256,recordSha256:sha(b)});
const successor=record(genesis.head,newRoster.sha256,transition.sha256);
const head3=headFor(3,newRoster.sha256,successor);
const forkRecord=record(genesis.head,sha('different-valid-roster-hash'),sha('different-transition-hash'));
const forkHead=headFor(3,sha('different-valid-roster-hash'),forkRecord);
const head4bytes=record(head3,sha('35AJ-roster-4'),sha('35AJ-transition-4'));
const head4=headFor(4,sha('35AJ-roster-4'),head4bytes);
const chain2=[genesis.bytes],chain3=[genesis.bytes,successor],chain4=[...chain3,head4bytes];
const evidence2=createOfflineEpochChainEvidence(eargs(chain2,genesis.head));
const evidence3=createOfflineEpochChainEvidence(eargs(chain3,head3));
const evidence4=createOfflineEpochChainEvidence(eargs(chain4,head4));
const forkEvidence=createOfflineEpochChainEvidence(eargs([genesis.bytes,forkRecord],forkHead));
const observer=(signer,id,evidence,head,challenge=sha('challenge-'+id),issued=now-100,expiry=now+100)=>{
 const receipt=createOfflineEpochObserverReceipt({signingKey:signer.privateKey,observerId:id,
  namespacePin,rootPin,registryId,audience,challenge,evidenceSha256:evidence.sha256,
  headEpoch:head.epoch,headRecordSha256:head.recordSha256,issuedAtMs:issued,expiresAtMs:expiry});
 return {view:{evidenceBytes:evidence.bytes,receiptBytes:receipt.bytes,observerPublicKey:signer.publicKey},
  pin:{observerId:id,observerKeyFingerprint:fp(signer.publicKey),receiptSha256:receipt.sha256,challenge,expectedHead:head},receipt};
};
const a=observer(o1,sha('observer-a'),evidence3,head3),b=observer(o2,sha('observer-b'),evidence3,head3);
const c=observer(o2,sha('observer-b'),forkEvidence,forkHead),d=observer(o3,sha('observer-c'),evidence4,head4);
const adjudicate=(observers,extra={})=>inspectOfflineEpochObserverViews({views:observers.map(o=>o.view),
 observerPins:observers.map(o=>o.pin),...pins,expectedAudience:audience,trustedNowMs:now,...extra});
const verifyReceipt=(o,extra={})=>verifyOfflineEpochObserverReceipt({receiptBytes:o.receipt.bytes,
 observerPublicKey:o.view.observerPublicKey,expectedObserverId:o.pin.observerId,
 expectedObserverKeyFingerprint:o.pin.observerKeyFingerprint,expectedReceiptSha256:o.pin.receiptSha256,
 expectedNamespacePin:namespacePin,expectedRootPin:rootPin,expectedRegistryId:registryId,
 expectedAudience:audience,expectedChallenge:o.pin.challenge,
 expectedEvidenceSha256:sha(o.view.evidenceBytes),expectedHead:o.pin.expectedHead,trustedNowMs:now,...extra});
const fails=(fn,code)=>assert.throws(fn,{code});
const mutate=(obj,patch)=>Buffer.from(JSON.stringify({...obj,...patch}));
const json=b=>JSON.parse(b.toString('utf8'));
test('35AJ actual 35AI signed rotation exports a pinned portable chain',async()=>{
 const directory=await mkdtemp(join(tmpdir(),'tj35aj-'));await chmod(directory,0o700);
 try{await initializeOfflineEpochHeadRegistry({directory,namespacePin,genesisBytes:genesis.bytes,
  expectedGenesisSha256:genesis.head.recordSha256});
  const next=await advanceOfflinePinnedEpochHead({directory,namespacePin,expectedGenesisSha256:genesis.head.recordSha256,
   expectedHead:genesis.head,transitionVerification});
  const records=[await readFile(join(directory,'epoch-000000000000002.json')),
   await readFile(join(directory,'epoch-000000000000003.json'))];
  const evidence=createOfflineEpochChainEvidence(eargs(records,external(next)));
  const result=verifyOfflineEpochChainEvidence(readargs(evidence,external(next)));
  assert.equal(result.recordCount,2);assert.equal(result.chainHashesVerified,true);
  assert.equal(result.transitionSignaturesVerified,false);assert.equal(result.authorizesProduction,false);
 }finally{await rm(directory,{recursive:true,force:true});}
});
test('35AJ deterministic evidence bytes for same chain',()=>{
 assert.deepEqual(createOfflineEpochChainEvidence(eargs(chain3,head3)).bytes,evidence3.bytes);
});
test('35AJ verified genesis-only evidence retains external genesis pin',()=>{
 assert.equal(verifyOfflineEpochChainEvidence(readargs(evidence2,genesis.head)).recordCount,1);
});
test('35AJ signed independent observer receipt verifies offline signature',()=>{
 const v=verifyReceipt(a);assert.equal(v.signatureVerified,true);assert.equal(v.replayConsumed,false);
});
test('35AJ two separately pinned observers agree on identical chain',()=>{
 const v=adjudicate([a,b]);assert.equal(v.relationship,'AGREEMENT');assert.equal(v.observerCount,2);
 assert.equal(v.crossHostConsensusVerified,false);assert.equal(v.authorizesProduction,false);
});
test('35AJ signed observers distinguish prefix from fork',()=>{
 const v=adjudicate([a,d]);assert.equal(v.relationship,'PREFIX');assert.equal(v.fork,null);
});
test('35AJ signed observers detect same-epoch fork',()=>{
 const v=adjudicate([a,c]);assert.equal(v.relationship,'FORK');assert.equal(v.fork.epoch,3);
 assert.notEqual(v.fork.leftRecordSha256,v.fork.rightRecordSha256);
});
test('35AJ portable fork digest invariant to observer order',()=>{
 assert.equal(adjudicate([a,c]).evidenceDigestSha256,adjudicate([c,a]).evidenceDigestSha256);
});
test('35AJ three observers still detect fork',()=>assert.equal(adjudicate([a,c,d]).relationship,'FORK'));
test('35AJ no fake independent custody or consensus claims',()=>{
 const v=adjudicate([a,b]);assert.equal(v.independentCustodyVerified,false);
 assert.equal(v.transitionSignaturesVerified,false);assert.equal(v.replayConsumed,false);
});
for(const [label,patch,code] of [
 ['missing namespace',{expectedNamespacePin:undefined},'OFFLINE_EPOCH_EVIDENCE_MISSING_PIN'],
 ['wrong namespace',{expectedNamespacePin:sha('wrong')},'OFFLINE_EPOCH_EVIDENCE_PIN_MISMATCH'],
 ['wrong registry',{expectedRegistryId:sha('wrong')},'OFFLINE_EPOCH_EVIDENCE_PIN_MISMATCH'],
 ['wrong root',{expectedRootPin:sha('wrong')},'OFFLINE_EPOCH_EVIDENCE_PIN_MISMATCH'],
 ['wrong genesis',{expectedGenesisSha256:sha('wrong')},'OFFLINE_EPOCH_EVIDENCE_PIN_MISMATCH'],
 ['wrong head',{expectedHead:{...head3,recordSha256:sha('wrong')}},'OFFLINE_EPOCH_EVIDENCE_PIN_MISMATCH'],
 ['wrong evidence hash',{expectedEvidenceSha256:sha('wrong')},'OFFLINE_EPOCH_EVIDENCE_DIGEST_MISMATCH'],
])test(`35AJ evidence rejects ${label}`,()=>fails(()=>verifyOfflineEpochChainEvidence({...readargs(evidence3,head3),...patch}),code));
for(const [label,change,code] of [
 ['reordered fields',b=>{const o=json(b);return Buffer.from(JSON.stringify({authority:o.authority,...o}));},'OFFLINE_EPOCH_EVIDENCE_NONCANONICAL'],
 ['extra field',b=>mutate(json(b),{extra:true}),'OFFLINE_EPOCH_EVIDENCE_NONCANONICAL'],
 ['removed genesis',b=>mutate(json(b),{records:[json(b).records[1]]}),'OFFLINE_EPOCH_EVIDENCE_GENESIS_MISMATCH'],
 ['missing second record',b=>mutate(json(b),{records:[json(b).records[0]]}),'OFFLINE_EPOCH_EVIDENCE_HEAD_MISMATCH'],
 ['noncanonical base64',b=>{const o=json(b);o.records[0]+='=';return Buffer.from(JSON.stringify(o));},'OFFLINE_EPOCH_EVIDENCE_INVALID_RECORD'],
 ['tampered record',b=>{const o=json(b);let r=json(Buffer.from(o.records[1],'base64url'));r.rosterSha256=sha('altered');o.records[1]=Buffer.from(JSON.stringify(r)).toString('base64url');return Buffer.from(JSON.stringify(o));},'OFFLINE_EPOCH_EVIDENCE_HEAD_MISMATCH'],
 ['unexpected head epoch',b=>{const o=json(b);o.head.epoch=44;return Buffer.from(JSON.stringify(o));},'OFFLINE_EPOCH_EVIDENCE_PIN_MISMATCH'],
 ['record order swapped',b=>{const o=json(b);o.records.reverse();return Buffer.from(JSON.stringify(o));},'OFFLINE_EPOCH_EVIDENCE_GENESIS_MISMATCH'],
])test(`35AJ evidence rejects ${label}`,()=>{
 const changed=change(evidence3.bytes);
 fails(()=>verifyOfflineEpochChainEvidence({...readargs(evidence3,head3),evidenceBytes:changed,
 expectedEvidenceSha256:sha(changed)}),code);
});
for(const [label,records,expected,code] of [
 ['missing genesis',[],head3,'OFFLINE_EPOCH_EVIDENCE_MISSING_PIN'],
 ['gap',[genesis.bytes,head4bytes],head4,'OFFLINE_EPOCH_EVIDENCE_CHAIN_MISMATCH'],
 ['stale head',chain3,genesis.head,'OFFLINE_EPOCH_EVIDENCE_HEAD_MISMATCH'],
 ['unlinked successor',[genesis.bytes,record({...genesis.head,recordSha256:sha('other')},newRoster.sha256,transition.sha256)],head3,'OFFLINE_EPOCH_EVIDENCE_CHAIN_MISMATCH'],
 ['duplicate epoch',[genesis.bytes,genesis.bytes],head3,'OFFLINE_EPOCH_EVIDENCE_CHAIN_MISMATCH'],
 ['unchanged roster',[genesis.bytes,record(genesis.head,oldRoster.sha256,transition.sha256)],head3,'OFFLINE_EPOCH_EVIDENCE_CHAIN_MISMATCH'],
 ['zero transition',[genesis.bytes,record(genesis.head,newRoster.sha256,'0'.repeat(64))],head3,'OFFLINE_EPOCH_EVIDENCE_CHAIN_MISMATCH'],
])test(`35AJ source export rejects ${label}`,()=>fails(()=>createOfflineEpochChainEvidence(eargs(records,expected)),code));
for(const [label,patch,code] of [
 ['wrong key',{observerPublicKey:o2.publicKey},'OFFLINE_EPOCH_OBSERVER_MISSING_PINS'],
 ['wrong observer',{expectedObserverId:sha('other')},'OFFLINE_EPOCH_OBSERVER_PIN_MISMATCH'],
 ['wrong audience',{expectedAudience:sha('other')},'OFFLINE_EPOCH_OBSERVER_PIN_MISMATCH'],
 ['wrong challenge',{expectedChallenge:sha('other')},'OFFLINE_EPOCH_OBSERVER_PIN_MISMATCH'],
 ['wrong receipt digest',{expectedReceiptSha256:sha('other')},'OFFLINE_EPOCH_OBSERVER_RECEIPT_PIN_MISMATCH'],
 ['wrong evidence digest',{expectedEvidenceSha256:sha('other')},'OFFLINE_EPOCH_OBSERVER_PIN_MISMATCH'],
 ['wrong head',{expectedHead:genesis.head},'OFFLINE_EPOCH_OBSERVER_PIN_MISMATCH'],
 ['before issue',{trustedNowMs:now-101},'OFFLINE_EPOCH_OBSERVER_NOT_YET_VALID'],
 ['at expiration',{trustedNowMs:now+100},'OFFLINE_EPOCH_OBSERVER_EXPIRED'],
])test(`35AJ observer receipt rejects ${label}`,()=>fails(()=>verifyReceipt(a,patch),code));
test('35AJ validly pinned forged signature is rejected',()=>{
 const o=json(a.receipt.bytes);o.signature='A'.repeat(86);const raw=Buffer.from(JSON.stringify(o));
 fails(()=>verifyReceipt(a,{receiptBytes:raw,expectedReceiptSha256:sha(raw)}),'OFFLINE_EPOCH_OBSERVER_BAD_SIGNATURE');
});
test('35AJ noncanonical observer receipt rejected even with independently updated digest',()=>{
 const o=json(a.receipt.bytes);const raw=Buffer.from(JSON.stringify({signature:o.signature,...o}));
 fails(()=>verifyReceipt(a,{receiptBytes:raw,expectedReceiptSha256:sha(raw)}),'OFFLINE_EPOCH_OBSERVER_NONCANONICAL');
});
test('35AJ duplicated observer identity rejected',()=>fails(()=>adjudicate([a,a]),'OFFLINE_EPOCH_OBSERVER_DISTINCT_PINS_REQUIRED'));
test('35AJ same signing key with different identity rejected',()=>{
 const fake=observer(o1,sha('other-observer'),evidence3,head3);
 fails(()=>adjudicate([a,fake]),'OFFLINE_EPOCH_OBSERVER_DISTINCT_PINS_REQUIRED');
});
test('35AJ repeated challenge across distinct observers rejected',()=>{
 const sameChallenge=observer(o2,sha('observer-b'),evidence3,head3,a.pin.challenge);
 fails(()=>adjudicate([a,sameChallenge]),'OFFLINE_EPOCH_OBSERVER_DISTINCT_PINS_REQUIRED');
});
test('35AJ stale independently retained observer head rejects rollback',()=>{
 const old=observer(o2,sha('observer-b'),evidence2,genesis.head);
 fails(()=>adjudicate([a,{...old,pin:{...old.pin,expectedHead:head3}}]),'OFFLINE_EPOCH_EVIDENCE_PIN_MISMATCH');
});
test('35AJ observer cannot substitute fork evidence without new signature',()=>{
 const bad={...a,view:{...a.view,evidenceBytes:forkEvidence.bytes}};
 fails(()=>adjudicate([bad,b]),'OFFLINE_EPOCH_EVIDENCE_PIN_MISMATCH');
});
test('35AJ corrupted observation with matching new SHA still requires signature',()=>{
 const altered=mutate(json(a.receipt.bytes),{headRecordSha256:forkHead.recordSha256});
 const bad={...a,view:{...a.view,receiptBytes:altered},pin:{...a.pin,receiptSha256:sha(altered)}};
 fails(()=>adjudicate([bad,b]),'OFFLINE_EPOCH_OBSERVER_PIN_MISMATCH');
});
test('35AJ signed observation with expired time cannot adjudicate',()=>{
 fails(()=>adjudicate([a,b],{trustedNowMs:now+100}),'OFFLINE_EPOCH_OBSERVER_EXPIRED');
});
test('35AJ rejects insufficient observer quorum',()=>fails(()=>adjudicate([a]),'OFFLINE_EPOCH_OBSERVER_INVALID_VIEWS'));
test('35AJ rejects unsupported private key as observer public key',()=>fails(()=>verifyReceipt(a,{observerPublicKey:o1.privateKey}),'OFFLINE_EPOCH_OBSERVER_MISSING_PINS'));
test('35AJ rejects truncated evidence before digest acceptance',()=>{
 const truncated=Buffer.from('{');fails(()=>verifyOfflineEpochChainEvidence({...readargs(evidence3,head3),evidenceBytes:truncated,
 expectedEvidenceSha256:sha(truncated)}),'OFFLINE_EPOCH_EVIDENCE_INVALID_BYTES');
});
test('35AJ rejects too many record entries',()=>{
 const records=Array.from({length:257},()=>genesis.bytes);
 fails(()=>createOfflineEpochChainEvidence(eargs(records,genesis.head)),'OFFLINE_EPOCH_EVIDENCE_MISSING_PIN');
});
