import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync} from 'node:crypto';
import {createOfflineRetentionReceipt,createOfflineRetentionPruneCertificate,
 verifyOfflineRetentionReceiptWindow,OFFLINE_RETENTION_RECEIPT_SCHEMA,
 OFFLINE_RETENTION_ZERO_SHA256} from '../src/preview-local-artwork-retention-receipts.mjs';
const sha=x=>createHash('sha256').update(x).digest('hex');
const now=1_700_000_000_000;
const keys=generateKeyPairSync('ed25519');
const other=generateKeyPairSync('ed25519');
const fp=k=>sha(k.export({type:'spki',format:'der'}));
const streamId=sha('35AM-retention-stream');
const checkpoints=Array.from({length:5},(_,i)=>({epoch:20+i,
 provenanceSha256:sha(`35AM-provenance-${i}`),evidenceSha256:sha(`35AM-evidence-${i}`),
 headSha256:sha(`35AM-head-${i}`)}));
const observed=[now-20000,now-15000,now-10000,now-5000,now-1000];
const retain=[now-1000,now-500,now+40000,now+50000,now+60000];
const signed=[];let previous=OFFLINE_RETENTION_ZERO_SHA256;
for(let i=0;i<5;i++){
 const r=createOfflineRetentionReceipt({streamId,sequence:i,observedAtMs:observed[i],
  retainUntilMs:retain[i],checkpoint:checkpoints[i],previousReceiptSha256:previous,
  signingKey:keys.privateKey,publicKey:keys.publicKey});
 signed.push(r);previous=r.sha256;
}
const anchor=i=>({sequence:i,receiptSha256:signed[i].sha256,
 observedAtMs:observed[i],retainUntilMs:retain[i]});
const pin=i=>({checkpoint:checkpoints[i],observedAtMs:observed[i],retainUntilMs:retain[i]});
const ext=(mode,first,last,at=now)=>({mode,streamId,signerFingerprint:fp(keys.publicKey),
 trustedNowMs:at,expectedHead:{sequence:last,receiptSha256:signed[last].sha256},
 expectedAnchor:mode==='genesis'?null:anchor(first-1),
 expectedCheckpoints:Array.from({length:last-first+1},(_,j)=>pin(first+j))});
const prune=createOfflineRetentionPruneCertificate({streamId,anchorSequence:1,
 anchorReceiptSha256:signed[1].sha256,anchorRetainUntilMs:retain[1],
 pruneAtMs:now-400,firstRetainedSequence:2,
 signingKey:keys.privateKey,publicKey:keys.publicKey});
const run=(mode='pruned',first=2,last=4,opts={})=>
 verifyOfflineRetentionReceiptWindow({receiptBytes:signed.slice(first,last+1).map(r=>r.bytes),
  externalPins:ext(mode,first,last,mode==='genesis'?now-9000:now),
  signerPublicKey:keys.publicKey,pruneCertificateBytes:mode==='pruned'?prune.bytes:null,...opts});
const rejects=(code,opts)=>assert.throws(()=>run('pruned',2,4,opts),{code});
const env=b=>JSON.parse(b.toString('utf8'));
const reb=o=>Buffer.from(JSON.stringify(o));

test('35AM genesis verification with complete retained receipt chain',()=>{
 const r=run('genesis',0,2);
 assert.equal(r.schema,OFFLINE_RETENTION_RECEIPT_SCHEMA);
 assert.equal(r.verifiedCount,3);assert.equal(r.firstSequence,0);
 assert.equal(r.completeHistoryVerified,true);assert.equal(r.authorizesProduction,false);
 assert.equal(r.independentCustodyVerified,false);
});
test('35AM append verifies pinned preceding receipt without claiming complete history',()=>{
 const r=run('append',3,4);assert.equal(r.verifiedCount,2);
 assert.equal(r.firstSequence,3);assert.equal(r.completeHistoryVerified,false);
 assert.equal(r.pruneCertificateVerified,false);
});
test('35AM prune requires signed expired-anchor evidence and independent pins',()=>{
 const r=run();assert.equal(r.verifiedCount,3);assert.equal(r.firstSequence,2);
 assert.equal(r.pruneCertificateVerified,true);assert.equal(r.prunedPrefixVerified,false);
 assert.equal(r.headSha256,signed[4].sha256);
});
test('35AM output is frozen and deterministic',()=>{
 assert.equal(Object.isFrozen(run().verifiedReceipts),true);
 assert.deepEqual(run().verifiedReceipts,run().verifiedReceipts);
});
test('35AM refuses old head replay when independently pinned newer head',()=>
 rejects('OFFLINE_RETENTION_MISSING_EXTERNAL_PINS',{receiptBytes:[signed[2].bytes,signed[3].bytes]}));
test('35AM rejects swapped receipts',()=>rejects('OFFLINE_RETENTION_CHAIN_BROKEN',{
 receiptBytes:[signed[3].bytes,signed[2].bytes,signed[4].bytes]}));
test('35AM rejects duplicate signed receipt',()=>rejects('OFFLINE_RETENTION_CHAIN_BROKEN',{
 receiptBytes:[signed[2].bytes,signed[2].bytes,signed[4].bytes]}));
test('35AM rejects removed middle receipt',()=>rejects('OFFLINE_RETENTION_MISSING_EXTERNAL_PINS',{
 receiptBytes:[signed[2].bytes,signed[4].bytes]}));
test('35AM rejects extra injected receipt',()=>rejects('OFFLINE_RETENTION_MISSING_EXTERNAL_PINS',{
 receiptBytes:[signed[2].bytes,signed[3].bytes,signed[4].bytes,signed[4].bytes]}));
test('35AM rejects missing independent external pins',()=>rejects('OFFLINE_RETENTION_MISSING_EXTERNAL_PINS',{
 externalPins:undefined}));
test('35AM rejects transport-derived fake signer key',()=>rejects('OFFLINE_RETENTION_SIGNER_SUBSTITUTION',{
 signerPublicKey:other.publicKey}));
test('35AM rejects fingerprint substitution',()=>rejects('OFFLINE_RETENTION_SIGNER_SUBSTITUTION',{
 externalPins:{...ext('pruned',2,4),signerFingerprint:fp(other.publicKey)}}));
test('35AM rejects stream substitution',()=>rejects('OFFLINE_RETENTION_CHAIN_BROKEN',{
 externalPins:{...ext('pruned',2,4),streamId:sha('attacker stream')}}));
test('35AM rejects wrong independent checkpoint pin',()=>{
 const p=ext('pruned',2,4);p.expectedCheckpoints[1]={...p.expectedCheckpoints[1],
  checkpoint:{...checkpoints[3],headSha256:sha('tamper')}};
 rejects('OFFLINE_RETENTION_CHECKPOINT_PIN_MISMATCH',{externalPins:p});
});
test('35AM rejects wrong externally retained head',()=>rejects('OFFLINE_RETENTION_HEAD_MISMATCH',{
 externalPins:{...ext('pruned',2,4),expectedHead:{sequence:4,receiptSha256:sha('old head')}}}));
test('35AM rejects forged independently retained anchor',()=>rejects('OFFLINE_RETENTION_CHAIN_BROKEN',{
 externalPins:{...ext('pruned',2,4),expectedAnchor:{...anchor(1),receiptSha256:sha('bad anchor')}}}));
test('35AM rejects invalid signature after payload tamper',()=>{
 const o=env(signed[3].bytes);const b=JSON.parse(Buffer.from(o.body,'base64url'));
 b.checkpoint.epoch+=1;o.body=Buffer.from(JSON.stringify(b)).toString('base64url');
 rejects('OFFLINE_RETENTION_INVALID_SIGNATURE',{receiptBytes:[signed[2].bytes,reb(o),signed[4].bytes]});
});
test('35AM rejects tampered Ed25519 signature',()=>{
 const o=env(signed[3].bytes);const sig=Buffer.from(o.signature,'base64url');sig[0]^=1;
 o.signature=sig.toString('base64url');
 rejects('OFFLINE_RETENTION_INVALID_SIGNATURE',{receiptBytes:[signed[2].bytes,reb(o),signed[4].bytes]});
});
test('35AM rejects envelope key injection even if signature untouched',()=>{
 const o=env(signed[3].bytes);o.authorizesProduction=true;
 rejects('OFFLINE_RETENTION_INVALID_ENVELOPE',{receiptBytes:[signed[2].bytes,reb(o),signed[4].bytes]});
});
test('35AM rejects noncanonical envelope order',()=>{
 const o=env(signed[3].bytes);const reordered={signature:o.signature,body:o.body,
  schema:o.schema,signerFingerprint:o.signerFingerprint};
 rejects('OFFLINE_RETENTION_INVALID_ENVELOPE',{receiptBytes:[signed[2].bytes,reb(reordered),signed[4].bytes]});
});
test('35AM rejects JSON duplicate envelope key',()=>{
 const s=signed[3].bytes.toString('utf8');const malformed=s.replace('{','{"schema":"BAD",');
 rejects('OFFLINE_RETENTION_INVALID_ENVELOPE',{
  receiptBytes:[signed[2].bytes,Buffer.from(malformed),signed[4].bytes]});
});
test('35AM rejects malformed base64url signature',()=>{
 const o=env(signed[3].bytes);o.signature='*';
 rejects('OFFLINE_RETENTION_INVALID_ENVELOPE',{receiptBytes:[signed[2].bytes,reb(o),signed[4].bytes]});
});
test('35AM rejects sparse receipt array',()=>{
 const r=[signed[2].bytes,signed[3].bytes,signed[4].bytes];delete r[1];
 rejects('OFFLINE_RETENTION_MISSING_EXTERNAL_PINS',{receiptBytes:r});
});
test('35AM rejects sparse checkpoint pin array',()=>{
 const p=ext('pruned',2,4);delete p.expectedCheckpoints[1];
 rejects('OFFLINE_RETENTION_MISSING_EXTERNAL_PINS',{externalPins:p});
});
test('35AM rejects external prototype inherited pins',()=>{
 const p=Object.create(ext('pruned',2,4));
 rejects('OFFLINE_RETENTION_MISSING_EXTERNAL_PINS',{externalPins:p});
});
test('35AM rejects unsafe external pin getters without invoking them',()=>{
 let invoked=false;const p=ext('pruned',2,4);
 Object.defineProperty(p,'streamId',{enumerable:true,get(){invoked=true;return streamId;}});
 rejects('OFFLINE_RETENTION_MISSING_EXTERNAL_PINS',{externalPins:p});
 assert.equal(invoked,false);
});
test('35AM rejects future observation against independently supplied clock',()=>{
 const p=ext('pruned',2,4);p.trustedNowMs=now-2000;
 rejects('OFFLINE_RETENTION_TIME_REPLAY',{externalPins:p});
});
test('35AM rejects expired retained window',()=>{
 const p=ext('pruned',2,4);p.trustedNowMs=now+70000;
 rejects('OFFLINE_RETENTION_WINDOW_EXPIRED',{externalPins:p});
});
test('35AM rejects pruning without signed certificate',()=>rejects('OFFLINE_RETENTION_MISSING_EXTERNAL_PINS',{
 pruneCertificateBytes:null}));
test('35AM rejects pruning too early for retained anchor',()=>{
 const p=ext('pruned',2,4);p.expectedAnchor={...anchor(1),retainUntilMs:now+100};
 rejects('OFFLINE_RETENTION_PRUNE_MISMATCH',{externalPins:p});
});
test('35AM rejects certificate anchored to a different hash',()=>{
 const bad=createOfflineRetentionPruneCertificate({streamId,anchorSequence:1,
  anchorReceiptSha256:sha('different'),anchorRetainUntilMs:retain[1],
  pruneAtMs:now-400,firstRetainedSequence:2,signingKey:keys.privateKey,publicKey:keys.publicKey});
 rejects('OFFLINE_RETENTION_PRUNE_MISMATCH',{pruneCertificateBytes:bad.bytes});
});
test('35AM rejects signed pruning certificate from different signer',()=>{
 const bad=createOfflineRetentionPruneCertificate({streamId,anchorSequence:1,
  anchorReceiptSha256:signed[1].sha256,anchorRetainUntilMs:retain[1],
  pruneAtMs:now-400,firstRetainedSequence:2,signingKey:other.privateKey,publicKey:other.publicKey});
 rejects('OFFLINE_RETENTION_SIGNER_SUBSTITUTION',{pruneCertificateBytes:bad.bytes});
});
test('35AM rejects tampered signed pruning certificate',()=>{
 const o=env(prune.bytes);const b=JSON.parse(Buffer.from(o.body,'base64url'));
 b.pruneAtMs++;o.body=Buffer.from(JSON.stringify(b)).toString('base64url');
 rejects('OFFLINE_RETENTION_INVALID_SIGNATURE',{pruneCertificateBytes:reb(o)});
});
test('35AM rejects signed certificate issued in the future',()=>{
 const bad=createOfflineRetentionPruneCertificate({streamId,anchorSequence:1,
  anchorReceiptSha256:signed[1].sha256,anchorRetainUntilMs:retain[1],
  pruneAtMs:now+1,firstRetainedSequence:2,signingKey:keys.privateKey,publicKey:keys.publicKey});
 rejects('OFFLINE_RETENTION_PRUNE_TOO_EARLY',{pruneCertificateBytes:bad.bytes});
});
test('35AM rejects certificate issued before retention expiry',()=>{
 assert.throws(()=>createOfflineRetentionPruneCertificate({streamId,anchorSequence:1,
  anchorReceiptSha256:signed[1].sha256,anchorRetainUntilMs:retain[1],
  pruneAtMs:retain[1],firstRetainedSequence:2,signingKey:keys.privateKey,publicKey:keys.publicKey}),
 {code:'OFFLINE_RETENTION_INVALID_BODY'});
});
test('35AM rejects missing external anchor in append mode',()=>{
 assert.throws(()=>run('append',3,4,{externalPins:{...ext('append',3,4),expectedAnchor:null}}),
 {code:'OFFLINE_RETENTION_MISSING_EXTERNAL_PINS'});
});
test('35AM rejects pruning certificate smuggled into append mode',()=>{
 assert.throws(()=>run('append',3,4,{pruneCertificateBytes:prune.bytes}),
 {code:'OFFLINE_RETENTION_MISSING_EXTERNAL_PINS'});
});
test('35AM rejects forged first sequence and anchor',()=>rejects('OFFLINE_RETENTION_MISSING_EXTERNAL_PINS',{
 externalPins:{...ext('pruned',2,4),expectedAnchor:{...anchor(1),sequence:0}}}));
test('35AM refuses signer/private key mismatch on issuance',()=>{
 assert.throws(()=>createOfflineRetentionReceipt({streamId,sequence:5,
  observedAtMs:now,retainUntilMs:now+1000,checkpoint:checkpoints[4],
  previousReceiptSha256:signed[4].sha256,signingKey:other.privateKey,publicKey:keys.publicKey}),
 {code:'OFFLINE_RETENTION_KEY_MISMATCH'});
});
test('35AM refuses extra production flag on checkpoint',()=>{
 assert.throws(()=>createOfflineRetentionReceipt({streamId,sequence:5,
  observedAtMs:now,retainUntilMs:now+1000,checkpoint:{...checkpoints[4],authorizesProduction:true},
  previousReceiptSha256:signed[4].sha256,signingKey:keys.privateKey,publicKey:keys.publicKey}),
 {code:'OFFLINE_RETENTION_INVALID_BODY'});
});
test('35AM refuses invalid retention duration',()=>{
 assert.throws(()=>createOfflineRetentionReceipt({streamId,sequence:5,
  observedAtMs:now,retainUntilMs:now,checkpoint:checkpoints[4],
  previousReceiptSha256:signed[4].sha256,signingKey:keys.privateKey,publicKey:keys.publicKey}),
 {code:'OFFLINE_RETENTION_INVALID_BODY'});
});
test('35AM does not accept receipt bytes as independent pins',()=>{
 rejects('OFFLINE_RETENTION_MISSING_EXTERNAL_PINS',{externalPins:{...ext('pruned',2,4),
  expectedCheckpoints:signed.slice(2).map(r=>r.bytes)}});
});
test('35AM rejects separately signed same-sequence fork against external checkpoint pins',()=>{
 const fork=createOfflineRetentionReceipt({streamId,sequence:3,
  observedAtMs:observed[3],retainUntilMs:retain[3],
  checkpoint:{...checkpoints[3],evidenceSha256:sha('signed fork')},
  previousReceiptSha256:signed[2].sha256,signingKey:keys.privateKey,publicKey:keys.publicKey});
 rejects('OFFLINE_RETENTION_CHECKPOINT_PIN_MISMATCH',{
  receiptBytes:[signed[2].bytes,fork.bytes,signed[4].bytes]});
});
test('35AM rejects nonmonotonic first receipt relative to independently pinned anchor',()=>{
 const bad=createOfflineRetentionReceipt({streamId,sequence:2,
  observedAtMs:observed[1],retainUntilMs:retain[2],checkpoint:checkpoints[2],
  previousReceiptSha256:signed[1].sha256,signingKey:keys.privateKey,publicKey:keys.publicKey});
 const p=ext('pruned',2,4);p.expectedCheckpoints[0]={...pin(2),observedAtMs:observed[1]};
 rejects('OFFLINE_RETENTION_TIME_REPLAY',{
  receiptBytes:[bad.bytes,signed[3].bytes,signed[4].bytes],externalPins:p});
});
test('35AM rejects independently pinned future anchor pruning, even with matching signed certificate',()=>{
 const futureUntil=now+1000;
 const future=createOfflineRetentionPruneCertificate({streamId,anchorSequence:1,
  anchorReceiptSha256:signed[1].sha256,anchorRetainUntilMs:futureUntil,
  pruneAtMs:now+1001,firstRetainedSequence:2,signingKey:keys.privateKey,publicKey:keys.publicKey});
 const p=ext('pruned',2,4);p.expectedAnchor={...anchor(1),retainUntilMs:futureUntil};
 rejects('OFFLINE_RETENTION_PRUNE_TOO_EARLY',{
  pruneCertificateBytes:future.bytes,externalPins:p});
});
test('35AM rejects pruning certificate with incorrect first retained sequence',()=>{
 assert.throws(()=>createOfflineRetentionPruneCertificate({streamId,anchorSequence:1,
  anchorReceiptSha256:signed[1].sha256,anchorRetainUntilMs:retain[1],
  pruneAtMs:now-400,firstRetainedSequence:4,
  signingKey:keys.privateKey,publicKey:keys.publicKey}),{code:'OFFLINE_RETENTION_INVALID_BODY'});
});
