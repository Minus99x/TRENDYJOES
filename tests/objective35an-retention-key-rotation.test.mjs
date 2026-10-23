import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync} from 'node:crypto';
import {createOfflineRetentionReceipt,OFFLINE_RETENTION_ZERO_SHA256} from '../src/preview-local-artwork-retention-receipts.mjs';
import {createOfflineRetentionKeyRotation,verifyOfflineRetentionKeyRotation,
 OFFLINE_RETENTION_ROTATION_SCHEMA} from '../src/preview-local-artwork-retention-key-rotation.mjs';
const sha=x=>createHash('sha256').update(x).digest('hex');
const keys=generateKeyPairSync('ed25519'),successor=generateKeyPairSync('ed25519'),attacker=generateKeyPairSync('ed25519');
const fp=k=>sha(k.export({type:'spki',format:'der'}));
const streamId=sha('35AN stream'),now=1_700_000_000_000;
const times=[now-4000,now-3000,now-2000,now-1000];
const checkpoints=times.map((_,i)=>({epoch:i+100,provenanceSha256:sha('p'+i),
 evidenceSha256:sha('e'+i),headSha256:sha('h'+i)}));
const signed=[];let prior=OFFLINE_RETENTION_ZERO_SHA256;
for(let i=0;i<4;i++){
 const k=i<2?keys:successor;
 const r=createOfflineRetentionReceipt({streamId,sequence:i,observedAtMs:times[i],
  retainUntilMs:now+60000+i,checkpoint:checkpoints[i],previousReceiptSha256:prior,
  signingKey:k.privateKey,publicKey:k.publicKey});
 signed.push(r);prior=r.sha256;
}
const pin=i=>({checkpoint:checkpoints[i],observedAtMs:times[i],retainUntilMs:now+60000+i});
const oldPins={mode:'genesis',streamId,signerFingerprint:fp(keys.publicKey),trustedNowMs:now,
 expectedHead:{sequence:1,receiptSha256:signed[1].sha256},expectedAnchor:null,
 expectedCheckpoints:[pin(0),pin(1)]};
const newPins={mode:'append',streamId,signerFingerprint:fp(successor.publicKey),trustedNowMs:now,
 expectedHead:{sequence:3,receiptSha256:signed[3].sha256},
 expectedAnchor:{sequence:1,receiptSha256:signed[1].sha256,observedAtMs:times[1],retainUntilMs:now+60001},
 expectedCheckpoints:[pin(2),pin(3)]};
const make=(changes={})=>createOfflineRetentionKeyRotation({streamId,cutoverSequence:2,
 priorReceiptSha256:signed[1].sha256,nextReceiptSha256:signed[2].sha256,
 cutoverAtMs:times[2],oldSigningKey:keys.privateKey,oldPublicKey:keys.publicKey,
 newSigningKey:successor.privateKey,newPublicKey:successor.publicKey,...changes});
const rotation=make();
const fixture=()=>({oldReceiptBytes:signed.slice(0,2).map(x=>x.bytes),
 newReceiptBytes:signed.slice(2).map(x=>x.bytes),rotationBytes:rotation.bytes,
 oldPublicKey:keys.publicKey,newPublicKey:successor.publicKey,
 externalPins:{oldPins:structuredClone(oldPins),newPins:structuredClone(newPins),expectedRotationSha256:rotation.sha256}});
const reject=(code,change)=>assert.throws(()=>verifyOfflineRetentionKeyRotation({...fixture(),...change}),{code});
const rejPin=(code,change)=>{const f=fixture();f.externalPins={...f.externalPins,...change};
 assert.throws(()=>verifyOfflineRetentionKeyRotation(f),{code});};
const decode=bytes=>JSON.parse(bytes.toString('utf8'));
const encode=obj=>Buffer.from(JSON.stringify(obj));
const modified=(f)=>{const e=decode(rotation.bytes);f(e);return encode(e);};

test('35AN accepts dual-signed independently pinned cross-key receipt cutover',()=>{
 const v=verifyOfflineRetentionKeyRotation(fixture());
 assert.equal(v.schema,OFFLINE_RETENTION_ROTATION_SCHEMA);
 assert.equal(v.oldVerifiedCount,2);assert.equal(v.newVerifiedCount,2);
 assert.equal(v.cutoverSequence,2);assert.equal(v.headSha256,signed[3].sha256);
 assert.equal(v.bothSignaturesVerified,true);assert.equal(v.authorizesProduction,false);
 assert.equal(v.independentlyCustodied,false);assert.equal(v.completeHistoryVerified,true);
 assert.equal(Object.isFrozen(v),true);
});
test('35AN issuance is deterministic for fixed Ed25519 keys and data',()=>assert.equal(make().sha256,rotation.sha256));
test('35AN refuses missing external pins',()=>reject('OFFLINE_ROTATION_MISSING_EXTERNAL_PINS',{externalPins:undefined}));
test('35AN refuses attacker-provided unpinned cutover',()=>rejPin('OFFLINE_ROTATION_EXTERNAL_DIGEST_MISMATCH',{expectedRotationSha256:sha('bad')}));
test('35AN refuses replay of prior rotation digest',()=>rejPin('OFFLINE_ROTATION_EXTERNAL_DIGEST_MISMATCH',{expectedRotationSha256:sha('prior')}));
test('35AN refuses missing old receipt',()=>reject('OFFLINE_RETENTION_MISSING_EXTERNAL_PINS',{oldReceiptBytes:[signed[1].bytes]}));
test('35AN refuses missing new receipt',()=>reject('OFFLINE_RETENTION_MISSING_EXTERNAL_PINS',{newReceiptBytes:[signed[2].bytes]}));
test('35AN refuses duplicated new receipt',()=>reject('OFFLINE_RETENTION_CHAIN_BROKEN',{newReceiptBytes:[signed[2].bytes,signed[2].bytes]}));
test('35AN refuses reordered new receipts',()=>reject('OFFLINE_ROTATION_BOUNDARY_MISMATCH',{newReceiptBytes:[signed[3].bytes,signed[2].bytes]}));
test('35AN refuses altered first successor receipt',()=>reject('OFFLINE_ROTATION_BOUNDARY_MISMATCH',{newReceiptBytes:[signed[3].bytes,signed[3].bytes]}));
test('35AN refuses substituted old signer',()=>reject('OFFLINE_ROTATION_SIGNER_SUBSTITUTION',{oldPublicKey:attacker.publicKey}));
test('35AN refuses substituted new signer',()=>reject('OFFLINE_ROTATION_SIGNER_SUBSTITUTION',{newPublicKey:attacker.publicKey}));
test('35AN refuses old signer reused as new',()=>reject('OFFLINE_ROTATION_SIGNER_SUBSTITUTION',{newPublicKey:keys.publicKey}));
test('35AN refuses old external fingerprint substitution',()=>rejPin('OFFLINE_ROTATION_SIGNER_SUBSTITUTION',{oldPins:{...oldPins,signerFingerprint:fp(attacker.publicKey)}}));
test('35AN refuses new external fingerprint substitution',()=>rejPin('OFFLINE_ROTATION_SIGNER_SUBSTITUTION',{newPins:{...newPins,signerFingerprint:fp(attacker.publicKey)}}));
test('35AN refuses cross-stream substitution',()=>rejPin('OFFLINE_ROTATION_BOUNDARY_MISMATCH',{newPins:{...newPins,streamId:sha('other stream')}}));
test('35AN refuses wrong old head anchor',()=>rejPin('OFFLINE_ROTATION_BOUNDARY_MISMATCH',{oldPins:{...oldPins,expectedHead:{sequence:1,receiptSha256:sha('bad')}}}));
test('35AN refuses wrong successor anchor',()=>rejPin('OFFLINE_ROTATION_BOUNDARY_MISMATCH',{newPins:{...newPins,expectedAnchor:{...newPins.expectedAnchor,receiptSha256:sha('bad')}}}));
test('35AN refuses rollback to older successor head',()=>rejPin('OFFLINE_RETENTION_MISSING_EXTERNAL_PINS',{newPins:{...newPins,expectedHead:{sequence:2,receiptSha256:signed[2].sha256}}}));
test('35AN refuses mismatched trusted clocks',()=>rejPin('OFFLINE_ROTATION_BOUNDARY_MISMATCH',{newPins:{...newPins,trustedNowMs:now-1}}));
test('35AN refuses successor not in append mode',()=>rejPin('OFFLINE_ROTATION_BOUNDARY_MISMATCH',{newPins:{...newPins,mode:'genesis'}}));
test('35AN refuses cutover time earlier than previous observation',()=>{
 const r=make({cutoverAtMs:times[1]});reject('OFFLINE_ROTATION_EXTERNAL_DIGEST_MISMATCH',{rotationBytes:r.bytes});
 const f=fixture();f.rotationBytes=r.bytes;f.externalPins.expectedRotationSha256=r.sha256;
 assert.throws(()=>verifyOfflineRetentionKeyRotation(f),{code:'OFFLINE_ROTATION_BOUNDARY_MISMATCH'});
});
test('35AN refuses future cutover',()=>{
 const r=make({cutoverAtMs:now+1});const f=fixture();f.rotationBytes=r.bytes;
 f.externalPins.expectedRotationSha256=r.sha256;
 assert.throws(()=>verifyOfflineRetentionKeyRotation(f),{code:'OFFLINE_ROTATION_BOUNDARY_MISMATCH'});
});
test('35AN refuses signed fork with different first successor',()=>{
 const fork=createOfflineRetentionReceipt({streamId,sequence:2,observedAtMs:times[2],
  retainUntilMs:now+60002,checkpoint:{...checkpoints[2],evidenceSha256:sha('fork')},
  previousReceiptSha256:signed[1].sha256,signingKey:successor.privateKey,publicKey:successor.publicKey});
 reject('OFFLINE_ROTATION_BOUNDARY_MISMATCH',{newReceiptBytes:[fork.bytes,signed[3].bytes]});
});
test('35AN refuses forged old signature',()=>{
 const bytes=modified(e=>{const s=Buffer.from(e.oldSignature,'base64url');s[0]^=1;e.oldSignature=s.toString('base64url');});
 const f=fixture();f.rotationBytes=bytes;f.externalPins.expectedRotationSha256=sha(bytes);
 assert.throws(()=>verifyOfflineRetentionKeyRotation(f),{code:'OFFLINE_ROTATION_INVALID_SIGNATURE'});
});
test('35AN refuses forged new signature',()=>{
 const bytes=modified(e=>{const s=Buffer.from(e.newSignature,'base64url');s[0]^=1;e.newSignature=s.toString('base64url');});
 const f=fixture();f.rotationBytes=bytes;f.externalPins.expectedRotationSha256=sha(bytes);
 assert.throws(()=>verifyOfflineRetentionKeyRotation(f),{code:'OFFLINE_ROTATION_INVALID_SIGNATURE'});
});
test('35AN refuses tampered signed cutover body',()=>{
 const bytes=modified(e=>{const p=JSON.parse(Buffer.from(e.body,'base64url'));p.cutoverSequence++;
  e.body=Buffer.from(JSON.stringify(p)).toString('base64url');});
 const f=fixture();f.rotationBytes=bytes;f.externalPins.expectedRotationSha256=sha(bytes);
 assert.throws(()=>verifyOfflineRetentionKeyRotation(f),{code:'OFFLINE_ROTATION_INVALID_SIGNATURE'});
});
test('35AN refuses unknown envelope field',()=>{
 const bytes=modified(e=>e.production=true);const f=fixture();f.rotationBytes=bytes;
 f.externalPins.expectedRotationSha256=sha(bytes);
 assert.throws(()=>verifyOfflineRetentionKeyRotation(f),{code:'OFFLINE_ROTATION_INVALID_ENVELOPE'});
});
test('35AN refuses duplicate envelope key',()=>{
 const bytes=Buffer.from(rotation.bytes.toString().replace('{','{"schema":"BAD",'));
 const f=fixture();f.rotationBytes=bytes;f.externalPins.expectedRotationSha256=sha(bytes);
 assert.throws(()=>verifyOfflineRetentionKeyRotation(f),{code:'OFFLINE_ROTATION_INVALID_ENVELOPE'});
});
test('35AN refuses reordered envelope keys',()=>{
 const e=decode(rotation.bytes);const bytes=encode({newSignature:e.newSignature,...e});
 const f=fixture();f.rotationBytes=bytes;f.externalPins.expectedRotationSha256=sha(bytes);
 assert.throws(()=>verifyOfflineRetentionKeyRotation(f),{code:'OFFLINE_ROTATION_INVALID_ENVELOPE'});
});
test('35AN refuses inherited pins',()=>reject('OFFLINE_ROTATION_MISSING_EXTERNAL_PINS',{externalPins:Object.create(fixture().externalPins)}));
test('35AN refuses external getter without invoking it',()=>{
 const f=fixture();let called=false;
 Object.defineProperty(f.externalPins,'oldPins',{enumerable:true,get(){called=true;return oldPins;}});
 assert.throws(()=>verifyOfflineRetentionKeyRotation(f),{code:'OFFLINE_ROTATION_MISSING_EXTERNAL_PINS'});
 assert.equal(called,false);
});
test('35AN refuses old and new key equality on issuance',()=>assert.throws(()=>make({newSigningKey:keys.privateKey,newPublicKey:keys.publicKey}),{code:'OFFLINE_ROTATION_INVALID_BODY'}));
test('35AN refuses mismatched new signing key on issuance',()=>assert.throws(()=>make({newSigningKey:attacker.privateKey}),{code:'OFFLINE_ROTATION_KEY_MISMATCH'}));
test('35AN refuses extra production field on issuance',()=>assert.throws(()=>make({cutoverSequence:-1}),{code:'OFFLINE_ROTATION_INVALID_BODY'}));
test('35AN refuses retention-expired old receipt against trusted clock',()=>rejPin('OFFLINE_RETENTION_WINDOW_EXPIRED',{oldPins:{...oldPins,trustedNowMs:now+100000},newPins:{...newPins,trustedNowMs:now+100000}}));

test('35AN refuses nested pin getter without invoking it',()=>{
 const f=fixture();let called=false;
 Object.defineProperty(f.externalPins.newPins.expectedHead,'sequence',{enumerable:true,get(){called=true;return 3;}});
 assert.throws(()=>verifyOfflineRetentionKeyRotation(f),{code:'OFFLINE_ROTATION_MISSING_EXTERNAL_PINS'});
 assert.equal(called,false);
});
test('35AN supports old signer append window with independent predecessor anchor',()=>{
 const f=fixture();f.oldReceiptBytes=[signed[1].bytes];
 f.externalPins.oldPins={...oldPins,mode:'append',expectedAnchor:{sequence:0,
  receiptSha256:signed[0].sha256,observedAtMs:times[0],retainUntilMs:now+60000},
  expectedCheckpoints:[pin(1)]};
 const result=verifyOfflineRetentionKeyRotation(f);
 assert.equal(result.oldVerifiedCount,1);
 assert.equal(result.completeHistoryVerified,false);
});
test('35AN rejects old signer appended receipt with forged independent predecessor anchor',()=>{
 const f=fixture();f.oldReceiptBytes=[signed[1].bytes];
 f.externalPins.oldPins={...oldPins,mode:'append',expectedAnchor:{sequence:0,
  receiptSha256:sha('forged predecessor'),observedAtMs:times[0],retainUntilMs:now+60000},
  expectedCheckpoints:[pin(1)]};
 assert.throws(()=>verifyOfflineRetentionKeyRotation(f),{code:'OFFLINE_RETENTION_CHAIN_BROKEN'});
});
