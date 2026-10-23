import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,createHash} from 'node:crypto';
import {mkdtemp,chmod,rm,writeFile,readFile,symlink,mkdir} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {createOfflineWitnessAcknowledgement} from '../src/preview-local-artwork-review-witness-acknowledgements.mjs';
import {LOCAL_REVIEW_RETAINED_HEAD_SCHEMA} from '../src/preview-local-artwork-review-policy-checkpoints.mjs';
import {OFFLINE_WITNESS_ROSTER_SCHEMA,OFFLINE_WITNESS_LEDGER_SCHEMA,
 serializeOfflineWitnessRoster,verifyOfflinePinnedWitnessRoster,
 initializeOfflineWitnessChallengeLedger,openOfflineWitnessChallengeLedger,
 verifyOfflineWitnessWithPinnedRoster,deriveOfflineWitnessChallengeReceiptPin}
 from '../src/preview-local-artwork-review-witness-roster-ledger.mjs';
const hash=x=>createHash('sha256').update(x).digest('hex');
const kp=generateKeyPairSync('ed25519'),a=generateKeyPairSync('ed25519'),b=generateKeyPairSync('ed25519'),c=generateKeyPairSync('ed25519');
const fp=k=>hash(k.export({type:'spki',format:'der'}));
const rootPin=hash('35AG-root'),registryId=hash('35AG-registry'),audience=hash('35AG-audience');
const parentSha=hash('35AG-parent'),candidateSha=hash('35AG-candidate'),signerFp=fp(kp.publicKey);
const witnessA=hash('35AG-a'),witnessB=hash('35AG-b'),witnessC=hash('35AG-c');
const challenge=hash('35AG-challenge'),now=1700000000000;
const head={schema:LOCAL_REVIEW_RETAINED_HEAD_SCHEMA,rootPin,registryId,signerFingerprint:signerFp,
 checkpointSha256:parentSha,revision:4};
const witnesses=[{witnessId:witnessA,publicKeyFingerprint:fp(a.publicKey),status:'active'},
 {witnessId:witnessB,publicKeyFingerprint:fp(b.publicKey),status:'active'}].sort((x,y)=>x.witnessId.localeCompare(y.witnessId));
const base={rootPin,registryId,policySignerFingerprint:signerFp,audience,
 validFromMs:now-5000,validUntilMs:now+5000,witnesses};
const roster=serializeOfflineWitnessRoster(base);
const pins={rosterBytes:roster.bytes,expectedRosterSha256:roster.sha256,
 expectedRootPin:rootPin,expectedRegistryId:registryId,
 expectedPolicySignerFingerprint:signerFp,expectedAudience:audience,trustedNowMs:now};
const ack=(key=a.privateKey,wid=witnessA,ch=challenge,more={})=>createOfflineWitnessAcknowledgement({
 signingKey:key,witnessId:wid,head,candidateCheckpointSha256:candidateSha,
 challenge:ch,audience,issuedAtMs:now-1000,expiresAtMs:now+1000,...more}).bytes;
const receipt=ack();
const args=(ledger,extra={})=>({...pins,witnessId:witnessA,witnessPublicKey:a.publicKey,
 challenge,receiptBytes:receipt,expectedParentCheckpointSha256:parentSha,
 expectedParentRevision:4,expectedCandidateSha256:candidateSha,expectedCandidateRevision:5,
 ledger,...extra});
const rejection=(p,code)=>assert.rejects(p,{code});
const invalid=(extra,code)=>assert.throws(()=>verifyOfflinePinnedWitnessRoster({...pins,...extra}),{code});
const altered=(change)=>{const o=JSON.parse(roster.bytes);change(o);const bytes=Buffer.from(JSON.stringify(o));return {rosterBytes:bytes,expectedRosterSha256:hash(bytes)};};
const tmp=async()=>{const dir=await mkdtemp(join(tmpdir(),'tj35ag-'));await chmod(dir,0o700);return dir;};
const openLedger=async(dir,ns=roster.sha256)=>{await initializeOfflineWitnessChallengeLedger({directory:dir,namespacePin:ns});return openOfflineWitnessChallengeLedger({directory:dir,namespacePin:ns});};
const replayToken=bytes=>{const p=JSON.parse(bytes);return hash(Buffer.from(`TRENDYJOES_LOCAL_POLICY_WITNESS_ACK_35AF_V1\nREPLAY\n${hash(bytes)}\n${p.witnessId}\n${p.audience}\n${p.challenge}`));};
const receiptParams=(bytes=receipt)=>({witnessId:witnessA,challenge,audience,registryId,receiptReplayToken:replayToken(bytes)});
const runChild=(directory,ns,params)=>new Promise((resolve,reject)=>{
 const src=`import {openOfflineWitnessChallengeLedger} from ${JSON.stringify(fileURLToPath(new URL('../src/preview-local-artwork-review-witness-roster-ledger.mjs',import.meta.url)))};\nconst l=await openOfflineWitnessChallengeLedger({directory:process.env.DIR,namespacePin:process.env.NS});\ntry{const r=await l.consumeOnce(JSON.parse(process.env.PARAMS));console.log(JSON.stringify({ok:r}));}catch(e){console.log(JSON.stringify({error:e.code}));}`;
 const p=spawn(process.execPath,['--input-type=module','-e',src],{env:{...process.env,DIR:directory,NS:ns,PARAMS:JSON.stringify(params)},stdio:['ignore','pipe','pipe']});
 let out='',err='';p.stdout.on('data',d=>out+=d);p.stderr.on('data',d=>err+=d);
 p.on('error',reject);p.on('close',code=>{if(code!==0)return reject(Error(`child ${code} ${err}`));try{resolve(JSON.parse(out.trim()));}catch(e){reject(Error(`invalid child: ${out} ${err}`));}});
});

test('35AG roster serialization is non-authorizing and pinable',()=>{
 const r=verifyOfflinePinnedWitnessRoster(pins);
 assert.equal(r.schema,OFFLINE_WITNESS_ROSTER_SCHEMA);assert.equal(r.rosterSha256,roster.sha256);
 assert.equal(r.authorizesProduction,false);assert.equal(r.independentCustodyVerified,false);
 assert.equal(r.witnesses.length,2);assert.ok(Object.isFrozen(r.witnesses));
});
for(const [label,field,value] of [
 ['roster hash','expectedRosterSha256',hash('wrong')],
 ['root','expectedRootPin',hash('wrong')],['registry','expectedRegistryId',hash('wrong')],
 ['policy signer','expectedPolicySignerFingerprint',hash('wrong')],
 ['audience','expectedAudience',hash('wrong')]
])test(`35AG rejects ${label} pin substitution`,()=>{
 invalid({[field]:value},label==='roster hash'?'OFFLINE_ROSTER_PIN_MISMATCH':'OFFLINE_ROSTER_INVALID_POLICY');
});
test('35AG requires independent roster pin',()=>invalid({expectedRosterSha256:undefined},'OFFLINE_ROSTER_MISSING_EXTERNAL_PINS'));
test('35AG rejects invalid trusted clock',()=>invalid({trustedNowMs:NaN},'OFFLINE_ROSTER_MISSING_EXTERNAL_PINS'));
test('35AG rejects not-yet-valid roster',()=>invalid({trustedNowMs:now-5001},'OFFLINE_ROSTER_OUTSIDE_VALIDITY'));
test('35AG rejects expired roster',()=>invalid({trustedNowMs:now+5000},'OFFLINE_ROSTER_OUTSIDE_VALIDITY'));
test('35AG rejects noncanonical whitespace',()=>{
 const b=Buffer.from(JSON.stringify(JSON.parse(roster.bytes),null,2));invalid({rosterBytes:b,expectedRosterSha256:hash(b)},'OFFLINE_ROSTER_NONCANONICAL');
});
test('35AG rejects reordered JSON fields',()=>{
 const b=Buffer.from(JSON.stringify(Object.fromEntries(Object.entries(JSON.parse(roster.bytes)).reverse())));
 invalid({rosterBytes:b,expectedRosterSha256:hash(b)},'OFFLINE_ROSTER_NONCANONICAL');
});
test('35AG rejects unknown privilege fields',()=>invalid(altered(o=>o.allowCheckout=true),'OFFLINE_ROSTER_NONCANONICAL'));
for(const [label,edit] of [
 ['duplicate witness id',o=>o.witnesses[1].witnessId=o.witnesses[0].witnessId],
 ['duplicate witness key',o=>o.witnesses[1].publicKeyFingerprint=o.witnesses[0].publicKeyFingerprint],
 ['unsorted witnesses',o=>o.witnesses.reverse()],
 ['unknown status',o=>o.witnesses[0].status='administrator'],
 ['one witness',o=>o.witnesses.pop()],
 ['too many witnesses',o=>o.witnesses=Array.from({length:33},(_,i)=>({witnessId:hash(`w${i}`).toLowerCase(),publicKeyFingerprint:hash(`k${i}`),status:'active'}))],
 ['production authority',o=>o.authority='PRODUCTION'],
 ['invalid expiry',o=>o.validUntilMs=o.validFromMs]
])test(`35AG rejects ${label}`,()=>invalid(altered(edit),label==='one witness'||label==='too many witnesses'||label==='production authority'||label==='invalid expiry'?'OFFLINE_ROSTER_INVALID_POLICY':'OFFLINE_ROSTER_INVALID_WITNESSES'));
test('35AG rejects malformed UTF8/JSON',()=>{
 const b=Buffer.from('{bad');invalid({rosterBytes:b,expectedRosterSha256:hash(b)},'OFFLINE_ROSTER_NONCANONICAL');
});
test('35AG rejects oversized roster',()=>invalid({rosterBytes:Buffer.alloc(16385)},'OFFLINE_ROSTER_INVALID_BYTES'));

test('35AG initialize/open namespace marker is stable across reopen',async()=>{
 const d=await tmp();try{await initializeOfflineWitnessChallengeLedger({directory:d,namespacePin:roster.sha256});
  await initializeOfflineWitnessChallengeLedger({directory:d,namespacePin:roster.sha256});
  assert.equal((await openOfflineWitnessChallengeLedger({directory:d,namespacePin:roster.sha256})).namespacePin,roster.sha256);
 }finally{await rm(d,{recursive:true,force:true});}
});
test('35AG rejects mismatched namespace on open',async()=>{
 const d=await tmp();try{await openLedger(d);await rejection(openOfflineWitnessChallengeLedger({directory:d,namespacePin:hash('other')}),'OFFLINE_LEDGER_NAMESPACE_MISMATCH');}
 finally{await rm(d,{recursive:true,force:true});}
});
test('35AG rejects missing namespace marker',async()=>{
 const d=await tmp();try{await rejection(openOfflineWitnessChallengeLedger({directory:d,namespacePin:roster.sha256}),'OFFLINE_LEDGER_UNAVAILABLE');}
 finally{await rm(d,{recursive:true,force:true});}
});
test('35AG rejects partial namespace marker after crash',async()=>{
 const d=await tmp();try{await writeFile(join(d,'.tj-witness-namespace.json'),'{');
  await rejection(initializeOfflineWitnessChallengeLedger({directory:d,namespacePin:roster.sha256}),'OFFLINE_LEDGER_NAMESPACE_MISMATCH');
 }finally{await rm(d,{recursive:true,force:true});}
});
test('35AG rejects missing directory',async()=>{
 const d=await tmp();await rm(d,{recursive:true,force:true});
 await rejection(openOfflineWitnessChallengeLedger({directory:d,namespacePin:roster.sha256}),'OFFLINE_LEDGER_UNAVAILABLE');
});
test('35AG rejects symlink directory',async()=>{
 const d=await tmp(),link=d+'-link';try{await symlink(d,link);
  await rejection(openOfflineWitnessChallengeLedger({directory:link,namespacePin:roster.sha256}),'OFFLINE_LEDGER_UNSAFE_DIRECTORY');
 }finally{await rm(link,{force:true});await rm(d,{recursive:true,force:true});}
});
test('35AG rejects unsafe world-readable directory',async()=>{
 const d=await tmp();try{await chmod(d,0o755);
  await rejection(openOfflineWitnessChallengeLedger({directory:d,namespacePin:roster.sha256}),'OFFLINE_LEDGER_UNSAFE_DIRECTORY');
 }finally{await chmod(d,0o700);await rm(d,{recursive:true,force:true});}
});
test('35AG rejects relative directory',async()=>{
 await rejection(openOfflineWitnessChallengeLedger({directory:'./tmp',namespacePin:roster.sha256}),'OFFLINE_LEDGER_INVALID_DIRECTORY');
});
test('35AG refuses forged in-memory ledger adapter',async()=>{
 await rejection(verifyOfflineWitnessWithPinnedRoster(args({namespacePin:roster.sha256,consumeOnce:async()=>true})),'OFFLINE_LEDGER_TRUST_BOUNDARY');
});
test('35AG refuses mismatched roster namespace',async()=>{
 const d=await tmp();try{const l=await openLedger(d,hash('wrong'));
  await rejection(verifyOfflineWitnessWithPinnedRoster(args(l)),'OFFLINE_LEDGER_TRUST_BOUNDARY');
 }finally{await rm(d,{recursive:true,force:true});}
});
test('35AG signed receipt consumes a challenge durably',async()=>{
 const d=await tmp();try{const l=await openLedger(d),result=await verifyOfflineWitnessWithPinnedRoster(args(l));
  assert.equal(result.signatureVerified,true);assert.equal(result.authorizesProduction,false);
  const pin=deriveOfflineWitnessChallengeReceiptPin({namespacePin:roster.sha256,...receiptParams()});
  assert.equal((await l.assertRetainedReceipt({...receiptParams(),expectedReceiptSha256:pin.receiptSha256})).retained,true);
 }finally{await rm(d,{recursive:true,force:true});}
});
test('35AG same receipt replay fails after reopening durable ledger',async()=>{
 const d=await tmp();try{const l=await openLedger(d);await verifyOfflineWitnessWithPinnedRoster(args(l));
  const reopened=await openOfflineWitnessChallengeLedger({directory:d,namespacePin:roster.sha256});
  await rejection(verifyOfflineWitnessWithPinnedRoster(args(reopened)),'OFFLINE_WITNESS_REPLAY');
 }finally{await rm(d,{recursive:true,force:true});}
});
test('35AG differently signed receipt cannot reuse same witness challenge',async()=>{
 const d=await tmp();try{const l=await openLedger(d);await verifyOfflineWitnessWithPinnedRoster(args(l));
  const changed=ack(a.privateKey,witnessA,challenge,{issuedAtMs:now-500});
  assert.notEqual(hash(changed),hash(receipt));
  await rejection(verifyOfflineWitnessWithPinnedRoster(args(l,{receiptBytes:changed})),'OFFLINE_WITNESS_REPLAY');
 }finally{await rm(d,{recursive:true,force:true});}
});
test('35AG separate challenges can be consumed independently',async()=>{
 const d=await tmp();try{const l=await openLedger(d);await verifyOfflineWitnessWithPinnedRoster(args(l));
  const second=hash('35AG-second');const r=await verifyOfflineWitnessWithPinnedRoster(args(l,{challenge:second,receiptBytes:ack(a.privateKey,witnessA,second)}));
  assert.equal(r.signatureVerified,true);
 }finally{await rm(d,{recursive:true,force:true});}
});
test('35AG distinct witness same challenge uses distinct ledger key',async()=>{
 const d=await tmp();try{const l=await openLedger(d);await verifyOfflineWitnessWithPinnedRoster(args(l));
  const r=await verifyOfflineWitnessWithPinnedRoster(args(l,{witnessId:witnessB,witnessPublicKey:b.publicKey,receiptBytes:ack(b.privateKey,witnessB)}));
  assert.equal(r.signatureVerified,true);
 }finally{await rm(d,{recursive:true,force:true});}
});
test('35AG concurrent in-process attempts admit exactly one',async()=>{
 const d=await tmp();try{const l=await openLedger(d);const results=await Promise.allSettled(Array.from({length:8},()=>verifyOfflineWitnessWithPinnedRoster(args(l))));
  assert.equal(results.filter(r=>r.status==='fulfilled').length,1);
  assert.equal(results.filter(r=>r.status==='rejected'&&r.reason.code==='OFFLINE_WITNESS_REPLAY').length,7);
 }finally{await rm(d,{recursive:true,force:true});}
});
test('35AG independent child processes race atomically on same challenge',async()=>{
 const d=await tmp();try{await openLedger(d);const results=await Promise.all(Array.from({length:6},()=>runChild(d,roster.sha256,receiptParams())));
  assert.equal(results.filter(x=>x.ok===true).length,1);assert.equal(results.filter(x=>x.ok===false).length,5);
 }finally{await rm(d,{recursive:true,force:true});}
});
test('35AG independent child process cannot replay parent-consumed challenge',async()=>{
 const d=await tmp();try{const l=await openLedger(d);await verifyOfflineWitnessWithPinnedRoster(args(l));
  assert.deepEqual(await runChild(d,roster.sha256,receiptParams()),{ok:false});
 }finally{await rm(d,{recursive:true,force:true});}
});
test('35AG empty token file simulates crash and permanently blocks reuse',async()=>{
 const d=await tmp();try{const l=await openLedger(d);const pin=deriveOfflineWitnessChallengeReceiptPin({namespacePin:roster.sha256,...receiptParams()});
  await writeFile(join(d,`c-${pin.challengeKey}.json`),'');
  await rejection(verifyOfflineWitnessWithPinnedRoster(args(l)),'OFFLINE_WITNESS_REPLAY');
  await rejection(l.assertRetainedReceipt({...receiptParams(),expectedReceiptSha256:pin.receiptSha256}),'OFFLINE_LEDGER_RETENTION_MISMATCH');
 }finally{await rm(d,{recursive:true,force:true});}
});
test('35AG deleted token fails independently pinned retention check',async()=>{
 const d=await tmp();try{const l=await openLedger(d);await verifyOfflineWitnessWithPinnedRoster(args(l));
  const pin=deriveOfflineWitnessChallengeReceiptPin({namespacePin:roster.sha256,...receiptParams()});
  await rm(join(d,`c-${pin.challengeKey}.json`));
  await rejection(l.assertRetainedReceipt({...receiptParams(),expectedReceiptSha256:pin.receiptSha256}),'OFFLINE_LEDGER_RETENTION_MISSING');
 }finally{await rm(d,{recursive:true,force:true});}
});
test('35AG tampered token fails externally pinned retention check',async()=>{
 const d=await tmp();try{const l=await openLedger(d);await verifyOfflineWitnessWithPinnedRoster(args(l));
  const pin=deriveOfflineWitnessChallengeReceiptPin({namespacePin:roster.sha256,...receiptParams()});
  await writeFile(join(d,`c-${pin.challengeKey}.json`),'tampered');
  await rejection(l.assertRetainedReceipt({...receiptParams(),expectedReceiptSha256:pin.receiptSha256}),'OFFLINE_LEDGER_RETENTION_MISMATCH');
 }finally{await rm(d,{recursive:true,force:true});}
});
test('35AG retention verification requires external SHA pin',async()=>{
 const d=await tmp();try{const l=await openLedger(d);await rejection(l.assertRetainedReceipt(receiptParams()),'OFFLINE_LEDGER_EXTERNAL_PIN_REQUIRED');}
 finally{await rm(d,{recursive:true,force:true});}
});
test('35AG rejects wrong externally retained SHA pin',async()=>{
 const d=await tmp();try{const l=await openLedger(d);await verifyOfflineWitnessWithPinnedRoster(args(l));
  await rejection(l.assertRetainedReceipt({...receiptParams(),expectedReceiptSha256:hash('other')}),'OFFLINE_LEDGER_RETENTION_MISMATCH');
 }finally{await rm(d,{recursive:true,force:true});}
});
test('35AG revoked roster witness fails closed before token consumption',async()=>{
 const d=await tmp();try{const l=await openLedger(d),r=altered(o=>o.witnesses.find(w=>w.witnessId===witnessA).status='revoked');
  await rejection(verifyOfflineWitnessWithPinnedRoster(args(l,{...r})),'OFFLINE_LEDGER_TRUST_BOUNDARY');
 }finally{await rm(d,{recursive:true,force:true});}
});
test('35AG unknown witness rejected without ledger mutation',async()=>{
 const d=await tmp();try{const l=await openLedger(d);
  await rejection(verifyOfflineWitnessWithPinnedRoster(args(l,{witnessId:witnessC,witnessPublicKey:c.publicKey,
   receiptBytes:ack(c.privateKey,witnessC)})),'OFFLINE_ROSTER_WITNESS_NOT_ACTIVE');
  assert.equal((await verifyOfflineWitnessWithPinnedRoster(args(l))).signatureVerified,true);
 }finally{await rm(d,{recursive:true,force:true});}
});
test('35AG substituted witness key rejected before ledger mutation',async()=>{
 const d=await tmp();try{const l=await openLedger(d);
  await rejection(verifyOfflineWitnessWithPinnedRoster(args(l,{witnessPublicKey:c.publicKey})),'OFFLINE_WITNESS_INVALID_TRUST_BOUNDARY');
  assert.equal((await verifyOfflineWitnessWithPinnedRoster(args(l))).signatureVerified,true);
 }finally{await rm(d,{recursive:true,force:true});}
});
test('35AG substituted candidate checkpoint rejected before ledger mutation',async()=>{
 const d=await tmp();try{const l=await openLedger(d);
  await rejection(verifyOfflineWitnessWithPinnedRoster(args(l,{expectedCandidateSha256:hash('other')})),'OFFLINE_WITNESS_PIN_MISMATCH');
  assert.equal((await verifyOfflineWitnessWithPinnedRoster(args(l))).signatureVerified,true);
 }finally{await rm(d,{recursive:true,force:true});}
});
test('35AG expired acknowledgement rejected before ledger mutation',async()=>{
 const d=await tmp();try{const l=await openLedger(d);
  await rejection(verifyOfflineWitnessWithPinnedRoster(args(l,{receiptBytes:ack(a.privateKey,witnessA,challenge,{expiresAtMs:now})})),'OFFLINE_WITNESS_EXPIRED');
  assert.equal((await verifyOfflineWitnessWithPinnedRoster(args(l))).signatureVerified,true);
 }finally{await rm(d,{recursive:true,force:true});}
});
test('35AG invalid challenge token rejected without creating file',async()=>{
 const d=await tmp();try{const l=await openLedger(d);
  await rejection(l.consumeOnce({...receiptParams(),challenge:'oops'}),'OFFLINE_LEDGER_INVALID_CHALLENGE');
  assert.equal((await verifyOfflineWitnessWithPinnedRoster(args(l))).signatureVerified,true);
 }finally{await rm(d,{recursive:true,force:true});}
});
test('35AG token creation uses fixed namespace and schema',async()=>{
 const d=await tmp();try{const l=await openLedger(d);await verifyOfflineWitnessWithPinnedRoster(args(l));
  const pin=deriveOfflineWitnessChallengeReceiptPin({namespacePin:roster.sha256,...receiptParams()});
  const data=JSON.parse(await readFile(join(d,`c-${pin.challengeKey}.json`)));
  assert.equal(data.schema,OFFLINE_WITNESS_LEDGER_SCHEMA);assert.equal(data.namespacePin,roster.sha256);
  assert.equal(data.challengeKey,pin.challengeKey);
 }finally{await rm(d,{recursive:true,force:true});}
});
test('35AG externally pinned retention prevents opening rolled-back ledger',async()=>{
 const d=await tmp();try{const l=await openLedger(d);await verifyOfflineWitnessWithPinnedRoster(args(l));
  const pin=deriveOfflineWitnessChallengeReceiptPin({namespacePin:roster.sha256,...receiptParams()});
  const retained={...receiptParams(),expectedReceiptSha256:pin.receiptSha256};
  const pinned=await openOfflineWitnessChallengeLedger({directory:d,namespacePin:roster.sha256,pinnedRetainedReceipts:[retained]});
  assert.equal(pinned.namespacePin,roster.sha256);
  await rm(join(d,`c-${pin.challengeKey}.json`));
  await rejection(openOfflineWitnessChallengeLedger({directory:d,namespacePin:roster.sha256,pinnedRetainedReceipts:[retained]}),'OFFLINE_LEDGER_RETENTION_MISSING');
  await rejection(pinned.consumeOnce({...receiptParams(),challenge:hash('new-challenge')}),'OFFLINE_LEDGER_RETENTION_MISSING');
 }finally{await rm(d,{recursive:true,force:true});}
});
test('35AG retained pin mismatch fails before opening ledger',async()=>{
 const d=await tmp();try{const l=await openLedger(d);await verifyOfflineWitnessWithPinnedRoster(args(l));
  await rejection(openOfflineWitnessChallengeLedger({directory:d,namespacePin:roster.sha256,
   pinnedRetainedReceipts:[{...receiptParams(),expectedReceiptSha256:hash('forged')}]}),'OFFLINE_LEDGER_RETENTION_MISMATCH');
 }finally{await rm(d,{recursive:true,force:true});}
});
test('35AG rejects invalid retention pin array',async()=>{
 const d=await tmp();try{await openLedger(d);
  await rejection(openOfflineWitnessChallengeLedger({directory:d,namespacePin:roster.sha256,pinnedRetainedReceipts:[{}]}),'OFFLINE_LEDGER_INVALID_RETENTION_PINS');
 }finally{await rm(d,{recursive:true,force:true});}
});
test('35AG rejects namespace marker symlink even if content matches',async()=>{
 const d=await tmp();try{const target=join(d,'real-marker');
  await writeFile(target,JSON.stringify({schema:OFFLINE_WITNESS_LEDGER_SCHEMA,namespacePin:roster.sha256}));
  await symlink(target,join(d,'.tj-witness-namespace.json'));
  await rejection(initializeOfflineWitnessChallengeLedger({directory:d,namespacePin:roster.sha256}),'OFFLINE_LEDGER_NAMESPACE_MISMATCH');
  await rejection(openOfflineWitnessChallengeLedger({directory:d,namespacePin:roster.sha256}),'OFFLINE_LEDGER_NAMESPACE_MISMATCH');
 }finally{await rm(d,{recursive:true,force:true});}
});
test('35AG rejects world-readable namespace marker',async()=>{
 const d=await tmp();try{await openLedger(d);await chmod(join(d,'.tj-witness-namespace.json'),0o644);
  await rejection(openOfflineWitnessChallengeLedger({directory:d,namespacePin:roster.sha256}),'OFFLINE_LEDGER_NAMESPACE_MISMATCH');
 }finally{await rm(d,{recursive:true,force:true});}
});
test('35AG rejects world-readable retained challenge receipt',async()=>{
 const d=await tmp();try{const l=await openLedger(d);await verifyOfflineWitnessWithPinnedRoster(args(l));
  const pin=deriveOfflineWitnessChallengeReceiptPin({namespacePin:roster.sha256,...receiptParams()});
  await chmod(join(d,`c-${pin.challengeKey}.json`),0o644);
  await rejection(l.assertRetainedReceipt({...receiptParams(),expectedReceiptSha256:pin.receiptSha256}),'OFFLINE_LEDGER_RETENTION_MISMATCH');
 }finally{await rm(d,{recursive:true,force:true});}
});
test('35AG pinned revoked roster prevents witness acceptance with matching namespace',async()=>{
 const d=await tmp();try{const r=altered(o=>o.witnesses.find(w=>w.witnessId===witnessA).status='revoked');
  const l=await openLedger(d,r.expectedRosterSha256);
  await rejection(verifyOfflineWitnessWithPinnedRoster(args(l,{...r})),'OFFLINE_ROSTER_WITNESS_NOT_ACTIVE');
 }finally{await rm(d,{recursive:true,force:true});}
});
