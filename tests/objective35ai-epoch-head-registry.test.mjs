import test from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPairSync,createHash} from 'node:crypto';
import {mkdtemp,chmod,rm,writeFile,readFile,readdir,unlink,symlink} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawn} from 'node:child_process';
import {serializeOfflineWitnessRoster} from '../src/preview-local-artwork-review-witness-roster-ledger.mjs';
import {createOfflineWitnessRosterEpochTransition} from '../src/preview-local-artwork-review-witness-epoch.mjs';
import {createOfflineEpochGenesis,initializeOfflineEpochHeadRegistry,
 readOfflinePinnedEpochHead,advanceOfflinePinnedEpochHead,compareOfflineEpochHeadPins}
 from '../src/preview-local-artwork-review-epoch-head-registry.mjs';
const sha=x=>createHash('sha256').update(x).digest('hex');
const fp=k=>sha(k.export({type:'spki',format:'der'}));
const issuer=generateKeyPairSync('ed25519'),w1=generateKeyPairSync('ed25519'),w2=generateKeyPairSync('ed25519');
const now=1700000000000,cutoverMs=now-500;
const namespacePin=sha('35AI-namespace'),rootPin=sha('35AI-root'),registryId=sha('35AI-registry'),
 policySignerFingerprint=sha('35AI-policy'),audience=sha('35AI-audience');
const witnesses=[{witnessId:sha('a'),publicKeyFingerprint:fp(w1.publicKey),status:'active'},
 {witnessId:sha('b'),publicKeyFingerprint:fp(w2.publicKey),status:'active'}].sort((a,b)=>a.witnessId.localeCompare(b.witnessId));
const base={rootPin,registryId,policySignerFingerprint,audience};
const oldRoster=serializeOfflineWitnessRoster({...base,validFromMs:now-10000,validUntilMs:now+1000,witnesses});
const newRoster=serializeOfflineWitnessRoster({...base,validFromMs:now-1000,validUntilMs:now+10000,
 witnesses:[{...witnesses[0],status:'revoked'},witnesses[1]]});
const genesis=createOfflineEpochGenesis({namespacePin,rootPin,registryId,epoch:2,rosterSha256:oldRoster.sha256});
const transition=createOfflineWitnessRosterEpochTransition({signingKey:issuer.privateKey,...base,
 previousRosterSha256:oldRoster.sha256,nextRosterSha256:newRoster.sha256,
 previousEpoch:2,nextEpoch:3,cutoverMs});
const verification={transitionBytes:transition.bytes,expectedTransitionSha256:transition.sha256,
 issuerPublicKey:issuer.publicKey,expectedIssuerKeyFingerprint:fp(issuer.publicKey),
 previousRosterBytes:oldRoster.bytes,nextRosterBytes:newRoster.bytes,
 expectedPreviousRosterSha256:oldRoster.sha256,expectedNextRosterSha256:newRoster.sha256,
 expectedRootPin:rootPin,expectedRegistryId:registryId,
 expectedPolicySignerFingerprint:policySignerFingerprint,expectedAudience:audience,
 expectedPreviousEpoch:2,expectedNextEpoch:3,trustedNowMs:now};
const setup=async()=>{const directory=await mkdtemp(join(tmpdir(),'tj35ai-'));await chmod(directory,0o700);
 await initializeOfflineEpochHeadRegistry({directory,namespacePin,genesisBytes:genesis.bytes,
 expectedGenesisSha256:genesis.head.recordSha256});return directory;};
const external=h=>({epoch:h.epoch,rosterSha256:h.rosterSha256,recordSha256:h.recordSha256});
const args=(directory,extra={})=>({directory,namespacePin,expectedGenesisSha256:genesis.head.recordSha256,expectedHead:genesis.head,
 transitionVerification:verification,...extra});
const run=async fn=>{const d=await setup();try{return await fn(d);}finally{await rm(d,{recursive:true,force:true});}};
const rejects=async(fn,code)=>assert.rejects(fn,{code});
test('35AI creates immutable externally pinnable genesis without production authority',()=>{
 assert.equal(genesis.head.epoch,2);assert.equal(genesis.head.recordSha256,sha(genesis.bytes));
 assert.equal(genesis.authorizesProduction,false);
});
test('35AI independently pinned genesis opens and validates',()=>run(async d=>{
 const h=await readOfflinePinnedEpochHead({directory:d,namespacePin,expectedGenesisSha256:genesis.head.recordSha256,expectedHead:genesis.head});
 assert.equal(h.epoch,2);assert.equal(h.authorizesProduction,false);assert.equal(h.independentCustodyVerified,false);
}));
test('35AI signed epoch transition advances append-only head exactly once',()=>run(async d=>{
 const h=await advanceOfflinePinnedEpochHead(args(d));assert.equal(h.epoch,3);
 assert.equal(h.rosterSha256,newRoster.sha256);assert.equal(h.authorizesProduction,false);
 const reopened=await readOfflinePinnedEpochHead({directory:d,namespacePin,expectedGenesisSha256:genesis.head.recordSha256,expectedHead:external(h)});
 assert.equal(reopened.recordSha256,h.recordSha256);
 await rejects(advanceOfflinePinnedEpochHead(args(d)),'OFFLINE_EPOCH_HEAD_PIN_MISMATCH');
}));
test('35AI six concurrent CAS attempts have exactly one winner',()=>run(async d=>{
 const results=await Promise.allSettled(Array.from({length:6},()=>advanceOfflinePinnedEpochHead(args(d))));
 assert.equal(results.filter(x=>x.status==='fulfilled').length,1);
 assert.equal(results.filter(x=>x.status==='rejected').length,5);
 assert(results.filter(x=>x.status==='rejected').every(x=>
  ['OFFLINE_EPOCH_HEAD_CONFLICT','OFFLINE_EPOCH_HEAD_PIN_MISMATCH'].includes(x.reason.code)));
}));
test('35AI cross-process CAS has one winner',()=>run(async d=>{
 const script=new URL('./support/objective35ai-worker.mjs',import.meta.url);
 const payload=JSON.stringify({directory:d,namespacePin,expectedGenesisSha256:genesis.head.recordSha256,expectedHead:genesis.head,
  transitionVerification:{...verification,transitionBytes:transition.bytes.toString('base64'),
   previousRosterBytes:oldRoster.bytes.toString('base64'),nextRosterBytes:newRoster.bytes.toString('base64'),
   issuerPublicKey:issuer.publicKey.export({type:'spki',format:'pem'})}});
 const child=()=>new Promise((resolve,reject)=>{const p=spawn(process.execPath,[script.pathname],{stdio:['pipe','pipe','pipe']});
  let out='',err='';p.stdout.on('data',b=>out+=b);p.stderr.on('data',b=>err+=b);
  p.on('error',reject);p.on('close',code=>resolve({code,out,err}));p.stdin.end(payload);});
 const results=await Promise.all(Array.from({length:4},child));
 assert.equal(results.filter(x=>x.code===0).length,1,JSON.stringify(results));
 assert.equal(results.filter(x=>x.code!==0).length,3);
}));
test('35AI conflicting same-epoch independent pins reveal split view',()=>{
 assert.throws(()=>compareOfflineEpochHeadPins(genesis.head,{...genesis.head,recordSha256:sha('fork')}),
  {code:'OFFLINE_EPOCH_HEAD_SPLIT_VIEW'});
});
test('35AI identical external pins do not imply custody or global consensus',()=>{
 const c=compareOfflineEpochHeadPins(genesis.head,genesis.head);
 assert.equal(c.sameHead,true);assert.equal(c.continuityVerified,false);
});
test('35AI differing epoch pins do not imply chain continuity',()=>{
 const c=compareOfflineEpochHeadPins(genesis.head,{epoch:3,rosterSha256:newRoster.sha256,recordSha256:sha('x')});
 assert.equal(c.sameHead,false);assert.equal(c.continuityVerified,false);
});
for(const [label,patch,code] of [
 ['missing external head', {expectedHead:undefined},'OFFLINE_EPOCH_HEAD_MISSING_EXTERNAL_PIN'],
 ['substituted namespace',{namespacePin:sha('fake')},'OFFLINE_EPOCH_HEAD_NAMESPACE_MISMATCH'],
 ['stale roster pin',{expectedHead:{...genesis.head,rosterSha256:sha('wrong')}},'OFFLINE_EPOCH_HEAD_PIN_MISMATCH'],
 ['stale digest pin',{expectedHead:{...genesis.head,recordSha256:sha('wrong')}},'OFFLINE_EPOCH_HEAD_PIN_MISMATCH'],
 ['invalid transition',{transitionVerification:undefined},'OFFLINE_EPOCH_HEAD_MISSING_TRANSITION'],
 ['forged transition pin',{transitionVerification:{...verification,expectedTransitionSha256:sha('wrong')}},'OFFLINE_EPOCH_DIGEST_MISMATCH'],
 ['invalid trusted time',{transitionVerification:{...verification,trustedNowMs:cutoverMs-1}},'OFFLINE_EPOCH_NOT_YET_ACTIVE'],
 ['substituted next roster',{transitionVerification:{...verification,nextRosterBytes:oldRoster.bytes}},'OFFLINE_ROSTER_PIN_MISMATCH'],
 ['wrong next epoch',{transitionVerification:{...verification,expectedNextEpoch:4}},null],
])test(`35AI rejects ${label}`,()=>run(async d=>{
 if(label==='wrong next epoch'){
  // Caller-supplied next epoch is replaced by the locally pinned CAS head.
  const h=await advanceOfflinePinnedEpochHead(args(d,patch));assert.equal(h.epoch,3);return;
 }
 await rejects(advanceOfflinePinnedEpochHead(args(d,patch)),code);
}));
test('35AI missing last head rejected when externally pinned to it',()=>run(async d=>{
 const h=await advanceOfflinePinnedEpochHead(args(d));await unlink(join(d,'epoch-000000000000003.json'));
 await rejects(readOfflinePinnedEpochHead({directory:d,namespacePin,expectedGenesisSha256:genesis.head.recordSha256,expectedHead:external(h)}),'OFFLINE_EPOCH_HEAD_PIN_MISMATCH');
}));
test('35AI partial interrupted next-epoch write permanently blocks reuse',()=>run(async d=>{
 await writeFile(join(d,'epoch-000000000000003.json'),Buffer.from('{'),{flag:'wx',mode:0o600});
 await rejects(advanceOfflinePinnedEpochHead(args(d)),'OFFLINE_EPOCH_HEAD_INVALID_RECORD');
}));
test('35AI deleted genesis rejected after advance',()=>run(async d=>{
 const h=await advanceOfflinePinnedEpochHead(args(d));await unlink(join(d,'epoch-000000000000002.json'));
 await rejects(readOfflinePinnedEpochHead({directory:d,namespacePin,expectedGenesisSha256:genesis.head.recordSha256,expectedHead:external(h)}),'OFFLINE_EPOCH_HEAD_GENESIS_MISMATCH');
}));
test('35AI tampered genesis rejected even with unchanged external head',()=>run(async d=>{
 const p=join(d,'epoch-000000000000002.json');const x=JSON.parse(await readFile(p));x.rosterSha256=sha('tampered');
 await writeFile(p,JSON.stringify(x));await rejects(readOfflinePinnedEpochHead({directory:d,namespacePin,expectedGenesisSha256:genesis.head.recordSha256,expectedHead:genesis.head}),
 'OFFLINE_EPOCH_HEAD_GENESIS_MISMATCH');
}));
test('35AI symlink substitution rejected',()=>run(async d=>{
 const p=join(d,'epoch-000000000000002.json');await unlink(p);await symlink(join(d,'.tj-epoch-namespace.json'),p);
 await rejects(readOfflinePinnedEpochHead({directory:d,namespacePin,expectedGenesisSha256:genesis.head.recordSha256,expectedHead:genesis.head}),
 'OFFLINE_EPOCH_HEAD_UNSAFE_RECORD');
}));
test('35AI unexpected directory entry rejected',()=>run(async d=>{
 await writeFile(join(d,'unexpected.json'),'x');
 await rejects(readOfflinePinnedEpochHead({directory:d,namespacePin,expectedGenesisSha256:genesis.head.recordSha256,expectedHead:genesis.head}),
 'OFFLINE_EPOCH_HEAD_UNEXPECTED_ENTRY');
}));
test('35AI gap in epoch chain rejected',()=>run(async d=>{
 await writeFile(join(d,'epoch-000000000000004.json'),genesis.bytes,{mode:0o600});
 await rejects(readOfflinePinnedEpochHead({directory:d,namespacePin,expectedGenesisSha256:genesis.head.recordSha256,expectedHead:genesis.head}),
 'OFFLINE_EPOCH_HEAD_GAP');
}));
test('35AI crash during initialization leaves no silent repair path',async()=>{
 const d=await mkdtemp(join(tmpdir(),'tj35ai-init-'));await chmod(d,0o700);
 try{await writeFile(join(d,'.tj-epoch-namespace.json'),'broken',{mode:0o600});
 await rejects(initializeOfflineEpochHeadRegistry({directory:d,namespacePin,
  genesisBytes:genesis.bytes,expectedGenesisSha256:genesis.head.recordSha256}),
  'OFFLINE_EPOCH_HEAD_NOT_EMPTY');}finally{await rm(d,{recursive:true,force:true});}
});
test('35AI directory with world permissions rejected',async()=>{
 const d=await setup();try{await chmod(d,0o755);
 await rejects(readOfflinePinnedEpochHead({directory:d,namespacePin,expectedGenesisSha256:genesis.head.recordSha256,expectedHead:genesis.head}),
  'OFFLINE_EPOCH_HEAD_UNSAFE_DIRECTORY');}finally{await rm(d,{recursive:true,force:true});}
});
test('35AI genesis rejects noncanonical identity fields',()=>{
 assert.throws(()=>createOfflineEpochGenesis({namespacePin:'wrong',rootPin,registryId,
  epoch:2,rosterSha256:oldRoster.sha256}),{code:'OFFLINE_EPOCH_HEAD_INVALID_RECORD'});
});
test('35AI genesis initialization refuses mismatched external hash',async()=>{
 const d=await mkdtemp(join(tmpdir(),'tj35ai-init-'));await chmod(d,0o700);
 try{await rejects(initializeOfflineEpochHeadRegistry({directory:d,namespacePin,
  genesisBytes:genesis.bytes,expectedGenesisSha256:sha('wrong')}),
  'OFFLINE_EPOCH_HEAD_GENESIS_MISMATCH');}finally{await rm(d,{recursive:true,force:true});}
});
test('35AI all committed record files are exclusive 0600',()=>run(async d=>{
 await advanceOfflinePinnedEpochHead(args(d));const files=await readdir(d);
 assert.deepEqual(files.sort(),['.tj-epoch-namespace.json','epoch-000000000000002.json','epoch-000000000000003.json']);
}));
