import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,readFile,writeFile,chmod,symlink,truncate,readdir,unlink,link,stat} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash,generateKeyPairSync} from 'node:crypto';
import {spawn} from 'node:child_process';
import {make,now} from './support/objective32l-fixture.mjs';
import {createOfflineConflictExchangeOffer,acceptOfflineConflictExchangeOffer,
 encodeOfflineConflictExchangeTranscript,verifyOfflineConflictExchange} from '../src/offline-conflict-proof-exchange.mjs';
import {createOfflineConflictExchangeJournal,offlineConflictExchangeJournalGenesisHead,
 OFFLINE_CONFLICT_EXCHANGE_JOURNAL_SCHEMA} from '../src/offline-conflict-exchange-journal.mjs';
const sha=x=>createHash('sha256').update(x).digest('hex');
const err=code=>e=>e?.code===code;
const sender=generateKeyPairSync('ed25519'),receiver=generateKeyPairSync('ed25519');
const genesisExchangeDigest=sha('independent-prior-exchange-pin');
const proof=make(),proofBytes=proof.bytes,expectedPin=proof.pinCandidate,expectedProofDigest=sha(proofBytes);
const common={proofBytes,expectedPin,expectedProofDigest,senderPublicKey:sender.publicKey,
 receiverPublicKey:receiver.publicKey,nowMs:now+2000};
function exchange(sequence=1,previousExchangeDigest=genesisExchangeDigest,nonce='sender_nonce_32m_0001'){
 const context={sessionId:'session_32m_0001',senderId:'sender_32m_0001',receiverId:'receiver_32m_0001',
  senderNonce:nonce,receiverChallenge:'receiver_challenge_32m_0001',sequence,previousExchangeDigest};
 const offer=createOfflineConflictExchangeOffer({...common,...context,senderPrivateKey:sender.privateKey,
  issuedAt:now,expiresAt:now+60000});
 const ack=acceptOfflineConflictExchangeOffer({...common,...context,offer,receiverPrivateKey:receiver.privateKey,
  nowMs:now+1000,issuedAt:now+1000,expiresAt:now+59000});
 return {transcriptBytes:encodeOfflineConflictExchangeTranscript({offer,ack}),
  verificationArgs:{...common,...context},exchangeDigest:verifyOfflineConflictExchange({...common,...context,offer,ack}).exchangeDigest};
}
const first=exchange();
const name=(n)=>`32M ${n}`;
async function temp(fn){const root=await mkdtemp(join(tmpdir(),'tj32m-'));try{return await fn(join(root,'journal'),root);}finally{await rm(root,{recursive:true,force:true});}}
const journal=dir=>createOfflineConflictExchangeJournal({directory:dir,genesisExchangeDigest});
const head0=offlineConflictExchangeJournalGenesisHead(genesisExchangeDigest);
const claim=(j,head=head0,x=first)=>j.claim({transcriptBytes:x.transcriptBytes,verificationArgs:x.verificationArgs,expectedHead:head});
const t=(n,fn)=>test(name(n),fn);
t('genesis requires independently supplied well-formed digest',()=>{
 assert.deepEqual(head0,{count:0,headDigest:offlineConflictExchangeJournalGenesisHead(genesisExchangeDigest).headDigest});
 assert.throws(()=>offlineConflictExchangeJournalGenesisHead('bad'),err('EXCHANGE32M_GENESIS_INVALID'));
});
t('configuration rejects missing path, bad genesis, and fault injection nonfunction',()=>{
 assert.throws(()=>createOfflineConflictExchangeJournal({genesisExchangeDigest}),err('EXCHANGE32M_CONFIGURATION'));
 assert.throws(()=>createOfflineConflictExchangeJournal({directory:'/tmp/x',genesisExchangeDigest:'bad'}),err('EXCHANGE32M_CONFIGURATION'));
 assert.throws(()=>createOfflineConflictExchangeJournal({directory:'/tmp/x',genesisExchangeDigest,injectFault:true}),err('EXCHANGE32M_CONFIGURATION'));
});
t('empty journal can be inspected only with independently pinned genesis',()=>temp(async dir=>{
 const j=journal(dir),v=await j.inspect({expectedHead:head0});assert.equal(v.count,0);
 assert.equal(v.productionApproved,false);assert.equal(v.externallyAnchored,false);
 await assert.rejects(j.inspect({}),err('EXCHANGE32M_EXTERNAL_HEAD_REQUIRED'));
}));
t('durable claim survives reopen and binds sequence and signed predecessor',()=>temp(async dir=>{
 const j=journal(dir),a=await claim(j);assert.equal(a.count,1);assert.equal(a.lastExchangeDigest,first.exchangeDigest);
 const b=await journal(dir).inspect({expectedHead:{count:a.count,headDigest:a.headDigest}});
 assert.equal(b.headDigest,a.headDigest);assert.equal(b.authorizesCheckout,false);
 const second=exchange(2,a.lastExchangeDigest,'sender_nonce_32m_0002');
 const c=await claim(j,{count:a.count,headDigest:a.headDigest},second);assert.equal(c.count,2);
 assert.equal(c.lastExchangeDigest,second.exchangeDigest);
 assert.equal((await readdir(dir)).filter(x=>x.endsWith('.json')).length,2);
}));
t('duplicate exchange rejected by monotonic sequence and replay policy',()=>temp(async dir=>{
 const j=journal(dir),a=await claim(j);
 await assert.rejects(claim(j,{count:a.count,headDigest:a.headDigest}),err('EXCHANGE32M_SEQUENCE_OR_PREDECESSOR'));
}));
t('stale independent head rejects retry after successful commit',()=>temp(async dir=>{
 const j=journal(dir);await claim(j);
 await assert.rejects(claim(j),err('EXCHANGE32M_STALE_OR_ROLLED_BACK_HEAD'));
 await assert.rejects(j.inspect({expectedHead:head0}),err('EXCHANGE32M_STALE_OR_ROLLED_BACK_HEAD'));
}));
t('sequence gap rejects even a correctly signed exchange',()=>temp(async dir=>{
 const j=journal(dir),gap=exchange(2,genesisExchangeDigest,'sender_nonce_32m_gap');
 await assert.rejects(claim(j,head0,gap),err('EXCHANGE32M_SEQUENCE_OR_PREDECESSOR'));
}));
t('predecessor rollback rejects correctly signed next exchange',()=>temp(async dir=>{
 const j=journal(dir),a=await claim(j),bad=exchange(2,genesisExchangeDigest,'sender_nonce_32m_bad');
 await assert.rejects(claim(j,{count:1,headDigest:a.headDigest},bad),err('EXCHANGE32M_SEQUENCE_OR_PREDECESSOR'));
}));
t('forged signature is rejected before durable journal writes',()=>temp(async dir=>{
 const j=journal(dir),bad={...first,transcriptBytes:Buffer.from(first.transcriptBytes)};
 const s=bad.transcriptBytes.toString().replace(/"signature":"([A-Za-z0-9_-])/,(_,a)=>`"signature":"${a==='A'?'B':'A'}`);
 bad.transcriptBytes=Buffer.from(s);
 await assert.rejects(claim(j,head0,bad));assert.equal((await j.inspect({expectedHead:head0})).count,0);
}));
t('noncanonical transcript fails closed with no pending record',()=>temp(async dir=>{
 const j=journal(dir);await assert.rejects(claim(j,head0,{...first,transcriptBytes:Buffer.concat([Buffer.from(' '),first.transcriptBytes])}));
 assert.equal((await j.inspect({expectedHead:head0})).count,0);
}));
t('independent proof pin substitution rejected before commit',()=>temp(async dir=>{
 const j=journal(dir),x={...first,verificationArgs:{...first.verificationArgs,expectedProofDigest:sha('forged')}};
 await assert.rejects(claim(j,head0,x));assert.equal((await j.inspect({expectedHead:head0})).count,0);
}));
t('expiry rejects signed but stale exchange before claim',()=>temp(async dir=>{
 const j=journal(dir),x={...first,verificationArgs:{...first.verificationArgs,nowMs:now+61000}};
 await assert.rejects(claim(j,head0,x),err('EXCHANGE32L_EXPIRED_OR_FUTURE'));
}));
t('caller-supplied receipt substitution cannot override signed transcript',()=>temp(async dir=>{
 const j=journal(dir),x={...first,verificationArgs:{...first.verificationArgs,offer:{evil:true},ack:{evil:true}}};
 assert.equal((await claim(j,head0,x)).count,1);
}));
t('tampered committed record fails closed despite recalculated JSON',()=>temp(async dir=>{
 const j=journal(dir),a=await claim(j),path=join(dir,'0001.json');
 const obj=JSON.parse(await readFile(path,'utf8'));obj.exchangeDigest=sha('replacement');
 await writeFile(path,JSON.stringify(obj));
 await assert.rejects(j.inspect({expectedHead:{count:1,headDigest:a.headDigest}}),err('EXCHANGE32M_HISTORY_INVALID'));
}));
t('truncated record fails closed',()=>temp(async dir=>{
 const j=journal(dir),a=await claim(j);await truncate(join(dir,'0001.json'),17);
 await assert.rejects(j.inspect({expectedHead:{count:1,headDigest:a.headDigest}}),err('EXCHANGE32M_HISTORY_INVALID'));
}));
t('deleted committed record cannot pass independent head pin',()=>temp(async dir=>{
 const j=journal(dir),a=await claim(j);await unlink(join(dir,'0001.json'));
 await assert.rejects(j.inspect({expectedHead:{count:a.count,headDigest:a.headDigest}}),err('EXCHANGE32M_STALE_OR_ROLLED_BACK_HEAD'));
}));
t('unexpected files and sequence gaps fail closed',()=>temp(async dir=>{
 const j=journal(dir),a=await claim(j);await writeFile(join(dir,'0003.json'),'{}');
 await assert.rejects(j.inspect({expectedHead:{count:a.count,headDigest:a.headDigest}}),err('EXCHANGE32M_HISTORY_INVALID'));
}));
t('symlinked record refused',()=>temp(async(dir,root)=>{
 const j=journal(dir),a=await claim(j);await writeFile(join(root,'replacement.json'),await readFile(join(dir,'0001.json')));
 await unlink(join(dir,'0001.json'));await symlink(join(root,'replacement.json'),join(dir,'0001.json'));
 await assert.rejects(j.inspect({expectedHead:{count:a.count,headDigest:a.headDigest}}),err('EXCHANGE32M_RECORD_UNSAFE'));
}));
t('world-readable journal directory rejected',()=>temp(async dir=>{
 const j=journal(dir);await j.inspect({expectedHead:head0});await chmod(dir,0o755);
 await assert.rejects(j.inspect({expectedHead:head0}),err('EXCHANGE32M_DIRECTORY_UNSAFE'));
}));
t('world-readable record rejected',()=>temp(async dir=>{
 const j=journal(dir),a=await claim(j);await chmod(join(dir,'0001.json'),0o644);
 await assert.rejects(j.inspect({expectedHead:{count:1,headDigest:a.headDigest}}),err('EXCHANGE32M_RECORD_UNSAFE'));
}));
t('fault after durable pending sync leaves permanently blocked uncertain commit',()=>temp(async dir=>{
 const j=createOfflineConflictExchangeJournal({directory:dir,genesisExchangeDigest,
  injectFault:phase=>{if(phase==='after-pending-sync')throw Error('SIMULATED_POWER_LOSS');}});
 await assert.rejects(claim(j),/SIMULATED_POWER_LOSS/);
 await assert.rejects(journal(dir).inspect({expectedHead:head0}),err('EXCHANGE32M_UNCERTAIN_COMMIT'));
 await assert.rejects(claim(journal(dir)),err('EXCHANGE32M_UNCERTAIN_COMMIT'));
}));
t('fault after hardlink sync blocks ambiguous double-linked record',()=>temp(async dir=>{
 const j=createOfflineConflictExchangeJournal({directory:dir,genesisExchangeDigest,
  injectFault:phase=>{if(phase==='after-link-sync')throw Error('SIMULATED_POWER_LOSS');}});
 await assert.rejects(claim(j),/SIMULATED_POWER_LOSS/);
 const files=await readdir(dir);assert(files.includes('0001.json'));assert(files.includes('.pending.json'));
 await assert.rejects(journal(dir).inspect({expectedHead:head0}),err('EXCHANGE32M_UNCERTAIN_COMMIT'));
}));
t('fault after final sync is durably committed but stale pin prevents retry',()=>temp(async dir=>{
 const j=createOfflineConflictExchangeJournal({directory:dir,genesisExchangeDigest,
  injectFault:phase=>{if(phase==='after-commit-sync')throw Error('SIMULATED_POWER_LOSS');}});
 await assert.rejects(claim(j),/SIMULATED_POWER_LOSS/);
 await assert.rejects(journal(dir).inspect({expectedHead:head0}),err('EXCHANGE32M_STALE_OR_ROLLED_BACK_HEAD'));
 const raw=JSON.parse(await readFile(join(dir,'0001.json'),'utf8'));
 const observed=await journal(dir).inspect({expectedHead:{count:1,headDigest:raw.recordDigest}});
 assert.equal(observed.count,1); // externally pinned head must be obtained by caller, not this local read
}));
t('parallel same-process claims serialize; exactly one succeeds',()=>temp(async dir=>{
 const j=journal(dir),results=await Promise.allSettled([claim(j),claim(j)]);
 assert.equal(results.filter(r=>r.status==='fulfilled').length,1);
 assert.equal(results.filter(r=>r.status==='rejected'&&r.reason.code==='EXCHANGE32M_STALE_OR_ROLLED_BACK_HEAD').length,1);
}));
const worker=join(dirname(fileURLToPath(import.meta.url)),'support','objective32m-worker.mjs');
const child=path=>new Promise((ok,no)=>{let out='',error='';const p=spawn(process.execPath,[worker,path],{stdio:['ignore','pipe','pipe']});
 p.stdout.on('data',b=>out+=b);p.stderr.on('data',b=>error+=b);
 p.on('error',no);p.on('close',code=>code===0?ok(JSON.parse(out)):no(Error(error||out)));
});
t('independent Node processes serialize competing signed claims under flock',()=>temp(async(dir,root)=>{
 const data={directory:dir,genesisExchangeDigest,expectedHead:head0,
  transcriptBase64:first.transcriptBytes.toString('base64'),proofBase64:proofBytes.toString('base64'),
  verificationArgs:Object.fromEntries(Object.entries(first.verificationArgs).filter(([k])=>!['proofBytes','senderPublicKey','receiverPublicKey'].includes(k))),
  senderPublicPem:sender.publicKey.export({type:'spki',format:'pem'}),
  receiverPublicPem:receiver.publicKey.export({type:'spki',format:'pem'})};
 const path=join(root,'worker-input.json');await writeFile(path,JSON.stringify(data),{mode:0o600});
 const [a,b]=await Promise.all([child(path),child(path)]);
 assert.equal([a,b].filter(x=>x.ok).length,1);assert.equal([a,b].filter(x=>!x.ok&&x.code==='EXCHANGE32M_STALE_OR_ROLLED_BACK_HEAD').length,1);
 assert.equal((await journal(dir).inspect({expectedHead:{count:1,headDigest:[a,b].find(x=>x.ok).headDigest}})).count,1);
}));
t('self-consistent malicious history rewrite is rejected by independent prior head',()=>temp(async dir=>{
 const j=journal(dir),a=await claim(j),path=join(dir,'0001.json');
 const obj=JSON.parse(await readFile(path,'utf8'));
 obj.exchangeDigest=sha('different-valid-looking-exchange');
 const {recordDigest:old,...body}=obj;
 obj.recordDigest=sha(Buffer.from(`TJ-32M-RECORD\0${JSON.stringify(body)}`));
 await writeFile(path,JSON.stringify(obj));
 await assert.rejects(j.inspect({expectedHead:{count:a.count,headDigest:a.headDigest}}),err('EXCHANGE32M_STALE_OR_ROLLED_BACK_HEAD'));
}));
t('symlinked lock file is refused before state access',()=>temp(async(dir,root)=>{
 const j=journal(dir);await j.inspect({expectedHead:head0});
 await unlink(join(dir,'.exchange-lock'));await writeFile(join(root,'decoy'),'');
 await symlink(join(root,'decoy'),join(dir,'.exchange-lock'));
 await assert.rejects(j.inspect({expectedHead:head0}),err('EXCHANGE32M_LOCK_UNSAFE'));
}));
t('unexpected pending file fails closed even with empty pinned genesis',()=>temp(async dir=>{
 const j=journal(dir);await j.inspect({expectedHead:head0});await writeFile(join(dir,'.pending.json'),'{}');
 await assert.rejects(j.inspect({expectedHead:head0}),err('EXCHANGE32M_UNCERTAIN_COMMIT'));
}));
t('incorrect claimed head digest cannot be used to inspect a committed journal',()=>temp(async dir=>{
 const j=journal(dir),a=await claim(j);
 await assert.rejects(j.inspect({expectedHead:{count:a.count,headDigest:sha('fake')}}),err('EXCHANGE32M_STALE_OR_ROLLED_BACK_HEAD'));
}));
