import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {OFFLINE_EXPORT_RECEIPT_SCHEMA,OFFLINE_EXPORT_REGISTRY_SCHEMA,offlineExportReceiptPolicyDigest,offlineExportReceiptSigningBytes} from '../src/offline-acquisition-export-receipt-registry.mjs';
import {OFFLINE_EXPORT_WITNESS_TRANSITION_SCHEMA,OFFLINE_EXPORT_ROTATED_HISTORY_SCHEMA,offlineExportWitnessTransitionSigningBytes,offlineExportWitnessTransitionPossessionBytes,offlineExportWitnessTransitionChainDigest,verifyOfflineExportRotatedReceiptHistory,encodeOfflineExportRotatedReceiptHistory,compareOfflineExportRotatedReceiptHistories} from '../src/offline-export-receipt-witness-rotation.mjs';
const sha=b=>createHash('sha256').update(b).digest('hex'),ROOT='0'.repeat(64),registryId='registry_objective31u',baseMs=1800000000000,nowMs=baseMs+100000;
const clone=x=>JSON.parse(JSON.stringify(x)),reject=(f,code)=>assert.throws(f,e=>e?.code===code,code);
const keys=Array.from({length:3},(_,epoch)=>Array.from({length:3},(_,j)=>({id:`witness_31u_e${epoch}_${j}`,...generateKeyPairSync('ed25519')})));
const policies=keys.map(k=>({witnesses:k.map(x=>({id:x.id,publicKey:x.publicKey})),quorum:2}));
const digests=policies.map(offlineExportReceiptPolicyDigest),recordDigest=r=>sha(Buffer.from(`${OFFLINE_EXPORT_REGISTRY_SCHEMA}\0${JSON.stringify(r)}`));
const head=e=>({count:e.length,headDigest:e.length?e.at(-1).digest:ROOT});
const signature=(bytes,k)=>sign(null,bytes,k.privateKey).toString('base64url');
const sorted=s=>s.sort((a,b)=>a.witnessId.localeCompare(b.witnessId));
function receipt(body,epoch,signers=[0,1]){return {body,signatures:sorted(signers.map(i=>({witnessId:keys[epoch][i].id,signature:signature(offlineExportReceiptSigningBytes(body),keys[epoch][i])})))};}
function makeEntries({branch='base',secondBranch=false,signers=[0,1]}={}){
 const entries=[];let prev=ROOT;
 for(let i=1;i<=4;i++){
  const epoch=i<=2?0:1,change=secondBranch&&i===4?branch:'common';
  const body={schema:OFFLINE_EXPORT_RECEIPT_SCHEMA,registryId,sequence:i,previousDigest:prev,exportId:`export_31u_${i}_${change}`,acquisitionId:`acquisition_31u_${i}_${change}`,archiveDigest:sha(Buffer.from(`archive-${i}-${change}`)),archiveBytes:100+i,issuedAt:baseMs+(i*1000),expiresAt:baseMs+i*1000+60000,nonce:`nonce_31u_${i}_${change}`,policyDigest:digests[epoch]};
  const r={schema:OFFLINE_EXPORT_REGISTRY_SCHEMA,index:i,previousDigest:prev,receipt:receipt(body,epoch,signers)};
  const e={...r,digest:recordDigest(r)};entries.push(e);prev=e.digest;
 }
 return entries;
}
function transition(body,from,to){
 const bytes=offlineExportWitnessTransitionSigningBytes(body);
 return {body,outgoingSignatures:sorted([0,1].map(i=>({witnessId:keys[from][i].id,signature:signature(bytes,keys[from][i])}))),
 incomingProofs:sorted(keys[to].map(k=>({witnessId:k.id,signature:signature(offlineExportWitnessTransitionPossessionBytes(body,k.id),k)})))};
}
function setup({branch='base',secondBranch=false,transitionNonce='transition_nonce_31u'}={}){
 const entries=makeEntries({branch,secondBranch});
 const body={schema:OFFLINE_EXPORT_WITNESS_TRANSITION_SCHEMA,registryId,fromEpoch:0,toEpoch:1,fromPolicyDigest:digests[0],toPolicyDigest:digests[1],anchorHead:head(entries.slice(0,2)),issuedAt:baseMs+2500,expiresAt:baseMs+90000,nonce:transitionNonce};
 const transitions=[transition(body,0,1)];
 const opts={registryId,nowMs,policies:policies.slice(0,2),transitions,expectedHead:head(entries),expectedGenesisPolicyDigest:digests[0],expectedFinalPolicyDigest:digests[1],expectedFinalEpoch:1,expectedTransitionDigest:offlineExportWitnessTransitionChainDigest({transitions})};
 const bytes=encodeOfflineExportRotatedReceiptHistory({entries,...opts});return {entries,opts,bytes};
}
const verify=(x)=>verifyOfflineExportRotatedReceiptHistory({...x.opts,bytes:x.bytes});
const mutate=(x,f)=>{const y={...x,opts:{...x.opts,transitions:clone(x.opts.transitions)},bytes:Buffer.from(x.bytes)};f(y);return y;};
const edit=(x,f)=>{const y=JSON.parse(x.bytes.toString());f(y);return {...x,bytes:Buffer.from(JSON.stringify(y))};};
const resignRecord=(entries,index,epoch)=>{const e=entries[index],r={schema:e.schema,index:e.index,previousDigest:e.previousDigest,receipt:receipt(e.receipt.body,epoch)};entries[index]={...r,digest:recordDigest(r)};};

test('31U independently pinned rotated history verifies both witness epochs',()=>{const x=setup(),v=verify(x);assert.equal(v.verified,true);assert.equal(v.count,4);assert.equal(v.epoch,1);assert.equal(v.productionApproved,false);assert.equal(v.mayManufacture,false);});
test('31U canonical encoding deterministic',()=>{const x=setup();assert.deepEqual(x.bytes,encodeOfflineExportRotatedReceiptHistory({entries:x.entries,...x.opts}));});
test('31U historically expired receipts remain evidence, not authorization',()=>{const x=setup();assert.equal(verify({...x,opts:{...x.opts,nowMs:nowMs+999999999}}).readOnly,true);});
test('31U transition signing bytes domain-separated',()=>{const x=setup();assert.notDeepEqual(offlineExportWitnessTransitionSigningBytes(x.opts.transitions[0].body),offlineExportWitnessTransitionPossessionBytes(x.opts.transitions[0].body,keys[1][0].id));});
test('31U rejects missing external head',()=>{const x=setup();reject(()=>verify({...x,opts:{...x.opts,expectedHead:undefined}}),'EXPORT_ROTATION_EXTERNAL_HEAD_REQUIRED');});
test('31U rejects wrong external head',()=>{const x=setup();reject(()=>verify({...x,opts:{...x.opts,expectedHead:head(x.entries.slice(0,3))}}),'EXPORT_ROTATION_HISTORY_INVALID');});
test('31U rejects wrong independent transition pin',()=>{const x=setup();reject(()=>verify({...x,opts:{...x.opts,expectedTransitionDigest:'f'.repeat(64)}}),'EXPORT_ROTATION_EXTERNAL_PIN_MISMATCH');});
test('31U rejects substituted trusted genesis policy',()=>{const x=setup();reject(()=>verify({...x,opts:{...x.opts,expectedGenesisPolicyDigest:'f'.repeat(64)}}),'EXPORT_ROTATION_EXTERNAL_PIN_MISMATCH');});
test('31U rejects substituted final policy pin',()=>{const x=setup();reject(()=>verify({...x,opts:{...x.opts,expectedFinalPolicyDigest:'f'.repeat(64)}}),'EXPORT_ROTATION_EXTERNAL_PIN_MISMATCH');});
test('31U rejects final epoch mismatch',()=>{const x=setup();reject(()=>verify({...x,opts:{...x.opts,expectedFinalEpoch:2}}),'EXPORT_ROTATION_REQUEST_INVALID');});
test('31U rejects transition with forged outgoing quorum signature even with repinned chain',()=>{const x=setup();const t=clone(x.opts.transitions);t[0].outgoingSignatures[0].signature='A'.repeat(86);reject(()=>verify({...x,opts:{...x.opts,transitions:t,expectedTransitionDigest:offlineExportWitnessTransitionChainDigest({transitions:t})}}),'EXPORT_ROTATION_OUTGOING_SIGNATURE_INVALID');});
test('31U rejects transition with minority outgoing quorum',()=>{const x=setup();const t=clone(x.opts.transitions);t[0].outgoingSignatures.pop();reject(()=>verify({...x,opts:{...x.opts,transitions:t,expectedTransitionDigest:offlineExportWitnessTransitionChainDigest({transitions:t})}}),'EXPORT_ROTATION_OUTGOING_SIGNATURE_INVALID');});
test('31U rejects missing incoming proof of possession',()=>{const x=setup();const t=clone(x.opts.transitions);t[0].incomingProofs.pop();reject(()=>verify({...x,opts:{...x.opts,transitions:t,expectedTransitionDigest:offlineExportWitnessTransitionChainDigest({transitions:t})}}),'EXPORT_ROTATION_PROOF_INVALID');});
test('31U rejects forged incoming proof of possession',()=>{const x=setup();const t=clone(x.opts.transitions);t[0].incomingProofs[0].signature='A'.repeat(86);reject(()=>verify({...x,opts:{...x.opts,transitions:t,expectedTransitionDigest:offlineExportWitnessTransitionChainDigest({transitions:t})}}),'EXPORT_ROTATION_PROOF_INVALID');});
test('31U rejects duplicate incoming signer',()=>{const x=setup();const t=clone(x.opts.transitions);t[0].incomingProofs[1]=t[0].incomingProofs[0];reject(()=>verify({...x,opts:{...x.opts,transitions:t,expectedTransitionDigest:offlineExportWitnessTransitionChainDigest({transitions:t})}}),'EXPORT_ROTATION_PROOF_INVALID');});
test('31U rejects retired key reuse under new witness identity',()=>{const x=setup();const p=[x.opts.policies[0],{witnesses:[{id:'new_identity_31u',publicKey:keys[0][0].publicKey},...x.opts.policies[1].witnesses.slice(1)],quorum:2}];reject(()=>verify({...x,opts:{...x.opts,policies:p}}),'EXPORT_ROTATION_RETIRED_KEY_REUSE');});
test('31U rejects retired witness identifier reuse with different key',()=>{const x=setup();const p=[x.opts.policies[0],{witnesses:[{id:keys[0][0].id,publicKey:keys[1][0].publicKey},...x.opts.policies[1].witnesses.slice(1)],quorum:2}];reject(()=>verify({...x,opts:{...x.opts,policies:p}}),'EXPORT_ROTATION_RETIRED_KEY_REUSE');});
test('31U rejects wrong signed anchor even with valid quorum',()=>{const x=setup();const t=clone(x.opts.transitions),b={...t[0].body,anchorHead:{count:1,headDigest:x.entries[0].digest}};t[0]=transition(b,0,1);reject(()=>verify({...x,opts:{...x.opts,transitions:t,expectedTransitionDigest:offlineExportWitnessTransitionChainDigest({transitions:t})}}),'EXPORT_RECEIPT_POLICY_MISMATCH');});
test('31U rejects anchor digest substitution with valid signatures',()=>{const x=setup();const t=clone(x.opts.transitions),b={...t[0].body,anchorHead:{count:2,headDigest:'f'.repeat(64)}};t[0]=transition(b,0,1);reject(()=>verify({...x,opts:{...x.opts,transitions:t,expectedTransitionDigest:offlineExportWitnessTransitionChainDigest({transitions:t})}}),'EXPORT_ROTATION_ANCHOR_MISMATCH');});
test('31U rejects record signed with retired keys after rotation',()=>{const x=setup();const entries=clone(x.entries);entries[2].receipt.body.policyDigest=digests[0];resignRecord(entries,2,0);const y={...x,bytes:Buffer.from(JSON.stringify({schema:OFFLINE_EXPORT_ROTATED_HISTORY_SCHEMA,registryId,head:head(entries),entries})),opts:{...x.opts,expectedHead:head(entries)}};reject(()=>verify(y),'EXPORT_RECEIPT_POLICY_MISMATCH');});
test('31U rejects receipt with future epoch key before rotation',()=>{const x=setup();const entries=clone(x.entries);entries[0].receipt.body.policyDigest=digests[1];resignRecord(entries,0,1);const y={...x,bytes:Buffer.from(JSON.stringify({schema:OFFLINE_EXPORT_ROTATED_HISTORY_SCHEMA,registryId,head:head(entries),entries})),opts:{...x.opts,expectedHead:head(entries)}};reject(()=>verify(y),'EXPORT_RECEIPT_POLICY_MISMATCH');});
test('31U rejects forged signed receipt after transition',()=>{const x=setup();const y=edit(x,h=>h.entries[3].receipt.signatures[0].signature='A'.repeat(86));reject(()=>verify(y),'EXPORT_RECEIPT_SIGNATURE_INVALID');});
test('31U rejects receipt issued before new policy activated',()=>{const x=setup();const entries=clone(x.entries);entries[2].receipt.body.issuedAt=baseMs+2000;resignRecord(entries,2,1);const y={...x,bytes:Buffer.from(JSON.stringify({schema:OFFLINE_EXPORT_ROTATED_HISTORY_SCHEMA,registryId,head:head(entries),entries})),opts:{...x.opts,expectedHead:head(entries)}};reject(()=>verify(y),'EXPORT_ROTATION_EPOCH_OR_CHAIN_INVALID');});
test('31U rejects receipt issued after outgoing policy retirement',()=>{const x=setup();const entries=clone(x.entries);entries[1].receipt.body.issuedAt=baseMs+2600;resignRecord(entries,1,0);const y={...x,bytes:Buffer.from(JSON.stringify({schema:OFFLINE_EXPORT_ROTATED_HISTORY_SCHEMA,registryId,head:head(entries),entries})),opts:{...x.opts,expectedHead:head(entries)}};reject(()=>verify(y),'EXPORT_ROTATION_EPOCH_OR_CHAIN_INVALID');});
test('31U rejects missing final epoch records',()=>{const x=setup();const y=edit(x,h=>{h.entries=h.entries.slice(0,2);h.head=head(h.entries);});reject(()=>verify({...y,opts:{...y.opts,expectedHead:head(y.entries.slice(0,2))}}),'EXPORT_ROTATION_HISTORY_INVALID');});
test('31U rejects replayed archive identity across epochs even if re-signed',()=>{const x=setup();const entries=clone(x.entries);entries[2].receipt.body.archiveDigest=entries[0].receipt.body.archiveDigest;resignRecord(entries,2,1);const y={...x,bytes:Buffer.from(JSON.stringify({schema:OFFLINE_EXPORT_ROTATED_HISTORY_SCHEMA,registryId,head:head(entries),entries})),opts:{...x.opts,expectedHead:head(entries)}};reject(()=>verify(y),'EXPORT_ROTATION_REPLAY');});
test('31U rejects noncanonical JSON and duplicate keys',()=>{const x=setup();reject(()=>verify({...x,bytes:Buffer.from(x.bytes.toString()+'\n')}),'EXPORT_ROTATION_NOT_CANONICAL');reject(()=>verify({...x,bytes:Buffer.from(x.bytes.toString().replace('"schema":','"schema":"evil","schema":'))}),'EXPORT_ROTATION_NOT_CANONICAL');});
test('31U rejects truncated JSON and invalid UTF-8',()=>{const x=setup();reject(()=>verify({...x,bytes:x.bytes.subarray(0,-1)}),'EXPORT_ROTATION_ENCODING_INVALID');const b=Buffer.from(x.bytes);b[5]=0xff;reject(()=>verify({...x,bytes:b}),'EXPORT_ROTATION_ENCODING_INVALID');});
test('31U rejects unknown authority field',()=>{const x=setup();reject(()=>verify(edit(x,h=>h.productionApproved=true)),'EXPORT_ROTATION_HISTORY_INVALID');});
test('31U rejects oversized portable payload',()=>{const x=setup();reject(()=>verify({...x,bytes:Buffer.alloc(32*1024*1024+1)}),'EXPORT_ROTATION_BYTES_INVALID');});
test('31U independent cross-epoch prefix extension not classified as conflict',()=>{const x=setup(),c=compareOfflineExportRotatedReceiptHistories({left:{...x.opts,bytes:x.bytes},right:{...x.opts,bytes:x.bytes},registryId,nowMs});assert.equal(c.status,'IDENTICAL');});
test('31U detects signed receipt-body equivocation in active epoch',()=>{const a=setup(),b=setup({branch:'other',secondBranch:true});const c=compareOfflineExportRotatedReceiptHistories({left:{...a.opts,bytes:a.bytes},right:{...b.opts,bytes:b.bytes},registryId,nowMs});assert.equal(c.status,'SIGNED_RECEIPT_EQUIVOCATION');assert.equal(c.firstConflictingReceiptSequence,4);});
test('31U detects independently signed policy transition equivocation',()=>{const a=setup(),b=setup({transitionNonce:'other_transition_nonce_31u'});const c=compareOfflineExportRotatedReceiptHistories({left:{...a.opts,bytes:a.bytes},right:{...b.opts,bytes:b.bytes},registryId,nowMs});assert.equal(c.status,'SIGNED_POLICY_EQUIVOCATION');assert.equal(c.firstConflictingPolicyEpoch,0);});
test('31U rejects forged second branch rather than claiming conflict',()=>{const a=setup(),b=setup({branch:'other',secondBranch:true});const forged=edit(b,h=>h.entries[3].receipt.signatures[0].signature='A'.repeat(86));reject(()=>compareOfflineExportRotatedReceiptHistories({left:{...a.opts,bytes:a.bytes},right:{...forged.opts,bytes:forged.bytes},registryId,nowMs}),'EXPORT_RECEIPT_SIGNATURE_INVALID');});
test('31U verifier works in independent child process with exported public keys only',()=>{
 const x=setup(),mod=fileURLToPath(new URL('../src/offline-export-receipt-witness-rotation.mjs',import.meta.url));
 const options={...x.opts,bytes:x.bytes.toString('base64'),policies:x.opts.policies.map(p=>({quorum:p.quorum,witnesses:p.witnesses.map(w=>({id:w.id,pem:w.publicKey.export({format:'pem',type:'spki'})}))}))};
 const code=`import {createPublicKey} from 'node:crypto';import {verifyOfflineExportRotatedReceiptHistory} from ${JSON.stringify(mod)};const x=JSON.parse(process.argv[1]);x.bytes=Buffer.from(x.bytes,'base64');x.policies=x.policies.map(p=>({quorum:p.quorum,witnesses:p.witnesses.map(w=>({id:w.id,publicKey:createPublicKey(w.pem)}))}));const v=verifyOfflineExportRotatedReceiptHistory(x);process.stdout.write(JSON.stringify({verified:v.verified,epoch:v.epoch,productionApproved:v.productionApproved}));`;
 const r=spawnSync(process.execPath,['--input-type=module','-e',code,JSON.stringify(options)],{encoding:'utf8',timeout:15000});assert.equal(r.status,0,r.stderr);assert.deepEqual(JSON.parse(r.stdout),{verified:true,epoch:1,productionApproved:false});
});

test('31U verifies two successive policy rotations and three independently supplied epochs',()=>{
 const x=setup(),entries=clone(x.entries);let previous=entries.at(-1).digest;
 for(let i=5;i<=6;i++){
  const body={schema:OFFLINE_EXPORT_RECEIPT_SCHEMA,registryId,sequence:i,previousDigest:previous,exportId:`export_31u_epoch2_${i}`,acquisitionId:`acquisition_31u_epoch2_${i}`,archiveDigest:sha(Buffer.from(`epoch2-archive-${i}`)),archiveBytes:100+i,issuedAt:baseMs+i*1000,expiresAt:baseMs+i*1000+60000,nonce:`nonce_31u_epoch2_${i}`,policyDigest:digests[2]};
  const r={schema:OFFLINE_EXPORT_REGISTRY_SCHEMA,index:i,previousDigest:previous,receipt:receipt(body,2)};const e={...r,digest:recordDigest(r)};entries.push(e);previous=e.digest;
 }
 const b={schema:OFFLINE_EXPORT_WITNESS_TRANSITION_SCHEMA,registryId,fromEpoch:1,toEpoch:2,fromPolicyDigest:digests[1],toPolicyDigest:digests[2],anchorHead:head(entries.slice(0,4)),issuedAt:baseMs+4500,expiresAt:baseMs+90000,nonce:'transition_nonce_epoch2_31u'};
 const transitions=[...x.opts.transitions,transition(b,1,2)],opts={...x.opts,policies,transitions,expectedHead:head(entries),expectedFinalPolicyDigest:digests[2],expectedFinalEpoch:2,expectedTransitionDigest:offlineExportWitnessTransitionChainDigest({transitions})};
 const bytes=encodeOfflineExportRotatedReceiptHistory({entries,...opts});const v=verifyOfflineExportRotatedReceiptHistory({...opts,bytes});assert.equal(v.epoch,2);assert.equal(v.count,6);
});
test('31U rejects historical transition with future issuance relative to independently supplied time',()=>{const x=setup();reject(()=>verify({...x,opts:{...x.opts,nowMs:baseMs+2000}}),'EXPORT_ROTATION_TIME_OR_REPLAY');});
test('31U rejects signed receipt timestamp beyond independently supplied time',()=>{const x=setup();reject(()=>verify({...x,opts:{...x.opts,nowMs:baseMs+3500}}),'EXPORT_ROTATION_EPOCH_OR_CHAIN_INVALID');});
test('31U rejects noncanonical transition field even if repinned',()=>{const x=setup(),t=clone(x.opts.transitions);t[0].manufactureApproved=true;reject(()=>verify({...x,opts:{...x.opts,transitions:t,expectedTransitionDigest:offlineExportWitnessTransitionChainDigest({transitions:t})}}),'EXPORT_ROTATION_CERTIFICATE_INVALID');});
test('31U rejects transition with wrong registry ID despite valid historical signatures',()=>{const x=setup(),t=clone(x.opts.transitions),b={...t[0].body,registryId:'other_registry_31u'};t[0]=transition(b,0,1);reject(()=>verify({...x,opts:{...x.opts,transitions:t,expectedTransitionDigest:offlineExportWitnessTransitionChainDigest({transitions:t})}}),'EXPORT_ROTATION_POLICY_MISMATCH');});
test('31U detects benign historical signature subset fork without claiming contradictory receipt',()=>{
 const a=setup(),entries=clone(a.entries);entries[3].receipt=receipt(entries[3].receipt.body,1,[0,2]);const {digest,...r}=entries[3];entries[3].digest=recordDigest(r);
 const opts={...a.opts,expectedHead:head(entries)},bytes=encodeOfflineExportRotatedReceiptHistory({entries,...opts});
 const c=compareOfflineExportRotatedReceiptHistories({left:{...a.opts,bytes:a.bytes},right:{...opts,bytes},registryId,nowMs});assert.equal(c.status,'SIGNED_HISTORY_ENCODING_FORK');assert.equal(c.firstConflictingReceiptSequence,null);
});
test('31U detects signed policy certificate encoding fork without false policy-body equivocation',()=>{
 const a=setup(),t=clone(a.opts.transitions),b=t[0].body;
 t[0].outgoingSignatures=sorted([0,2].map(i=>({witnessId:keys[0][i].id,signature:signature(offlineExportWitnessTransitionSigningBytes(b),keys[0][i])})));
 const opts={...a.opts,transitions:t,expectedTransitionDigest:offlineExportWitnessTransitionChainDigest({transitions:t})};
 const c=compareOfflineExportRotatedReceiptHistories({left:{...a.opts,bytes:a.bytes},right:{...opts,bytes:a.bytes},registryId,nowMs});assert.equal(c.status,'SIGNED_POLICY_CERTIFICATE_ENCODING_FORK');
});
test('31U signed transition does not allow use of untrusted substituted public keys',()=>{
 const x=setup(),replacement=generateKeyPairSync('ed25519').publicKey;
 const policiesSub=[x.opts.policies[0],{...x.opts.policies[1],witnesses:[{...x.opts.policies[1].witnesses[0],publicKey:replacement},...x.opts.policies[1].witnesses.slice(1)]}];
 reject(()=>verify({...x,opts:{...x.opts,policies:policiesSub}}),'EXPORT_ROTATION_EXTERNAL_PIN_MISMATCH');
});
