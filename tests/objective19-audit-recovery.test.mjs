import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,readFile,writeFile,unlink} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {generateKeyPairSync,sign} from 'node:crypto';
import {createOfflineDurableLedger} from '../src/offline-durable-ledger.mjs';

const shop='gucgmp-bc.myshopify.com',owner='gid://shopify/Customer/45678';
const secret=Buffer.alloc(32,0x92),ledgerId='tj-test-independent-witness';
const recoverySchema='TJ-OFFLINE-LEDGER-RECOVERY-1';
const payloadKeys=['schema','ledgerId','authorizationId','issuedAt','expiresAt','expectedAnchor','targetAnchor','reason'];
const design=(revision=1)=>({shop,ownerSubject:owner,reference:'TJ-'+'A'.repeat(24),revision,
 productGid:'gid://shopify/Product/101',variantGid:'gid://shopify/ProductVariant/201',
 compositionSha256:'a'.repeat(64),status:'CURRENT'});
const clone=x=>structuredClone(x);
const rejects=(p,code)=>assert.rejects(p,e=>e?.code===code);
async function fixture(t,{recovery=true,genesis=false}={}){
 const directory=await mkdtemp(join(tmpdir(),'tj-recovery19-'));
 t.after(()=>rm(directory,{recursive:true,force:true}));
 const {privateKey,publicKey}=generateKeyPairSync('ed25519');
 const state={current:null,casCount:0,failRead:false,failWrite:false,conflict:false};
 const anchor={readAnchor:async()=>{if(state.failRead)throw Error('unavailable');return clone(state.current);},
  compareAndSetAnchor:async(prior,next)=>{state.casCount++;
   if(state.failWrite)throw Error('unavailable');
   if(state.conflict||JSON.stringify(prior)!==JSON.stringify(state.current))return false;
   state.current=clone(next);return true;}};
 const audit={keys:[{id:'audit-1',secret}],activeKeyId:'audit-1',...anchor,
  ...(recovery?{recovery:{ledgerId,publicKey}}:{})};
 const options={directory,audit,lockTimeoutMs:2500};
 const open=(extra={})=>createOfflineDurableLedger({...options,...extra});
 const file=join(directory,'ledger.json');
 const snapshot=async()=>JSON.parse(await readFile(file,'utf8'));
 const permit=(prior,target,override={})=>{
  const now=Date.now();const data={schema:recoverySchema,ledgerId,
   authorizationId:'123e4567-e89b-42d3-a456-426614174019',issuedAt:now-1000,
   expiresAt:now+60_000,expectedAnchor:clone(prior),targetAnchor:clone(target),
   reason:'Independent operator inspected signed ledger and anchor',...override};
  const canonical=Object.fromEntries(payloadKeys.map(k=>[k,data[k]]));
  return {...data,signature:sign(null,Buffer.from(`${recoverySchema}\0${JSON.stringify(canonical)}`),privateKey).toString('base64url')};
 };
 if(!genesis)await open().putDesignCAS({design:design()});
 const pending=async()=>{
  const before=clone(state.current);
  const broken=open({injectFault:stage=>{if(stage==='after-rename')throw Error('synthetic-crash');}});
  await assert.rejects(broken.putDesignCAS({design:design(2),expectedRevision:1}),/synthetic-crash/);
  const s=await snapshot(),target={sequence:s.audit.sequence,mac:s.audit.mac};
  return {before,target,s};
 };
 return {state,anchor,open,permit,pending,file,snapshot,directory,audit,privateKey,publicKey};
}
test('operator-signed one-step fast-forward restores read/write after after-rename crash',async t=>{
 const e=await fixture(t),{before,target}=await e.pending();
 await rejects(e.open().lookupDesign({shop,reference:design().reference}),'LEDGER_AUDIT_ROLLBACK');
 const proof=e.permit(before,target);assert.equal(await e.open().recoverInterruptedAudit({authorization:proof}),'recovered');
 assert.deepEqual(e.state.current,target);assert.deepEqual(await e.open().lookupDesign({shop,reference:design().reference}),design(2));
 await e.open().putDesignCAS({design:design(3),expectedRevision:2});
 assert.equal(e.state.current.sequence,3);
});
test('signed retry after lost recovery acknowledgement is idempotent, no extra CAS',async t=>{
 const e=await fixture(t),{before,target}=await e.pending(),proof=e.permit(before,target);
 assert.equal(await e.open().recoverInterruptedAudit({authorization:proof}),'recovered');
 const count=e.state.casCount;
 assert.equal(await e.open().recoverInterruptedAudit({authorization:proof}),'already-recovered');
 assert.equal(e.state.casCount,count);
});
test('unconfigured recovery refuses any repair',async t=>{
 const e=await fixture(t,{recovery:false}),{before,target}=await e.pending();
 await rejects(e.open().recoverInterruptedAudit({authorization:e.permit(before,target)}),'LEDGER_AUDIT_RECOVERY_UNAVAILABLE');
});
test('normal reads and writes never silently recover',async t=>{
 const e=await fixture(t);await e.pending();
 await rejects(e.open().lookupDesign({shop,reference:design().reference}),'LEDGER_AUDIT_ROLLBACK');
 await rejects(e.open().putDesignCAS({design:design(3),expectedRevision:2}),'LEDGER_AUDIT_ROLLBACK');
});
test('tampered signed authorization is rejected before anchor CAS',async t=>{
 const e=await fixture(t),{before,target}=await e.pending(),p=e.permit(before,target);
 const n=e.state.casCount;await rejects(e.open().recoverInterruptedAudit({authorization:{...p,reason:'Forged evidence'}}),'LEDGER_AUDIT_RECOVERY_SIGNATURE');
 assert.equal(e.state.casCount,n);
});
test('wrong independent signing key cannot authorize recovery',async t=>{
 const e=await fixture(t),{before,target}=await e.pending(),p=e.permit(before,target);
 const rogue=generateKeyPairSync('ed25519');
 const canonical=Object.fromEntries(payloadKeys.map(k=>[k,p[k]]));
 p.signature=sign(null,Buffer.from(`${recoverySchema}\0${JSON.stringify(canonical)}`),rogue.privateKey).toString('base64url');
 await rejects(e.open().recoverInterruptedAudit({authorization:p}),'LEDGER_AUDIT_RECOVERY_SIGNATURE');
});
test('expired authorization cannot fast-forward anchor',async t=>{
 const e=await fixture(t),{before,target}=await e.pending();
 await rejects(e.open().recoverInterruptedAudit({authorization:e.permit(before,target,{issuedAt:Date.now()-120_000,expiresAt:Date.now()-60_000})}),'LEDGER_AUDIT_RECOVERY_AUTH_INVALID');
});
test('future-issued authorization cannot fast-forward anchor',async t=>{
 const e=await fixture(t),{before,target}=await e.pending();
 await rejects(e.open().recoverInterruptedAudit({authorization:e.permit(before,target,{issuedAt:Date.now()+1000,expiresAt:Date.now()+60_000})}),'LEDGER_AUDIT_RECOVERY_AUTH_INVALID');
});
test('oversized authorization validity window is rejected',async t=>{
 const e=await fixture(t),{before,target}=await e.pending();
 await rejects(e.open().recoverInterruptedAudit({authorization:e.permit(before,target,{issuedAt:Date.now()-1000,expiresAt:Date.now()+900_000})}),'LEDGER_AUDIT_RECOVERY_AUTH_INVALID');
});
test('different ledger identity cannot reuse signed permit',async t=>{
 const e=await fixture(t),{before,target}=await e.pending();
 const changed=e.open({audit:{...e.audit,recovery:{ledgerId:'tj-another-ledger-instance',publicKey:e.publicKey}}});
 await rejects(changed.recoverInterruptedAudit({authorization:e.permit(before,target)}),'LEDGER_AUDIT_RECOVERY_AUTH_INVALID');
});
test('signed permit targeting another snapshot fails closed',async t=>{
 const e=await fixture(t),{before,target}=await e.pending();
 const other={sequence:target.sequence,mac:'b'.repeat(64)};
 await rejects(e.open().recoverInterruptedAudit({authorization:e.permit(before,other)}),'LEDGER_AUDIT_RECOVERY_TARGET');
});
test('anchor rollback by more than one sequence cannot be repaired',async t=>{
 const e=await fixture(t),{before,target}=await e.pending();e.state.current=null;
 await rejects(e.open().recoverInterruptedAudit({authorization:e.permit(null,target)}),'LEDGER_AUDIT_RECOVERY_CHAIN');
 e.state.current=before;
});
test('anchor with same sequence but different MAC cannot be repaired',async t=>{
 const e=await fixture(t),{before,target}=await e.pending();
 e.state.current={sequence:before.sequence,mac:'f'.repeat(64)};
 await rejects(e.open().recoverInterruptedAudit({authorization:e.permit(before,target)}),'LEDGER_AUDIT_RECOVERY_CHAIN');
});
test('future anchor cannot be rolled back through recovery',async t=>{
 const e=await fixture(t),{before,target}=await e.pending();
 e.state.current={sequence:target.sequence+1,mac:'f'.repeat(64)};
 await rejects(e.open().recoverInterruptedAudit({authorization:e.permit(before,target)}),'LEDGER_AUDIT_RECOVERY_CHAIN');
});
test('restored prior ledger snapshot cannot be recovered against newer anchor',async t=>{
 const e=await fixture(t),old=await readFile(e.file);await e.open().putDesignCAS({design:design(2),expectedRevision:1});
 const anchor=clone(e.state.current);await writeFile(e.file,old);
 await rejects(e.open().recoverInterruptedAudit({authorization:e.permit(anchor,anchor)}),'LEDGER_AUDIT_RECOVERY_TARGET');
});
test('tampered ledger with valid-looking fields cannot be repaired by signed permit',async t=>{
 const e=await fixture(t),{before,target}=await e.pending();
 const s=await e.snapshot();s.designs[0].ownerSubject='gid://shopify/Customer/999';
 await writeFile(e.file,JSON.stringify(s));
 await rejects(e.open().recoverInterruptedAudit({authorization:e.permit(before,target)}),'LEDGER_AUDIT_TAMPERED');
});
test('corrupt JSON cannot be repaired',async t=>{
 const e=await fixture(t),{before,target}=await e.pending();await writeFile(e.file,'{');
 await rejects(e.open().recoverInterruptedAudit({authorization:e.permit(before,target)}),'LEDGER_STATE_CORRUPT');
});
test('deleted ledger cannot be rebuilt from an anchor and permit',async t=>{
 const e=await fixture(t),{before,target}=await e.pending();await unlink(e.file);
 await rejects(e.open().recoverInterruptedAudit({authorization:e.permit(before,target)}),'LEDGER_AUDIT_RECOVERY_STATE_MISSING');
});
test('external anchor read outage refuses recovery',async t=>{
 const e=await fixture(t),{before,target}=await e.pending();e.state.failRead=true;
 await rejects(e.open().recoverInterruptedAudit({authorization:e.permit(before,target)}),'LEDGER_AUDIT_ANCHOR_UNAVAILABLE');
});
test('external anchor CAS conflict refuses recovery and keeps normal operations blocked',async t=>{
 const e=await fixture(t),{before,target}=await e.pending();e.state.conflict=true;
 await rejects(e.open().recoverInterruptedAudit({authorization:e.permit(before,target)}),'LEDGER_AUDIT_ANCHOR_CONFLICT');
 await rejects(e.open().lookupDesign({shop,reference:design().reference}),'LEDGER_AUDIT_ROLLBACK');
});
test('external anchor write outage refuses recovery',async t=>{
 const e=await fixture(t),{before,target}=await e.pending();e.state.failWrite=true;
 await rejects(e.open().recoverInterruptedAudit({authorization:e.permit(before,target)}),'LEDGER_AUDIT_ANCHOR_UNAVAILABLE');
});
test('valid signed authorization cannot repair a pre-rename crash that needs no repair',async t=>{
 const e=await fixture(t),before=clone(e.state.current);
 const broken=e.open({injectFault:stage=>{if(stage==='before-rename')throw Error('synthetic-crash');}});
 await assert.rejects(broken.putDesignCAS({design:design(2),expectedRevision:1}),/synthetic-crash/);
 const s=await e.snapshot(),target={sequence:s.audit.sequence,mac:s.audit.mac};
 assert.equal(await e.open().recoverInterruptedAudit({authorization:e.permit(before,target)}),'already-recovered');
 assert.deepEqual(await e.open().lookupDesign({shop,reference:design().reference}),design());
});
test('no recovery for unaudited ledger',async t=>{
 const e=await fixture(t),plain=e.open({audit:undefined});
 await rejects(plain.recoverInterruptedAudit({authorization:{}}),'LEDGER_AUDIT_RECOVERY_UNAVAILABLE');
});
test('missing recovery authorization is rejected',async t=>{
 const e=await fixture(t);await e.pending();
 await rejects(e.open().recoverInterruptedAudit(),'LEDGER_AUDIT_RECOVERY_AUTH_INVALID');
});
test('missing recovery public key fails configuration',async t=>{
 const e=await fixture(t);
 assert.throws(()=>e.open({audit:{...e.audit,recovery:{ledgerId}}}),x=>x.code==='LEDGER_AUDIT_RECOVERY_CONFIGURATION');
});
test('private key cannot be passed as trusted public verifier',async t=>{
 const e=await fixture(t);
 assert.throws(()=>e.open({audit:{...e.audit,recovery:{ledgerId,publicKey:e.privateKey}}}),x=>x.code==='LEDGER_AUDIT_RECOVERY_CONFIGURATION');
});
test('signed permit with noncanonical signature bytes is rejected',async t=>{
 const e=await fixture(t),{before,target}=await e.pending(),p=e.permit(before,target);
 await rejects(e.open().recoverInterruptedAudit({authorization:{...p,signature:p.signature.slice(0,-1)+'='}}),'LEDGER_AUDIT_RECOVERY_AUTH_INVALID');
});
test('recovery does not rewrite ledger snapshot bytes',async t=>{
 const e=await fixture(t),{before,target}=await e.pending(),prior=await readFile(e.file);
 assert.equal(await e.open().recoverInterruptedAudit({authorization:e.permit(before,target)}),'recovered');
 assert.deepEqual(await readFile(e.file),prior);
});
test('recovery proof requires exact expected anchor even when chain is valid',async t=>{
 const e=await fixture(t),{before,target}=await e.pending();
 await rejects(e.open().recoverInterruptedAudit({authorization:e.permit(null,target)}),'LEDGER_AUDIT_RECOVERY_CHAIN');
});
test('genesis crash can be repaired only with independently signed null-to-one permit',async t=>{
 const e=await fixture(t,{genesis:true});
 const broken=e.open({injectFault:stage=>{if(stage==='after-rename')throw Error('synthetic-crash');}});
 await assert.rejects(broken.putDesignCAS({design:design()}),/synthetic-crash/);
 const s=await e.snapshot(),target={sequence:1,mac:s.audit.mac};
 await rejects(e.open().lookupDesign({shop,reference:design().reference}),'LEDGER_AUDIT_ROLLBACK');
 assert.equal(await e.open().recoverInterruptedAudit({authorization:e.permit(null,target)}),'recovered');
 assert.deepEqual(await e.open().lookupDesign({shop,reference:design().reference}),design());
});
test('concurrent recovery calls under one lock produce one CAS and one idempotent acknowledgement',async t=>{
 const e=await fixture(t),{before,target}=await e.pending(),p=e.permit(before,target);
 const baseline=e.state.casCount;
 const results=await Promise.all([e.open().recoverInterruptedAudit({authorization:p}),e.open().recoverInterruptedAudit({authorization:p})]);
 assert.deepEqual(results.sort(),['already-recovered','recovered']);
 assert.equal(e.state.casCount,baseline+1);
});
test('anchor readback outage after successful CAS remains fail closed until normal verification',async t=>{
 const e=await fixture(t),{before,target}=await e.pending(),p=e.permit(before,target);
 let reads=0;
 const audit={...e.audit,readAnchor:async()=>{reads++;if(reads===2)throw Error('readback unavailable');return clone(e.state.current);}};
 await rejects(e.open({audit}).recoverInterruptedAudit({authorization:p}),'LEDGER_AUDIT_ANCHOR_UNAVAILABLE');
 assert.deepEqual(e.state.current,target);
 assert.deepEqual(await e.open().lookupDesign({shop,reference:design().reference}),design(2));
});
test('malformed independent anchor shape blocks recovery',async t=>{
 const e=await fixture(t),{before,target}=await e.pending();e.state.current={sequence:'1',mac:before.mac};
 await rejects(e.open().recoverInterruptedAudit({authorization:e.permit(before,target)}),'LEDGER_AUDIT_ANCHOR_INVALID');
});
test('malformed recovery permit with unexpected field is rejected',async t=>{
 const e=await fixture(t),{before,target}=await e.pending(),p=e.permit(before,target);
 await rejects(e.open().recoverInterruptedAudit({authorization:{...p,autoApprove:true}}),'LEDGER_AUDIT_RECOVERY_AUTH_INVALID');
});
