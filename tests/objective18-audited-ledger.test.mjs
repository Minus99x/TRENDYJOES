import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,rm,readFile,writeFile,unlink} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {createOfflineDurableLedger} from '../src/offline-durable-ledger.mjs';

const shop='gucgmp-bc.myshopify.com',owner='gid://shopify/Customer/45678';
const secretA=Buffer.alloc(32,0x9a),secretB=Buffer.alloc(32,0x9b);
const keyA={id:'audit-a',secret:secretA},keyB={id:'audit-b',secret:secretB};
const design=(n=1,revision=1)=>({shop,ownerSubject:owner,reference:'TJ-'+String(n).padStart(24,'A'),revision,
 productGid:`gid://shopify/Product/${100+n}`,variantGid:`gid://shopify/ProductVariant/${200+n}`,
 compositionSha256:String(n).repeat(64),status:'CURRENT'});
const rejects=(promise,code)=>assert.rejects(promise,e=>e?.code===code);
const clone=x=>structuredClone(x);
async function fixture(t,{audited=true,injectFault}={}){
 const directory=await mkdtemp(join(tmpdir(),'tj-audit18-'));
 t.after(()=>rm(directory,{recursive:true,force:true}));
 const anchorState={current:null,readFailure:false,writeFailure:false,writeConflict:false,readCount:0,writeCount:0};
 const anchor={
  readAnchor:async()=>{anchorState.readCount++;if(anchorState.readFailure)throw Error('anchor offline');return clone(anchorState.current);},
  compareAndSetAnchor:async(previous,next)=>{
   anchorState.writeCount++;
   if(anchorState.writeFailure)throw Error('anchor write offline');
   if(anchorState.writeConflict||JSON.stringify(previous)!==JSON.stringify(anchorState.current))return false;
   anchorState.current=clone(next);return true;
  }
 };
 const options={directory,lockTimeoutMs:3000,...(audited?{audit:{keys:[keyA,keyB],activeKeyId:'audit-a',...anchor}}:{}),
  ...(injectFault?{injectFault}:{})};
 const open=(extra={})=>createOfflineDurableLedger({...options,...extra});
 const file=join(directory,'ledger.json');
 const snapshot=async()=>JSON.parse(await readFile(file,'utf8'));
 const replace=async fn=>{const s=await snapshot();fn(s);await writeFile(file,JSON.stringify(s));};
 return {directory,anchorState,anchor,options,open,file,snapshot,replace};
}
const binding=d=>Object.fromEntries(['reference','revision','productGid','variantGid','compositionSha256'].map(k=>[k,d[k]]));
async function twoLineOrder(e){
 const ledger=e.open(),a=design(1),b=design(2);
 await ledger.putDesignCAS({design:a});await ledger.putDesignCAS({design:b});
 const lines=[{lineId:1,...binding(a)},{lineId:2,...binding(b)}];
 const checkoutId='offline-checkout:'+'Z'.repeat(24),orderGid='gid://shopify/Order/9000';
 const sessionHash='f'.repeat(64),t=Date.now();
 const proofs=[a,b].map((d,i)=>({schema:'TJ-OFFLINE-PREPARED-CART-2',shop,
  ownerSubject:owner,sessionHash,...binding(d),nonceKey:String(i+1).repeat(64),
  receiptSha256:String(i+3).repeat(64),expiresAt:t+120_000,checkoutEnabled:false,
  paymentVerified:false,productionApproved:false,fulfillmentAuthorized:false,expectedDesign:d}));
 const event={shop,eventId:'123e4567-e89b-42d3-a456-426614174000',bodySha256:'a'.repeat(64),
  action:'ORDER_OBSERVED',orderGid,checkoutId,ownerSubject:owner,sessionHash,lines,
  preparedReceipts:proofs,assertPreparedReceipt:x=>x};
 assert.equal(await ledger.commitMultiLineageWithReceipts(event),'acquired');
 const cancel={shop,eventId:'123e4567-e89b-42d3-a456-426614174001',bodySha256:'b'.repeat(64),
  action:'CANCELLATION_OBSERVED',orderGid,checkoutId,ownerSubject:owner,sessionHash,lines};
 assert.equal(await ledger.commitMultiLineageCancellation(cancel),'acquired');
 return {ledger,event,cancel,orderGid,lines};
}

test('fresh authenticated ledger commits sequence one and external anchor',async t=>{
 const e=await fixture(t),l=e.open();await l.putDesignCAS({design:design()});
 const s=await e.snapshot();assert.equal(s.audit.schema,'TJ-OFFLINE-LEDGER-AUDIT-1');
 assert.equal(s.audit.sequence,1);assert.equal(s.audit.previousMac,'0'.repeat(64));
 assert.equal(s.audit.keyId,'audit-a');assert.deepEqual(e.anchorState.current,{sequence:1,mac:s.audit.mac});
 assert.equal((await readFile(e.file,'utf8')).includes(secretA.toString('hex')),false);
});
test('sequential writes form MAC-linked commitment chain',async t=>{
 const e=await fixture(t),l=e.open();await l.putDesignCAS({design:design()});const first=await e.snapshot();
 await l.putDesignCAS({design:design(1,2),expectedRevision:1});const second=await e.snapshot();
 assert.equal(second.audit.sequence,2);assert.equal(second.audit.previousMac,first.audit.mac);
 assert.notEqual(second.audit.mac,first.audit.mac);assert.equal(e.anchorState.current.sequence,2);
});
test('reopened ledger verifies against same independently held anchor',async t=>{
 const e=await fixture(t);await e.open().putDesignCAS({design:design()});
 assert.deepEqual(await e.open().lookupDesign({shop,reference:design().reference}),design());
});
test('valid but changed owner is cryptographically rejected',async t=>{
 const e=await fixture(t);await e.open().putDesignCAS({design:design()});
 await e.replace(s=>{s.designs[0].ownerSubject='gid://shopify/Customer/9999';});
 await rejects(e.open().lookupDesign({shop,reference:design().reference}),'LEDGER_AUDIT_TAMPERED');
});
test('valid but changed variant is cryptographically rejected',async t=>{
 const e=await fixture(t);await e.open().putDesignCAS({design:design()});
 await e.replace(s=>{s.designs[0].variantGid='gid://shopify/ProductVariant/999';});
 await rejects(e.open().lookupDesign({shop,reference:design().reference}),'LEDGER_AUDIT_TAMPERED');
});
test('valid but changed composition hash is cryptographically rejected',async t=>{
 const e=await fixture(t);await e.open().putDesignCAS({design:design()});
 await e.replace(s=>{s.designs[0].compositionSha256='c'.repeat(64);});
 await rejects(e.open().lookupDesign({shop,reference:design().reference}),'LEDGER_AUDIT_TAMPERED');
});
test('missing audit envelope fails closed without legacy fallback',async t=>{
 const e=await fixture(t);await e.open().putDesignCAS({design:design()});
 await e.replace(s=>{delete s.audit;});
 await rejects(e.open().lookupDesign({shop,reference:design().reference}),'LEDGER_AUDIT_INVALID');
});
test('forged audit MAC fails closed',async t=>{
 const e=await fixture(t);await e.open().putDesignCAS({design:design()});
 await e.replace(s=>{s.audit.mac='a'.repeat(64);});
 await rejects(e.open().lookupDesign({shop,reference:design().reference}),'LEDGER_AUDIT_TAMPERED');
});
test('forged previous MAC fails closed',async t=>{
 const e=await fixture(t);await e.open().putDesignCAS({design:design()});
 await e.replace(s=>{s.audit.previousMac='b'.repeat(64);});
 await rejects(e.open().lookupDesign({shop,reference:design().reference}),'LEDGER_AUDIT_TAMPERED');
});
test('unknown historical key fails closed',async t=>{
 const e=await fixture(t);await e.open().putDesignCAS({design:design()});
 const reduced={keys:[keyB],activeKeyId:'audit-b',...e.anchor};
 await rejects(e.open({audit:reduced}).lookupDesign({shop,reference:design().reference}),'LEDGER_AUDIT_KEY_UNAVAILABLE');
});
test('key rotation changes signing key while preserving old commitment link',async t=>{
 const e=await fixture(t);await e.open().putDesignCAS({design:design()});const old=await e.snapshot();
 const rotated=e.open({audit:{keys:[keyA,keyB],activeKeyId:'audit-b',...e.anchor}});
 await rotated.putDesignCAS({design:design(2)});const next=await e.snapshot();
 assert.equal(next.audit.keyId,'audit-b');assert.equal(next.audit.previousMac,old.audit.mac);
 assert.deepEqual(await rotated.lookupDesign({shop,reference:design(1).reference}),design(1));
});
test('missing trusted anchor rejects existing state',async t=>{
 const e=await fixture(t);await e.open().putDesignCAS({design:design()});e.anchorState.current=null;
 await rejects(e.open().lookupDesign({shop,reference:design().reference}),'LEDGER_AUDIT_ROLLBACK');
});
test('older anchor rejects newer state',async t=>{
 const e=await fixture(t);await e.open().putDesignCAS({design:design()});const older=clone(e.anchorState.current);
 await e.open().putDesignCAS({design:design(2)});e.anchorState.current=older;
 await rejects(e.open().lookupDesign({shop,reference:design().reference}),'LEDGER_AUDIT_ROLLBACK');
});
test('forged future anchor rejects older state',async t=>{
 const e=await fixture(t);await e.open().putDesignCAS({design:design()});
 e.anchorState.current={sequence:99,mac:'f'.repeat(64)};
 await rejects(e.open().lookupDesign({shop,reference:design().reference}),'LEDGER_AUDIT_ROLLBACK');
});
test('restoring earlier valid snapshot cannot pass newer external anchor',async t=>{
 const e=await fixture(t),l=e.open();await l.putDesignCAS({design:design()});const old=await readFile(e.file);
 await l.putDesignCAS({design:design(2)});await writeFile(e.file,old);
 await rejects(e.open().lookupDesign({shop,reference:design().reference}),'LEDGER_AUDIT_ROLLBACK');
});
test('deleting ledger while external anchor remains is rollback, not fresh state',async t=>{
 const e=await fixture(t);await e.open().putDesignCAS({design:design()});await unlink(e.file);
 await rejects(e.open().lookupDesign({shop,reference:design().reference}),'LEDGER_AUDIT_ROLLBACK');
});
test('unaudited adapter cannot silently downgrade audited ledger',async t=>{
 const e=await fixture(t);await e.open().putDesignCAS({design:design()});
 await rejects(e.open({audit:undefined}).lookupDesign({shop,reference:design().reference}),'LEDGER_AUDIT_REQUIRED');
});
test('existing legacy snapshot cannot silently adopt audit protection',async t=>{
 const e=await fixture(t,{audited:false});await e.open().putDesignCAS({design:design()});
 const cfg={keys:[keyA],activeKeyId:'audit-a',...e.anchor};
 await rejects(e.open({audit:cfg}).lookupDesign({shop,reference:design().reference}),'LEDGER_AUDIT_INVALID');
});
test('short key and duplicate key IDs are rejected before any filesystem writes',async t=>{
 const e=await fixture(t);assert.throws(()=>e.open({audit:{keys:[{id:'bad',secret:Buffer.alloc(16)}],
  activeKeyId:'bad',...e.anchor}}),x=>x.code==='LEDGER_AUDIT_CONFIGURATION');
 assert.throws(()=>e.open({audit:{keys:[keyA,keyA],activeKeyId:'audit-a',...e.anchor}}),
  x=>x.code==='LEDGER_AUDIT_CONFIGURATION');
});
test('anchor read outage fails closed without state changes',async t=>{
 const e=await fixture(t);await e.open().putDesignCAS({design:design()});const before=await readFile(e.file);
 e.anchorState.readFailure=true;
 await rejects(e.open().lookupDesign({shop,reference:design().reference}),'LEDGER_AUDIT_ANCHOR_UNAVAILABLE');
 assert.deepEqual(await readFile(e.file),before);
});
test('anchor CAS rejection leaves ledger ahead and blocks subsequent operations',async t=>{
 const e=await fixture(t);await e.open().putDesignCAS({design:design()});e.anchorState.writeConflict=true;
 await rejects(e.open().putDesignCAS({design:design(2)}),'LEDGER_AUDIT_ANCHOR_CONFLICT');
 e.anchorState.writeConflict=false;
 await rejects(e.open().putDesignCAS({design:design(3)}),'LEDGER_AUDIT_ROLLBACK');
});
test('anchor write outage leaves ledger ahead and cannot be silently retried',async t=>{
 const e=await fixture(t);await e.open().putDesignCAS({design:design()});e.anchorState.writeFailure=true;
 await rejects(e.open().putDesignCAS({design:design(2)}),'LEDGER_AUDIT_ANCHOR_UNAVAILABLE');
 e.anchorState.writeFailure=false;
 await rejects(e.open().lookupDesign({shop,reference:design().reference}),'LEDGER_AUDIT_ROLLBACK');
});
test('after-rename interruption fails closed instead of accepting unanchored state',async t=>{
 const e=await fixture(t);await e.open().putDesignCAS({design:design()});
 const broken=e.open({injectFault:stage=>{if(stage==='after-rename')throw Error('crash');}});
 await assert.rejects(broken.putDesignCAS({design:design(2)}),/crash/);
 await rejects(e.open().lookupDesign({shop,reference:design().reference}),'LEDGER_AUDIT_ROLLBACK');
});
test('before-rename interruption retains prior anchor and state, permits retry',async t=>{
 const e=await fixture(t);await e.open().putDesignCAS({design:design()});
 const old=await readFile(e.file),anchor=clone(e.anchorState.current);
 const broken=e.open({injectFault:stage=>{if(stage==='before-rename')throw Error('crash');}});
 await assert.rejects(broken.putDesignCAS({design:design(2)}),/crash/);
 assert.deepEqual(await readFile(e.file),old);assert.deepEqual(e.anchorState.current,anchor);
 await e.open().putDesignCAS({design:design(2)});
});
test('invalid anchor shape fails closed',async t=>{
 const e=await fixture(t);await e.open().putDesignCAS({design:design()});
 e.anchorState.current={sequence:'1',mac:'f'.repeat(64)};
 await rejects(e.open().lookupDesign({shop,reference:design().reference}),'LEDGER_AUDIT_ANCHOR_INVALID');
});
test('syntactically corrupted ledger remains rejected',async t=>{
 const e=await fixture(t);await e.open().putDesignCAS({design:design()});await writeFile(e.file,'{');
 await rejects(e.open().lookupDesign({shop,reference:design().reference}),'LEDGER_STATE_CORRUPT');
});
test('audited multi-line order cancellation and compaction preserve replay claims',async t=>{
 const e=await fixture(t),o=await twoLineOrder(e),l=e.open();
 const before=await l.getMultiLineageHistory({shop,orderGid:o.orderGid});
 assert.equal(await l.compactMultiLineageHistory({shop,orderGid:o.orderGid}),'acquired');
 assert.deepEqual(await e.open().getMultiLineageHistory({shop,orderGid:o.orderGid}),before);
 assert.equal(await e.open().commitMultiLineageCancellation(o.cancel),'duplicate');
 assert.equal(await e.open().compactMultiLineageHistory({shop,orderGid:o.orderGid}),'duplicate');
 assert.equal((await e.snapshot()).audit.sequence,5);
});
test('tampered compacted archived event digest is rejected even when semantically valid',async t=>{
 const e=await fixture(t),o=await twoLineOrder(e);await o.ledger.compactMultiLineageHistory({shop,orderGid:o.orderGid});
 await e.replace(s=>{s.multiArchives[0].entries[1][1]='d'.repeat(64);});
 await rejects(e.open().getMultiLineageHistory({shop,orderGid:o.orderGid}),'LEDGER_AUDIT_TAMPERED');
});
test('duplicate event and duplicate compaction do not advance audit anchor',async t=>{
 const e=await fixture(t),o=await twoLineOrder(e);await o.ledger.compactMultiLineageHistory({shop,orderGid:o.orderGid});
 const before=clone(e.anchorState.current),count=e.anchorState.writeCount;
 assert.equal(await o.ledger.commitMultiLineageCancellation(o.cancel),'duplicate');
 assert.equal(await o.ledger.compactMultiLineageHistory({shop,orderGid:o.orderGid}),'duplicate');
 assert.deepEqual(e.anchorState.current,before);assert.equal(e.anchorState.writeCount,count);
});
test('key identifier substitution fails even if both key IDs share identical bytes',async t=>{
 const e=await fixture(t);
 const sameSecret={id:'audit-b',secret:secretA};
 const cfg={keys:[keyA,sameSecret],activeKeyId:'audit-a',...e.anchor};
 await e.open({audit:cfg}).putDesignCAS({design:design()});
 await e.replace(s=>{s.audit.keyId='audit-b';});
 await rejects(e.open({audit:cfg}).lookupDesign({shop,reference:design().reference}),'LEDGER_AUDIT_TAMPERED');
});
