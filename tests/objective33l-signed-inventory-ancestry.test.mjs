import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {offlineConflictAdjudicationInventoryGenesisHead,OFFLINE_CONFLICT_ADJUDICATION_INVENTORY_SCHEMA} from '../src/offline-conflict-adjudication-transcript-inventory.mjs';
import {OFFLINE_CONFLICT_INVENTORY_HEAD_RECEIPT_SCHEMA,offlineConflictInventoryHeadReceiptBodyBytes,
 offlineConflictInventoryHeadReceiptDigest} from '../src/offline-conflict-adjudication-inventory-head-receipts.mjs';
import {OFFLINE_CONFLICT_INVENTORY_ANCESTRY_LINK_SCHEMA,offlineConflictInventoryAncestryLinkBodyBytes,
 offlineConflictInventoryAncestryLinkDigest,reconcileOfflineConflictInventoryAncestry} from '../src/offline-conflict-adjudication-inventory-ancestry.mjs';
const sha=s=>createHash('sha256').update(s).digest('hex');
const ns='namespace_33l_test',scope=sha('33l-scope'),now=1792280000000;
const genesis=offlineConflictAdjudicationInventoryGenesisHead(ns,scope);
const hosts=['host_33l_alpha','host_33l_bravo'].map(hostId=>({hostId,...generateKeyPairSync('ed25519')}));
const pub=h=>h.publicKey.export({format:'der',type:'spki'}).toString('base64url');
const head=(count,headDigest)=>({count,headDigest});
const first=head(1,sha('33l-record-1')),second=head(2,sha('33l-record-2')),third=head(3,sha('33l-record-3'));
const receipt=(host,h)=>{
 const body={schema:OFFLINE_CONFLICT_INVENTORY_HEAD_RECEIPT_SCHEMA,inventorySchema:OFFLINE_CONFLICT_ADJUDICATION_INVENTORY_SCHEMA,
  namespaceId:ns,journalScopeDigest:scope,hostId:host.hostId,genesisHead:genesis,inventoryHead:h,
  observedAt:now-1000,expiresAt:now+30000,nonce:`receipt_${host.hostId}`};
 return Buffer.from(JSON.stringify({body,signature:sign(null,offlineConflictInventoryHeadReceiptBodyBytes(body),host.privateKey).toString('base64url')}));
};
const witness=(fromHead,toHead,changes={})=>{
 const body={schema:OFFLINE_CONFLICT_INVENTORY_ANCESTRY_LINK_SCHEMA,namespaceId:ns,journalScopeDigest:scope,
  higherHostId:hosts[1].hostId,lowerHostId:hosts[0].hostId,fromHead,toHead,recordDigest:toHead.headDigest,
  observedAt:now-2000,expiresAt:now+30000,nonce:`link_33l_${toHead.count}`,...changes};
 return Buffer.from(JSON.stringify({body,signature:sign(null,offlineConflictInventoryAncestryLinkBodyBytes(body),hosts[1].privateKey).toString('base64url')}));
};
const build=(lower=first,upper=third)=>{
 const receipts=[receipt(hosts[0],lower),receipt(hosts[1],upper)];
 const hostPins=hosts.map((h,i)=>({hostId:h.hostId,publicKey:pub(h),expectedReceiptDigest:offlineConflictInventoryHeadReceiptDigest(receipts[i]),expectedInventoryHead:[lower,upper][i]}));
 const chain=lower.count===1&&upper.count===3?[[first,second],[second,third]]:
  lower.count===2&&upper.count===3?[[second,third]]:[];
 const links=chain.map(([a,b])=>witness(a,b));
 const linkPins=links.map((b,i)=>({expectedLinkDigest:offlineConflictInventoryAncestryLinkDigest(b),
  expectedFromHead:chain[i][0],expectedToHead:chain[i][1]}));
 return {receiptArgs:{receipts,hostPins,expectedNamespaceId:ns,expectedJournalScopeDigest:scope,
  expectedGenesisHead:genesis,nowMs:now,seenDigests:[],seenNonces:[]},links,linkPins};
};
const check=a=>reconcileOfflineConflictInventoryAncestry(a);
const reject=(a,code)=>assert.throws(()=>check(a),e=>e?.code===code);
const t=(name,fn)=>test('33L '+name,fn);
t('authenticates two contiguous signed predecessor claims',()=>{const v=check(build());assert.equal(v.status,'authenticated-signed-predecessor-claims');assert.equal(v.signedPredecessorAssertions,true);});
t('does not claim filesystem ancestry, global consensus, production or recovery',()=>{const v=check(build());for(const k of ['provesActualInventoryAncestry','independentlyWitnessedDisk','independentTimestamp','globallyComplete','authorizesRecovery','authorizesRepair','authorizesCheckout','authorizesProduction'])assert.equal(v[k],false);});
t('one transition is sufficient for adjacent signed heads',()=>assert.equal(check(build(second,third)).status,'authenticated-signed-predecessor-claims'));
t('no witnesses means explicitly unresolved',()=>{const a=build();a.links=[];a.linkPins=[];assert.equal(check(a).status,'unresolved-no-predecessor-evidence');});
t('equal heads do not require ancestry evidence',()=>{const a=build(first,first);assert.equal(check(a).status,'consistent-signed-heads');});
t('same-height divergent heads classified conflict not ancestry',()=>{const a=build(first,head(1,sha('fork')));assert.equal(check(a).status,'conflicting-same-height');});
t('same-height supplied ancestry is rejected',()=>{const a=build(first,first);a.links=[witness(first,second)];reject(a,'EXCHANGE33L_UNEXPECTED_LINKS');});
t('omitted middle link rejected',()=>{const a=build();a.links.splice(0,1);a.linkPins.splice(0,1);reject(a,'EXCHANGE33L_MISSING_LINK');});
t('omitted independent link pin rejected',()=>{const a=build();a.linkPins.pop();reject(a,'EXCHANGE33L_MISSING_LINK');});
t('wrong order of links rejected',()=>{const a=build();a.links.reverse();a.linkPins.reverse();reject(a,'EXCHANGE33L_CHAIN_MISMATCH');});
t('wrong predecessor head rejected despite valid signature',()=>{const a=build();a.links[0]=witness(head(1,sha('wrong-predecessor')),second);reject(a,'EXCHANGE33L_CHAIN_MISMATCH');});
t('forged link rejected even with attacker-repinned digest',()=>{const a=build();const r=JSON.parse(a.links[0]);r.signature=sign(null,offlineConflictInventoryAncestryLinkBodyBytes(r.body),hosts[0].privateKey).toString('base64url');a.links[0]=Buffer.from(JSON.stringify(r));a.linkPins[0].expectedLinkDigest=offlineConflictInventoryAncestryLinkDigest(a.links[0]);reject(a,'EXCHANGE33L_LINK_SIGNATURE_INVALID');});
t('link digest substitution rejected',()=>{const a=build();a.linkPins[0].expectedLinkDigest=sha('attacker-pin');reject(a,'EXCHANGE33L_LINK_PIN_MISMATCH');});
t('external transition-head pin substitution rejected',()=>{const a=build();a.linkPins[0].expectedToHead=third;reject(a,'EXCHANGE33L_CHAIN_MISMATCH');});
t('link signature tampering rejected',()=>{const a=build();const r=JSON.parse(a.links[0]);r.signature=(r.signature.startsWith('A')?'B':'A')+r.signature.slice(1);a.links[0]=Buffer.from(JSON.stringify(r));reject(a,'EXCHANGE33L_LINK_PIN_MISMATCH');});
t('wrong higher host rejected',()=>{const a=build();a.links[0]=witness(first,second,{higherHostId:'host_33l_other'});reject(a,'EXCHANGE33L_CHAIN_MISMATCH');});
t('wrong lower host rejected',()=>{const a=build();a.links[0]=witness(first,second,{lowerHostId:'host_33l_other'});reject(a,'EXCHANGE33L_CHAIN_MISMATCH');});
t('wrong namespace rejected',()=>{const a=build();a.links[0]=witness(first,second,{namespaceId:'namespace_33l_other'});reject(a,'EXCHANGE33L_CHAIN_MISMATCH');});
t('wrong scope rejected',()=>{const a=build();a.links[0]=witness(first,second,{journalScopeDigest:sha('other')});reject(a,'EXCHANGE33L_CHAIN_MISMATCH');});
t('stale signed witness rejected',()=>{const a=build();a.links[0]=witness(first,second,{observedAt:now-90000,expiresAt:now-100});a.linkPins[0].expectedLinkDigest=offlineConflictInventoryAncestryLinkDigest(a.links[0]);reject(a,'EXCHANGE33L_LINK_EXPIRED');});
t('link observed after upper receipt rejected',()=>{const a=build();a.links[0]=witness(first,second,{observedAt:now-500});a.linkPins[0].expectedLinkDigest=offlineConflictInventoryAncestryLinkDigest(a.links[0]);reject(a,'EXCHANGE33L_LINK_EXPIRED');});
t('duplicate nonce rejected',()=>{const a=build();a.links[1]=witness(second,third,{nonce:'link_33l_2'});a.linkPins[1].expectedLinkDigest=offlineConflictInventoryAncestryLinkDigest(a.links[1]);reject(a,'EXCHANGE33L_LINK_REPLAY');});
t('invalid UTF8 rejected',()=>{const a=build();a.links[0]=Buffer.from([0xff,0xfe]);reject(a,'EXCHANGE33L_BYTES_INVALID');});
t('noncanonical whitespace rejected',()=>{const a=build();a.links[0]=Buffer.concat([a.links[0],Buffer.from(' ')]);reject(a,'EXCHANGE33L_NONCANONICAL');});
t('duplicate JSON keys rejected',()=>{const a=build();a.links[0]=Buffer.from(a.links[0].toString().replace('{"body":','{"body":null,"body":'));reject(a,'EXCHANGE33L_NONCANONICAL');});
t('noncanonical field order rejected',()=>{const a=build();const r=JSON.parse(a.links[0]);a.links[0]=Buffer.from(JSON.stringify({signature:r.signature,body:r.body}));reject(a,'EXCHANGE33L_NONCANONICAL');});
t('missing record digest rejected at signing boundary',()=>{assert.throws(()=>witness(first,second,{recordDigest:sha('wrong')}),e=>e?.code==='EXCHANGE33L_LINK_INVALID');});
t('skipped count rejected at signing boundary',()=>{assert.throws(()=>witness(first,third),e=>e?.code==='EXCHANGE33L_LINK_INVALID');});
t('unapproved 10 minute+ witness validity rejected',()=>{assert.throws(()=>witness(first,second,{expiresAt:now+900000}),e=>e?.code==='EXCHANGE33L_LINK_INVALID');});
t('sparse link arrays rejected',()=>{const a=build();delete a.links[0];reject(a,'EXCHANGE33L_ARGUMENTS_INVALID');});
t('extra top-level args rejected',()=>{const a=build();a.extra=true;reject(a,'EXCHANGE33L_ARGUMENTS_INVALID');});
t('missing independently pinned host key rejected',()=>{const a=build();a.receiptArgs.hostPins[1].publicKey='invalid';assert.throws(()=>check(a));});
t('different signed chains produce distinct evidence digests',()=>{const a=check(build()),b=check(build(second,third));assert.notEqual(a.linkEvidenceDigest,b.linkEvidenceDigest);});
t('output is immutable',()=>{const v=check(build());assert.throws(()=>{v.status='fake';},TypeError);});
t('large count gaps remain unresolved without guessing ancestry',()=>{const a=build(first,head(50,sha('far')));assert.equal(check(a).status,'unresolved-gap-exceeds-bound');});
t('large count gaps reject supplied links',()=>{const a=build(first,head(50,sha('far')));a.links=[witness(first,second)];reject(a,'EXCHANGE33L_GAP_EXCEEDS_BOUND');});
