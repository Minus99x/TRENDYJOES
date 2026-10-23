import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {OFFLINE_CONFLICT_ACQUISITION_HEAD_PUBLICATION_SCHEMA as SCHEMA,
 offlineConflictAcquisitionHeadPublicationBodyBytes as bodyBytes,
 offlineConflictAcquisitionHeadPublicationDigest as receiptDigest,
 reconcileOfflineConflictAcquisitionHeadPublications as reconcile} from '../src/offline-conflict-acquisition-head-publications.mjs';
const sha=s=>createHash('sha256').update(s).digest('hex');
const h=(count,headDigest)=>({count,headDigest});
const ns='namespace_33p_test',scope=sha('33p-scope'),target='registry_33p_target',host='host_33p_target';
const genesis=h(0,sha('33p-registry-genesis')),head1=h(1,sha('33p-registry-1')),
 head2=h(2,sha('33p-registry-2')),inv1=h(1,sha('33p-inventory-1')),
 inv2=h(2,sha('33p-inventory-2')),directoryPin={dev:'25',ino:'1822'},now=1792280000000;
const publishers=['publisher_33p_alpha','publisher_33p_bravo','publisher_33p_charlie'].map(publisherId=>({publisherId,...generateKeyPairSync('ed25519')}));
const pub=k=>k.publicKey.export({format:'der',type:'spki'}).toString('base64url');
function issue(p,changes={}){
 const body={schema:SCHEMA,namespaceId:ns,journalScopeDigest:scope,targetRegistryId:target,targetHostId:host,
  publisherId:p.publisherId,registryGenesisHead:genesis,registryHead:head1,inventoryHead:inv1,
  registryDirectoryPin:directoryPin,observedAtMs:now-1000,expiresAtMs:now+60000,
  nonce:`nonce_${p.publisherId}`,...changes};
 const signature=sign(null,bodyBytes(body),p.privateKey).toString('base64url');
 return Buffer.from(JSON.stringify({body,signature}));
}
function build(opts={}){
 const ps=opts.publishers??publishers.slice(0,2);
 const receipts=ps.map((p,i)=>issue(p,opts.changes?.[i]??{}));
 const publisherPins=ps.map((p,i)=>({publisherId:p.publisherId,publicKey:pub(p),expectedReceiptDigest:receiptDigest(receipts[i])}));
 return {receipts,publisherPins,expectedNamespaceId:ns,expectedJournalScopeDigest:scope,
  expectedTargetRegistryId:target,expectedTargetHostId:host,expectedRegistryGenesisHead:genesis,
  expectedRegistryDirectoryPin:directoryPin,minimumPinnedHead:genesis,nowMs:now,seenDigests:[],seenNonces:[]};
}
const t=(name,fn)=>test('33P '+name,fn),bad=(a,code)=>assert.throws(()=>reconcile(a),e=>e?.code===code);
const change=(a,i,fn)=>{const r=JSON.parse(a.receipts[i]);fn(r);a.receipts[i]=Buffer.from(JSON.stringify(r));};
t('two independent signatures authenticate matching head claims',()=>{const v=reconcile(build());assert.equal(v.status,'consistent-head');assert.equal(v.verified,true);});
t('three independent publishers accepted with explicit pins',()=>{const v=reconcile(build({publishers}));assert.equal(v.publisherIds.length,3);});
t('same-height conflicting registry heads flagged, not silently reconciled',()=>{const v=reconcile(build({changes:[{}, {registryHead:h(1,sha('fork'))}]}));assert.equal(v.status,'conflicting-same-height');});
t('unequal heights remain unresolved without predecessor evidence',()=>{const v=reconcile(build({changes:[{}, {registryHead:head2,inventoryHead:inv2}]}));assert.equal(v.status,'unresolved-different-heights');assert.equal(v.provesAncestry,false);});
t('same registry head with conflicting inventory claim is not consistent',()=>{const v=reconcile(build({changes:[{}, {inventoryHead:h(1,sha('other-inventory'))}]}));assert.equal(v.status,'conflicting-inventory-claim');});
t('no remote proof, actual publication, timestamps or production authorization',()=>{const v=reconcile(build());for(const x of ['provesRemoteFilesystemState','provesPublication','provesAncestry','independentlyWitnessed','trustedTimestamp','globallyComplete','authorizesRecovery','authorizesCheckout','authorizesProduction'])assert.equal(v[x],false);});
t('forged Ed25519 signature rejected despite independently repinned digest',()=>{const a=build();change(a,0,r=>{r.signature=sign(null,bodyBytes(r.body),publishers[1].privateKey).toString('base64url');});a.publisherPins[0].expectedReceiptDigest=receiptDigest(a.receipts[0]);bad(a,'EXCHANGE33P_SIGNATURE_INVALID');});
t('tampered signed head rejected',()=>{const a=build();change(a,0,r=>{r.body.registryHead.headDigest=sha('tamper');});a.publisherPins[0].expectedReceiptDigest=receiptDigest(a.receipts[0]);bad(a,'EXCHANGE33P_SIGNATURE_INVALID');});
t('independently pinned receipt digest cannot be substituted',()=>{const a=build();a.publisherPins[0].expectedReceiptDigest=sha('different');bad(a,'EXCHANGE33P_RECEIPT_PIN_MISMATCH');});
t('missing publisher receipt rejected',()=>{const a=build();a.receipts.pop();bad(a,'EXCHANGE33P_EXTERNAL_PINS_REQUIRED');});
t('unapproved extra publisher rejected',()=>{const a=build();a.receipts.push(issue(publishers[2]));bad(a,'EXCHANGE33P_EXTERNAL_PINS_REQUIRED');});
t('publisher identity substitution rejected',()=>{const a=build();a.publisherPins[0].publisherId='publisher_33p_fake';bad(a,'EXCHANGE33P_SCOPE_OR_PIN_MISMATCH');});
t('duplicate publisher identity rejected',()=>{const a=build();a.publisherPins[1].publisherId=a.publisherPins[0].publisherId;bad(a,'EXCHANGE33P_PUBLISHER_PINS_INVALID');});
t('same signing key cannot represent two independent publishers',()=>{const a=build();a.publisherPins[1].publicKey=a.publisherPins[0].publicKey;bad(a,'EXCHANGE33P_DUPLICATE_PUBLISHER_KEY');});
t('publisher pins must be strictly sorted',()=>{const a=build();a.publisherPins.reverse();a.receipts.reverse();bad(a,'EXCHANGE33P_PUBLISHER_PINS_INVALID');});
t('externally retained nonce replay rejected',()=>{const a=build();a.seenNonces=[JSON.parse(a.receipts[0]).body.nonce];bad(a,'EXCHANGE33P_REPLAY');});
t('externally retained digest replay rejected',()=>{const a=build();a.seenDigests=[a.publisherPins[0].expectedReceiptDigest];bad(a,'EXCHANGE33P_REPLAY');});
t('duplicate nonce across separately signed observers rejected',()=>{const a=build({changes:[{}, {nonce:'nonce_publisher_33p_alpha'}]});bad(a,'EXCHANGE33P_REPLAY');});
t('expired signed observation rejected',()=>{const a=build();a.nowMs=now+60001;bad(a,'EXCHANGE33P_EXPIRED');});
t('future-dated observation rejected',()=>{const a=build();a.nowMs=now-1001;bad(a,'EXCHANGE33P_EXPIRED');});
t('historical rollback below externally pinned count rejected',()=>{const a=build({changes:[{}, {registryHead:genesis,inventoryHead:inv1}]});a.minimumPinnedHead=head1;bad(a,'EXCHANGE33P_ROLLBACK_OR_FORK_AGAINST_PIN');});
t('same-height fork against independently pinned head rejected',()=>{const a=build({changes:[{}, {registryHead:h(1,sha('fork'))}]});a.minimumPinnedHead=head1;bad(a,'EXCHANGE33P_ROLLBACK_OR_FORK_AGAINST_PIN');});
t('higher count does not pretend to prove pinned predecessor ancestry',()=>{const a=build({changes:[{registryHead:head2,inventoryHead:inv2},{registryHead:head2,inventoryHead:inv2}]});a.minimumPinnedHead=head1;assert.equal(reconcile(a).provesAncestry,false);});
t('namespace substitution rejected',()=>{const a=build();a.expectedNamespaceId='namespace_33p_other';bad(a,'EXCHANGE33P_SCOPE_OR_PIN_MISMATCH');});
t('journal scope substitution rejected',()=>{const a=build();a.expectedJournalScopeDigest=sha('different');bad(a,'EXCHANGE33P_SCOPE_OR_PIN_MISMATCH');});
t('target registry substitution rejected',()=>{const a=build();a.expectedTargetRegistryId='registry_33p_other';bad(a,'EXCHANGE33P_SCOPE_OR_PIN_MISMATCH');});
t('target host substitution rejected',()=>{const a=build();a.expectedTargetHostId='host_33p_other';bad(a,'EXCHANGE33P_SCOPE_OR_PIN_MISMATCH');});
t('registry genesis substitution rejected',()=>{const a=build();a.expectedRegistryGenesisHead=h(0,sha('different'));a.minimumPinnedHead=a.expectedRegistryGenesisHead;bad(a,'EXCHANGE33P_SCOPE_OR_PIN_MISMATCH');});
t('registry directory inode substitution rejected',()=>{const a=build();a.expectedRegistryDirectoryPin={...directoryPin,ino:'19'};bad(a,'EXCHANGE33P_SCOPE_OR_PIN_MISMATCH');});
t('noncanonical trailing whitespace rejected',()=>{const a=build();a.receipts[0]=Buffer.concat([a.receipts[0],Buffer.from(' ')]);bad(a,'EXCHANGE33P_NONCANONICAL');});
t('duplicate JSON keys rejected',()=>{const a=build();a.receipts[0]=Buffer.from(a.receipts[0].toString().replace('{"body":','{"body":null,"body":'));bad(a,'EXCHANGE33P_NONCANONICAL');});
t('invalid UTF-8 rejected',()=>{const a=build();a.receipts[0]=Buffer.from([0xff,0xfe]);bad(a,'EXCHANGE33P_BYTES_INVALID');});
t('oversized receipt rejected',()=>{const a=build();a.receipts[0]=Buffer.alloc(4097);bad(a,'EXCHANGE33P_BYTES_INVALID');});
t('invalid publisher public key rejected',()=>{const a=build();a.publisherPins[0].publicKey='not-a-key';bad(a,'EXCHANGE33P_PUBLISHER_KEY_INVALID');});
t('extra unsigned field rejected at signing boundary',()=>{const b=JSON.parse(issue(publishers[0])).body;b.authorizesProduction=true;assert.throws(()=>bodyBytes(b),e=>e?.code==='EXCHANGE33P_BODY_INVALID');});
t('zero count cannot assert a non-genesis head',()=>{assert.throws(()=>issue(publishers[0],{registryHead:h(0,sha('fake'))}),e=>e?.code==='EXCHANGE33P_GENESIS_MISMATCH');});
t('head count cannot exceed supplied inventory count',()=>{assert.throws(()=>issue(publishers[0],{registryHead:head2}),e=>e?.code==='EXCHANGE33P_HEAD_COUNT_MISMATCH');});
t('overlong validity window rejected',()=>{assert.throws(()=>issue(publishers[0],{expiresAtMs:now+900000}),e=>e?.code==='EXCHANGE33P_BODY_INVALID');});
t('invalid directory inode string rejected',()=>{assert.throws(()=>issue(publishers[0],{registryDirectoryPin:{dev:'25',ino:'0001'}}),e=>e?.code==='EXCHANGE33P_BODY_INVALID');});
t('missing independent floor pin rejected',()=>{const a=build();delete a.minimumPinnedHead;bad(a,'EXCHANGE33P_EXTERNAL_PINS_REQUIRED');});
t('reconciliation output is immutable',()=>{const v=reconcile(build());assert.throws(()=>{v.registryHeads[0].count=999;},TypeError);});
t('different signed assertions have different reconciliation evidence digest',()=>{const a=reconcile(build()),b=reconcile(build({changes:[{}, {registryHead:h(1,sha('fork'))}]}));assert.notEqual(a.evidenceDigest,b.evidenceDigest);});
