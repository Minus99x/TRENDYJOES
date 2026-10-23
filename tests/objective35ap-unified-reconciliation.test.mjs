import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';
const script=new URL('../scripts/check-unified-reconciliation.py',import.meta.url).pathname;
test('35AP combined guard is read-only and production fails closed',async()=>{
 const source=await readFile(script,'utf8');
 for(const sig of ['allWritesBlocked','productionApproved','sourceCompleteHostedCapture','MAIN_ARCHIVE_HASH_MISMATCH','MAIN_ARCHIVE_CRC_ERROR','MISSING_OR_UNSAFE_SOURCE'])assert.ok(source.includes(sig),sig);
 assert.doesNotMatch(source,/graphql_mutation|requests\.post|urllib\.request|subprocess\.run|shopify\.com/);
});
test('35AP combined guard requires independent Main archive SHA and arguments',()=>{
 const r=spawnSync('python',[script],{encoding:'utf8'});
 assert.notEqual(r.status,0);
 assert.match(r.stderr,/--main-archive/);assert.match(r.stderr,/--main-sha256/);
});
test('35AP combined guard rejects nonexistent Main archive with no output files',()=>{
 const r=spawnSync('python',[script,'--main-archive','/no/such/authoritative.zip','--main-sha256','0'.repeat(64)],{encoding:'utf8'});
 assert.equal(r.status,2);assert.match(r.stderr,/BLOCKED \/ NO RELEASE ADVANCEMENT/);
});
