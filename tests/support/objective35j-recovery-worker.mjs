/** Independent Node process: explicit read-only recovery from a fresh ledger instance. */
import {readFileSync} from 'node:fs';
import {createOfflineDurableLedger} from '../../src/offline-durable-ledger.mjs';
import {createOfflineMultiLineage,authenticateSyntheticMultiLineEvent} from '../../src/offline-multiline-order.mjs';
const input=JSON.parse(readFileSync(0,'utf8'));
const verifiedEvent=authenticateSyntheticMultiLineEvent({
 rawBody:Buffer.from(input.rawBody,'base64'),headers:input.headers,
 secret:Buffer.from(input.secret,'base64'),expectedShop:input.shop});
const ledger=createOfflineDurableLedger({directory:input.directory});
const unavailable=async()=>{throw Error('mutation must never run during recovery');};
const lineage=createOfflineMultiLineage({prepareCartReceipt:unavailable,
 resolveCheckout:async()=>({...input.checkout}),commitObserved:unavailable,
 commitCancellation:unavailable,lookupEvent:ledger.lookupMultiLineageEvent,
 inspectCommitted:ledger.inspectCommittedMultiLineage,clock:()=>input.now});
try{const result=await lineage.recoverCommitted({verifiedEvent});process.stdout.write(JSON.stringify({ok:true,result}));}
catch(e){process.stdout.write(JSON.stringify({ok:false,code:e.code||'UNEXPECTED'}));}
