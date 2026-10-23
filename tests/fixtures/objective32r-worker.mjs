import {readFile} from 'node:fs/promises';
import {createOfflineConflictExchangeJournal} from '../../src/offline-conflict-exchange-journal.mjs';
const {root,gen,args,crashAt}=JSON.parse(await readFile(process.argv[2],'utf8'));
const journal=createOfflineConflictExchangeJournal({directory:root,genesisExchangeDigest:gen,lockTimeoutMs:8000,
 injectFault:stage=>{if(stage===crashAt)process.exit(87);}});
try{
 const r=await journal.adjudicateInterruptedRecoveryPolicyCutover(args);
 process.stdout.write(JSON.stringify({ok:true,digest:r.receiptDigest})+'\n');
}catch(e){process.stdout.write(JSON.stringify({ok:false,code:e.code||e.message})+'\n');process.exitCode=2;}
