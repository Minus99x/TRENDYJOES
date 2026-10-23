/** Synthetic public-only fixture transport for cross-process locking regression. */
import {readFile} from 'node:fs/promises';
import {createPublicKey} from 'node:crypto';
import {createOfflineConflictExchangeJournal} from '../../src/offline-conflict-exchange-journal.mjs';
const data=JSON.parse(await readFile(process.argv[2],'utf8'));
const verificationArgs={...data.verificationArgs,proofBytes:Buffer.from(data.proofBase64,'base64'),
 senderPublicKey:createPublicKey(data.senderPublicPem),receiverPublicKey:createPublicKey(data.receiverPublicPem)};
try{
 const r=await createOfflineConflictExchangeJournal({directory:data.directory,genesisExchangeDigest:data.genesisExchangeDigest}).claim({
  transcriptBytes:Buffer.from(data.transcriptBase64,'base64'),verificationArgs,expectedHead:data.expectedHead});
 process.stdout.write(JSON.stringify({ok:true,count:r.count,headDigest:r.headDigest}));
}catch(e){process.stdout.write(JSON.stringify({ok:false,code:e.code||e.message}));}
