/** Synthetic independent-process durability/race worker; no customer data. */
import {readFile} from 'node:fs/promises';
import {createPublicKey} from 'node:crypto';
import {createLocalArtworkReviewJournal} from '../../src/preview-local-artwork-review-journal.mjs';
const fixture=JSON.parse(await readFile(process.argv[2],'utf8'));
const {root,directory,ticket,evidence,expectedHead,now,reviewKey,publicKey,stage}=fixture;
const journal=createLocalArtworkReviewJournal({root,directory,
 injectFault:stage?async at=>{if(at===stage)process.kill(process.pid,'SIGKILL');}:undefined});
try{
 const result=await journal.admit({ticket,evidence,expectedHead,now,reviewKey:Buffer.from(reviewKey,'hex'),
  expectedChallenge:evidence.challenge,resolvePublicKey:async()=>createPublicKey(publicKey)});
 console.log(JSON.stringify({ok:true,head:result.head}));
}catch(e){console.log(JSON.stringify({ok:false,code:e?.code||e?.message}));process.exitCode=2;}
