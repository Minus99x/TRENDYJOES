import {readFile} from 'node:fs/promises';
import {createOfflineConflictManifestJournal} from '../../src/offline-conflict-resolution-manifest-journal.mjs';
const [directory,fixtureFile,mode='normal']=process.argv.slice(2);
const payload=JSON.parse(await readFile(fixtureFile,'utf8'));
const verificationArgs={...payload,manifestBytes:Buffer.from(payload.manifestBytes,'base64'),
 chunks:payload.chunks.map(c=>({...c,bytes:Buffer.from(c.bytes,'base64')}))};
const journal=createOfflineConflictManifestJournal({directory,injectFault:mode==='crash'?async(stage)=>{
 if(stage==='after-pending-sync')process.kill(process.pid,'SIGKILL');
}:undefined});
try{
 const result=await journal.claim({verificationArgs,expectedHead:payload.expectedHead});
 process.stdout.write(JSON.stringify({ok:true,result})+'\n');
}catch(e){process.stdout.write(JSON.stringify({ok:false,code:e.code||e.message})+'\n');process.exitCode=1;}
