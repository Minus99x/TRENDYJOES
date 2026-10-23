/** Test-only independent process for 33J concurrent admission and SIGKILL. */
import {readFile} from 'node:fs/promises';
import {createOfflineConflictAdjudicationTranscriptInventory} from '../../src/offline-conflict-adjudication-transcript-inventory.mjs';
const [input,crashStage='none']=process.argv.slice(2);
try{
 const p=JSON.parse(await readFile(input,'utf8'));
 const revive=x=>({...x,bytes:Buffer.from(x.bytes,'base64url')});
 const r=createOfflineConflictAdjudicationTranscriptInventory({directory:p.directory,
  namespaceId:p.namespaceId,journalScopeDigest:p.journalScopeDigest,
  injectFault:crashStage==='none'?undefined:stage=>{if(stage===crashStage)process.kill(process.pid,'SIGKILL');}});
 const result=await r.accept({left:revive(p.left),right:revive(p.right),expectedHead:p.expectedHead});
 process.stdout.write(JSON.stringify({ok:true,count:result.count,headDigest:result.headDigest})+'\n');
}catch(e){process.stdout.write(JSON.stringify({ok:false,code:e.code||'UNKNOWN'})+'\n');process.exitCode=1;}
