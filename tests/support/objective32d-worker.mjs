import {readFile} from 'node:fs/promises';
import {createPublicKey} from 'node:crypto';
import {createOfflineSupervisorReplayCommit} from '../../src/offline-supervisor-replay-commit.mjs';
const config=JSON.parse(await readFile(process.argv[2],'utf8'));
const {directory,registryId,genesisBase64,expectedGenesisDigest,args,fault}=config;
const r=createOfflineSupervisorReplayCommit({directory,registryId,genesisBytes:Buffer.from(genesisBase64,'base64'),expectedGenesisDigest,
 faultHook:stage=>{if(stage===fault)process.kill(process.pid,'SIGKILL');}});
try{
 const out=await r.commit({...args,reviewers:args.reviewers.map(x=>({...x,publicKey:createPublicKey(x.publicKey)}))});
 process.stdout.write(JSON.stringify({ok:true,out})+'\n');
}catch(e){process.stdout.write(JSON.stringify({ok:false,code:e.code||e.message})+'\n');process.exitCode=2;}
