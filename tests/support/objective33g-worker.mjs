// Independent Node process used only by Objective 33G offline fault/race tests.
import {readFile} from 'node:fs/promises';
import {createOfflineConflictEquivocationAcceptanceRegistry} from '../../src/offline-conflict-equivocation-acceptance-registry.mjs';
const payload=JSON.parse(await readFile(process.argv[2],'utf8'));
const {directory,namespaceId,journalScopeDigest,expectedHead,verificationArgs,crashAt}=payload;
verificationArgs.bytes=Buffer.from(verificationArgs.bytes,'base64');
const registry=createOfflineConflictEquivocationAcceptanceRegistry({directory,namespaceId,journalScopeDigest,
 injectFault:crashAt?stage=>{if(stage===crashAt)process.kill(process.pid,'SIGKILL');}:undefined});
try{await registry.accept({expectedHead,verificationArgs});process.exit(0);}
catch(e){process.stderr.write(String(e.code||e.message));process.exit(11);}
