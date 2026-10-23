import {createPublicKey} from 'node:crypto';
import {advanceOfflinePinnedEpochHead} from '../../src/preview-local-artwork-review-epoch-head-registry.mjs';
let text='';for await(const chunk of process.stdin)text+=chunk;
try{const p=JSON.parse(text),v=p.transitionVerification;
 const transitionVerification={...v,transitionBytes:Buffer.from(v.transitionBytes,'base64'),
  previousRosterBytes:Buffer.from(v.previousRosterBytes,'base64'),
  nextRosterBytes:Buffer.from(v.nextRosterBytes,'base64'),issuerPublicKey:createPublicKey(v.issuerPublicKey)};
 await advanceOfflinePinnedEpochHead({...p,transitionVerification});process.stdout.write('OK\n');}
catch(e){process.stderr.write(`${e.code||e.message}\n`);process.exitCode=1;}
