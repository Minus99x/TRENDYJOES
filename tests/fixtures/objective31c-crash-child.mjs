// Disposable child-process fixture. Uses only ephemeral test keys and local files.
import {readFile,writeFile,rename} from 'node:fs/promises';
import {createPublicKey} from 'node:crypto';
import {join} from 'node:path';
import {createOfflineAuditedRegistryService} from '../../src/offline-audited-registry-service.mjs';
const c=JSON.parse(await readFile(process.argv[2],'utf8'));
const read=path=>readFile(path,'utf8').then(JSON.parse,e=>{if(e.code==='ENOENT')return null;throw e;});
const cas=path=>async(old,next)=>{
 if(JSON.stringify(await read(path))!==JSON.stringify(old))return false;
 const tmp=path+'.tmp-'+process.pid;await writeFile(tmp,JSON.stringify(next),{mode:0o600});await rename(tmp,path);return true;
};
const readR=()=>read(join(c.base,'external-registry-anchor.json'));
const readJ=()=>read(join(c.base,'external-journal-anchor.json'));
const independent=createPublicKey(c.independentPublic),issuer=createPublicKey(c.issuerPublic);
const registryOptions={directory:join(c.base,'registry'),secret:Buffer.from(c.secret,'base64'),readAnchor:readR,
 compareAndSetAnchor:cas(join(c.base,'external-registry-anchor.json')),
 recovery:{registryId:c.registryId,publicKey:independent},
 encryption:{activeKeyId:'objective31b-encryption-key',resolveKey:()=>Buffer.from(c.assetKey,'base64')},
 verifyArtworkAccess:async token=>token===c.session?{shop:c.shop,ownerId:'owner-1',issuedAt:Date.now()-1000,expiresAt:Date.now()+60000}:null,
 mutationAuthorization:{registryId:c.registryId,publicKey:issuer},
 adminAuthorization:{registryId:c.registryId,publicKey:issuer,verifyOperator:async token=>token===c.operator?{operatorId:'operator-31b',issuedAt:Date.now()-1000,expiresAt:Date.now()+60000}:null}
};
const journalOptions={directory:join(c.base,'journal'),registryId:c.registryId,readJournalAnchor:readJ,
 compareAndSetJournalAnchor:cas(join(c.base,'external-journal-anchor.json')),
 readRegistryAnchor:readR,recovery:{registryId:c.registryId,publicKey:independent}};
const coordinatorOptions={directory:join(c.base,'coord'),registryId:c.registryId,readRegistryAnchor:readR,
 readJournalAnchor:readJ,recovery:{publicKey:independent},injectFault:stage=>{if(stage==='after-registry-commit')process.exit(91);}};
const s=createOfflineAuditedRegistryService({registryOptions,journalOptions,coordinatorOptions});
await s.mutate({action:'revokeAuthenticatedArtwork',envelope:c.envelope,auditEnvelope:async()=>({})});
process.exit(0); // Reaching this line is a test failure.
