/** Objective 35V: cooperative, local-filesystem lease for prototype artwork/revision operations.
 * A crash leaves the lease in place. NEVER automatically steal, age out, or reclaim it.
 * Only code paths that explicitly use this lease participate. This is not a production
 * distributed lock, nor permission to quarantine/delete artwork.
 */
import * as fs from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {setTimeout as delay} from 'node:timers/promises';
const fail=(code,cause)=>Object.assign(new Error(code),{code,cause});
const same=(a,b)=>a.dev===b.dev&&a.ino===b.ino&&a.isDirectory()&&b.isDirectory()&&!a.isSymbolicLink()&&!b.isSymbolicLink();
export async function withLocalArtworkLease(root,operation,{io=fs,waitMs=3000,pollMs=15}={}){
 if(typeof root!=='string'||!root||typeof operation!=='function'||
  !Number.isSafeInteger(waitMs)||waitMs<0||waitMs>30000||
  !Number.isSafeInteger(pollMs)||pollMs<1||pollMs>1000)
  throw fail('LOCAL_ARTWORK_LEASE_INVALID');
 const base=resolve(root),path=join(base,'.artwork-retention-lease');
 let rootStat;try{rootStat=await io.lstat(base);}catch(e){throw fail('LOCAL_ARTWORK_LEASE_ROOT_UNSAFE',e);}
 if(!rootStat.isDirectory()||rootStat.isSymbolicLink())throw fail('LOCAL_ARTWORK_LEASE_ROOT_UNSAFE');
 const deadline=Date.now()+waitMs;
 for(;;){
  try{await io.mkdir(path,{mode:0o700});break;}
  catch(e){
   if(e.code!=='EEXIST')throw fail('LOCAL_ARTWORK_LEASE_ACQUIRE_FAILED',e);
   // Refuse non-directory/symlink locks, and never remove stale locks.
   let s;try{s=await io.lstat(path);}catch(err){
    // Another cooperating writer may have released the lease between EEXIST and lstat.
    if(err.code==='ENOENT')continue;
    throw fail('LOCAL_ARTWORK_LEASE_UNCERTAIN',err);
   }
   if(!s.isDirectory()||s.isSymbolicLink())throw fail('LOCAL_ARTWORK_LEASE_UNSAFE');
   if(Date.now()>=deadline)throw fail('LOCAL_ARTWORK_LEASE_BUSY');
   await delay(Math.min(pollMs,Math.max(1,deadline-Date.now())));
  }
 }
 let acquired;try{acquired=await io.lstat(path);}catch(e){throw fail('LOCAL_ARTWORK_LEASE_UNCERTAIN',e);}
 let result,problem;
 try{
  if(!acquired.isDirectory()||acquired.isSymbolicLink())throw fail('LOCAL_ARTWORK_LEASE_UNSAFE');
  result=await operation();
 }catch(e){problem=e;}
 try{
  const current=await io.lstat(path);
  if(!same(acquired,current))throw fail('LOCAL_ARTWORK_LEASE_REPLACED');
  await io.rmdir(path);
 }catch(e){throw fail('LOCAL_ARTWORK_LEASE_RELEASE_UNCERTAIN',e);}
 if(problem)throw problem;
 return result;
}
