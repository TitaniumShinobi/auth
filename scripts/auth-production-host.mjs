/** Concrete Linux deployment observer. All subprocesses are read-only, shell-free. */
import {createHash} from 'node:crypto';
import {readFile,lstat,realpath,open} from 'node:fs/promises';
import {execFile,spawn} from 'node:child_process';
import {promisify} from 'node:util';
import path from 'node:path';
import {constants} from 'node:fs';
import {fileURLToPath} from 'node:url';
import {digest,diskObservation,validateManifest} from './auth-release-reliability.mjs';
const exec=promisify(execFile),sha=b=>createHash('sha256').update(b).digest('hex');
const fail=code=>{throw Object.assign(new Error(code),{code});};
const worker=fileURLToPath(new URL('./auth-host-database.py',import.meta.url));
const safePath=p=>typeof p==='string'&&!p.startsWith('/')&&!p.split('/').some(x=>!x||x==='..'||x==='.')&&!p.includes('\\');
export async function command(bin,args,{signal}={}){try{return (await exec(bin,args,{signal,timeout:5000,maxBuffer:1024*1024,encoding:'utf8',env:{PATH:'/usr/bin:/bin'},killSignal:'SIGKILL'})).stdout.trim();}catch{fail('HOST_COMMAND_FAILED');}}
export async function protectedJson(file){
 if(!path.isAbsolute(file||''))fail('PROTECTED_HOST_INPUT_REQUIRED');
 const fd=await open(file,constants.O_RDONLY|constants.O_NOFOLLOW);
 try{const s=await fd.stat();if(!s.isFile()||s.uid!==0||(s.mode&0o022)||s.size>1024*1024)fail('PROTECTED_HOST_INPUT_REQUIRED');return JSON.parse(await fd.readFile('utf8'));}finally{await fd.close();}
}
export function validateSchema(c){
 if(c?.contract!=='life.auth.production-schema-contract/1'||!Array.isArray(c.authCriticalPaths)||!c.authCriticalPaths.length)fail('SCHEMA_CONTRACT_REQUIRED');
 const keys=new Set();
 for(const m of c.requiredMigrations||[]){
  const key=m.ledger+'/'+m.id;
  if(keys.has(key))fail('MIGRATION_NAMESPACE_COLLISION');keys.add(key);
  if(!safePath(m.sourcePath)||path.posix.basename(m.sourcePath)!==m.artifactName||m.artifactName!==`${m.id}_${m.semanticId}.up.sql`)fail('MIGRATION_SEMANTIC_IDENTITY_MISMATCH');
 }
 if(!keys.size||!c.authCriticalPaths.every(safePath))fail('SCHEMA_CONTRACT_REQUIRED');return c;
}
export async function sourceBinding(c,{root,revision,git='/usr/bin/git',signal},run=sourceCommand){
 validateSchema(c);if(!path.isAbsolute(root)||!/^[a-f0-9]{40}$/.test(revision))fail('CANDIDATE_REVISION_REQUIRED');
 const g=args=>run(git,['-c',`safe.directory=${root}`,'-C',root,...args],{signal});
 if(await g(['rev-parse',`${revision}^{commit}`])!==revision)fail('CANDIDATE_REVISION_MISMATCH');
 const artifacts={};
 for(const p of [...new Set([...c.authCriticalPaths,...c.requiredMigrations.map(m=>m.sourcePath)])].sort()){
  const entry=await g(['ls-tree',revision,'--',p]);
  if(!entry.startsWith('100644 blob ')&&!entry.startsWith('100755 blob '))fail('REQUIRED_SOURCE_ARTIFACT_ABSENT');
  // exec wrapper's text trim must not change file bytes.
  const hex=await g(['show',`${revision}:${p}`]);artifacts[p]=sha(Buffer.from(hex,'hex'));
 }
 for(const m of c.requiredMigrations){
  if(artifacts[m.sourcePath]!==m.sha256)fail('MIGRATION_SOURCE_CHECKSUM_MISMATCH');
  const names=(await g(['ls-tree','--name-only',revision+':'+path.posix.dirname(m.sourcePath)])).split('\n');
  if(names.some(n=>n.startsWith(m.id+'_')&&n.endsWith('.up.sql')&&n!==m.artifactName))fail('MIGRATION_NAMESPACE_COLLISION');
 }
 return {revision,runtimeDigest:digest(artifacts),artifacts};
}
// Git blob bytes are converted to hex before the text protocol, preserving newlines.
export async function sourceCommand(bin,args,opts){
 if(args.at(-2)==='show'){
  try{return (await exec(bin,args,{signal:opts?.signal,timeout:5000,maxBuffer:8*1024*1024,killSignal:'SIGKILL',encoding:'buffer',env:{PATH:'/usr/bin:/bin'}})).stdout.toString('hex');}catch{fail('REQUIRED_SOURCE_ARTIFACT_ABSENT');}
 }
 return command(bin,args,opts);
}
export async function databaseObservation(c,h,{signal}={}){
 if(sha(await readFile(worker))!==h.databaseWorkerSha256)fail('DATABASE_WORKER_DRIFT');
 const request={...c,datasourceReference:h.datasourceReference};
 return new Promise((resolve,reject)=>{
  const child=spawn(h.python,[worker],{env:{PATH:'/usr/bin:/bin',PYTHONDONTWRITEBYTECODE:'1'},stdio:['pipe','pipe','ignore']});let out='',done=false;
  const stop=()=>{child.kill('SIGKILL');};const timer=setTimeout(stop,Math.min(10000,c.databaseBounds.acquireTimeoutMs));
  signal?.addEventListener('abort',stop,{once:true});if(signal?.aborted)stop();
  const finish=(err,value)=>{if(done)return;done=true;clearTimeout(timer);signal?.removeEventListener('abort',stop);err?reject(err):resolve(value);};
  child.stdout.on('data',b=>{if(out.length<=65536)out+=b.toString().slice(0,65537-out.length);if(out.length>65536)stop();});child.stdin.on('error',()=>{});
  child.on('error',()=>finish(new Error('DATABASE_OBSERVATION_UNAVAILABLE')));
  child.on('close',code=>{try{if(code!==0||out.length>65536)throw Error();finish(null,JSON.parse(out));}catch{finish(new Error('DATABASE_OBSERVATION_UNAVAILABLE'));}});
  child.stdin.end(JSON.stringify(request));
 });
}
export function combineObservation(m,source,db,receipt,disk,serving={}){
 const fresh=receipt?.manifestDigest===digest(m)&&Number.isFinite(Date.parse(receipt.observedAt))&&Date.parse(receipt.observedAt)<=Date.now()&&Date.now()-Date.parse(receipt.observedAt)<=60000;
 // DB observer limits are not falsely represented as application driver/pool limits.
 const runtime=fresh?receipt.runtimeDatabase:undefined;
 return {observedAt:new Date().toISOString(),service:m.service,...source,configurationDigest:m.configurationDigest,...serving,
  providerConfiguration:fresh?receipt.providerConfiguration:undefined,
  database:{reachable:db.reachable===true,authority:db.authority,poolValidated:runtime?.poolValidated,bounds:runtime?.bounds},
  migrations:(db.migrations||[]).map(row=>{const expected=m.requiredMigrations.find(x=>x.ledger===row.ledger&&x.id===row.id);return {...row,semanticId:expected?.semanticId,artifactName:expected?.artifactName,sourceVerified:!!expected&&source.artifacts?.[expected.sourcePath]===expected.sha256};}),
  probes:fresh?receipt.probes:undefined,disk,operations:fresh?receipt.operations:undefined};
}
export async function configurationBinding(h){
 const refs=[];
 for(const p of h.configurationReferences||[]){const s=await lstat(p);if(!path.isAbsolute(p)||!s.isFile()||s.uid!==0||(s.mode&0o022))fail('CONFIGURATION_REFERENCE_UNSAFE');refs.push({path:p,size:s.size,mtimeMs:s.mtimeMs,ctimeMs:s.ctimeMs,ino:s.ino,mode:s.mode});}
 if(!refs.some(x=>x.path===h.datasourceReference))fail('DATASOURCE_REFERENCE_NOT_BOUND');
 return digest({host:h,references:refs});
}
export function serviceInvocation(value){
 const commands=[...(value||'').matchAll(/\bpath=([^;]+);/g)],arguments_=[...(value||'').matchAll(/\bargv\[\]=([^;]+);/g)];
 if(commands.length!==1||arguments_.length!==1)fail('SERVING_COMMAND_AMBIGUOUS');
 return {executable:commands[0][1].trim(),argv:arguments_[0][1].trim()};
}
export function createHostAdapter(h,c,deps={}){
 if(!deps.source&&(!path.isAbsolute(h.python||'')||!path.isAbsolute(h.repository||'')||!path.isAbsolute(h.diskMount||'')||!path.isAbsolute(h.receiptPath||'')))fail('HOST_PATHS_REQUIRED');
 const source=deps.source||((c,x)=>sourceBinding(c,x,sourceCommand));
 return {invalidatePool:async()=>{},async observeReadOnly(m,{signal,phase='candidate'}={}){
  validateManifest(m);validateSchema(c);
  for(const k of ['service','databaseAuthority','requiredMigrations','databaseBounds','diskFloorBytes','diskFloorFraction'])if(digest(m[k])!==digest(c[k]))fail('SCHEMA_MANIFEST_MISMATCH');
  if(await (deps.configuration||configurationBinding)(h)!==m.configurationDigest)fail('HOST_CONFIGURATION_DRIFT');
  const s=await source(c,{root:h.repository,revision:m.revision,signal});
  const db=await (deps.database||databaseObservation)(c,h,{signal});
  const receipt=await (deps.receipt||protectedJson)(h.receiptPath).catch(()=>null);
  const disk=await (deps.disk||diskObservation)(h.diskMount);
  let serving={};
  if(phase==='serving'){
   const run=deps.command||command;const root=await realpath(h.repository);
   const unit=await run('/usr/bin/systemctl',['show',h.systemdService,'-p','ActiveState','-p','MainPID','-p','ExecMainStartTimestamp','-p','WorkingDirectory','-p','User','-p','ExecStart'],{signal});
   const props=Object.fromEntries(unit.split('\n').map(l=>{const i=l.indexOf('=');return [l.slice(0,i),l.slice(i+1)];}));
   if(props.User!==h.serviceUser||digest(serviceInvocation(props.ExecStart))!==h.execStartSha256||props.ActiveState!=='active'||!/^[1-9][0-9]*$/.test(props.MainPID)||await realpath(`/proc/${props.MainPID}/cwd`)!==root)fail('SERVING_PROCESS_MISMATCH');
   if(await run('/usr/bin/git',['-c',`safe.directory=${root}`,'-C',root,'rev-parse','HEAD'],{signal})!==m.revision)fail('SERVING_REVISION_MISMATCH');
   const started=Date.parse(props.ExecMainStartTimestamp);if(!Number.isFinite(started))fail('SERVING_START_UNKNOWN');
   for(const [p,hash] of Object.entries(s.artifacts)){const file=path.join(root,p),st=await lstat(file);if(await realpath(file)!==file||!st.isFile()||st.mtimeMs>started||sha(await readFile(file))!==hash)fail('SERVING_ARTIFACT_DRIFT');}
   for(const p of h.configurationReferences)if((await lstat(p)).mtimeMs>started)fail('SERVING_CONFIGURATION_NEWER_THAN_PROCESS');
   serving={servingRevision:m.revision,servingRuntimeDigest:s.runtimeDigest};
  }
  if(await (deps.configuration||configurationBinding)(h)!==m.configurationDigest)fail('HOST_CONFIGURATION_DRIFT');
  return combineObservation(m,s,db,receipt,disk,serving);
 }};
}
let pending;
export default {invalidatePool:async()=>{},async observeReadOnly(m,options){
 if(sha(await readFile(process.env.AUTH_RELIABILITY_HOST_CONFIG))!==process.env.AUTH_RELIABILITY_HOST_CONFIG_SHA256)fail('HOST_CONFIGURATION_PIN_REQUIRED');
 if(!pending)pending=(async()=>{const h=await protectedJson(process.env.AUTH_RELIABILITY_HOST_CONFIG);if(sha(await readFile(process.env.AUTH_RELIABILITY_HOST_CONFIG))!==process.env.AUTH_RELIABILITY_HOST_CONFIG_SHA256)fail('HOST_CONFIGURATION_PIN_REQUIRED');const c=JSON.parse(await readFile(h.schemaContract,'utf8'));if(sha(await readFile(h.schemaContract))!==h.schemaContractSha256)fail('SCHEMA_CONTRACT_DRIFT');return createHostAdapter(h,c);})();
 return (await pending).observeReadOnly(m,options);
}};
