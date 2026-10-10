/** AUTH-owned release/readiness gate. Host adapters own DB/deployment operations. */
import {createHash,randomUUID} from 'node:crypto';
import {readFile,statfs} from 'node:fs/promises';
import {pathToFileURL} from 'node:url';
import path from 'node:path';
const sha=b=>createHash('sha256').update(b).digest('hex');
const canonical=x=>Array.isArray(x)?x.map(canonical):x&&typeof x==='object'?Object.fromEntries(Object.keys(x).sort().map(k=>[k,canonical(x[k])])):x;
export const digest=x=>sha(JSON.stringify(canonical(x)));
const fail=code=>{throw Object.assign(new Error(code),{code});};
const id=x=>typeof x==='string'&&/^[a-zA-Z0-9][a-zA-Z0-9._:/-]{0,255}$/.test(x);
const hash=x=>typeof x==='string'&&/^[a-f0-9]{64}$/.test(x);
const hostFailures=new Set(['HOST_COMMAND_FAILED','HOST_CONFIGURATION_DRIFT','SCHEMA_MANIFEST_MISMATCH','SCHEMA_CONTRACT_REQUIRED','REQUIRED_SOURCE_ARTIFACT_ABSENT','MIGRATION_SOURCE_CHECKSUM_MISMATCH','MIGRATION_NAMESPACE_COLLISION','MIGRATION_SEMANTIC_IDENTITY_MISMATCH','CANDIDATE_REVISION_REQUIRED','CANDIDATE_REVISION_MISMATCH','DATABASE_WORKER_DRIFT','SERVING_PROCESS_MISMATCH','SERVING_REVISION_MISMATCH','SERVING_START_UNKNOWN','SERVING_ARTIFACT_DRIFT','SERVING_CONFIGURATION_NEWER_THAN_PROCESS','SERVING_COMMAND_AMBIGUOUS','CONFIGURATION_REFERENCE_UNSAFE','DATASOURCE_REFERENCE_NOT_BOUND']);
export const GIB=1024**3;
export function validateManifest(m){
 if(m?.contract!=='life.auth.release-reliability/1'||!id(m.service)||!id(m.databaseAuthority)||!id(m.revision)||!hash(m.runtimeDigest)||!hash(m.configurationDigest)||!Array.isArray(m.requiredMigrations)||!m.requiredMigrations.length)fail('RELEASE_MANIFEST_REQUIRED');
 const keys=new Set();for(const x of m.requiredMigrations){const key=x.ledger+'/'+x.id;if(keys.has(key))fail('MIGRATION_NAMESPACE_COLLISION');if(!id(x.id)||!id(x.ledger)||!id(x.semanticId)||!id(x.artifactName)||x.artifactName.includes('/')||!hash(x.sha256))fail('INVALID_MIGRATION_CONTRACT');keys.add(key);}
 if(!Number.isSafeInteger(m.diskFloorBytes)||m.diskFloorBytes<5*GIB||!Number.isFinite(m.diskFloorFraction)||m.diskFloorFraction<0.15||m.diskFloorFraction>0.5)fail('DISK_SAFETY_FLOOR_REQUIRED');
 for(const key of ['connectTimeoutMs','statementTimeoutMs','acquireTimeoutMs','maxConnections'])if(!Number.isInteger(m.databaseBounds?.[key])||m.databaseBounds[key]<1||m.databaseBounds[key]>(key==='maxConnections'?100:10000))fail('DATABASE_BOUNDS_REQUIRED');
 return m;
}
export function retentionPlan(releases,{active,rollback}){
 if(!id(active)||!id(rollback)||active===rollback||!Array.isArray(releases))fail('RETENTION_IDENTITY_REQUIRED');
 const ids=releases.map(r=>r.id);if(new Set(ids).size!==ids.length||!ids.includes(active)||!ids.includes(rollback))fail('RETENTION_IDENTITY_REQUIRED');
 // IDs only. No filesystem deletion or database/storage path is accepted here.
 return {keep:[active,rollback],eligible:releases.filter(r=>r.id!==active&&r.id!==rollback&&id(r.id)&&r.kind==='immutable-release-artifact'&&r.verifiedDisposable===true&&r.containsCanonicalData===false&&r.recoveryMaterial===false).map(r=>r.id).sort()};
}
export function assessRelease(m,o,{now=Date.now(),maxAgeMs=60000,phase='candidate'}={}){
 validateManifest(m);const checks=[];const add=(id,result)=>checks.push({id,result:result===true?'PASS':result===false?'FAIL':'INDETERMINATE'});
 const at=Date.parse(o?.observedAt),fresh=Number.isFinite(at)&&at<=now&&now-at<=maxAgeMs;
 const bound=fresh&&o?.service===m.service&&o?.revision===m.revision&&o?.runtimeDigest===m.runtimeDigest&&o?.configurationDigest===m.configurationDigest;
 add('deployment_binding',bound);
 if(phase==='serving')add('serving_artifact_binding',bound&&o.servingRevision===m.revision&&o.servingRuntimeDigest===m.runtimeDigest);
 const value=x=>bound?x:undefined;
 add('provider_configuration',value(o?.providerConfiguration));
 add('database_connectivity',value(o?.database?.reachable));
 add('canonical_database_authority',bound&&o?.database?.authority===m.databaseAuthority);
 add('database_pool_validation',value(o?.database?.poolValidated));
 add('database_bounds',bound&&Object.entries(m.databaseBounds).every(([key,limit])=>Number.isInteger(o?.database?.bounds?.[key])&&o.database.bounds[key]>0&&o.database.bounds[key]<=limit));
 for(const required of m.requiredMigrations){
  const rows=(Array.isArray(o?.migrations)?o.migrations:[]).filter(r=>r.id===required.id&&r.ledger===required.ledger);
  add('migration:'+required.ledger+'/'+required.id,bound?(rows.length===1&&rows[0].applied===true&&rows[0].sha256===required.sha256&&rows[0].semanticId===required.semanticId&&rows[0].artifactName===required.artifactName&&rows[0].sourceVerified===true):undefined);
 }
 for(const name of ['session_issuance','callback_completion']){
  const proof=o?.probes?.[name],t=Date.parse(proof?.observedAt);
  const valid=bound&&proof?.manifestDigest===digest(m)&&proof?.controlledFixture===true&&proof?.cleanupVerified===true&&Number.isFinite(t)&&t<=now&&now-t<=maxAgeMs&&Array.isArray(proof?.references)&&proof.references.length>0&&proof.references.every(id);
  add(name,valid?(proof.result==='PASS'?true:proof.result==='FAIL'?false:undefined):undefined);
 }
 const bytes=o?.disk?.availableBytes,total=o?.disk?.totalBytes;
 const floor=Number.isFinite(total)&&total>0?Math.max(m.diskFloorBytes,total*m.diskFloorFraction):Infinity;
 add('disk_safety',bound&&Number.isSafeInteger(bytes)&&bytes>=0&&bytes<=total?bytes>=floor:undefined);
 add('bounded_logs',value(o?.operations?.boundedLogs));
 add('alert_delivery',value(o?.operations?.alertDeliveryVerified));
 add('failed_staging_cleanup',value(o?.operations?.failedStagingCleanupVerified));
 let retention;try{retention=retentionPlan(o?.operations?.releases,o?.operations||{});}catch{}
 add('active_and_rollback_retention',bound?Boolean(retention):undefined);
 const verification=checks.some(c=>c.result==='FAIL')?'FAIL':checks.every(c=>c.result==='PASS')?'PASS':'INDETERMINATE';
 return {contract:m.contract,phase,service:m.service,revision:m.revision,manifestDigest:digest(m),verification,ready:verification==='PASS',httpStatus:verification==='PASS'?200:503,checks,
  disk:{requiredFreeBytes:Number.isFinite(floor)?Math.ceil(floor):null,availableBytes:Number.isSafeInteger(bytes)?bytes:null},
  alerts:[...checks.filter(c=>c.result!=='PASS').map(c=>({code:c.id==='disk_safety'?'DISK_CAPACITY_ACTION_REQUIRED':'AUTH_READINESS_ACTION_REQUIRED',check:c.id,severity:'critical'})),...(bound&&Number.isSafeInteger(bytes)&&bytes>=floor&&bytes<Math.max(8*GIB,total*0.20)?[{code:'DISK_CAPACITY_WARNING',check:'disk_safety',severity:'warning'}]:[])],
  retention:retention||null,observedAt:fresh?o.observedAt:null};
}
export async function boundedRead(operation,{timeoutMs=3000,retries=1,invalidatePool=async()=>{}}={}){
 if(!Number.isInteger(timeoutMs)||timeoutMs<1||timeoutMs>10000||![0,1].includes(retries))fail('INVALID_READ_TIMEOUT');
 const deadline=Date.now()+timeoutMs;
 for(let attempt=0;;attempt++){
  const remaining=deadline-Date.now();if(remaining<=0)fail('DATABASE_READ_TIMEOUT');
  const controller=new AbortController();let timer;
  try{return await Promise.race([Promise.resolve().then(()=>operation({signal:controller.signal})),new Promise((_,reject)=>{timer=setTimeout(()=>{controller.abort();reject(Object.assign(new Error('DATABASE_READ_TIMEOUT'),{code:'DATABASE_READ_TIMEOUT'}));},remaining);})]);}
  catch(e){
   // Never retry timeout/unknown outcomes or mutations. Only documented read-only
   // connection failures may retry; the adapter must cancel/reset its driver pool.
   if(hostFailures.has(e?.code))fail(e.code);
   if(attempt>=retries||!['ECONNRESET','ECONNREFUSED'].includes(e?.code))fail(e?.code==='DATABASE_READ_TIMEOUT'?'DATABASE_READ_TIMEOUT':'DATABASE_UNAVAILABLE');
   await boundedRead(()=>invalidatePool(),{timeoutMs:Math.max(1,deadline-Date.now()),retries:0});
  }finally{clearTimeout(timer);}
 }
}
export async function observeRelease(m,adapter,options={}){
 validateManifest(m);
 try{return assessRelease(m,await boundedRead(signal=>adapter.observeReadOnly(m,{...signal,phase:options.phase||'candidate'}),{...options,invalidatePool:()=>adapter.invalidatePool?.()}),options);}
 catch(e){return {reasonCode:/^[A-Z_]+$/.test(e?.code||e?.message||'')?(e.code||e.message):'HOST_OBSERVATION_UNAVAILABLE',contract:m.contract,service:m.service,revision:m.revision,manifestDigest:digest(m),ready:false,verification:'INDETERMINATE',httpStatus:503,checks:[{id:'host_observation',result:'INDETERMINATE'}],alerts:[{code:'AUTH_DEPENDENCY_UNAVAILABLE',severity:'critical'}]};}
}
export async function guardedRelease(m,adapter,authorization){
 validateManifest(m);
 if(authorization?.authorized!==true||authorization.manifestDigest!==digest(m)||!id(authorization.operator)||!id(authorization.runId))fail('DEPLOYMENT_AUTHORIZATION_REQUIRED');
 for(const name of ['observeReadOnly','invalidatePool','stage','publish','restart','rollback','cleanupStaging','retainReleases'])if(typeof adapter[name]!=='function')fail('DEPLOYMENT_ADAPTER_INCOMPLETE');
 const first=await observeRelease(m,adapter);if(!first.ready)return {...first,published:false};
 let stage,result,published=false;
 try{
  // Stage receives no authority to migrate or mutate accounts. Host adapter must
  // ensure a unique run-owned directory and clean partial stages on thrown errors.
  stage=await adapter.stage({manifest:m,runId:authorization.runId});
  const beforePublish=await observeRelease(m,adapter);if(!beforePublish.ready)fail('PRE_PUBLISH_GATE_FAILED');
  // Set before calling: a partially completed publication must roll back too.
  published=true;await adapter.publish(stage);await adapter.restart(stage);
  const after=await observeRelease(m,adapter,{phase:'serving'});if(!after.ready)fail('POST_DEPLOY_GATE_FAILED');
  await adapter.retainReleases(after.retention);
  result={...after,published:true};
 }catch{
  let rollback='NOT_REQUIRED';
  if(published){try{await adapter.rollback({runId:authorization.runId});rollback='RESTORED_PREVIOUS_ARTIFACT';}catch{rollback='OPERATOR_REQUIRED';}}
  result={ready:false,verification:'FAIL',published,rollback,error:'RELEASE_FAILED',correlationId:randomUUID()};
 }finally{try{await adapter.cleanupStaging({stage,runId:authorization.runId});}catch{result={...result,ready:false,verification:'FAIL',error:'STAGING_CLEANUP_FAILED',correlationId:randomUUID()};}}
 return result;
}
export async function releaseCli(args){
 const [mode,manifestPath,adapterPath,expected]=args;
 if(args.length!==4||!['check','monitor'].includes(mode)||!hash(expected))fail('USAGE_CHECK_MANIFEST_ADAPTER_SHA256');
 const file=path.resolve(adapterPath),bytes=await readFile(file);if(sha(bytes)!==expected)fail('ADAPTER_DIGEST_MISMATCH');
 const m=JSON.parse(await readFile(manifestPath,'utf8'));
 const mod=await import(pathToFileURL(file));const report=await observeRelease(m,mod.default,{phase:mode==='monitor'?'serving':'candidate'});
 console.log(JSON.stringify(report,null,2));if(!report.ready)process.exitCode=2;else if(mode==='monitor'&&report.alerts.length)process.exitCode=3;
}
if(process.argv[1]&&pathToFileURL(path.resolve(process.argv[1])).href===import.meta.url)releaseCli(process.argv.slice(2)).catch(e=>{console.error(e.code||'AUTH_RELEASE_GATE_FAILED');process.exitCode=2;});
/** Protected deployment configuration references only; never reads secret values. */
export async function createReadinessObserver({manifestPath,adapterPath,adapterSha256}){
 if(!path.isAbsolute(manifestPath||'')||!path.isAbsolute(adapterPath||'')||!hash(adapterSha256))fail('READINESS_CONFIGURATION_REQUIRED');
 const manifestBytes=await readFile(manifestPath),m=JSON.parse(manifestBytes);validateManifest(m);
 if(sha(await readFile(adapterPath))!==adapterSha256)fail('ADAPTER_DIGEST_MISMATCH');
 const mod=await import(pathToFileURL(adapterPath));
 let pending;
 if(typeof mod.default?.observeReadOnly!=='function'||typeof mod.default?.invalidatePool!=='function')fail('READINESS_ADAPTER_REQUIRED');
 return async()=>{
  if(sha(await readFile(adapterPath))!==adapterSha256||sha(await readFile(manifestPath))!==sha(manifestBytes))fail('READINESS_CONFIGURATION_DRIFT');
  if(!pending)pending=observeRelease(m,mod.default,{phase:'serving'}).finally(()=>{pending=undefined;});
  return pending;
 };
}

export async function diskObservation(mount){
 const s=await statfs(mount,{bigint:true});const available=s.bavail*s.bsize,total=s.blocks*s.bsize;
 if(available>BigInt(Number.MAX_SAFE_INTEGER)||total>BigInt(Number.MAX_SAFE_INTEGER))fail('DISK_MEASUREMENT_UNSUPPORTED');
 return {availableBytes:Number(available),totalBytes:Number(total)};
}
