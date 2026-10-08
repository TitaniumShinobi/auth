/** Health is liveness; authentication readiness requires fresh bound host proof. */
export type LoginReadinessProbe = () => Promise<any>;
export async function loginReadiness(probe?:LoginReadinessProbe,timeoutMs=5000){
 let timer:ReturnType<typeof setTimeout>|undefined;
 try{
  if(!probe)throw new Error('READINESS_ADAPTER_REQUIRED');
  const r=await Promise.race([probe(),new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error('READINESS_TIMEOUT')),timeoutMs);})]) as any;
  const required=['deployment_binding','serving_artifact_binding','provider_configuration','database_connectivity','canonical_database_authority','database_pool_validation','database_bounds','session_issuance','callback_completion','disk_safety','bounded_logs','alert_delivery','failed_staging_cleanup','active_and_rollback_retention'];
  const checks=Array.isArray(r?.checks)?r.checks:[];
  const at=Date.parse(r?.observedAt);
  const complete=required.every(id=>checks.filter((c:any)=>c.id===id).length===1)&&checks.some((c:any)=>String(c.id).startsWith('migration:'));
  const ready=r?.contract==='life.auth.release-reliability/1'&&r.phase==='serving'&&r.ready===true&&r.verification==='PASS'&&complete&&Number.isFinite(at)&&at<=Date.now()&&Date.now()-at<=60000&&checks.every((c:any)=>c.result==='PASS');
  return {ready,httpStatus:ready?200:503,scope:'AUTHENTICATION',state:ready?'READY':'DEGRADED',checks:checks.filter((c:any)=>typeof c.id==='string'&&/^[a-zA-Z0-9._:/-]{1,300}$/.test(c.id)).map((c:any)=>({id:c.id,result:['PASS','FAIL','INDETERMINATE'].includes(c.result)?c.result:'INDETERMINATE'}))};
 }catch{return {ready:false,httpStatus:503,scope:'AUTHENTICATION',state:'DEGRADED',error:'AUTH_READINESS_UNPROVEN'};}
 finally{clearTimeout(timer);}
}
