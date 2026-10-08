/** Operator CLI: build a reviewed candidate manifest, or check without mutation. */
import {readFile,writeFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {pathToFileURL} from 'node:url';
import path from 'node:path';
import {validateManifest,observeRelease} from './auth-release-reliability.mjs';
import {protectedJson,configurationBinding,sourceBinding,sourceCommand,createHostAdapter} from './auth-production-host.mjs';
export async function main([mode,hostPath,hostHash,revision,manifestPath]){
 if(!['prepare','candidate','serving'].includes(mode)||!/^[a-f0-9]{40}$/.test(revision)||!/^[a-f0-9]{64}$/.test(hostHash))throw Error('USAGE_MODE_HOST_HOSTSHA_REVISION_MANIFEST');
 const bytes=await readFile(hostPath);if(createHash('sha256').update(bytes).digest('hex')!==hostHash)throw Error('HOST_CONFIG_HASH_MISMATCH');
 const h=await protectedJson(hostPath),cb=await readFile(h.schemaContract);
 if(createHash('sha256').update(cb).digest('hex')!==h.schemaContractSha256)throw Error('SCHEMA_CONTRACT_DRIFT');
 const c=JSON.parse(cb),configurationDigest=await configurationBinding(h);
 if(mode==='prepare'){
  const s=await sourceBinding(c,{root:h.repository,revision},sourceCommand);
  const m=validateManifest({...c,contract:'life.auth.release-reliability/1',revision,runtimeDigest:s.runtimeDigest,configurationDigest});
  await writeFile(manifestPath,JSON.stringify(m,null,2)+'\n',{flag:'wx',mode:0o600});
  console.log(JSON.stringify({state:'CANDIDATE_MANIFEST_REQUIRES_REVIEW',revision}));return;
 }
 const m=await protectedJson(manifestPath);if(m.revision!==revision)throw Error('DEPLOYMENT_REVISION_MISMATCH');
 const report=await observeRelease(m,createHostAdapter(h,c),{phase:mode,timeoutMs:10000,retries:0});
 console.log(JSON.stringify(report));if(!report.ready)process.exitCode=2;
}
if(process.argv[1]&&pathToFileURL(path.resolve(process.argv[1])).href===import.meta.url)main(process.argv.slice(2)).catch(e=>{console.error(/^[A-Z_]+$/.test(e.message)?e.message:'PRODUCTION_GATE_UNAVAILABLE');process.exitCode=2;});
