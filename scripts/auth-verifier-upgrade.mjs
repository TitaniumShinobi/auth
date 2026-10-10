/** Offline, explicitly authorized bootstrap. Never changes product history/baselines. */
import {readFile,writeFile,mkdir,mkdtemp,rm,rename,open,realpath,lstat} from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {pathToFileURL} from 'node:url';
import {randomUUID} from 'node:crypto';
import {digest,protocol,fail,safeRead,launcher,activeDigest,generationDigest,upgradeChain} from './auth-verifier-upgrade-chain.mjs';
const json=x=>JSON.stringify(x,null,2)+'\n';
function replaceOnce(s,from,to){if(s.split(from).length!==2)fail('UNSUPPORTED_INSTALLED_VERIFIER');return s.replace(from,to);}
export function patchedContract(source){
 let s=source;
 const bad="||c.verification!=='PASS'||c.checks.find";
 if(s.includes(bad))s=replaceOnce(s,bad,'||c.checks.find');
 else if(!s.includes("c.implementation!=='ESTABLISHED'||c.checks.find"))fail('UNSUPPORTED_INSTALLED_VERIFIER');
 if(!s.includes("import { verifiedArtifactHashes } from './auth-verifier-upgrade-chain.mjs';")){
  s="import { verifiedArtifactHashes } from './auth-verifier-upgrade-chain.mjs';\n"+s;
  s=replaceOnce(s,'hash(await hashes(root,artifactPaths))!==hash(p.files)','hash(await verifiedArtifactHashes(root,artifactPaths,hashes))!==hash(p.files)');
 }
 if(!s.includes('export async function currentBinding(root,c)'))s=replaceOnce(s,'async function currentBinding(root,c)','export async function currentBinding(root,c)');
 return s;
}
async function candidate(root,authorization){
 root=await realpath(root);
 const contract=JSON.parse(await safeRead(root,'.auth-kit/contract.json'));
 if(contract.state!=='ESTABLISHED')fail('ESTABLISHED_CONTRACT_REQUIRED');
 const provenance=JSON.parse(await safeRead(root,'.auth-kit/provenance.json'));
 if(digest(provenance)!==contract.provenanceDigest||provenance.productId!==contract.productId)fail('VERIFIER_OR_GATE_DRIFT');
 const chain=await upgradeChain(root),verify=await safeRead(root,'.auth-kit/verify.mjs');
 for(const [name,hash] of Object.entries(provenance.files)){
  const bytes=name==='.auth-kit/verify.mjs'&&chain?chain.initialVerifier:await safeRead(root,name);
  if(digest(bytes)!==hash)fail('VERIFIER_OR_GATE_DRIFT');
 }
 const files={};
 if(chain){for(const name of Object.keys(chain.active.files))files[name]=await safeRead(root,`.auth-kit/upgrades/generations/${chain.head}/${name}`);}
 else for(const name of Object.keys(provenance.files).filter(x=>x.startsWith('.auth-kit/runtime/'))){
  const leaf=name.slice('.auth-kit/runtime/'.length);if(!/^[a-zA-Z0-9._-]+\.mjs$/.test(leaf))fail('UNSUPPORTED_INSTALLED_VERIFIER');files[leaf]=await safeRead(root,name);
 }
 if(!files['auth-product-contract.mjs'])fail('UNSUPPORTED_INSTALLED_VERIFIER');
 files['auth-product-contract.mjs']=Buffer.from(patchedContract(files['auth-product-contract.mjs'].toString()));
 files['auth-verifier-upgrade-chain.mjs']=await readFile(new URL('./auth-verifier-upgrade-chain.mjs',import.meta.url));
 const manifest=Object.fromEntries(Object.entries(files).map(([n,b])=>[n,digest(b)]).sort(([a],[b])=>a.localeCompare(b)));
 const oldDigest=chain?chain.active.newDigest:activeDigest(provenance.files,digest(verify)),newDigest=generationDigest(manifest);
 if(authorization)for(const [key,expected] of Object.entries({productId:contract.productId,expectedHead:contract.head,expectedContractDigest:digest(contract),expectedUpgradeHead:chain?.head||null,oldDigest,newDigest}))if(authorization[key]!==expected)fail('UPGRADE_AUTHORIZATION_MISMATCH');
 const temp=await mkdtemp(path.join(os.tmpdir(),'auth-upgrade-validation-'));
 try{
  for(const [name,bytes] of Object.entries(files))await writeFile(path.join(temp,name),bytes,{flag:'wx'});
  const mod=await import(pathToFileURL(path.join(temp,'auth-product-contract.mjs')));
  // Run the installed contract's complete history validator with only the reviewed
  // upgrade hook and check-level fix. No product observer or baseline writer runs.
  const state=await mod.inspectProductBundle(root);
  const binding=await mod.currentBinding(root,contract);
  return {root,contract,state,binding,files,manifest,chain,verify,
   oldDigest,newDigest};
 }finally{await rm(temp,{recursive:true,force:true});}
}
export async function prepareUpgrade(root){
 const c=await candidate(root);
 return {authorized:false,operation:'upgrade-verifier',productId:c.contract.productId,revision:c.binding.revision,
  expectedHead:c.contract.head,expectedContractDigest:digest(c.contract),expectedUpgradeHead:c.chain?.head||null,
  oldDigest:c.oldDigest,newDigest:c.newDigest,operator:'',reason:'',runId:randomUUID()};
}
async function directory(root,relative){
 let p=root;
 for(const part of relative.split('/')){p=path.join(p,part);try{await mkdir(p);}catch(e){if(e.code!=='EEXIST')throw e;}const s=await lstat(p);if(s.isSymbolicLink()||!s.isDirectory())fail('UNSAFE_UPGRADE_PATH');}
 return p;
}
async function existingDirectory(root,relative){
 let current=root;
 for(const part of relative.split('/')){current=path.join(current,part);try{const s=await lstat(current);if(s.isSymbolicLink()||!s.isDirectory())fail('UNSAFE_UPGRADE_PATH');}catch(e){if(e.code==='ENOENT')return false;throw e;}}
 return true;
}
export async function applyUpgrade(root,a,{fault}={}){
 // Reject malformed authorization before executing any installed module.
 if(!a||a.authorized!==true||a.operation!=='upgrade-verifier'||!a.operator?.trim()||!a.reason?.trim()||!a.runId?.trim())fail('UPGRADE_AUTHORIZATION_REQUIRED');
 root=await realpath(root);
 const kitStat=await lstat(path.join(root,'.auth-kit'));if(kitStat.isSymbolicLink()||!kitStat.isDirectory())fail('UNSAFE_UPGRADE_PATH');
 const lock=path.join(root,'.auth-kit/advancement.lock');
 const originalVerifierDigest=digest(await safeRead(root,'.auth-kit/verify.mjs'));
 const journal={contract:protocol,pid:process.pid,authorizationDigest:digest(a),originalVerifierDigest};
 const handle=await open(lock,'wx');await handle.writeFile(json(journal));await handle.close();
 let gen,eventPath,tempEntry,receipt,activated=false;
 try{
  const c=await candidate(root,a);
  for(const [key,expected] of Object.entries({productId:c.contract.productId,revision:c.binding.revision,expectedHead:c.contract.head,expectedContractDigest:digest(c.contract),expectedUpgradeHead:c.chain?.head||null,oldDigest:c.oldDigest,newDigest:c.newDigest}))if(a[key]!==expected)fail('UPGRADE_AUTHORIZATION_MISMATCH');
  if(c.chain?.events.some(e=>e.authorization.runId===a.runId))fail('UPGRADE_RUN_ID_REUSED');
  const payload={contract:protocol,sequence:(c.chain?.events.length||0)+1,previous:c.chain?.head||null,
   productId:a.productId,revision:a.revision,historyHead:c.contract.head,historySequence:c.contract.sequence,
   contractDigest:digest(c.contract),oldDigest:c.oldDigest,newDigest:c.newDigest,files:c.manifest,
   authorization:a,...(!c.chain?{initialVerifier:c.verify.toString()}:{}),generatedAt:new Date().toISOString()};
  const event={...payload,digest:digest(payload)};
  await writeFile(lock,json({...journal,event}));
  await directory(root,'.auth-kit/upgrades/generations');await directory(root,'.auth-kit/upgrades/history');
  gen=path.join(root,'.auth-kit/upgrades/generations',event.digest);await mkdir(gen);
  for(const [name,bytes] of Object.entries(c.files)){const f=await open(path.join(gen,name),'wx');try{await f.writeFile(bytes);await f.sync();}finally{await f.close();}}
  eventPath=path.join(root,'.auth-kit/upgrades/history',event.digest+'.json');
  const eh=await open(eventPath,'wx');try{await eh.writeFile(json(event));await eh.sync();}finally{await eh.close();}
  if(typeof fault==='function')await fault('after-stage');
  if(fault==='after-stage')fail('INJECTED_INTERRUPTION');
  // Recheck full source/contract/provenance after staging; .auth-kit is excluded by contract.
  const final=await candidate(root,a);
  if(digest(final.binding)!==digest(c.binding)||digest(final.contract)!==digest(c.contract)||final.oldDigest!==c.oldDigest||final.newDigest!==c.newDigest||!final.verify.equals(c.verify))fail('UPGRADE_SOURCE_DRIFT');
  for(const [name,hash] of Object.entries(c.manifest))if(digest(await safeRead(root,`.auth-kit/upgrades/generations/${event.digest}/${name}`))!==hash)fail('VERIFIER_OR_GATE_DRIFT');
  if(digest(JSON.parse(await safeRead(root,`.auth-kit/upgrades/history/${event.digest}.json`)))!==digest(event))fail('UPGRADE_HISTORY_TAMPERED');
  tempEntry=path.join(root,'.auth-kit',`verify.${randomUUID()}.tmp`);
  const vh=await open(tempEntry,'wx');try{await vh.writeFile(launcher(event.digest));await vh.sync();}finally{await vh.close();}
  if(fault==='before-activate')fail('INJECTED_INTERRUPTION');
  // Single atomic publication point. Before rename the old entrypoint remains active.
  await rename(tempEntry,path.join(root,'.auth-kit/verify.mjs'));activated=true;
  receipt={operation:'upgrade-verifier',verification:'UPGRADED_VERIFY_REQUIRED',upgradeHead:event.digest,historyHead:c.contract.head,historySequence:c.contract.sequence,oldDigest:c.oldDigest,newDigest:c.newDigest,baselineUnchanged:true};
  return receipt;
 }finally{
  if(!activated){if(tempEntry)await rm(tempEntry,{force:true});if(eventPath)await rm(eventPath,{force:true});if(gen)await rm(gen,{recursive:true,force:true});}
  try{await rm(lock,{force:true});}catch(e){if(!activated)throw e;receipt.cleanup='LOCK_RELEASE_REQUIRED';}
 }
}
/** Recovery is explicit and only cleans an abandoned, not-activated upgrade. */
export async function recoverUpgrade(root,a){
 if(!a||a.authorized!==true||a.operation!=='upgrade-verifier')fail('UPGRADE_AUTHORIZATION_REQUIRED');
 root=await realpath(root);
 const lock=JSON.parse(await safeRead(root,'.auth-kit/advancement.lock'));
 if(lock.contract!==protocol||lock.authorizationDigest!==digest(a)||!Number.isInteger(lock.pid)||lock.pid<1)fail('UPGRADE_RECOVERY_MISMATCH');
 try{process.kill(lock.pid,0);fail('UPGRADE_PROCESS_STILL_RUNNING');}catch(e){if(e.code!=='ESRCH')throw e;}
 if(digest(await safeRead(root,'.auth-kit/verify.mjs'))!==lock.originalVerifierDigest)fail('UPGRADE_ALREADY_ACTIVATED_OR_DRIFTED');
 const c=await candidate(root);
 for(const [key,expected] of Object.entries({productId:c.contract.productId,revision:c.binding.revision,expectedHead:c.contract.head,expectedContractDigest:digest(c.contract),expectedUpgradeHead:c.chain?.head||null,oldDigest:c.oldDigest,newDigest:c.newDigest}))if(a[key]!==expected)fail('UPGRADE_RECOVERY_MISMATCH');
 if(lock.event){
  const {digest:head,...payload}=lock.event;
  if(digest(payload)!==head||digest(lock.event.authorization)!==digest(a)||head===c.chain?.head)fail('UPGRADE_RECOVERY_MISMATCH');
  const directory=path.join(root,'.auth-kit/upgrades/generations',head);
  if(await existingDirectory(root,'.auth-kit/upgrades/generations'))try{const s=await lstat(directory);if(s.isSymbolicLink()||!s.isDirectory())fail('UNSAFE_UPGRADE_PATH');await rm(directory,{recursive:true});}catch(e){if(e.code!=='ENOENT')throw e;}
  if(await existingDirectory(root,'.auth-kit/upgrades/history'))await rm(path.join(root,'.auth-kit/upgrades/history',head+'.json'),{force:true});
 }
 await rm(path.join(root,'.auth-kit/advancement.lock'));
 return {verification:'OLD_VERIFIER_RETAINED',historyHead:c.contract.head};
}
export async function upgradeCli(args){
 const [op,root,file]=args;
 if(args.length!==3||!['prepare','apply','recover'].includes(op))fail('USAGE_PREPARE_APPLY_RECOVER_ROOT_AUTHORIZATION_JSON');
 if(op==='prepare'){const plan=await prepareUpgrade(root);await writeFile(file,json(plan),{flag:'wx'});console.log(json({authorizationFile:path.resolve(file),...plan}));}
 else console.log(json(await (op==='recover'?recoverUpgrade:applyUpgrade)(root,JSON.parse(await readFile(file,'utf8')))));
}
if(process.argv[1]&&pathToFileURL(path.resolve(process.argv[1])).href===import.meta.url)upgradeCli(process.argv.slice(2)).catch(e=>{console.error(e.code||'UPGRADE_FAILED');process.exitCode=2;});
