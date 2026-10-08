/** Export only public consumer binding, using the installed product's reviewed collector. */
import {readFile,writeFile,realpath,lstat} from 'node:fs/promises';
import {createReadStream} from 'node:fs';
import path from 'node:path';import {pathToFileURL} from 'node:url';import {createHash} from 'node:crypto';
const sha=bytes=>createHash('sha256').update(bytes).digest('hex');
export function sanitizeBinding(binding,authority){
 if(!binding||typeof binding.productId!=='string'||!binding.productId||typeof binding.revision!=='string'||!binding.revision||!authority)throw Error('CURRENT_CONSUMER_BINDING_REQUIRED');
 const origin=new URL(authority.id);if(origin.protocol!=='https:'||origin.origin!==authority.id||origin.username||origin.password)throw Error('PUBLIC_AUTHORITY_ORIGIN_REQUIRED');
 if(!/^[a-f0-9]{40,64}$/.test(authority.revision||''))throw Error('DECLARED_AUTHORITY_REVISION_REQUIRED');
 const identityAuthority={id:authority.id,revision:authority.revision};
 for(const k of ['configurationDigest','runtimeDigest'])if(authority[k]!==undefined){if(!/^[a-f0-9]{64}$/.test(authority[k]))throw Error('INVALID_AUTHORITY_DIGEST');identityAuthority[k]=authority[k];}
 return {productId:binding.productId,revision:binding.revision,identityAuthority};
}
export async function exportAuthorityBinding({repo,out,report,reportSha256,refreshSource=false,env=process.env,now}){
 const root=await realpath(repo),output=path.resolve(out),rel=path.relative(root,output);
 if(!rel.startsWith('..'+path.sep)&&rel!=='..'&&!path.isAbsolute(rel))throw Error('OUTPUT_MUST_BE_OUTSIDE_PRODUCT');
 const runtime=await import(pathToFileURL(path.join(root,'.auth-kit/runtime/auth-product-contract.mjs')).href);
 const state=await runtime.inspectProductBundle(root,{checkpoint:env.AUTH_CONTRACT_CHECKPOINT});
 let observed;
 if(refreshSource){observed=await runtime.verifyProduct(root);}
 else {
  if(!report||!/^[a-f0-9]{64}$/.test(reportSha256||''))throw Error('REVIEWED_REPORT_AND_SHA256_REQUIRED');
  const bytes=await readFile(report);if(sha(bytes)!==reportSha256)throw Error('REVIEWED_REPORT_DIGEST_MISMATCH');observed=JSON.parse(bytes);
 }
 const b=observed.binding,c=state.contract;
 if(!b||b.productId!==c.productId||observed.productId!==c.productId||observed.revision!==b.revision||!/^[a-f0-9]{64}$/.test(b.revision||''))throw Error('PRODUCT_BINDING_MISMATCH');
 const age=(now??Date.now())-Date.parse(b.observedAt);if(!Number.isFinite(age)||age<0||age>86400000)throw Error('REVIEWED_REPORT_STALE_REFRESH_SOURCE_REQUIRED');
 if(observed.contractDigest!==runtime.hash(c)||observed.contractHead!==c.head)throw Error('REPORT_CONTRACT_MISMATCH');
 const observerDigest=sha(await readFile(path.join(root,'.auth-kit/observe.mjs')));
 if(observed.observerDigest!==observerDigest)throw Error('OBSERVER_DRIFT');
 const {runGit}=await import(pathToFileURL(path.join(root,'.auth-kit/runtime/auth-git.mjs')).href);
 if(await realpath(runGit(['rev-parse','--show-toplevel'],{cwd:root}).trim())!==root||runGit(['rev-parse','HEAD'],{cwd:root}).trim()!==b.commit)throw Error('PRODUCT_HEAD_CHANGED_REFRESH_SOURCE_REQUIRED');
 async function inputDigest(paths){const hashes={};for(const name of paths){
  if(typeof name!=='string'||path.isAbsolute(name)||name.includes('\\')||name.split('/').some(x=>!x||x==='.'||x==='..'))throw Error('UNSAFE_INPUT_PATH');
  let p=root;for(const segment of name.split('/')){p=path.join(p,segment);if((await lstat(p)).isSymbolicLink())throw Error('SYMLINK_INPUT_UNSUPPORTED');}
  if(!(await lstat(p)).isFile())throw Error('INPUT_FILE_REQUIRED');const h=createHash('sha256');for await(const chunk of createReadStream(p))h.update(chunk);hashes[name]=h.digest('hex');
 }return runtime.hash(hashes);}
 if(!c.inputs.artifact.length||!c.inputs.configuration.length)throw Error('INPUTS_REQUIRED');
 if(await inputDigest(c.inputs.artifact)!==b.artifactDigest||await inputDigest(c.inputs.configuration)!==b.configurationDigest)throw Error('ARTIFACT_OR_CONFIGURATION_CHANGED_REFRESH_REQUIRED');
 const prefix=c.productId.toUpperCase().replace(/[^A-Z0-9]/g,'_');
 const authority={id:env[prefix+'_AUTH_AUTHORITY_ID'],revision:env[prefix+'_AUTH_AUTHORITY_REVISION']};
 const handoff=sanitizeBinding(b,authority);
 const after=await runtime.inspectProductBundle(root,{checkpoint:env.AUTH_CONTRACT_CHECKPOINT});
 if(runtime.hash(after.contract)!==runtime.hash(c)||sha(await readFile(path.join(root,'.auth-kit/observe.mjs')))!==observerDigest||runGit(['rev-parse','HEAD'],{cwd:root}).trim()!==b.commit)throw Error('BINDING_CHANGED_DURING_EXPORT');
 if(await inputDigest(c.inputs.artifact)!==b.artifactDigest||await inputDigest(c.inputs.configuration)!==b.configurationDigest)throw Error('INPUT_CHANGED_DURING_EXPORT');
 const bytes=JSON.stringify(handoff,null,2)+'\n';await writeFile(output,bytes,{flag:'wx',mode:0o600});
 return {file:output,sha256:sha(bytes),sourceInventoryRefreshed:refreshSource,reviewedRevision:b.revision,observedAt:b.observedAt,note:'Exports the reviewed snapshot revision only. Unbuilt/untracked source drift is not asserted absent; consumer VERIFY must recompute and match this revision. No PASS or baseline advancement.'};
}
if(process.argv[1]&&pathToFileURL(await realpath(process.argv[1])).href===import.meta.url){try{
 const [repo,out,...args]=process.argv.slice(2);const options={repo,out};
 for(let i=0;i<args.length;i++){if(args[i]==='--refresh-source')options.refreshSource=true;else if(args[i]==='--report')options.report=args[++i];else if(args[i]==='--report-sha256')options.reportSha256=args[++i];else throw Error('UNKNOWN_OPTION');}
 console.log(JSON.stringify(await exportAuthorityBinding(options),null,2));
}catch(e){console.error(/^[A-Z_]+$/.test(e.message)?e.message:'AUTHORITY_BINDING_EXPORT_FAILED');process.exitCode=2;}}
