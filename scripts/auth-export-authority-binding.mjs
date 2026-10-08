/** Export only public consumer binding, using the installed product's reviewed collector. */
import {writeFile,realpath} from 'node:fs/promises';
import {isDeepStrictEqual} from 'node:util';
import path from 'node:path';import {pathToFileURL} from 'node:url';import {spawnSync} from 'node:child_process';import {createHash} from 'node:crypto';
export function sanitizeBinding(binding,authority){
 if(!binding||typeof binding.productId!=='string'||!binding.productId||typeof binding.revision!=='string'||!binding.revision||!authority)throw Error('CURRENT_CONSUMER_BINDING_REQUIRED');
 const origin=new URL(authority.id);if(origin.protocol!=='https:'||origin.origin!==authority.id||origin.username||origin.password)throw Error('PUBLIC_AUTHORITY_ORIGIN_REQUIRED');
 if(!/^[a-f0-9]{40,64}$/.test(authority.revision||''))throw Error('DECLARED_AUTHORITY_REVISION_REQUIRED');
 const identityAuthority={id:authority.id,revision:authority.revision};
 for(const k of ['configurationDigest','runtimeDigest'])if(authority[k]!==undefined){if(!/^[a-f0-9]{64}$/.test(authority[k]))throw Error('INVALID_AUTHORITY_DIGEST');identityAuthority[k]=authority[k];}
 return {productId:binding.productId,revision:binding.revision,identityAuthority};
}
export async function exportAuthorityBinding({repo,out}){
 const root=await realpath(repo),output=path.resolve(out),rel=path.relative(root,output);
 if(!rel.startsWith('..'+path.sep)&&rel!=='..'&&!path.isAbsolute(rel))throw Error('OUTPUT_MUST_BE_OUTSIDE_PRODUCT');
 const {verifyProduct}=await import(pathToFileURL(path.join(root,'.auth-kit/runtime/auth-product-contract.mjs')).href);
 const before=await verifyProduct(root);if(!before.binding)throw Error('FRESH_PRODUCT_OBSERVATION_REQUIRED');
 const run=spawnSync(process.execPath,[path.join(root,'.auth-kit/observe.mjs')],{cwd:root,input:JSON.stringify(before.binding),encoding:'utf8',timeout:120000,maxBuffer:8*1024*1024});
 if(run.status!==0)throw Error('PRODUCT_OBSERVATION_FAILED');
 let o;try{o=JSON.parse(run.stdout);}catch{throw Error('MALFORMED_PRODUCT_OBSERVATION');}
 if(!isDeepStrictEqual(o.binding,before.binding)||o.adapter?.productId!==before.binding.productId||o.adapter?.revision!==before.binding.revision)throw Error('CONSUMER_BINDING_MISMATCH');
 const handoff=sanitizeBinding(before.binding,o.adapter.identityAuthority);
 const after=await verifyProduct(root);for(const k of ['revision','artifactDigest','configurationDigest'])if(after.binding?.[k]!==before.binding[k])throw Error('PRODUCT_CHANGED_DURING_EXPORT');
 if(before.observerDigest!==after.observerDigest||before.contractDigest!==after.contractDigest)throw Error('CONTRACT_CHANGED_DURING_EXPORT');
 const bytes=JSON.stringify(handoff,null,2)+'\n';await writeFile(output,bytes,{flag:'wx',mode:0o600});
 return {file:output,sha256:createHash('sha256').update(bytes).digest('hex'),verification:after.verification,note:'Binding only; no authority conformance or product PASS claimed'};
}
if(process.argv[1]&&pathToFileURL(await realpath(process.argv[1])).href===import.meta.url){try{console.log(JSON.stringify(await exportAuthorityBinding({repo:process.argv[2],out:process.argv[3]}),null,2));}catch(e){console.error(/^[A-Z_]+$/.test(e.message)?e.message:'AUTHORITY_BINDING_EXPORT_FAILED');process.exitCode=2;}}
