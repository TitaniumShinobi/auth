/** Authorized runtime generations supplement, never rewrite, product history. */
import {readFile,lstat,readdir} from 'node:fs/promises';
import path from 'node:path';
import {createHash} from 'node:crypto';
const canonical=v=>Array.isArray(v)?v.map(canonical):v&&typeof v==='object'?Object.fromEntries(Object.keys(v).sort().map(k=>[k,canonical(v[k])])):v;
export const digest=v=>createHash('sha256').update(typeof v==='string'||Buffer.isBuffer(v)?v:JSON.stringify(canonical(v))).digest('hex');
export const protocol='life.auth.verifier-upgrade/1';
export function fail(code){throw Object.assign(new Error(code),{code});}
export async function safeRead(root,relative){
 if(!relative||path.isAbsolute(relative)||relative.includes('\\')||relative.split('/').some(x=>!x||x==='.'||x==='..'))fail('UNSAFE_UPGRADE_PATH');
 let p=root;const parts=relative.split('/');
 for(let i=0;i<parts.length;i++){p=path.join(p,parts[i]);const s=await lstat(p);if(s.isSymbolicLink()||(i<parts.length-1?!s.isDirectory():!s.isFile()))fail('UNSAFE_UPGRADE_PATH');}
 return readFile(p);
}
export const launcher=head=>`// AUTH authorized verifier upgrade ${head}
import {readFile,lstat,readdir} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {fileURLToPath} from 'node:url';
const root=new URL('../',import.meta.url), head='${head}';
const canonical=v=>Array.isArray(v)?v.map(canonical):v&&typeof v==='object'?Object.fromEntries(Object.keys(v).sort().map(k=>[k,canonical(v[k])])):v;
const hash=v=>createHash('sha256').update(Buffer.isBuffer(v)?v:JSON.stringify(canonical(v))).digest('hex');
const fail=code=>{throw Object.assign(new Error(code),{code});};
async function read(relative){
 let u=root;
 for(const part of relative.split('/')){u=new URL(part,u);const s=await lstat(u);if(s.isSymbolicLink())fail('UNSAFE_UPGRADE_PATH');if(s.isDirectory())u=new URL(u.href+'/');}
 return readFile(u);
}
try{
 const e=JSON.parse(await read('.auth-kit/upgrades/history/'+head+'.json'));
 const {digest,...payload}=e;if(digest!==head||hash(payload)!==head)fail('UPGRADE_HISTORY_TAMPERED');
 const base='.auth-kit/upgrades/generations/'+head+'/';
 if(hash((await readdir(new URL(base,root))).sort())!==hash(Object.keys(e.files).sort()))fail('VERIFIER_OR_GATE_DRIFT');
 for(const [name,expected] of Object.entries(e.files)){
  if(!/^[a-zA-Z0-9._-]+[.]mjs$/.test(name)||hash(await read(base+name))!==expected)fail('VERIFIER_OR_GATE_DRIFT');
 }
 const {upgradeChain}=await import(new URL(base+'auth-verifier-upgrade-chain.mjs',root));
 await upgradeChain(fileURLToPath(root));
 const {runProductCli}=await import(new URL(base+'auth-product-contract.mjs',root));
 await runProductCli(process.argv.slice(2),root);
}catch(e){console.log(JSON.stringify({verification:'FAIL',durability_verification:'FAIL',error:e.code||'UPGRADE_INVALID'}));process.exitCode=2;}
`;
export const activeDigest=(files,entrypoint)=>digest({files,entrypoint});
export const generationDigest=files=>activeDigest(files,protocol);
export async function upgradeChain(root){
 const verify=(await safeRead(root,'.auth-kit/verify.mjs')).toString();
 const match=/^\/\/ AUTH authorized verifier upgrade ([a-f0-9]{64})\n/.exec(verify);
 if(!match)return null;
 const head=match[1];if(verify!==launcher(head))fail('VERIFIER_OR_GATE_DRIFT');
 const contract=JSON.parse(await safeRead(root,'.auth-kit/contract.json'));
 let current=head;const reverse=[],seen=new Set();
 while(current){
  if(!/^[a-f0-9]{64}$/.test(current)||seen.has(current)||seen.size>=1000)fail('UPGRADE_HISTORY_TAMPERED');seen.add(current);
  const e=JSON.parse(await safeRead(root,`.auth-kit/upgrades/history/${current}.json`));
  const {digest:claimed,...payload}=e;
  if(claimed!==current||digest(payload)!==current||e.contract!==protocol)fail('UPGRADE_HISTORY_TAMPERED');
  reverse.push(e);current=e.previous;
 }
 const events=reverse.reverse(),runIds=new Set();let previous=null,previousNew=null,initialVerifier;
 for(let i=0;i<events.length;i++){
  const e=events[i],a=e.authorization;
  if(e.sequence!==i+1||e.previous!==previous||e.productId!==contract.productId||e.newDigest!==generationDigest(e.files))fail('UPGRADE_HISTORY_TAMPERED');
  if(!a||a.authorized!==true||a.operation!=='upgrade-verifier'||a.productId!==e.productId||a.revision!==e.revision||a.expectedHead!==e.historyHead||a.expectedContractDigest!==e.contractDigest||a.expectedUpgradeHead!==e.previous||a.oldDigest!==e.oldDigest||a.newDigest!==e.newDigest||!a.operator?.trim()||!a.reason?.trim()||!a.runId?.trim()||runIds.has(a.runId))fail('UPGRADE_AUTHORIZATION_INVALID');
  runIds.add(a.runId);
  // Every upgrade anchors to an existing immutable product-history event.
  if(!Number.isInteger(e.historySequence)||e.historySequence<1||e.historySequence>contract.sequence)fail('UPGRADE_HISTORY_TAMPERED');
  const historicalContract={...contract,sequence:e.historySequence,head:e.historyHead};
  const history=JSON.parse(await safeRead(root,`.auth-kit/history/${String(e.historySequence).padStart(6,'0')}.json`));
  if(digest(historicalContract)!==e.contractDigest||history.digest!==e.historyHead)fail('UPGRADE_HISTORY_TAMPERED');
  if(i===0){
   initialVerifier=e.initialVerifier;
   const p=JSON.parse(await safeRead(root,'.auth-kit/provenance.json'));
   if(typeof initialVerifier!=='string'||digest(initialVerifier)!==p.files['.auth-kit/verify.mjs']||e.oldDigest!==activeDigest(p.files,digest(initialVerifier)))fail('VERIFIER_OR_GATE_DRIFT');
  }else if(e.initialVerifier!==undefined||e.oldDigest!==previousNew)fail('UPGRADE_HISTORY_TAMPERED');
  const directory=`.auth-kit/upgrades/generations/${e.digest}`;
  const names=await readdir(path.join(root,directory));
  if(digest(names.sort())!==digest(Object.keys(e.files).sort()))fail('VERIFIER_OR_GATE_DRIFT');
  for(const [name,hash] of Object.entries(e.files)){
   if(!/^[a-zA-Z0-9._-]+\.mjs$/.test(name)||digest(await safeRead(root,`${directory}/${name}`))!==hash)fail('VERIFIER_OR_GATE_DRIFT');
  }
  previous=e.digest;previousNew=e.newDigest;
 }
 return {head,events,initialVerifier,active:events.at(-1)};
}
export async function verifiedArtifactHashes(root,paths,hashes){
 const actual=await hashes(root,paths),chain=await upgradeChain(root);
 if(chain)actual['.auth-kit/verify.mjs']=digest(chain.initialVerifier);
 return actual;
}
