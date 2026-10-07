/** Git-authorized inventory only: never walk arbitrary filesystem directories. */
import path from 'node:path';
import {lstat,realpath,readlink,readFile} from 'node:fs/promises';
import {createReadStream} from 'node:fs';
import {createHash} from 'node:crypto';
import {inventoryPaths,runGit,filesystemPath} from './auth-git.mjs';
const canonical=v=>Array.isArray(v)?v.map(canonical):v&&typeof v==='object'?Object.fromEntries(Object.keys(v).sort().map(k=>[k,canonical(v[k])])):v;
const digest=v=>createHash('sha256').update(typeof v==='string'?v:JSON.stringify(canonical(v))).digest('hex');
const inside=(root,p)=>{const r=path.relative(root,p);return r===''||(!r.startsWith('..'+path.sep)&&r!=='..'&&!path.isAbsolute(r));};
function fail(relative,type,reason){throw Object.assign(new Error(reason),{code:'PRODUCT_INVENTORY_UNSUPPORTED',diagnostic:`Inventory path ${JSON.stringify(relative)} (${type}): ${reason}`});}
async function fileDigest(p){const h=createHash('sha256');for await(const chunk of createReadStream(filesystemPath(p)))h.update(chunk);return h.digest('hex');}
async function safeEntry(root,relative){
 const name=relative.endsWith('/')?relative.slice(0,-1):relative;
 if(!name||path.isAbsolute(name)||name.includes('\\')||name.split('/').some(x=>!x||x==='.'||x==='..'))fail(relative,'path','Unsafe Git path; outside-root traversal prohibited.');
 let p=root;const parts=name.split('/');
 for(let i=0;i<parts.length;i++){p=path.join(p,parts[i]);try{const s=await lstat(filesystemPath(p));if(i<parts.length-1&&(!s.isDirectory()||s.isSymbolicLink()))fail(relative,'parent','Parent is not a real directory; refusing traversal.');if(i===parts.length-1)return {p,s};}catch(e){if(e.code==='ENOENT')return {p:path.join(root,name),s:null};throw e;}}
}
function stage(root,name){const out=runGit(['ls-files','--stage','-z','--',name],{cwd:root});return out.split('\0').filter(Boolean).map(x=>{const m=/^(\d+) ([a-f0-9]+) ([0-3])\t/.exec(x);return m?{mode:m[1],oid:m[2],stage:Number(m[3])}:null;}).filter(Boolean);}
async function metadataBoundary(root,outer,label){
 const marker=path.join(root,'.git');const st=await lstat(filesystemPath(marker));let target;
 if(st.isSymbolicLink())fail(label,'embedded_repository','Symbolic .git metadata is unsupported.');
 if(st.isDirectory())target=marker;
 else if(st.isFile()){
  const text=await readFile(filesystemPath(marker),'utf8');const m=/^gitdir: (.+)\r?\n?$/.exec(text);if(!m)fail(label,'embedded_repository','Malformed .git indirection.');target=path.resolve(root,m[1].trim());
 }else fail(label,'embedded_repository','Unsupported .git metadata type.');
 const actual=await realpath(target);if(!inside(outer,actual))fail(label,'embedded_repository','Git metadata points outside product root.');
 // Linked worktree metadata may redirect again via commondir.
 try{const common=(await readFile(path.join(actual,'commondir'),'utf8')).trim();if(!inside(outer,await realpath(path.resolve(actual,common))))fail(label,'embedded_repository','Git common directory points outside product root.');}catch(e){if(e.code!=='ENOENT')throw e;}
}
export async function collectProductInventory(root,{excludeKit=true,records}={}){
 root=await realpath(root);const active=new Set();
 async function collect(current,depth,sourceRecords){
  const resolved=await realpath(current);if(!inside(root,resolved))fail(path.relative(root,current),'repository','Outside product root.');
  if(active.has(resolved)||depth>8)fail(path.relative(root,current),'repository','Repository cycle or nesting depth exceeds eight.');active.add(resolved);
  try{
   const files=Object.create(null);
   for await(const relative of sourceRecords||inventoryPaths({cwd:current})){
    if(depth===0&&excludeKit&&relative.startsWith('.auth-kit/'))continue;
    if(Object.hasOwn(files,relative))continue;
    const label=path.relative(root,path.join(current,relative));const {p,s}=await safeEntry(current,relative);
    if(!s){files[relative]='DELETED';continue;}
    if(s.isFile()){files[relative]=await fileDigest(p);continue;}
    if(s.isSymbolicLink()){
     const entries=stage(current,relative);files[relative]={type:'symlink',tracked:entries.some(x=>x.mode==='120000'),targetDigest:digest(await readlink(filesystemPath(p))),indexEntries:entries};continue;
    }
    if(s.isDirectory()){
     const entries=stage(current,relative.replace(/\/$/,''));const gitlink=entries.some(x=>x.mode==='160000');
     try{await metadataBoundary(p,root,label);}catch(e){if(e.code==='ENOENT')fail(label,gitlink?'gitlink':'directory','No local Git metadata; directory cannot be treated as a file or recursively walked.');throw e;}
     if(await realpath(runGit(['rev-parse','--show-toplevel'],{cwd:p}).trim())!==await realpath(p))fail(label,'directory','Not an independent Git worktree.');
     const head=runGit(['rev-parse','--verify','HEAD'],{cwd:p}).trim();
     const indexPath=path.resolve(p,runGit(['rev-parse','--git-path','index'],{cwd:p}).trim());
     if(!inside(root,await realpath(indexPath)))fail(label,'repository','Index outside product root.');
     const indexDigest=await fileDigest(indexPath);const status=createHash('sha256');let dirty=false;
     for await(const row of inventoryPaths({cwd:p,args:['status','--porcelain=v1','-z','--untracked-files=all','--ignore-submodules=none']})){dirty=true;status.update(row).update('\0');}
     const nested=await collect(p,depth+1);
     if(head!==runGit(['rev-parse','--verify','HEAD'],{cwd:p}).trim()||indexDigest!==await fileDigest(indexPath))fail(label,'repository','HEAD/index changed during fingerprinting.');
     files[relative]={type:gitlink?'gitlink':'embedded_repository',head,indexDigest,statusDigest:status.digest('hex'),dirty,worktreeDigest:digest(nested),indexEntries:entries};continue;
    }
    const type=s.isFIFO()?'fifo':s.isSocket()?'socket':s.isBlockDevice()?'block_device':s.isCharacterDevice()?'character_device':'unknown';fail(label,type,'Unsupported filesystem object; nothing was excluded.');
   }
   return files;
  }finally{active.delete(resolved);}
 }
 return collect(root,0,records);
}
