/** Shell-free Git discovery shared by setup and installed product verification. */
import path from 'node:path';
import { statSync } from 'node:fs';
import { spawn, spawnSync } from 'node:child_process';
function error(code, message) { return Object.assign(new Error(message), {code, diagnostic:message}); }
export function discoverGit({platform=process.platform,env=process.env,stat=statSync,spawn=spawnSync}={}) {
  const windows=platform==='win32', p=windows?path.win32:path.posix;
  const get=name=>env[name] ?? (windows?env[Object.keys(env).find(k=>k.toUpperCase()===name.toUpperCase())]:undefined);
  const explicit=get('AUTH_GIT_EXECUTABLE');
  if(explicit && !p.isAbsolute(explicit)) throw error('GIT_OVERRIDE_INVALID','AUTH_GIT_EXECUTABLE must be an absolute executable path (no surrounding quotes).');
  const candidates=explicit?[explicit]:[
    ...(get('PATH')||'').split(windows?';':':').filter(Boolean).map(d=>d.replace(/^"(.*)"$/,'$1')).filter(d=>p.isAbsolute(d)).map(d=>p.join(d,windows?'git.exe':'git')),
    ...(windows?[get('ProgramW6432'),get('ProgramFiles'),get('ProgramFiles(x86)')].filter(Boolean).flatMap(d=>[p.join(d,'Git','cmd','git.exe'),p.join(d,'Git','bin','git.exe')]):[]),
    ...(windows&&get('LOCALAPPDATA')?[p.join(get('LOCALAPPDATA'),'Programs','Git','cmd','git.exe')]:[])
  ];
  let present=false;
  for(const executable of [...new Set(candidates)]) {
    try {if(!stat(executable).isFile())continue;}catch{continue;}
    present=true;
    const probe=spawn(executable,['--version'],{encoding:'utf8',windowsHide:true,timeout:5000,maxBuffer:65536,shell:false});
    if(!probe.error&&probe.status===0&&/^git version /m.test(probe.stdout||''))return executable;
  }
  throw error(explicit?'GIT_OVERRIDE_UNUSABLE':'GIT_EXECUTABLE_UNAVAILABLE',
    `Git ${present?'was found but could not execute':'was not found'} using ${explicit?'AUTH_GIT_EXECUTABLE':'absolute PATH entries and standard Windows installation locations'}. Set AUTH_GIT_EXECUTABLE to the absolute git executable; confirm it runs --version in this Node environment.`);
}
export function runGit(args,{cwd,...discovery}={}) {
  const executable=discoverGit(discovery);
  const result=(discovery.spawn||spawnSync)(executable,args,{cwd,encoding:'utf8',maxBuffer:32*1024*1024,timeout:30000,windowsHide:true,shell:false});
  if(result.error)throw error('GIT_EXECUTION_FAILED',`Git could not run (${result.error.code||'process error'}). Check executable access and the repository working directory.`);
  if(result.status!==0)throw error('GIT_COMMAND_FAILED',`Git exited ${result.status ?? 'without a status'}. Check repository access and Git safe.directory policy with the selected executable. Raw Git output is withheld.`);
  return result.stdout;
}

/** Per-command long-path support; never writes Git config. */
export function inventoryArguments(platform=process.platform) {
  return [...(platform==='win32'?['-c','core.longpaths=true']:[]),'ls-files','-z','--cached','--others','--exclude-standard'];
}
export function filesystemPath(value,platform=process.platform) {
  return platform==='win32'?path.win32.toNamespacedPath(value):value;
}
/** Bounded to one filename, preserving UTF-8 across arbitrary chunk boundaries. */
export async function* parseGitPaths(chunks) {
  let parts=[],length=0;
  const decoder=new TextDecoder('utf-8',{fatal:true});
  for await (const input of chunks) {
    const chunk=Buffer.isBuffer(input)?input:Buffer.from(input);let start=0;
    for(let end=0;end<chunk.length;end++)if(chunk[end]===0){
      const tail=chunk.subarray(start,end);length+=tail.length;
      if(length>1024*1024)throw error('GIT_INVENTORY_INVALID','A single Git path exceeds the supported 1 MiB limit; inventory is incomplete.');
      const bytes=parts.length?Buffer.concat([...parts,tail],length):tail;
      let name;try{name=decoder.decode(bytes);}catch{throw error('GIT_INVENTORY_INVALID','A Git path is not valid UTF-8; inventory cannot safely represent it.');}
      if(!name)throw error('GIT_INVENTORY_INVALID','Empty Git path record; inventory is incomplete.');
      yield name;parts=[];length=0;start=end+1;
    }
    if(start<chunk.length){const tail=chunk.subarray(start);parts.push(Buffer.from(tail));length+=tail.length;
      if(length>1024*1024)throw error('GIT_INVENTORY_INVALID','A single Git path exceeds the supported 1 MiB limit; inventory is incomplete.');}
  }
  if(length)throw error('GIT_INVENTORY_TRUNCATED','Git inventory ended without its terminating NUL; no inventory may be accepted.');
}
export async function* inventoryPaths({cwd,platform=process.platform,launch=spawn,args,...discovery}={}) {
  const executable=discoverGit({platform,...discovery});
  const child=launch(executable,(args?[...(platform==='win32'?['-c','core.longpaths=true']:[]),...args]:inventoryArguments(platform)),{cwd,windowsHide:true,shell:false,stdio:['ignore','pipe','pipe'],env:{...process.env,...discovery.env,GIT_OPTIONAL_LOCKS:'0'}});
  let stderrBytes=0;
  child.stderr.on('data',chunk=>{stderrBytes+=chunk.length;}); // Drain, never retain/log paths or secrets.
  const completed=new Promise(resolve=>{child.once('error',e=>resolve({error:e}));child.once('close',(code,signal)=>resolve({code,signal}));});
  let finished=false;
  try {
    yield* parseGitPaths(child.stdout);
    const status=await completed;
    if(status.error)throw error('GIT_INVENTORY_EXECUTION_FAILED',`Git inventory could not start (${status.error.code||'process error'}); check the executable and repository access.`);
    if(status.code!==0||status.signal)throw error('GIT_INVENTORY_INCOMPLETE','Git inventory failed or was interrupted. Inspect Git diagnostics locally; check long-path support, permissions and repository access. No partial inventory is valid.');
    if(stderrBytes)throw error('GIT_INVENTORY_WARNINGS','Git emitted diagnostics while enumerating paths. Inventory is rejected even with exit 0. Run the same read-only ls-files command locally with core.longpaths=true to inspect warnings; do not clean or exclude paths to obtain PASS.');
    finished=true;
  } finally {if(!finished){child.kill();await completed;}}
}
