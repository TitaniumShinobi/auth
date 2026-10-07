/** Shell-free Git discovery shared by setup and installed product verification. */
import path from 'node:path';
import { statSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
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
