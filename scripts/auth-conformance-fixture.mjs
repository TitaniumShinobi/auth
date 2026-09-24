import { readFileSync, mkdtempSync, mkdirSync, writeFileSync, symlinkSync, rmSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';
import { digest } from './auth-conformance-binding.mjs';

// Follow only the compiled application's explicit relative imports, never product data.
export function fixtureArtifacts(root) {
  const queue=['dist/app.js'];const artifacts={};
  while(queue.length) {
    const file=queue.shift();if(artifacts[file]!==undefined)continue;
    if(!file.startsWith('dist/') || file.includes('..'))throw new Error('Unsafe artifact import');
    const code=readFileSync(join(root,file),'utf8');artifacts[file]=code;
    for(const match of code.matchAll(/(?:from\s*|import\s*(?:\()?)\s*['"](\.[^'"]+\.js)['"]/g)) {
      const absolute=resolve(root,dirname(file),match[1]);
      if(!absolute.startsWith(resolve(root,'dist')+'/'))throw new Error('Artifact escapes compiled AUTH');
      queue.push(absolute.slice(root.length+1));
    }
  }
  return artifacts;
}
export function runControlledFixture(root, node = process.execPath) {
  const dir=mkdtempSync(join(tmpdir(),'auth-fixture-'));
  let report;
  try {
    const artifacts=fixtureArtifacts(root);
    for(const [file,code] of Object.entries(artifacts)){mkdirSync(dirname(join(dir,file)),{recursive:true});writeFileSync(join(dir,file),code);}
    writeFileSync(join(dir,'package.json'),'{"type":"module"}');
    symlinkSync(join(root,'node_modules'),join(dir,'node_modules'),'dir');
    const worker=readFileSync(new URL('./auth-conformance-fixture-worker.mjs',import.meta.url),'utf8');
    writeFileSync(join(dir,'worker.mjs'),worker);
    const child=spawnSync(node,[join(dir,'worker.mjs')],{cwd:dir,env:{PATH:process.env.PATH || '/usr/bin:/bin',NODE_ENV:'test',AUTH_CONFORMANCE_CHILD:'1',AUTH_STORAGE_ADAPTER:'memory'},encoding:'utf8',timeout:45000,maxBuffer:65536});
    let value;try{value=JSON.parse(child.stdout);}catch{value={error:'FIXTURE_PROCESS_FAILED',results:{}};}
    // Never forward child logs, stderr, or unexpected fields containing proofs.
    report={scope:'ISOLATED_ARTIFACT_FIXTURE',artifactDigest:digest(artifacts),fixtureDigest:digest({worker,runner:readFileSync(new URL('./auth-conformance-fixture.mjs',import.meta.url),'utf8')}),
      results:Object.fromEntries(Object.entries(value.results||{}).filter(([key,v])=>/^[a-z_]+$/.test(key)&&typeof v==='boolean')),
      stage:['IMPORT','CREATE_APP','SOCKET','REGISTER'].includes(value.stage)?value.stage:null,serverClosed:value.serverClosed===true,completed:child.status===0 && !value.error};
  } finally {rmSync(dir,{recursive:true,force:true});}
  return {...report,cleanup:true};
}
