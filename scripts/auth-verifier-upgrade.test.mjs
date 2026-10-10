import test from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp,writeFile,readFile,rm,readdir} from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {spawnSync} from 'node:child_process';
import {pathToFileURL} from 'node:url';
import {CAPABILITIES} from './auth-capability-catalog.mjs';
import {installProductBundle,hash} from './auth-product-contract.mjs';
import {prepareUpgrade,applyUpgrade,recoverUpgrade} from './auth-verifier-upgrade.mjs';
import {upgradeChain,launcher} from './auth-verifier-upgrade-chain.mjs';
const legacy=spawnSync('git',['show','0b4552d8552aacdb36ca7c312719b4f769221f57:scripts/auth-product-contract.mjs'],{encoding:'utf8'}).stdout.replace("||c.checks.find","||c.verification!=='PASS'||c.checks.find");
assert(legacy.includes("||c.verification!=='PASS'||c.checks.find"));
const observer=`import fs from 'node:fs';const binding=JSON.parse(fs.readFileSync(0,'utf8'));console.log(JSON.stringify({binding,adapter:{schemaVersion:1,authenticationRole:'RELYING_PARTY',productId:binding.productId,revision:binding.revision,capabilities:JSON.parse(fs.readFileSync('facts.json'))},independence:{wizardStopped:true,authOrchestrationRequests:0,runtimePassed:true,evidence:['synthetic offline runtime fixture']}}));`;
async function fixture(fn){
 const root=await mkdtemp(path.join(os.tmpdir(),'auth-upgrade-test-'));
 const git=args=>{const r=spawnSync('git',args,{cwd:root,encoding:'utf8'});assert.equal(r.status,0,r.stderr);};
 try{
  git(['init','-q']);git(['-c','user.name=Fixture','-c','user.email=f@example.test','commit','--allow-empty','-qm','fixture']);
  await writeFile(path.join(root,'config.json'),'{}');await writeFile(path.join(root,'runtime.mjs'),'// product fixture');await writeFile(path.join(root,'observer.mjs'),observer);
  const facts=Object.fromEntries(CAPABILITIES.map(c=>[c.id,{applicability:'FALSE',reason:'synthetic scope'}]));
  facts.signup={applicability:'TRUE',implementation:'ESTABLISHED',evidence:['synthetic'],checks:{explicit_entry:true}};
  await writeFile(path.join(root,'facts.json'),JSON.stringify(facts));
  await installProductBundle(root,{authorized:true,productId:'desktop-fixture',profile:'RELYING_PARTY_CLIENT',adapterSource:path.join(root,'observer.mjs'),inputs:{artifact:['runtime.mjs'],configuration:['config.json']}});
  const core=path.join(root,'.auth-kit/runtime/auth-product-contract.mjs');await writeFile(core,legacy);
  const pp=path.join(root,'.auth-kit/provenance.json'),cp=path.join(root,'.auth-kit/contract.json');
  const p=JSON.parse(await readFile(pp));delete p.files['.auth-kit/runtime/auth-verifier-upgrade-chain.mjs'];await rm(path.join(root,'.auth-kit/runtime/auth-verifier-upgrade-chain.mjs'));
  p.files['.auth-kit/runtime/auth-product-contract.mjs']=hash(legacy);await writeFile(pp,JSON.stringify(p));
  const c=JSON.parse(await readFile(cp));c.provenanceDigest=hash(p);await writeFile(cp,JSON.stringify(c));
  const old=await import(pathToFileURL(core));const before=await old.verifyProduct(root);
  assert.equal(before.profile_verification,'PASS');
  await old.advanceProduct(root,{authorized:true,operation:'establish',productId:c.productId,revision:before.binding.revision,expectedHead:null,expectedContractDigest:before.contractDigest,observerDigest:before.observerDigest,operator:'reviewer',reason:'synthetic reviewed fixture',runId:'first'});
  assert.equal((await old.verifyProduct(root)).error,'HISTORICAL_REGRESSION');
  const preserved=Object.fromEntries(await Promise.all(['contract.json','provenance.json','baseline/000001.json','history/000001.json','runtime/auth-product-contract.mjs'].map(async n=>[n,await readFile(path.join(root,'.auth-kit',n))])));
  const authorize=async()=>({...await prepareUpgrade(root),authorized:true,operator:'reviewer',reason:'Reviewed check-level fix'});
  const verify=()=>{const r=spawnSync(process.execPath,['.auth-kit/verify.mjs','verify'],{cwd:root,encoding:'utf8'});return JSON.parse(r.stdout);};
  await fn({root,authorize,verify,facts,preserved});
 }finally{await rm(root,{recursive:true,force:true});}
}
test('legacy bootstrap upgrades atomically; old history/baseline immutable; obligations preserved',()=>fixture(async({root,authorize,verify,preserved})=>{
 const result=await applyUpgrade(root,await authorize());assert.equal(result.verification,'UPGRADED_VERIFY_REQUIRED');
 for(const [n,b] of Object.entries(preserved))assert.deepEqual(await readFile(path.join(root,'.auth-kit',n)),b);
 const chain=await upgradeChain(root);assert.equal(chain.events.length,1);assert.equal(chain.active.historySequence,1);
 const report=verify();assert.equal(report.durability_verification,'PASS');assert.equal(report.capabilities.find(c=>c.id==='signup').verification,'INDETERMINATE');
 // A second separately authorized upgrade links the prior verifier provenance.
 await applyUpgrade(root,await authorize());assert.equal((await upgradeChain(root)).events.length,2);assert.equal(verify().verification,'PASS');
}));
for(const key of ['expectedHead','oldDigest','newDigest','revision','expectedContractDigest'])test(`reject mismatched ${key}`,()=>fixture(async({root,authorize})=>{
 const before=await readFile(path.join(root,'.auth-kit/verify.mjs'));const a=await authorize();a[key]='0'.repeat(64);
 await assert.rejects(applyUpgrade(root,a),/UPGRADE_AUTHORIZATION_MISMATCH/);assert.deepEqual(await readFile(path.join(root,'.auth-kit/verify.mjs')),before);
}));
test('authorization required',()=>fixture(async({root})=>{await assert.rejects(applyUpgrade(root,{authorized:false}),/UPGRADE_AUTHORIZATION_REQUIRED/);}));
test('tampered old history blocks bootstrap',()=>fixture(async({root,authorize})=>{
 const a=await authorize();await writeFile(path.join(root,'.auth-kit/history/000001.json'),'{}');await assert.rejects(applyUpgrade(root,a));
}));
for(const fault of ['after-stage','before-activate'])test(`interrupted upgrade ${fault} retains old entry/history`,()=>fixture(async({root,authorize,preserved})=>{
 const before=await readFile(path.join(root,'.auth-kit/verify.mjs'));
 await assert.rejects(applyUpgrade(root,await authorize(),{fault}),/INJECTED_INTERRUPTION/);
 assert.deepEqual(await readFile(path.join(root,'.auth-kit/verify.mjs')),before);
 for(const [n,b] of Object.entries(preserved))assert.deepEqual(await readFile(path.join(root,'.auth-kit',n)),b);
 assert.deepEqual(await readdir(path.join(root,'.auth-kit/upgrades/history')),[]);
}));
test('unrecorded runtime and generation replacement rejected',()=>fixture(async({root,authorize,verify})=>{
 await applyUpgrade(root,await authorize());const chain=await upgradeChain(root);
 const file=path.join(root,'.auth-kit/upgrades/generations',chain.head,'auth-lifecycle.mjs');await writeFile(file,(await readFile(file))+`\nimport fs from 'node:fs';fs.writeFileSync(${JSON.stringify(path.join(root,'must-not-execute'))},'BAD');`);
 assert.equal(verify().error,'VERIFIER_OR_GATE_DRIFT');
 await assert.rejects(readFile(path.join(root,'must-not-execute')),/ENOENT/);
}));
test('direct old runtime replacement remains rejected',()=>fixture(async({root,verify})=>{
 const p=path.join(root,'.auth-kit/runtime/auth-product-contract.mjs');await writeFile(p,(await readFile(p))+'\n// drift');assert.equal(verify().error,'VERIFIER_OR_GATE_DRIFT');
}));
test('upgrade history tamper rejected',()=>fixture(async({root,authorize,verify})=>{
 await applyUpgrade(root,await authorize());const chain=await upgradeChain(root);await writeFile(path.join(root,'.auth-kit/upgrades/history',chain.head+'.json'),'{}');assert.equal(verify().error,'UPGRADE_HISTORY_TAMPERED');
}));
test('real historical check regression still fails',()=>fixture(async({root,authorize,verify,facts})=>{
 await applyUpgrade(root,await authorize());facts.signup.checks.explicit_entry=false;await writeFile(path.join(root,'facts.json'),JSON.stringify(facts));assert.equal(verify().error,'HISTORICAL_REGRESSION');
}));
test('hard interruption before activation leaves old runtime and history active',()=>fixture(async({root,authorize,preserved})=>{
 const before=await readFile(path.join(root,'.auth-kit/verify.mjs')),a=await authorize();
 const module=new URL('./auth-verifier-upgrade.mjs',import.meta.url).href;
 const script=`import fs from 'node:fs';import {applyUpgrade} from ${JSON.stringify(module)};const x=JSON.parse(fs.readFileSync(0,'utf8'));await applyUpgrade(x.root,x.a,{fault:()=>process.kill(process.pid,'SIGKILL')});`;
 const r=spawnSync(process.execPath,['--input-type=module','-e',script],{input:JSON.stringify({root,a}),encoding:'utf8'});assert.notEqual(r.status,0);
 assert.deepEqual(await readFile(path.join(root,'.auth-kit/verify.mjs')),before);
 for(const [n,b] of Object.entries(preserved))assert.deepEqual(await readFile(path.join(root,'.auth-kit',n)),b);
 assert.equal(await upgradeChain(root),null);
 assert.equal((await recoverUpgrade(root,a)).verification,'OLD_VERIFIER_RETAINED');
 assert.deepEqual(await readdir(path.join(root,'.auth-kit/upgrades/history')),[]);
 await applyUpgrade(root,a);assert.equal((await upgradeChain(root)).events.length,1);
}));
test('repeat authorization cannot replay after upgrade',()=>fixture(async({root,authorize})=>{
 const a=await authorize();await applyUpgrade(root,a);await assert.rejects(applyUpgrade(root,a),/UPGRADE_AUTHORIZATION_MISMATCH/);
}));
test('legacy provenance validation rejects changed CI gate',()=>fixture(async({root,authorize})=>{
 const a=await authorize();await writeFile(path.join(root,'.auth-kit/ci.mjs'),'// removed gate');await assert.rejects(applyUpgrade(root,a),/VERIFIER_OR_GATE_DRIFT/);
}));
test('unsafe kit directory is rejected before lock creation',()=>fixture(async({root,authorize})=>{
 const {rename,symlink}=await import('node:fs/promises');const a=await authorize();
 await rename(path.join(root,'.auth-kit'),path.join(root,'kit-real'));await symlink(path.join(root,'kit-real'),path.join(root,'.auth-kit'),'dir');
 await assert.rejects(applyUpgrade(root,a),/UNSAFE_UPGRADE_PATH/);
}));
test('portable bootstrap checks bundle before importing it',async()=>{
 const dir=await mkdtemp(path.join(os.tmpdir(),'auth-upgrade-bundle-'));
 try{
  const files={};for(const [source,target] of [['auth-verifier-upgrade-bootstrap.mjs','upgrade.mjs'],['auth-verifier-upgrade.mjs','auth-verifier-upgrade.mjs'],['auth-verifier-upgrade-chain.mjs','auth-verifier-upgrade-chain.mjs']]){
   const bytes=await readFile(new URL(source,import.meta.url));await writeFile(path.join(dir,target),bytes);files[target]=hash(bytes);
  }
  await writeFile(path.join(dir,'manifest.json'),JSON.stringify({files}));
  const run=()=>spawnSync(process.execPath,[path.join(dir,'upgrade.mjs'),'--check'],{encoding:'utf8'});
  assert.equal(run().status,0);
  await writeFile(path.join(dir,'auth-verifier-upgrade.mjs'),"throw new Error('MUST_NOT_EXECUTE');");const r=run();assert.equal(r.status,2);assert.match(r.stderr,/BUNDLE_DIGEST_MISMATCH/);assert(!r.stderr.includes('MUST_NOT_EXECUTE'));
 }finally{await rm(dir,{recursive:true,force:true});}
});
test('later authorized baseline advancement keeps prior verifier history valid',()=>fixture(async({root,authorize,verify})=>{
 await applyUpgrade(root,await authorize());const chain=await upgradeChain(root),report=verify();
 const mod=await import(pathToFileURL(path.join(root,'.auth-kit/upgrades/generations',chain.head,'auth-product-contract.mjs')));
 await mod.advanceProduct(root,{authorized:true,operation:'advance',productId:'desktop-fixture',revision:report.binding.revision,expectedHead:report.contractHead,expectedContractDigest:report.contractDigest,observerDigest:report.observerDigest,operator:'fixture reviewer',reason:'synthetic future advancement compatibility',runId:'future-baseline'});
 assert.equal(verify().verification,'PASS');assert.equal((await upgradeChain(root)).head,chain.head);
}));
