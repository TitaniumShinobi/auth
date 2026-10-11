import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp,writeFile,readFile,rm,rename,readdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { CAPABILITIES } from './auth-capability-catalog.mjs';
import { installProductBundle,verifyProduct,advanceProduct,inspectProductBundle,validateCatalogMigration,hash } from './auth-product-contract.mjs';

const observe = `import {readFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
const binding=JSON.parse(readFileSync(0,'utf8'));
const facts=JSON.parse(readFileSync('facts.json','utf8'));
const runtime=spawnSync(process.execPath,['runtime.mjs'],{env:{},encoding:'utf8'});
console.log(JSON.stringify({binding,adapter:{schemaVersion:1,productId:binding.productId,revision:binding.revision,capabilities:facts},independence:{wizardStopped:true,authOrchestrationRequests:0,runtimePassed:runtime.status===0&&runtime.stdout.trim()==='PRODUCT_OK',evidence:['isolated-runtime-process']}}));`;
const fixtureFacts=()=>Object.fromEntries(CAPABILITIES.map(c=>[c.id,['signup','providers.github'].includes(c.id)
 ? {applicability:'TRUE',implementation:'ESTABLISHED',evidence:['synthetic-product-check'],checks:Object.fromEntries(c.checks.map(id=>[id,true]))}
 : {applicability:'FALSE',reason:'fixture scope',implementation:'NOT_ESTABLISHED'}]));
async function fixture(fn,{established=true,productId='arbitrary-desktop'}={}) {
 const root=await mkdtemp(path.join(tmpdir(),'auth-durable-'));
 const git=args=>{const r=spawnSync('git',args,{cwd:root,encoding:'utf8'});assert.equal(r.status,0,r.stderr);};
 try {
  git(['init','-q']);git(['-c','user.name=Fixture','-c','user.email=fixture@example.test','commit','--allow-empty','-qm','fixture']);
  await writeFile(path.join(root,'runtime.mjs'),"console.log('PRODUCT_OK');\n");
  await writeFile(path.join(root,'config.json'),'{}\n');
  await writeFile(path.join(root,'observer-source.mjs'),observe);
  await writeFile(path.join(root,'facts.json'),JSON.stringify(fixtureFacts()));
  await installProductBundle(root,{authorized:true,productId,adapterSource:path.join(root,'observer-source.mjs'),inputs:{artifact:['runtime.mjs'],configuration:['config.json']}});
  const authorize=async(operation='advance',extra={})=>{
   const state=await inspectProductBundle(root);const report=await verifyProduct(root);
   return {authorized:true,operation,productId,revision:report.binding.revision,expectedHead:state.contract.head,expectedContractDigest:report.contractDigest,observerDigest:report.observerDigest,operator:'fixture-reviewer',reason:'Reviewed fixture contract',runId:'approval-'+Date.now(),...extra};
  };
  if(established)await advanceProduct(root,await authorize('establish'));
  await fn({root,authorize,facts:fixtureFacts(),writeFacts:async f=>writeFile(path.join(root,'facts.json'),JSON.stringify(f))});
 } finally {await rm(root,{recursive:true,force:true});}
}

test('setup installs complete generic bundle; first VERIFY cannot claim establishment',()=>fixture(async({root,authorize})=>{
 assert.equal((await verifyProduct(root)).error,'UNESTABLISHED');
 for(const f of ['contract.json','observe.mjs','verify.mjs','ci.mjs','provenance.json'])assert.ok(await readFile(path.join(root,'.auth-kit',f)));
 await advanceProduct(root,await authorize('establish'));
 assert.equal((await verifyProduct(root)).verification,'PASS');
 assert.equal((await readdir(path.join(root,'.auth-kit/history'))).length,1);
 await assert.rejects(installProductBundle(root,{authorized:true,productId:'arbitrary-desktop'}),/CONTRACT_ALREADY_EXISTS/);
},{established:false}));

test('installed command uses baseline automatically without AUTH checkout/runtime service',()=>fixture(async({root})=>{
 const reportsBefore=await readdir(path.join(root,'.auth-kit/reports'));
 const r=spawnSync(process.execPath,['.auth-kit/verify.mjs','verify'],{cwd:root,encoding:'utf8',env:{PATH:process.env.PATH}});
 assert.equal(r.status,0,r.stderr);assert.equal(JSON.parse(r.stdout).verification,'PASS');
 assert.deepEqual(await readdir(path.join(root,'.auth-kit/reports')),reportsBefore);
 const omit=spawnSync(process.execPath,['.auth-kit/verify.mjs','verify','--no-baseline'],{cwd:root,encoding:'utf8'});
 assert.notEqual(omit.status,0);
}));
for(const mutation of ['missing','fail','indeterminate','not-applicable'])test(`historical PASS cannot become ${mutation}`,()=>fixture(async({root,facts,writeFacts})=>{
 if(mutation==='missing')delete facts['providers.github'];
 if(mutation==='fail')facts['providers.github'].checks.supported=false;
 if(mutation==='indeterminate')delete facts['providers.github'].checks.supported;
 if(mutation==='not-applicable')facts['providers.github']={applicability:'FALSE',reason:'casual removal'};
 await writeFacts(facts);assert.equal((await verifyProduct(root)).verification,'FAIL');
}));
for(const mutation of ['delete','empty','replace'])test(`baseline ${mutation} fails closed`,()=>fixture(async({root})=>{
 const p=path.join(root,'.auth-kit/baseline/000001.json');
 if(mutation==='delete')await rm(p);else await writeFile(p,mutation==='empty'?'{}':'{"capabilities":[]}');
 assert.equal((await verifyProduct(root)).verification,'FAIL');
}));
test('ACT authorization cannot retire; exact amendment appends history and preserves prior bytes',()=>fixture(async({root,authorize,facts,writeFacts})=>{
 const first=await readFile(path.join(root,'.auth-kit/history/000001.json'),'utf8');
 facts['providers.github']={applicability:'FALSE',reason:'reviewed product retirement'};await writeFacts(facts);
 await assert.rejects(advanceProduct(root,{authorized:true,capabilityId:'providers.github'}),/AUTHORIZATION/);
 await assert.rejects(advanceProduct(root,await authorize()),/HISTORICAL_REGRESSION/);
 const retireChecks=CAPABILITIES.find(c=>c.id==='providers.github').checks.map(k=>'providers.github/'+k);
 await assert.rejects(advanceProduct(root,await authorize('advance',{retireChecks})),/AMENDMENT_AUTHORIZATION/);
 const result=await advanceProduct(root,await authorize('amend',{retireChecks}));assert.equal(result.sequence,2);
 assert.equal(await readFile(path.join(root,'.auth-kit/history/000001.json'),'utf8'),first);
 assert.equal((await verifyProduct(root)).verification,'PASS');
}));
for(const f of ['history/000001.json','verify.mjs','ci.mjs','runtime/auth-wizard.mjs'])test(`detects removal/tampering of ${f}`,()=>fixture(async({root})=>{
 await writeFile(path.join(root,'.auth-kit',f),'{}');assert.equal((await verifyProduct(root)).verification,'FAIL');
}));
test('removed workflow and entire bundle fail trusted verifier',()=>fixture(async({root})=>{
 await rm(path.join(root,'.github/workflows/auth-product-contract.yml'));assert.equal((await verifyProduct(root)).verification,'FAIL');
 await rm(path.join(root,'.auth-kit'),{recursive:true});assert.equal((await verifyProduct(root)).verification,'FAIL');
}));
test('external checkpoint detects rollback to an older otherwise valid chain',()=>fixture(async({root,authorize})=>{
 const old=await readFile(path.join(root,'.auth-kit/contract.json'),'utf8');
 const result=await advanceProduct(root,await authorize());
 await writeFile(path.join(root,'.auth-kit/contract.json'),old);
 await rm(path.join(root,'.auth-kit/history/000002.json'));await rm(path.join(root,'.auth-kit/baseline/000002.json'));
 assert.equal((await verifyProduct(root,{checkpoint:result.head})).verification,'FAIL');
}));
test('catalog identity migrations preserve checks; removal/rename/unknown version blocks',()=>{
 const old=[{id:'providers.github',family:'providers',checks:['supported']}];
 assert.equal(validateCatalogMigration(old,'1'),true);
 assert.equal(validateCatalogMigration([{...old[0],checks:['renamed_old_check']}],'1'),false);
 assert.equal(validateCatalogMigration(old,'999'),false);
});
test('maintenance uses installed pinned contract after normal product runs without kit',()=>fixture(async({root})=>{
 await rename(path.join(root,'.auth-kit'),path.join(root,'.auth-kit-offline'));
 const r=spawnSync(process.execPath,['runtime.mjs'],{cwd:root,env:{},encoding:'utf8'});assert.equal(r.status,0);assert.equal(r.stdout.trim(),'PRODUCT_OK');
 await rename(path.join(root,'.auth-kit-offline'),path.join(root,'.auth-kit'));
 const m=spawnSync(process.execPath,['.auth-kit/verify.mjs','maintain'],{cwd:root,encoding:'utf8'});assert.equal(m.status,0,m.stderr);
}));
test('revision mismatch in amendment is rejected',()=>fixture(async({root,authorize})=>{
 await assert.rejects(advanceProduct(root,{...await authorize(),revision:'stale'}),/REVISION_MISMATCH/);
}));
test('observer mutation rejected after establishment',()=>fixture(async({root})=>{
 await writeFile(path.join(root,'.auth-kit/observe.mjs'),observe+'\n//changed');
 assert.equal((await verifyProduct(root)).error,'OBSERVER_DRIFT');
}));

test('maintenance validates older compatible catalog history without rewriting it',()=>fixture(async({root})=>{
 const eventPath=path.join(root,'.auth-kit/history/000001.json'),baselinePath=path.join(root,'.auth-kit/baseline/000001.json'),contractPath=path.join(root,'.auth-kit/contract.json');
 const e=JSON.parse(await readFile(eventPath)),b=JSON.parse(await readFile(baselinePath)),c=JSON.parse(await readFile(contractPath));
 b.catalogVersion='1';e.catalogVersion='1';e.baselineDigest=hash(b);delete e.digest;e.digest=hash(e);c.head=e.digest;
 await writeFile(baselinePath,JSON.stringify(b));await writeFile(eventPath,JSON.stringify(e));await writeFile(contractPath,JSON.stringify(c));
 const before=await readFile(eventPath,'utf8');
 const report=await verifyProduct(root);assert.equal(report.verification,'PASS');assert.deepEqual(report.catalog_migration.fromVersions,['1']);
 assert.equal(await readFile(eventPath,'utf8'),before);
}));
test('catalog semantics removed from current version block instead of silently passing',()=>fixture(async({root})=>{
 const p=path.join(root,'.auth-kit/history/000001.json'),cp=path.join(root,'.auth-kit/contract.json');
 const e=JSON.parse(await readFile(p)),c=JSON.parse(await readFile(cp));
 e.catalog[0].checks.push('old_obligation_no_longer_represented');delete e.digest;e.digest=hash(e);c.head=e.digest;
 await writeFile(p,JSON.stringify(e));await writeFile(cp,JSON.stringify(c));
 const report=await verifyProduct(root);assert.equal(report.verification,'INDETERMINATE');assert.equal(report.error,'CATALOG_MIGRATION_REQUIRED');
}));
test('fresh evidence with wrong product/revision is rejected before establishment',()=>fixture(async({root})=>{
 await writeFile(path.join(root,'.auth-kit/observe.mjs'),observe.replace('revision:binding.revision',"revision:'stale'"));
 assert.equal((await verifyProduct(root)).error,'EVIDENCE_BINDING_MISMATCH');
},{established:false}));
test('generic setup CLI installs gate and durable bundle without consumer-specific dispatch',async()=>{
 const root=await mkdtemp(path.join(tmpdir(),'auth-generic-cli-'));
 try {
  await writeFile(path.join(root,'config.json'),JSON.stringify({app:{id:'new-product',name:'New'},providers:[],allowedOrigins:[],redirects:{postLoginPath:'/done'}}));
  const cli=new URL('./auth-cli.mjs',import.meta.url);
  const r=spawnSync(process.execPath,[fileURLToPath(cli),'setup','--repo',root,'--app','new-product','--config',path.join(root,'config.json'),'--authorize'],{encoding:'utf8'});
  assert.equal(r.status,0,r.stderr);
  assert.equal((await inspectProductBundle(root)).contract.state,'UNESTABLISHED');
  assert.equal((await verifyProduct(root)).verification,'FAIL');
 }finally{await rm(root,{recursive:true,force:true});}
});
