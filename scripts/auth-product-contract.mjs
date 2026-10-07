/** Durable, product-local verification. No authentication runtime or network service. */
import { readFile, writeFile, mkdir, readdir, rename, lstat, realpath, rm } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash, randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { collectProductInventory } from './auth-product-inventory.mjs';
import { runGit, filesystemPath } from './auth-git.mjs';
import { evaluateAdapter } from './auth-wizard.mjs';
import { CAPABILITIES, CATALOG_VERSION, COMPATIBLE_BASELINE_VERSIONS } from './auth-capability-catalog.mjs';
import { createBlockerHandoffs } from './auth-blocker-handoff.mjs';

export const PRODUCT_CONTRACT = 'life.auth.product-contract/1';
const kit = '.auth-kit';
const canonical = v => Array.isArray(v) ? v.map(canonical) : v && typeof v === 'object'
  ? Object.fromEntries(Object.keys(v).sort().map(k => [k, canonical(v[k])])) : v;
export const hash = v => createHash('sha256').update(typeof v === 'string' || Buffer.isBuffer(v) ? v : JSON.stringify(canonical(v))).digest('hex');
const json = v => JSON.stringify(v, null, 2) + '\n';
const readJson = async p => JSON.parse(await readFile(p, 'utf8'));
const fail = code => { throw Object.assign(new Error(code), { code }); };
const text = v => typeof v === 'string' && v.trim().length > 0;
const runtimeFiles = ['auth-product-inventory.mjs','auth-git.mjs','auth-product-contract.mjs','auth-wizard.mjs','auth-capability-catalog.mjs','auth-lifecycle.mjs','auth-verification-profiles.mjs','auth-evidence-ownership.mjs','auth-conformance-binding.mjs','auth-blocker-handoff.mjs'];
const verifyScript = `import { runProductCli } from './runtime/auth-product-contract.mjs';\nawait runProductCli(process.argv.slice(2), new URL('../', import.meta.url));\n`;
const gateScript = `// Invoke this from a required build/release check. No AUTH service needed.\nimport './verify.mjs';\n`;
const workflow = `name: AUTH product contract\non: [pull_request, push, workflow_dispatch]\npermissions:\n  contents: read\njobs:\n  auth-product-contract:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - uses: actions/setup-node@v4\n        with:\n          node-version: 20\n      - run: node .auth-kit/ci.mjs verify\n`;

async function safeFile(root, relative) {
  if (!text(relative) || path.isAbsolute(relative) || relative.includes('\\') || relative.split('/').some(p => p === '..' || p === '')) fail('UNSAFE_BUNDLE_PATH');
  const target = filesystemPath(path.join(root, relative));
  // Reject symlinks on every component, including directories.
  let current = filesystemPath(root);
  for (const part of relative.split('/')) { current = path.join(current, part); if ((await lstat(current)).isSymbolicLink()) fail('SYMLINK_NOT_ALLOWED'); }
  if (!(await lstat(target)).isFile()) fail('EXPECTED_FILE');
  return target;
}

async function checkDirectories(root, relative, allowMissing=false) {
  let current=root;
  for(const part of relative.split('/')) {
    current=path.join(current,part);
    try {const entry=await lstat(current);if(entry.isSymbolicLink()||!entry.isDirectory())fail('UNSAFE_BUNDLE_DIRECTORY');}
    catch(e){if(allowMissing&&e.code==='ENOENT')return;throw e;}
  }
}

async function hashes(root, paths) {
  const result = {};
  for (const p of [...paths].sort()) result[p] = hash(await readFile(await safeFile(root,p)));
  return result;
}
const artifactPaths = runtimeFiles.map(f => `${kit}/runtime/${f}`).concat([`${kit}/verify.mjs`,`${kit}/ci.mjs`,'.github/workflows/auth-product-contract.yml']);
async function atomicJson(p,v) { const temp = `${p}.${randomUUID()}.tmp`; await writeFile(temp,json(v),{flag:'wx'}); await rename(temp,p); }
const catalogSnapshot = () => CAPABILITIES.map(c => ({ id:c.id, family:c.family, checks:[...c.checks] }));

/** Setup is unestablished until fresh evidence is explicitly approved. Never reset a bundle. */
export async function installProductBundle(root, { authorized = false, productId, adapterSource, gateSource, inputs = { artifact:[], configuration:[] }, profile = 'FULL_AUTHORITY_CONFORMANCE' } = {}) {
  if(authorized!==true)fail('SETUP_AUTHORIZATION_REQUIRED');
  root = await realpath(root);
  if (!text(productId) || !Array.isArray(inputs.artifact) || !Array.isArray(inputs.configuration)) fail('INVALID_INSTALL_INPUT');
  try { await lstat(path.join(root,kit,'contract.json')); fail('CONTRACT_ALREADY_EXISTS'); } catch(e) { if(e.code !== 'ENOENT') throw e; }
  // Preserve existing product workflows: installation never overwrites them.
  try { await lstat(path.join(root,'.github/workflows/auth-product-contract.yml')); fail('GATE_ALREADY_EXISTS'); } catch(e) { if(e.code !== 'ENOENT') throw e; }
  for(const dir of [kit,`${kit}/runtime`,`${kit}/baseline`,`${kit}/history`,`${kit}/reports`,'.github/workflows']) await checkDirectories(root,dir,true);
  for(const p of [...artifactPaths,`${kit}/observe.mjs`,`${kit}/provenance.json`]) {
    try{await lstat(path.join(root,p));fail('INSTALL_FILE_COLLISION');}catch(e){if(e.code!=='ENOENT')throw e;}
  }
  await hashes(root,[...inputs.artifact,...inputs.configuration]);
  const installedWorkflow=gateSource?await readFile(gateSource,'utf8'):workflow;
  if(!installedWorkflow.includes('node .auth-kit/ci.mjs verify'))fail('CI_GATE_COMMAND_REQUIRED');
  const observer = adapterSource ? await readFile(adapterSource,'utf8') : `// Replace before establishment with the product-owned, read-only evidence collector.\n// Read binding context JSON from stdin; emit {adapter, binding, independence}.\nthrow new Error('PRODUCT_OBSERVER_REQUIRED');\n`;
  for (const dir of ['runtime','baseline','history','reports']) await mkdir(path.join(root,kit,dir),{recursive:true});
  await mkdir(path.join(root,'.github/workflows'),{recursive:true});
  for (const f of runtimeFiles) await writeFile(path.join(root,kit,'runtime',f),await readFile(new URL(f,import.meta.url)),{flag:'wx'});
  await writeFile(path.join(root,kit,'observe.mjs'),observer,{flag:'wx'});
  await writeFile(path.join(root,kit,'verify.mjs'),verifyScript,{flag:'wx'});
  await writeFile(path.join(root,kit,'ci.mjs'),gateScript,{flag:'wx'});
  await writeFile(path.join(root,'.github/workflows/auth-product-contract.yml'),installedWorkflow,{flag:'wx'});
  const provenance={contract:PRODUCT_CONTRACT,productId,catalogVersion:CATALOG_VERSION,files:await hashes(root,artifactPaths)};
  await writeFile(path.join(root,kit,'provenance.json'),json(provenance),{flag:'wx'});
  const c={contract:PRODUCT_CONTRACT,productId,state:'UNESTABLISHED',profile,inputs,provenanceDigest:hash(provenance),head:null,sequence:0};
  await writeFile(path.join(root,kit,'contract.json'),json(c),{flag:'wx'});
  return c;
}

function protectedPolicy(c) { return {contract:c.contract,productId:c.productId,profile:c.profile,inputs:c.inputs,provenanceDigest:c.provenanceDigest}; }
function obligations(report) {
  return report.capabilities.filter(c=>c.applicability==='TRUE').flatMap(c=>c.checks.filter(x=>x.result==='PASS').map(x=>({capabilityId:c.id,checkId:x.id})));
}
const obligationKey = x => `${x.capabilityId}/${x.checkId}`;
function mergeObligations(old,report,retired=[]) {
  const removed=new Set(retired);
  const map=new Map(old.filter(x=>!removed.has(obligationKey(x))).map(x=>[obligationKey(x),x]));
  for(const x of obligations(report))map.set(obligationKey(x),x);
  return [...map.values()].sort((a,b)=>obligationKey(a).localeCompare(obligationKey(b)));
}
function changedChecks(previous,current) {
  const a=new Map((previous?.capabilities||[]).flatMap(c=>c.checks.map(x=>[`${c.id}/${x.id}`,{applicability:c.applicability,implementation:c.implementation,result:x.result}])));
  const b=new Map(current.capabilities.flatMap(c=>c.checks.map(x=>[`${c.id}/${x.id}`,{applicability:c.applicability,implementation:c.implementation,result:x.result}])));
  return [...new Set([...a.keys(),...b.keys()])].sort().filter(k=>hash(a.get(k)||null)!==hash(b.get(k)||null)).map(key=>({key,before:a.get(key)||null,after:b.get(key)||null}));
}
export function validateCatalogMigration(oldCatalog, oldVersion) {
  if(!COMPATIBLE_BASELINE_VERSIONS.includes(oldVersion))return false;
  const current=new Map(catalogSnapshot().map(c=>[c.id,c]));
  return oldCatalog.every(c=>current.get(c.id)?.family===c.family && c.checks.every(id=>current.get(c.id).checks.includes(id)));
}

export async function inspectProductBundle(root,{checkpoint}={}) {
  root=await realpath(root);
  const c=await readJson(await safeFile(root,`${kit}/contract.json`));
  if(c.contract!==PRODUCT_CONTRACT)fail('CONTRACT_MIGRATION_REQUIRED');
  if(!['UNESTABLISHED','ESTABLISHED'].includes(c.state)||!text(c.productId))fail('INVALID_CONTRACT');
  const p=await readJson(await safeFile(root,`${kit}/provenance.json`));
  if(hash(p)!==c.provenanceDigest || p.productId!==c.productId || hash(await hashes(root,artifactPaths))!==hash(p.files))fail('VERIFIER_OR_GATE_DRIFT');
  await safeFile(root,`${kit}/observe.mjs`);
  for(const dir of ['history','baseline','reports'])await checkDirectories(root,`${kit}/${dir}`);
  const names=(await readdir(path.join(root,kit,'history'))).sort();
  const baselines=(await readdir(path.join(root,kit,'baseline'))).sort();
  if(c.state==='UNESTABLISHED') {
    if(c.head!==null||c.sequence!==0||names.length||baselines.length||checkpoint)fail('HISTORY_RESET');
    return {root,contract:c,events:[],latest:null};
  }
  if(!c.head||!Number.isInteger(c.sequence)||c.sequence<1||names.length!==c.sequence||baselines.length!==c.sequence)fail('HISTORY_TRUNCATED');
  let previous=null; const events=[]; let historical=[];
  for(let i=0;i<names.length;i++) {
    if(names[i]!==`${String(i+1).padStart(6,'0')}.json`)fail('HISTORY_SEQUENCE_MISMATCH');
    const e=await readJson(await safeFile(root,`${kit}/history/${names[i]}`));
    const {digest,...payload}=e;
    if(hash(payload)!==digest||e.previous!==previous||e.previousBaselineDigest!==(events.at(-1)?.baselineDigest||null)||e.sequence!==i+1||e.productId!==c.productId||hash(e.policy)!==hash(protectedPolicy(c)))fail('HISTORY_TAMPERED');
    if(!e.authorization || e.authorization.authorized!==true || e.authorization.operation!==e.operation || e.authorization.productId!==c.productId || e.authorization.revision!==e.revision || e.authorization.expectedHead!==previous || !text(e.authorization.operator)||!text(e.authorization.reason)||!text(e.authorization.runId))fail('INVALID_HISTORY_AUTHORIZATION');
    if((i===0 && e.operation!=='establish') || (i>0 && !['advance','amend'].includes(e.operation)))fail('INVALID_HISTORY_OPERATION');
    if(!Array.isArray(e.retired) || new Set(e.retired).size!==e.retired.length || e.retired.some(k=>!historical.some(x=>obligationKey(x)===k)))fail('INVALID_HISTORICAL_AMENDMENT');
    if(e.operation!=='amend' && e.retired.length)fail('UNAUTHORIZED_RETIREMENT');
    if(hash(e.authorization.retireChecks||[])!==hash(e.retired))fail('AMENDMENT_MISMATCH');
    const previousContract={...c,state:i===0?'UNESTABLISHED':'ESTABLISHED',head:previous,sequence:i};
    if(hash(previousContract)!==e.previousContractDigest||e.authorization.expectedContractDigest!==e.previousContractDigest||e.authorization.observerDigest!==e.observerDigest)fail('PREVIOUS_CONTRACT_MISMATCH');
    const baseline=await readJson(await safeFile(root,`${kit}/baseline/${names[i]}`));
    if(baseline.durability_verification!=='PASS'||hash(baseline)!==e.baselineDigest||baseline.productId!==c.productId||baseline.revision!==e.revision||!Array.isArray(baseline.capabilities)||!baseline.capabilities.length)fail('BASELINE_TAMPERED');
    if(hash(changedChecks(events.at(-1)?.baseline,baseline))!==hash(e.changedChecks))fail('CHANGE_HISTORY_MISMATCH');
    historical=mergeObligations(historical,baseline,e.retired);
    if(hash(historical)!==hash(e.obligations))fail('OBLIGATIONS_TAMPERED');
    events.push({...e,baseline}); previous=digest;
  }
  if(previous!==c.head || (checkpoint && checkpoint!==c.head))fail('CHECKPOINT_MISMATCH');
  const latest=events.at(-1);
  if(hash(await readFile(await safeFile(root,`${kit}/observe.mjs`)))!==latest.observerDigest)fail('OBSERVER_DRIFT');
  return {root,contract:c,events,latest};
}

async function currentBinding(root,c) {
  const git=args=>runGit(args,{cwd:root});
  if(await realpath(git(['rev-parse','--show-toplevel']).trim())!==await realpath(root))fail('PRODUCT_REPOSITORY_ROOT_REQUIRED');
  const commit=git(['rev-parse','HEAD']).trim();
  const source=await collectProductInventory(root);
  if(!c.inputs.artifact.length||!c.inputs.configuration.length)fail('ARTIFACT_CONFIGURATION_INPUTS_REQUIRED');
  const artifact=await hashes(root,c.inputs.artifact),configuration=await hashes(root,c.inputs.configuration);
  return {productId:c.productId,revision:hash({commit,source}),commit,artifactDigest:hash(artifact),configurationDigest:hash(configuration)};
}
async function observeProduct(state) {
  const binding=await currentBinding(state.root,state.contract);
  const observedAt=new Date().toISOString(),runId=randomUUID();
  const r=spawnSync(process.execPath,[path.join(state.root,kit,'observe.mjs')],{cwd:state.root,input:json({...binding,observedAt,runId}),encoding:'utf8',timeout:120000,maxBuffer:8*1024*1024});
  if(r.status!==0)fail('OBSERVATION_FAILED'); // Never echo stderr: adapters may accidentally expose credentials.
  let o;try{o=JSON.parse(r.stdout);}catch{fail('MALFORMED_OBSERVATION');}
  if(hash(o.binding)!==hash({...binding,observedAt,runId}) || o.adapter?.productId!==binding.productId||o.adapter?.revision!==binding.revision)fail('EVIDENCE_BINDING_MISMATCH');
  if(hash(await currentBinding(state.root,state.contract))!==hash(binding))fail('PRODUCT_CHANGED_DURING_OBSERVATION');
  return {...o,binding:{...binding,observedAt,runId}};
}
function historicalFailures(state,report,retired=[]) {
  const removed=new Set(retired),rows=new Map(report.capabilities.map(c=>[c.id,c]));
  return (state.latest?.obligations||[]).filter(x=>!removed.has(obligationKey(x))).filter(x=>{
    const c=rows.get(x.capabilityId);return c?.applicability!=='TRUE'||c.implementation!=='ESTABLISHED'||c.verification!=='PASS'||c.checks.find(k=>k.id===x.checkId)?.result!=='PASS';
  });
}
async function assess(state, {allowUnestablished=false,retired=[]}={}) {
  const o=await observeProduct(state);
  const fresh=await inspectProductBundle(state.root);
  if(hash(fresh.contract)!==hash(state.contract))fail('CONTRACT_CHANGED_DURING_OBSERVATION');
  const migration=state.events.every(e=>validateCatalogMigration(e.catalog,e.catalogVersion));
  let trustedAuthorityEvidence=[];
  const evidencePath=process.env.AUTH_PRODUCT_AUTHORITY_EVIDENCE;
  const expected=process.env.AUTH_PRODUCT_AUTHORITY_SHA256;
  if(evidencePath || expected) {
    if(!evidencePath || !/^[a-f0-9]{64}$/.test(expected||''))fail('AUTHORITY_EVIDENCE_TRUST_REQUIRED');
    const bytes=await readFile(evidencePath);if(hash(bytes)!==expected)fail('AUTHORITY_EVIDENCE_DIGEST_MISMATCH');
    trustedAuthorityEvidence=JSON.parse(bytes);
  }
  const report=evaluateAdapter(o.adapter,{verificationProfile:state.contract.profile,trustedAuthorityEvidence});
  const regressions=historicalFailures(state,report,retired);
  const independent=o.independence?.wizardStopped===true && o.independence?.authOrchestrationRequests===0 && o.independence?.runtimePassed===true && Array.isArray(o.independence?.evidence) && o.independence.evidence.length>0 && o.independence.evidence.every(text);
  const result=!migration?'INDETERMINATE':regressions.length?'FAIL':report.profile_verification!=='PASS'?report.profile_verification:!independent?'INDETERMINATE':state.contract.state!=='ESTABLISHED'&&!allowUnestablished?'INDETERMINATE':'PASS';
  const error=!migration?'CATALOG_MIGRATION_REQUIRED':regressions.length?'HISTORICAL_REGRESSION':!independent?'RUNTIME_INDEPENDENCE_UNPROVEN':state.contract.state!=='ESTABLISHED'&&!allowUnestablished?'UNESTABLISHED':undefined;
  const resultReport={...report,full_verification:regressions.length?'FAIL':report.full_verification,catalog_migration:{fromVersions:[...new Set(state.events.map(e=>e.catalogVersion))],toVersion:CATALOG_VERSION,strategy:'ADDITIVE_IDENTITY_ONLY',verification:migration?'PASS':'INDETERMINATE'},verification:result,durability_verification:result,...(error?{error}:{}),regressions:[...report.regressions,...regressions.map(x=>({id:x.capabilityId,checkId:x.checkId,before:'PASS',after:'NOT_PASS'}))],binding:o.binding,independence:o.independence||null,contractHead:state.contract.head,contractDigest:hash(state.contract),observerDigest:hash(await readFile(await safeFile(state.root,`${kit}/observe.mjs`)))};
  resultReport.blockerHandoffs=createBlockerHandoffs(resultReport,{repository:state.root,requestedOutcome:'Preserve established product authentication',verificationCommand:['node','.auth-kit/verify.mjs','verify']});
  if(error==='CATALOG_MIGRATION_REQUIRED') resultReport.blockerHandoffs=resultReport.blockerHandoffs.map(h=>({...h,nextOwner:'AUTH DEVELOPMENT',reasonCode:error,resumeCondition:'Reviewed semantics-preserving catalog migration is supported',instruction:'STOP; do not discard historical obligations or compensate with a product repair.'}));
  return resultReport;
}
async function saveReport(root,report) {
  await checkDirectories(root,`${kit}/reports`);
  const dir=path.join(root,kit,'reports');
  await writeFile(path.join(dir,`${randomUUID()}.json`),json(report),{flag:'wx'});
}
export async function verifyProduct(root,options={}) {
  try {const state=await inspectProductBundle(root,options);const report=await assess(state);await saveReport(root,report);return report;}
  catch(e){const status=e.code==='CONTRACT_MIGRATION_REQUIRED'?'INDETERMINATE':'FAIL';const report={verification:status,durability_verification:status,error:e.code && /^[A-Z_]+$/.test(e.code)?e.code:'BUNDLE_INVALID',capabilities:[],...((e.code?.startsWith('GIT_')||e.code==='PRODUCT_INVENTORY_UNSUPPORTED')&&e.diagnostic?{diagnostic:e.diagnostic}:{})};report.blockerHandoffs=createBlockerHandoffs(report,{repository:root});
    if(e.code==='CONTRACT_MIGRATION_REQUIRED') report.blockerHandoffs=report.blockerHandoffs.map(h=>({...h,nextOwner:'AUTH DEVELOPMENT',reasonCode:e.code,resumeCondition:'Supported contract schema migration',instruction:'STOP; preserve the existing contract and history.'}));
    // Do not recreate a deleted bundle merely to write a report.
    try{await safeFile(root,`${kit}/contract.json`);await saveReport(root,report);}catch{}return report;}
}
export async function advanceProduct(root,authorization,{checkpoint}={}) {
  const state=await inspectProductBundle(root,{checkpoint});
  const a=authorization;
  const observerDigest=hash(await readFile(await safeFile(state.root,`${kit}/observe.mjs`)));
  if(!a||a.authorized!==true||a.productId!==state.contract.productId||a.expectedHead!==state.contract.head||a.expectedContractDigest!==hash(state.contract)||a.observerDigest!==observerDigest||!text(a.operator)||!text(a.reason)||!text(a.runId)||!['establish','advance','amend'].includes(a.operation)||(!state.latest&&a.operation!=='establish')||(state.latest&&a.operation==='establish'))fail('CONTRACT_AUTHORIZATION_REQUIRED');
  const retired=a.retireChecks||[];
  if(!Array.isArray(retired)||new Set(retired).size!==retired.length||retired.some(k=>!(state.latest?.obligations||[]).some(x=>obligationKey(x)===k)))fail('INVALID_AMENDMENT');
  if(retired.length&&a.operation!=='amend')fail('AMENDMENT_AUTHORIZATION_REQUIRED');
  const report=await assess(state,{allowUnestablished:true,retired});
  if(report.binding.revision!==a.revision)fail('AUTHORIZATION_REVISION_MISMATCH');
  if(report.verification!=='PASS')fail(report.error||'VERIFICATION_REQUIRED');
  if(!state.latest && !obligations(report).length)fail('NO_VERIFIED_OBLIGATIONS');
  const sequence=state.contract.sequence+1, name=`${String(sequence).padStart(6,'0')}.json`;
  const payload={sequence,previousContractDigest:hash(state.contract),previous:state.contract.head,previousBaselineDigest:state.latest?.baselineDigest||null,baselineDigest:hash(report),productId:state.contract.productId,revision:report.revision,catalogVersion:CATALOG_VERSION,catalog:catalogSnapshot(),policy:protectedPolicy(state.contract),observerDigest:hash(await readFile(path.join(state.root,kit,'observe.mjs'))),operation:a.operation,retired,obligations:mergeObligations(state.latest?.obligations||[],report,retired),changedChecks:changedChecks(state.latest?.baseline,report),authorization:a,timestamp:new Date().toISOString(),runId:report.binding.runId,provenance:report.binding};
  const event={...payload,digest:hash(payload)};
  // Exclusive lock and compare-before-write. Interrupted writes fail closed; never reset history.
  const lock=path.join(state.root,kit,'advancement.lock');await writeFile(lock,a.runId,{flag:'wx'});
  try {
    if(hash(await readJson(path.join(state.root,kit,'contract.json')))!==hash(state.contract))fail('CONTRACT_CHANGED');
    const current=await currentBinding(state.root,state.contract);
    if(current.revision!==report.binding.revision||current.artifactDigest!==report.binding.artifactDigest||current.configurationDigest!==report.binding.configurationDigest)fail('PRODUCT_CHANGED_BEFORE_ADVANCEMENT');
    await writeFile(path.join(state.root,kit,'baseline',name),json(report),{flag:'wx'});
    await writeFile(path.join(state.root,kit,'history',name),json(event),{flag:'wx'});
    await atomicJson(path.join(state.root,kit,'contract.json'),{...state.contract,state:'ESTABLISHED',sequence,head:event.digest});
  } finally {await rm(lock);}
  return {verification:'PASS',head:event.digest,contractDigest:hash({...state.contract,state:'ESTABLISHED',sequence,head:event.digest}),sequence,operation:a.operation,report};
}
export async function runProductCli(argv,rootUrl) {
  const root=rootUrl instanceof URL?fileURLToPath(rootUrl):path.resolve(rootUrl||'.');
  const [operation='verify',...rest]=argv;
  try {
    if(rest.length>1 || !['verify','maintain','establish','advance','amend'].includes(operation))fail('INVALID_PRODUCT_COMMAND');
    let result;
    if(['verify','maintain'].includes(operation)){if(rest.length)fail('VERIFY_TAKES_NO_BASELINE');result=await verifyProduct(root,{checkpoint:process.env.AUTH_CONTRACT_CHECKPOINT});}
    else {if(!rest[0])fail('AUTHORIZATION_FILE_REQUIRED');const a=await readJson(path.resolve(rest[0]));if(a.operation!==operation)fail('AUTHORIZATION_OPERATION_MISMATCH');result=await advanceProduct(root,a,{checkpoint:process.env.AUTH_CONTRACT_CHECKPOINT});}
    console.log(json(result));if(result.verification!=='PASS')process.exitCode=2;
  }catch(e){console.error(e.code && /^[A-Z_]+$/.test(e.code)?e.code:'PRODUCT_CONTRACT_FAILED');process.exitCode=2;}
}
