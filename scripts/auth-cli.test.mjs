import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { CAPABILITIES } from './auth-capability-catalog.mjs';

const cli = fileURLToPath(new URL('./auth-cli.mjs', import.meta.url));
function run(args) { return spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8', timeout: 5000, env: process.env }); }

test('help advertises only transient native and read-only wizard surfaces', () => {
  const result = run(['--help']);
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /auth native <discover\|assess\|plan\|align-plan\|apply\|verify\|repair\|migrate\|recover>/);
  assert.doesNotMatch(result.stdout, /auth setup|auth runtime|auth observer/);
});

test('removed persistent control-plane commands fail closed', () => {
  for (const command of ['setup', 'validate', 'runtime', 'product', 'observer', 'acceptance']) {
    const result = run([command]);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /LEGACY_PERSISTENT_AUTH_COMMAND_REMOVED_USE_NATIVE_WORKFLOW/);
  }
});

test('wizard ACT requires authorization and never runs arbitrary repairs', () => {
  for (const authorized of [false, true]) {
    const result = run(['wizard', '--adapter', '/does-not-exist.json', '--operator', 'ACT', ...(authorized ? ['--authorize'] : [])]);
    assert.equal(result.status, 2);
    const report = JSON.parse(result.stdout);
    assert.equal(report.error, authorized ? 'NO_SUPPORTED_REPAIR' : 'AUTHORIZATION_REQUIRED');
    assert.deepEqual(report.changedFiles, []);
    assert.equal(report.blockerHandoffs[0].reasonCode, report.error);
  }
});

test('ACT handoff preserves a declared capability without supporting mutations', () => {
  const result = run(['wizard', '--adapter', '/does-not-exist.json', '--operator', 'ACT', '--capability', 'signin', '--authorize']);
  assert.equal(result.status, 2);
  const report = JSON.parse(result.stdout);
  assert.equal(report.capabilityId, 'signin');
  assert.equal(report.blockerHandoffs[0].capabilityId, 'signin');
  assert.deepEqual(report.changedFiles, []);
  const unknown = run(['wizard', '--adapter', '/does-not-exist.json', '--operator', 'ACT', '--capability', 'invented-capability']);
  assert.equal(unknown.status, 1);
  assert.match(unknown.stderr, /Unknown capability/);
});

test('wizard ACT executes only a registered bounded handler and verifies fresh observations', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'auth-cli-act-'));
  try {
    const adapterPath = path.join(directory, 'adapter.json');
    const adapter = { schemaVersion: 1, productId: 'fixture', revision: 'r1', capabilities: Object.fromEntries(CAPABILITIES.map(({ id }) => [id, { applicability: 'FALSE', reason: 'Fixture excludes this capability', implementation: 'NOT_ESTABLISHED' }])) };
    const signin = CAPABILITIES.find(({ id }) => id === 'signin');
    adapter.capabilities.signin = { applicability: 'TRUE', implementation: 'ESTABLISHED', evidence: ['fixture:before'], checks: Object.fromEntries(signin.checks.map((id) => [id, id !== 'explicit_entry'])) };
    await writeFile(adapterPath, JSON.stringify(adapter));
    const modulePath = path.join(directory, 'registered-act.mjs');
    await writeFile(modulePath, `import {readFile,writeFile} from 'node:fs/promises';\nconst adapterPath=${JSON.stringify(adapterPath)};\nexport const handlers=new Map([['signin',async()=>{const a=JSON.parse(await readFile(adapterPath,'utf8'));a.capabilities.signin.checks.explicit_entry=true;a.capabilities.signin.evidence=['fixture:after'];await writeFile(adapterPath,JSON.stringify(a));}]]);\nexport const observe=async c=>{const a=JSON.parse(await readFile(adapterPath,'utf8'));return {...a,postRepairProof:{runId:c.runId,capabilityId:c.capabilityId,revision:c.resultingRevision,observedAt:Date.now(),checks:Object.keys(a.capabilities.signin.checks)}};};\n`);
    const blocked = run(['wizard', '--adapter', adapterPath, '--operator', 'ACT', '--capability', 'signin', '--repo', directory, '--act-module', modulePath]);
    assert.equal(blocked.status, 2);
    assert.equal(JSON.parse(blocked.stdout).blockerHandoffs[0].executionClassification, 'EXTERNAL_ACTION_REQUIRED');
    const result = run(['wizard', '--adapter', adapterPath, '--operator', 'ACT', '--capability', 'signin', '--repo', directory, '--act-module', modulePath, '--authorize']);
    assert.equal(result.status, 2, result.stderr);
    const report = JSON.parse(result.stdout);
    assert.equal(report.verification, 'PASS');
    assert.equal(report.verifiedAfterAct, true);
    assert.equal(report.rptvl.result, 'NOT_VERIFIED');
    assert.equal(report.durableCompletion, false);
    assert.deepEqual(report.blockerHandoffs, []);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('wizard rejects unknown operators before reading adapters', () => {
  const result = run(['wizard', '--adapter', '/does-not-exist.json', '--operator', 'DELETE']);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /supported --operator/);
});

test('wizard defaults to fail-closed VERIFY and OBSERVE accepts arbitrary products', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'auth-wizard-cli-'));
  try {
    const adapter = path.join(directory, 'adapter.json');
    await writeFile(adapter, JSON.stringify({ schemaVersion: 1, productId: 'arbitrary-product', revision: 'r1', capabilities: {} }));
    const verification = run(['wizard', '--adapter', adapter]);
    assert.equal(verification.status, 2, verification.stderr);
    assert.equal(JSON.parse(verification.stdout).verification, 'INDETERMINATE');
    const observation = run(['wizard', '--adapter', adapter, '--operator', 'OBSERVE', '--repo', directory, '--outcome', 'Restore login']);
    assert.equal(observation.status, 0, observation.stderr);
    assert.ok(JSON.parse(observation.stdout).blockerHandoffs.length > 0);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('PASS does not invent a blocker handoff', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'auth-wizard-pass-'));
  try {
    const adapter = path.join(directory, 'adapter.json');
    await writeFile(adapter, JSON.stringify({ schemaVersion: 1, productId: 'fixture', revision: 'r1', capabilities: Object.fromEntries(CAPABILITIES.map(({ id }) => [id, { applicability: 'FALSE', reason: 'Not offered', implementation: 'NOT_ESTABLISHED' }])) }));
    const result = run(['wizard', '--adapter', adapter]);
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(JSON.parse(result.stdout).blockerHandoffs, []);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('release gate requires current runtime evidence and externally pinned history',async()=>{
 const { evaluateAdapter }=await import('./auth-wizard.mjs');const { digest }=await import('./auth-conformance-binding.mjs');
 const root=await mkdtemp(path.join(os.tmpdir(),'auth-release-'));try{
 const adapter={schemaVersion:1,productId:'release-fixture',revision:'r2',capabilities:Object.fromEntries(CAPABILITIES.map(c=>[c.id,{applicability:'FALSE',reason:'Not adopted'}]))};adapter.capabilities.signin={applicability:'TRUE',implementation:'ESTABLISHED',evidence:['synthetic'],checks:Object.fromEntries(CAPABILITIES.find(c=>c.id==='signin').checks.map(id=>[id,true]))};
 const baseline=evaluateAdapter({...adapter,revision:'r1'});const report=evaluateAdapter(adapter);const runtime={schema:'life.auth.runtime-acceptance/1',productId:adapter.productId,revision:adapter.revision,runId:'synthetic',issuedAt:new Date(Date.now()-1000).toISOString(),expiresAt:new Date(Date.now()+60000).toISOString(),checks:report.profile_required_checks.filter(c=>c.applicability==='TRUE').map(c=>({capabilityId:c.capabilityId,checkId:c.checkId,result:'PASS',references:['synthetic:test']}))};
 for(const [name,data] of Object.entries({adapter,baseline,runtime}))await writeFile(path.join(root,name+'.json'),JSON.stringify(data));
 const base=['wizard','--adapter',path.join(root,'adapter.json'),'--release'];assert.equal(run(base).status,2);
 const args=[...base,'--runtime-evidence',path.join(root,'runtime.json'),'--runtime-digest',digest(runtime),'--require-history','--baseline',path.join(root,'baseline.json'),'--baseline-digest',digest(baseline)];const passed=run(args);assert.equal(passed.status,0,passed.stderr);assert.equal(JSON.parse(passed.stdout).release_acceptance,'PASS');
 await writeFile(path.join(root,'baseline.json'),JSON.stringify({...baseline,capabilities:[]}));const rejected=run(args);assert.equal(rejected.status,1);assert.match(rejected.stderr,/PIN_MISMATCH/);
 }finally{await rm(root,{recursive:true,force:true});}
});

test('every native operation rejects release flags and unknown options before accessing a target', () => {
  for (const operation of ['discover','assess','plan','align-plan','apply','verify','repair','migrate','recover']) {
    for (const [flag,values] of [['--release',[]],['--runtime-evidence',['missing.json']],['--runtime-digest',['abc']],['--require-history',[]],['--baseline',['missing.json']],['--baseline-digest',['abc']],['--authority-evidence',['missing.json']],['--authority-sha256',['abc']],['--profile',['RELYING_PARTY_CLIENT']]]) {
      const result=run(['native',operation,'--repo','/does-not-exist',flag,...values]);
      assert.equal(result.status,1);assert.match(result.stderr,/UNSUPPORTED_NATIVE_RELEASE_FLAG/);assert.match(result.stderr,/auth wizard --operator VERIFY --release/);assert.equal(result.stdout,'');
    }
    const unknown=run(['native',operation,'--repo','/does-not-exist','--invented','value']);assert.equal(unknown.status,1);assert.match(unknown.stderr,/UNSUPPORTED_FLAG/);
  }
});

test('flags for another native operation are rejected, including ignored safety requests', () => {
  for (const args of [
    ['native','repair','--repo','/missing','--dry-run','--authorize'],
    ['native','verify','--repo','/missing','--authorize'],
    ['native','discover','--repo','/missing','--receipt','missing.json'],
    ['native','plan','--repo','/missing','--auth-role','RELYING_PARTY'],
  ]) {const result=run(args);assert.equal(result.status,1);assert.match(result.stderr,/UNSUPPORTED_FLAG/);assert.equal(result.stdout,'');}
});

test('both CLI surfaces reject malformed, duplicate, and unsupported flags', () => {
  for (const prefix of [['native','verify','--repo','/missing'],['wizard','--adapter','/missing']]) {
    for (const [extra,error] of [
      [['--typo','value'],/UNSUPPORTED_FLAG/],
      [[prefix.find(value=>value.startsWith('--')),'again'],/DUPLICATE_FLAG/],
      [['unexpected'],/UNEXPECTED_POSITIONAL_ARGUMENT/],
      [[prefix[0]==='native'?'--receipt':'--baseline'],/FLAG_VALUE_REQUIRED/],
      [[prefix[0]==='native'?'--receipt':'--baseline','--unknown'],/FLAG_VALUE_REQUIRED/],
    ]) {const result=run([...prefix,...extra]);assert.equal(result.status,1);assert.match(result.stderr,error);}
  }
  const booleanValue=run(['wizard','--adapter','/missing','--release','false']);assert.equal(booleanValue.status,1);assert.match(booleanValue.stderr,/UNEXPECTED_POSITIONAL_ARGUMENT/);
  for (const args of [['--operator','VERIFY','--authorize'],['--operator','OBSERVE','--act-module','missing.mjs'],['--operator','ACT','--runtime-evidence','missing.json']]) {
    const result=run(['wizard','--adapter','/missing',...args]);assert.equal(result.status,1);assert.match(result.stderr,/ACT_FLAGS_REQUIRE_ACT_OPERATOR|RUNTIME_EVIDENCE_REQUIRES_SEPARATE_VERIFY/);
  }
});

test('native source-only PASS remains valid but --release cannot silently inherit that success', async () => {
  const {createHash}=await import('node:crypto');const {realpath,readFile}=await import('node:fs/promises');const {digest}=await import('./auth-conformance-binding.mjs');const {RECEIPT_SCHEMA}=await import('./auth-native-wizard.mjs');
  const root=await realpath(await mkdtemp(path.join(os.tmpdir(),'auth-source-scope-')));try {
    const hash=x=>createHash('sha256').update(x).digest('hex');const source='throw new Error("synthetic unavailable runtime");';await writeFile(path.join(root,'app.mjs'),source);
    const payload={schema:RECEIPT_SCHEMA,targetBinding:hash(root),files:{'app.mjs':hash(source)}};const receipt=path.join(root,'receipt.json');const bytes=JSON.stringify({...payload,receiptDigest:digest(payload)});await writeFile(receipt,bytes);
    const args=['native','verify','--repo',root,'--receipt',receipt];const valid=run(args);assert.equal(valid.status,0,valid.stderr);const report=JSON.parse(valid.stdout);assert.equal(report.verification_scope,'SOURCE_INTEGRITY');assert.equal(report.assurance.runtime_acceptance,'INDETERMINATE');
    const invalid=run([...args,'--release']);assert.equal(invalid.status,1);assert.match(invalid.stderr,/UNSUPPORTED_NATIVE_RELEASE_FLAG/);assert.equal(await readFile(receipt,'utf8'),bytes);assert.equal(await readFile(path.join(root,'app.mjs'),'utf8'),source);
  } finally {await rm(root,{recursive:true,force:true});}
});

test('reviewed repair flags require authorization, digest, and exclusive registry selection', () => {
  const base = ['wizard','--adapter','/missing','--operator','ACT','--repo','/tmp','--capability','signin','--repair-spec','/missing'];
  for (const [flags, error] of [[[], /EXPLICIT_AUTHORIZATION_REQUIRED/], [['--authorize'], /REVIEWED_SPEC_AND_DIGEST_REQUIRED/], [['--authorize','--act-module','/missing'], /REPAIR_SPEC_CONTEXT_INVALID/]]) {
    const result = run([...base,...flags]); assert.equal(result.status,1); assert.match(result.stderr,error);
  }
  const result=run(['wizard','--adapter','/missing','--operator','VERIFY','--repair-spec','/missing']);
  assert.equal(result.status,1); assert.match(result.stderr,/ACT_FLAGS_REQUIRE_ACT_OPERATOR/);
});

test('reviewed spec digest mismatch fails before reading product or adapter', async () => {
  const directory=await mkdtemp(path.join(os.tmpdir(),'auth-cli-spec-'));
  try {
    const spec=path.join(directory,'spec.json'); await writeFile(spec,'{}');
    const result=run(['wizard','--adapter','/missing','--operator','ACT','--repo','/missing','--capability','signin','--authorize','--repair-spec',spec,'--repair-sha256','0'.repeat(64)]);
    assert.equal(result.status,1); assert.match(result.stderr,/REVIEWED_SPEC_DIGEST_MISMATCH/);
  } finally {await rm(directory,{recursive:true,force:true});}
});
test('reviewed repair produces scoped lane evidence and successful CLI result without sibling fabrication', async () => {
 const {createHash}=await import('node:crypto');const hash=x=>createHash('sha256').update(x).digest('hex');const {LANES}=await import('./auth-verification-lane.mjs');
 const root=await mkdtemp(path.join(os.tmpdir(),'auth-cli-lane-'));
 try {
  const adapter={schemaVersion:1,productId:'fixture',revision:'r1',capabilities:Object.fromEntries(CAPABILITIES.map(c=>[c.id,{applicability:'FALSE',reason:'fixture scope'}]))};
  const checks=CAPABILITIES.find(c=>c.id==='signin').checks;adapter.capabilities.signin={applicability:'TRUE',implementation:'ESTABLISHED',checks:Object.fromEntries(checks.map(x=>[x,false])),evidence:['fixture']};
  const behavior="if(require('fs').readFileSync('source','utf8')!=='correct')process.exit(1)";
  await writeFile(path.join(root,'source'),'broken');await writeFile(path.join(root,'behavior.cjs'),behavior);await writeFile(path.join(root,'adapter.json'),JSON.stringify(adapter));
  const {productTestSource}=await import('./auth-product-test.mjs');const {mkdir}=await import('node:fs/promises');await mkdir(path.join(root,'test'));await writeFile(path.join(root,'test/auth-behavior.mjs'),productTestSource({argv:['$NODE','behavior.cjs'],timeoutMs:2000}));
  const command={argv:[process.execPath,'test/auth-behavior.mjs'],timeoutMs:2000,maxOutputBytes:4096};
  const spec={schemaVersion:1,productId:'fixture',revision:'r1',capabilityId:'signin',file:'source',beforeSha256:hash('broken'),afterSha256:hash('correct'),replacement:'correct',checks,evidenceFiles:[{path:'behavior.cjs',sha256:hash(behavior)}],command:{executable:process.execPath,args:['behavior.cjs'],timeoutMs:2000,maxOutputBytes:4096}};
  spec.verificationSpec={schema:'life.auth.verification-lane/1',productId:'fixture',revision:'r1',evidenceScope:'isolated',requestedOutcome:'Synthetic contract success',authorizedPaths:['source'],inputs:[...spec.evidenceFiles,{path:'test/auth-behavior.mjs',sha256:hash(await (await import('node:fs/promises')).readFile(path.join(root,'test/auth-behavior.mjs')))}],normalBuildGate:'test/auth-behavior.mjs',normalBuild:command,lanes:LANES.map(id=>({id,required:true,checks:checks.map(x=>`signin/${x}`),command}))};
  const bytes=JSON.stringify(spec);await writeFile(path.join(root,'repair.json'),bytes);
  const result=run(['wizard','--operator','ACT','--authorize','--repo',root,'--adapter',path.join(root,'adapter.json'),'--capability','signin','--repair-spec',path.join(root,'repair.json'),'--repair-sha256',hash(bytes)]);
  assert.equal(result.status,0,result.stderr);const report=JSON.parse(result.stdout);assert.equal(report.durableCompletion,true);assert.equal(report.rptvl.result,'VERIFIED');assert.equal(report.rptvl.evidenceScope,'isolated');
 }finally{await rm(root,{recursive:true,force:true});}
});
