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
    assert.equal(result.status, 0, result.stderr);
    const report = JSON.parse(result.stdout);
    assert.equal(report.verification, 'PASS');
    assert.equal(report.verifiedAfterAct, true);
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
