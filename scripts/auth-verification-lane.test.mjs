import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { LANES, runVerificationLane } from './auth-verification-lane.mjs';
import { integrateProductBuild, productTestSource } from './auth-product-test.mjs';
const hash = x => createHash('sha256').update(x).digest('hex');
async function fixture(t) {
 const root = await fs.mkdtemp(path.join(os.tmpdir(),'auth-lane-')); t.after(()=>fs.rm(root,{recursive:true,force:true}));
 const body = "import fs from 'node:fs'; if(fs.readFileSync('behavior','utf8')!=='correct') process.exit(1);";
 await fs.writeFile(path.join(root,'test.mjs'),body); await fs.writeFile(path.join(root,'behavior'),'correct');
 const c={argv:['$NODE','test.mjs'],timeoutMs:2000,maxOutputBytes:4096};
 await fs.mkdir(path.join(root,'test'));
 const runner=productTestSource({argv:['$NODE','test.mjs'],timeoutMs:2000});await fs.writeFile(path.join(root,'test/auth-behavior.mjs'),runner);
 const binding={productId:'fixture',revision:'candidate'};
 const spec={schema:'life.auth.verification-lane/1',...binding,evidenceScope:'isolated',requestedOutcome:'Preserve protected behavior',authorizedPaths:['behavior'],inputs:[{path:'test.mjs',sha256:hash(body)},{path:'test/auth-behavior.mjs',sha256:hash(runner)}],normalBuildGate:'test/auth-behavior.mjs',normalBuild:{...c,argv:['$NODE','test/auth-behavior.mjs']},lanes:LANES.map(id=>({id,required:true,checks:['signin/explicit_entry'],command:c}))};
 return {root,spec,binding};
}
test('all required lanes execute and ordinary command rejects regression without auth',async t=>{
 const f=await fixture(t); assert.equal((await runVerificationLane(f)).result,'VERIFIED');
 await fs.writeFile(path.join(f.root,'unrelated'),'safe');assert.equal((await runVerificationLane(f)).result,'VERIFIED');
 await fs.writeFile(path.join(f.root,'behavior'),'broken');assert.equal((await runVerificationLane(f)).result,'FAIL');
 assert.equal(spawnSync(process.execPath,['test.mjs'],{cwd:f.root}).status,1);
});
for(const id of LANES)test(`${id} failure prevents VERIFIED`,async t=>{const f=await fixture(t);f.spec.lanes.find(x=>x.id===id).command={argv:['$NODE','-e','process.exit(9)'],timeoutMs:1000,maxOutputBytes:4096};assert.equal((await runVerificationLane(f)).result,'FAIL');});
test('missing executor and omitted spec never pass',async t=>{const f=await fixture(t);delete f.spec.lanes[0].command;assert.equal((await runVerificationLane(f)).result,'NOT_VERIFIED');delete f.spec;assert.equal((await runVerificationLane(f)).result,'NOT_VERIFIED');});
test('scope, revision, coverage and input tampering rejected',async t=>{const f=await fixture(t);await assert.rejects(runVerificationLane({...f,changedPaths:['other']}),/SCOPE_DRIFT/);await assert.rejects(runVerificationLane({...f,binding:{...f.binding,revision:'wrong'}}),/BINDING_INVALID/);const old=f.spec.lanes.pop();await assert.rejects(runVerificationLane(f),/BINDING_INVALID/);f.spec.lanes.push(old);await fs.writeFile(path.join(f.root,'test.mjs'),'process.exit(0)');await assert.rejects(runVerificationLane(f),/INPUT_DRIFT/);});
test('timeout and missing dependency are explicit',async t=>{const f=await fixture(t);f.spec.lanes[0].command={argv:['$NODE','-e','setInterval(()=>{},1000)'],timeoutMs:20,maxOutputBytes:4096};assert.equal((await runVerificationLane(f)).lanes[0].reason,'TIMEOUT');f.spec.lanes[0].command.argv=['/nonexistent/auth-test'];assert.equal((await runVerificationLane(f)).result,'BLOCKED');});
test('symlink inputs rejected, no external traversal',async t=>{const f=await fixture(t);await fs.rename(path.join(f.root,'test.mjs'),path.join(f.root,'actual.mjs'));await fs.symlink('actual.mjs',path.join(f.root,'test.mjs'));await assert.rejects(runVerificationLane(f),/INPUT_UNSAFE/);});
test('ordinary npm gate preserves original build, rejects regression and runs independently',async t=>{
 const f=await fixture(t);await fs.mkdir(path.join(f.root,'test'),{recursive:true});
 await fs.writeFile(path.join(f.root,'test/auth-behavior.mjs'),productTestSource({argv:['$NODE','test.mjs'],timeoutMs:2000}));
 const before=JSON.stringify({scripts:{build:'node -e "process.exit(0)"',other:'retained'}});
 const after=integrateProductBuild(before,{script:'build'});assert.equal(JSON.parse(after).scripts.other,'retained');
 await fs.writeFile(path.join(f.root,'package.json'),after);
 const run=()=>spawnSync('npm',['run','build'],{cwd:f.root,encoding:'utf8'});
 assert.equal(run().status,0);await fs.writeFile(path.join(f.root,'behavior'),'broken');assert.notEqual(run().status,0);
 assert.throws(()=>integrateProductBuild(after,{script:'build'}),/ALREADY_INTEGRATED/);
});
test('a command mutating candidate cannot verify itself',async t=>{const f=await fixture(t);f.spec.lanes[0].command.argv=['$NODE','-e',"require('fs').writeFileSync('behavior','modified')"];await assert.rejects(runVerificationLane(f),/CANDIDATE_DRIFT/);});
test('unknown checks and empty required scope fail closed',async t=>{const f=await fixture(t);f.spec.lanes[0].checks=['invented/check'];await assert.rejects(runVerificationLane(f),/CHECK_MAPPING/);f.spec.lanes.forEach(x=>x.required=false);await assert.rejects(runVerificationLane(f),/SCOPE_REQUIRED/);});
test('zero-exit normal build that omits the product runner cannot establish integration',async t=>{const f=await fixture(t);f.spec.normalBuild={argv:['$NODE','-e','process.exit(0)'],timeoutMs:1000,maxOutputBytes:4096};const report=await runVerificationLane(f);assert.equal(report.result,'NOT_VERIFIED');assert.equal(report.normalBuild.reason,'NORMAL_BUILD_GATE_NOT_EXECUTED');});
test('serialized or forged green report is not execution proof',async t=>{const {verifiedLane}=await import('./auth-verification-lane.mjs');const f=await fixture(t);const report=await runVerificationLane(f);assert.equal(verifiedLane(report),true);assert.equal(verifiedLane(JSON.parse(JSON.stringify(report))),false);assert.equal(verifiedLane({result:'VERIFIED'}),false);});
test('affected check coverage cannot be narrowed by the lane specification',async t=>{const f=await fixture(t);f.binding.requiredChecks=['signin/invalid_credentials_rejected'];await assert.rejects(runVerificationLane(f),/COVERAGE_INCOMPLETE/);});
test('issued report mutation and different execution binding cannot authorize completion',async t=>{
 const {verifiedLane}=await import('./auth-verification-lane.mjs'); const f=await fixture(t);
 const good=await runVerificationLane({...f,executionId:'current'});
 assert.equal(verifiedLane(good,{...f.binding,executionId:'current'}),true);
 assert.equal(verifiedLane(good,{executionId:'previous'}),false);
 assert.equal(verifiedLane(good,{productId:'other'}),false);
 good.lanes[0].result='FAIL';assert.equal(verifiedLane(good),false);
 f.spec.lanes[0].command={argv:['$NODE','-e','process.exit(1)'],timeoutMs:1000,maxOutputBytes:4096};
 const bad=await runVerificationLane(f);bad.result='VERIFIED';assert.equal(verifiedLane(bad),false);
});
test('timeout terminates inherited subprocess pipes and descendants', {skip:process.platform==='win32'},async t=>{
 const f=await fixture(t);
 const marker=path.join(f.root,'descendant-ran');
 f.spec.lanes[0].command={argv:['$NODE','-e',`require('child_process').spawn(process.execPath,['-e',${JSON.stringify(`setTimeout(()=>require('fs').writeFileSync(${JSON.stringify(marker)},'bad'),1200)`)}],{stdio:'inherit'});setInterval(()=>{},1000)`],timeoutMs:200,maxOutputBytes:4096};
 const report=await runVerificationLane(f);assert.equal(report.lanes[0].reason,'TIMEOUT');
 await new Promise(r=>setTimeout(r,1300));await assert.rejects(fs.stat(marker),{code:'ENOENT'});
});
test('ordinary build cannot bypass gate through original shell exit or comments',async t=>{
 const f=await fixture(t);await fs.writeFile(path.join(f.root,'behavior'),'broken');
 for(const original of ['exit 0','node -e "process.exit(0)" # comment']) {
  const bytes=integrateProductBuild(JSON.stringify({scripts:{build:original}}),{script:'build'});
  await fs.writeFile(path.join(f.root,'package.json'),bytes);
  assert.notEqual(spawnSync('npm',['run','build'],{cwd:f.root}).status,0);
 }
 assert.throws(()=>integrateProductBuild(JSON.stringify({scripts:{build:'exit 0','preauth:original:build':'exit 0'}}),{script:'build'}),/ALIAS_COLLISION/);
});
