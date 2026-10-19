import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { createExistingRepair } from './auth-existing-repair.mjs';
import { executeRepair } from './auth-wizard.mjs';
const hash = s => createHash('sha256').update(s).digest('hex');
async function fixture(t, testBody = "import fs from 'node:fs'; if(fs.readFileSync('auth.txt','utf8')!=='correct') process.exit(1);") {
 const root=await fs.mkdtemp(path.join(os.tmpdir(),'auth-bounded-')); t.after(()=>fs.rm(root,{recursive:true,force:true}));
 await fs.writeFile(path.join(root,'auth.txt'),'broken'); await fs.writeFile(path.join(root,'behavior.mjs'),testBody); await fs.writeFile(path.join(root,'unrelated'),'untouched');
 const adapter={schemaVersion:1,productId:'fixture',revision:'reviewed',authenticationRole:'IDENTITY_AUTHORITY',capabilities:{'providers.callback':{applicability:'TRUE',implementation:'ESTABLISHED',evidence:['fixture'],checks:{provider_callback_contract_preserved:false}}}};
 const spec={schemaVersion:1,productId:'fixture',revision:'reviewed',capabilityId:'providers.callback',file:'auth.txt',beforeSha256:hash('broken'),afterSha256:hash('correct'),replacement:'correct',checks:['provider_callback_contract_preserved'],evidenceFiles:[{path:'behavior.mjs',sha256:hash(testBody)}],command:{executable:process.execPath,args:['behavior.mjs'],timeoutMs:2000,maxOutputBytes:4096}};
 return {root,adapter,spec};
}
const auth=f=>({authorized:true,productId:f.adapter.productId,revision:f.adapter.revision,capabilityId:f.spec.capabilityId});
async function act(f, kit, authorization=auth(f)) { return executeRepair(f.adapter,{capabilityId:f.spec.capabilityId,authorization,...kit}); }
test('existing machinery applies bounded repair and does not fabricate sibling proof',async t=>{const f=await fixture(t),kit=await createExistingRepair(f);const report=await act(f,kit);assert.equal(await fs.readFile(path.join(f.root,'auth.txt'),'utf8'),'correct');assert.equal(await fs.readFile(path.join(f.root,'unrelated'),'utf8'),'untouched');const cap=report.capabilities.find(c=>c.id===f.spec.capabilityId);assert.equal(cap.checks[0].result,'PASS');assert.equal(cap.checks[1].result,'INDETERMINATE');assert.equal(report.verifiedAfterAct,false);assert.deepEqual(kit.getResult().changedFiles,['auth.txt']);});
test('already-correct source is verified without mutation',async t=>{const f=await fixture(t);await fs.writeFile(path.join(f.root,'auth.txt'),'correct');const before=await fs.stat(path.join(f.root,'auth.txt'));const kit=await createExistingRepair(f);await act(f,kit);assert.deepEqual(kit.getResult().changedFiles,[]);assert.equal((await fs.stat(path.join(f.root,'auth.txt'))).mtimeMs,before.mtimeMs);});
test('authorization required by executeRepair',async t=>{const f=await fixture(t),kit=await createExistingRepair(f);await assert.rejects(act(f,kit,{}),/authorization/);assert.equal(await fs.readFile(path.join(f.root,'auth.txt'),'utf8'),'broken');});
test('unknown source hash prevents mutation',async t=>{const f=await fixture(t),kit=await createExistingRepair(f);await fs.writeFile(path.join(f.root,'auth.txt'),'drift');const report=await act(f,kit);assert.equal(report.error,'REPAIR_SOURCE_DRIFT');assert.equal(await fs.readFile(path.join(f.root,'auth.txt'),'utf8'),'drift');});
test('evidence drift fails before editing',async t=>{const f=await fixture(t),kit=await createExistingRepair(f);await fs.writeFile(path.join(f.root,'behavior.mjs'),'');await assert.rejects(act(f,kit),/REPAIR_EVIDENCE_DRIFT/);assert.equal(await fs.readFile(path.join(f.root,'auth.txt'),'utf8'),'broken');});
test('failing behavior restores exact preimage',async t=>{const f=await fixture(t,'process.exit(1)'),kit=await createExistingRepair(f);const report=await act(f,kit);assert.equal(report.error,'BEHAVIOR_FAILED');assert.equal(await fs.readFile(path.join(f.root,'auth.txt'),'utf8'),'broken');});
test('fresh observer failure also rolls repair back',async t=>{const f=await fixture(t,"import fs from 'node:fs'; if(fs.existsSync('ran'))process.exit(1);fs.writeFileSync('ran','1');"),kit=await createExistingRepair(f);const report=await act(f,kit);assert.equal(report.verification,'FAIL');assert.equal(await fs.readFile(path.join(f.root,'auth.txt'),'utf8'),'broken');assert.equal(kit.getResult().rolledBack,true);});
test('paths cannot escape or traverse symlink',async t=>{const f=await fixture(t);f.spec.file='../escape';const kit=await createExistingRepair(f);await assert.rejects(kit.handlers.get(f.spec.capabilityId)({...auth(f),runId:'x'}),/UNSAFE_REPAIR_PATH/);await fs.symlink(path.join(f.root,'unrelated'),path.join(f.root,'link'));f.spec.file='link';const other=await createExistingRepair(f);await assert.rejects(other.handlers.get(f.spec.capabilityId)({...auth(f),runId:'x'}),/UNSAFE_REPAIR_PATH/);});
test('invalid reviewed replacement and capability binding rejected',async t=>{const f=await fixture(t);f.spec.replacement='different';await assert.rejects(createExistingRepair(f),/INVALID_REPAIR_SPEC/);});
test('bounded command timeout produces no successful repair',async t=>{const f=await fixture(t,'setInterval(()=>{},1000)');f.spec.command.timeoutMs=30;const kit=await createExistingRepair(f);const report=await act(f,kit);assert.equal(report.error,'BEHAVIOR_TIMEOUT');assert.equal(await fs.readFile(path.join(f.root,'auth.txt'),'utf8'),'broken');});
test('output overflow is bounded and rolls back',async t=>{const f=await fixture(t,"process.stdout.write('x'.repeat(8192))");const kit=await createExistingRepair(f);const report=await act(f,kit);assert.equal(report.error,'BEHAVIOR_OUTPUT_LIMIT');assert.equal(await fs.readFile(path.join(f.root,'auth.txt'),'utf8'),'broken');});
test('reviewed identity and check mapping cannot be widened',async t=>{const f=await fixture(t);f.spec.revision='other';await assert.rejects(createExistingRepair(f),/INVALID_REPAIR_SPEC/);f.spec.revision='reviewed';f.spec.checks.push('unreviewed');await assert.rejects(createExistingRepair(f),/INVALID_REPAIR_SPEC/);});
test('index bytes and target permissions remain unchanged',async t=>{const f=await fixture(t);await fs.mkdir(path.join(f.root,'.git'));await fs.writeFile(path.join(f.root,'.git','index'),'staged bytes');await fs.chmod(path.join(f.root,'auth.txt'),0o640);const kit=await createExistingRepair(f);await act(f,kit);assert.equal(await fs.readFile(path.join(f.root,'.git','index'),'utf8'),'staged bytes');assert.equal((await fs.stat(path.join(f.root,'auth.txt'))).mode & 0o777,0o640);});
test('successful observer command cannot hide changed repair bytes',async t=>{const f=await fixture(t,"import fs from 'node:fs'; if(fs.existsSync('ran'))fs.writeFileSync('auth.txt','external');else fs.writeFileSync('ran','1');"),kit=await createExistingRepair(f);await assert.rejects(act(f,kit),/ROLLBACK_SOURCE_DRIFT/);assert.equal(await fs.readFile(path.join(f.root,'auth.txt'),'utf8'),'external');assert.equal(kit.getResult().behavior.passed,false);});

test('reviewed RPTVL runs after repair, binds candidate and reports scoped proof',async t=>{
 const f=await fixture(t);const {LANES}=await import('./auth-verification-lane.mjs');
 const {productTestSource}=await import('./auth-product-test.mjs');await fs.mkdir(path.join(f.root,'test'));await fs.writeFile(path.join(f.root,'test/auth-behavior.mjs'),productTestSource({argv:['$NODE','behavior.mjs'],timeoutMs:2000}));
 const command={argv:[process.execPath,'test/auth-behavior.mjs'],timeoutMs:2000,maxOutputBytes:4096};
 f.spec.verificationSpec={schema:'life.auth.verification-lane/1',productId:f.adapter.productId,revision:f.adapter.revision,requestedOutcome:'Restore callback behavior',evidenceScope:'isolated',authorizedPaths:[f.spec.file],inputs:[{path:f.spec.file,sha256:f.spec.afterSha256},...f.spec.evidenceFiles,{path:'test/auth-behavior.mjs',sha256:hash(await fs.readFile(path.join(f.root,'test/auth-behavior.mjs')))}],normalBuildGate:'test/auth-behavior.mjs',normalBuild:command,lanes:LANES.map(id=>({id,required:true,checks:[`${f.spec.capabilityId}/${f.spec.checks[0]}`],command}))};
 const kit=await createExistingRepair(f);const report=await act(f,kit);
 assert.equal(report.rptvl.result,'VERIFIED');assert.equal(report.rptvl.evidenceScope,'isolated');assert.equal(report.durableCompletion,false); // Unproven sibling requirements survive.
 assert.equal(kit.getResult().rptvl.lanes.length,7);
});
test('failed verification lane rolls back only owned repair delta',async t=>{
 const f=await fixture(t);const {LANES}=await import('./auth-verification-lane.mjs');
 const command={argv:[process.execPath,'-e','process.exit(1)'],timeoutMs:2000,maxOutputBytes:4096};
 f.spec.verificationSpec={schema:'life.auth.verification-lane/1',productId:f.adapter.productId,revision:f.adapter.revision,requestedOutcome:'Restore callback',evidenceScope:'isolated',authorizedPaths:[f.spec.file],inputs:f.spec.evidenceFiles,normalBuildGate:'behavior.mjs',normalBuild:command,lanes:LANES.map(id=>({id,required:true,checks:[`${f.spec.capabilityId}/${f.spec.checks[0]}`],command}))};
 const kit=await createExistingRepair(f);const report=await act(f,kit);assert.equal(report.rptvl.result,'FAIL');assert.equal(await fs.readFile(path.join(f.root,'auth.txt'),'utf8'),'broken');assert.equal(await fs.readFile(path.join(f.root,'unrelated'),'utf8'),'untouched');assert.equal(kit.getResult().rolledBack,true);
});
