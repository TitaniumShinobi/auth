import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm, realpath } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { evaluateAdapter, executeRepair } from './auth-wizard.mjs';
import { CAPABILITIES } from './auth-capability-catalog.mjs';
import { digest, validBinding, seal, CONFORMANCE_CONTRACT } from './auth-conformance-binding.mjs';
import { runtimeAcceptance } from './auth-assurance.mjs';
import { discoverNativeTarget, planNativeAlignment, verifyNativeReceipt, RECEIPT_SCHEMA } from './auth-native-wizard.mjs';
import { createHash } from 'node:crypto';
const hash=x=>createHash('sha256').update(x).digest('hex');
const fixture=()=>({schemaVersion:1,productId:'sample',revision:'r1',capabilities:Object.fromEntries(CAPABILITIES.map(c=>[c.id,{applicability:'FALSE',reason:'Not adopted'}]))});
function enable(a){a.capabilities.signin={applicability:'TRUE',implementation:'ESTABLISHED',evidence:['synthetic'],checks:Object.fromEntries(CAPABILITIES.find(c=>c.id==='signin').checks.map(c=>[c,true]))};return a;}
test('source receipt verifies only source and rejects identical files in another target',async()=>{
 const root=await mkdtemp(path.join(os.tmpdir(),'assurance-'));try{
 const a=path.join(root,'a'),b=path.join(root,'b');await mkdir(a);await mkdir(b);for(const p of[a,b])await writeFile(path.join(p,'x'),'broken runtime');
 const payload={schema:RECEIPT_SCHEMA,targetBinding:hash(await realpath(a)),files:{x:hash('broken runtime')}};
 const receipt=path.join(root,'receipt.json');await writeFile(receipt,JSON.stringify({...payload,receiptDigest:digest(payload)}));
 const v=await verifyNativeReceipt(a,receipt);assert.equal(v.verification,'PASS');assert.equal(v.assurance.runtime_acceptance,'INDETERMINATE');assert.equal(v.verification_scope,'SOURCE_INTEGRITY');await assert.rejects(verifyNativeReceipt(b,receipt),/TARGET_MISMATCH/);
 }finally{await rm(root,{recursive:true,force:true});}
});
test('mixed runtime requires explicit owner and role; RP alignment never assumes issuer metadata',async()=>{
 const root=await mkdtemp(path.join(os.tmpdir(),'assurance-owner-'));try{
 await mkdir(path.join(root,'backend/api'),{recursive:true});await writeFile(path.join(root,'backend/api/auth.py'),'oauth');await writeFile(path.join(root,'requirements.txt'),'flask');await writeFile(path.join(root,'package.json'),'{"dependencies":{"react":"1"}}');
 assert.equal((await discoverNativeTarget(root)).stack.runtime,'ambiguous');
 const opts={sourceRoot:process.cwd(),receiptPath:path.join(root,'receipt'),authenticationRole:'RELYING_PARTY',authenticationEntrypoint:'backend/api/auth.py'};
 await assert.rejects(planNativeAlignment(root,{...opts,authenticationRole:undefined}),/ROLE_REQUIRED/);await assert.rejects(planNativeAlignment(root,opts),/RUNTIME_AMBIGUOUS/);
 const p=await planNativeAlignment(root,{...opts,authenticationRuntime:'python'});const contract=JSON.parse(Buffer.from(p.operations[0].inlineBase64,'base64'));assert.equal(contract.profile,'python-flask-sqlite/1');assert.equal(contract.authenticationRuntime,'python');assert.doesNotMatch(Buffer.from(p.operations[1].inlineBase64,'base64').toString(),/well-known/);
 }finally{await rm(root,{recursive:true,force:true});}
});
test('legacy, stale, tampered and configuration-mismatched authority records cannot establish conformance',()=>{
 const a={identityAuthority:{configurationDigest:'a'.repeat(64)}};const payload={binding:{contractVersion:CONFORMANCE_CONTRACT,configurationDigest:'a'.repeat(64),runtimeDigest:'b'.repeat(64),generatedAt:new Date(Date.now()-1000).toISOString(),expiresAt:new Date(Date.now()+60000).toISOString()}};
 assert.equal(validBinding({},a),false);assert.equal(validBinding(seal(payload),a),true);assert.equal(validBinding({...seal(payload),unexpected:true},a),false);assert.equal(validBinding(seal(payload),{identityAuthority:{configurationDigest:'c'.repeat(64)}}),false);assert.equal(validBinding(seal(payload),a,Date.now()+120000),false);
});
test('history requires independent pin, allows revision progression and rejects truncation or missing baseline',()=>{
 const a=enable(fixture()),baseline=evaluateAdapter(a),pin=digest(baseline);a.revision='r2';assert.equal(evaluateAdapter(a,{baseline,baselineDigest:pin,requireHistory:true}).assurance.historical_continuity,'PASS');
 assert.throws(()=>evaluateAdapter(a,{requireHistory:true}),/TRUSTED_BASELINE/);assert.throws(()=>evaluateAdapter(a,{baseline:{...baseline,capabilities:[]},baselineDigest:pin}),/PIN_MISMATCH/);
 a.capabilities.signin.checks.explicit_entry=false;assert.equal(evaluateAdapter(a,{baseline,baselineDigest:pin}).assurance.historical_continuity,'FAIL');
});
test('repair rejects cached observer and admits only fresh run-bound affected-check proof',async()=>{
 const a=enable(fixture());const options={capabilityId:'signin',authorization:{authorized:true,productId:a.productId,revision:a.revision,capabilityId:'signin'},handlers:new Map([['signin',()=>({revision:'r2'})]])};
 const stale=await executeRepair(a,{...options,observe:async()=>a});assert.equal(stale.verifiedAfterAct,false);assert.notEqual(stale.verification,'PASS');
 const result=await executeRepair(a,{...options,observe:async c=>({...a,revision:'r2',postRepairProof:{runId:c.runId,capabilityId:c.capabilityId,revision:c.resultingRevision,observedAt:Date.now(),checks:Object.keys(a.capabilities.signin.checks)}})});assert.equal(result.verifiedAfterAct,true);assert.equal(result.verification,'PASS');
});
test('runtime acceptance needs independent pin, exact revision, freshness and every required behavior',()=>{
 const report=evaluateAdapter(enable(fixture()));const proof={schema:'life.auth.runtime-acceptance/1',productId:report.productId,revision:report.revision,runId:'synthetic',issuedAt:new Date(Date.now()-1000).toISOString(),expiresAt:new Date(Date.now()+60000).toISOString(),checks:report.profile_required_checks.filter(c=>c.applicability==='TRUE').map(c=>({capabilityId:c.capabilityId,checkId:c.checkId,result:'PASS',references:['synthetic-execution']}))};
 assert.equal(runtimeAcceptance(report), 'INDETERMINATE');assert.equal(runtimeAcceptance(report,proof,digest(proof)),'PASS');assert.equal(runtimeAcceptance({...report,revision:'other'},proof,digest(proof)),'FAIL');assert.equal(runtimeAcceptance(report,proof,digest(proof),Date.now()+120000),'FAIL');const absent={...proof,checks:[]};assert.equal(runtimeAcceptance(report,absent,digest(absent)),'INDETERMINATE');
});
test('frozen passing check survives indeterminate sibling but cannot be retired',()=>{
 const a=enable(fixture());delete a.capabilities.signin.checks.existing_identity_authenticated;const baseline=evaluateAdapter(a),pin=digest(baseline);
 assert.equal(evaluateAdapter(a,{baseline,baselineDigest:pin}).assurance.historical_continuity,'PASS');
 a.capabilities.signin.checks.explicit_entry=false;assert.equal(evaluateAdapter(a,{baseline,baselineDigest:pin}).assurance.historical_continuity,'FAIL');
 a.capabilities.signin={applicability:'FALSE',reason:'retired without approval'};assert.equal(evaluateAdapter(a,{baseline,baselineDigest:pin}).assurance.historical_continuity,'FAIL');
});
test('repair proof rejects wrong run, wrong revision, pre-ACT timestamp, and missing exercised checks',async()=>{
 for(const mutate of [p=>p.runId='old',p=>p.revision='old',p=>p.observedAt=0,p=>p.checks=[]]){
 const a=enable(fixture());const result=await executeRepair(a,{capabilityId:'signin',authorization:{authorized:true,productId:a.productId,revision:a.revision,capabilityId:'signin'},handlers:new Map([['signin',()=>{}]]),observe:async c=>{const p={runId:c.runId,capabilityId:c.capabilityId,revision:c.resultingRevision,observedAt:Date.now(),checks:Object.keys(a.capabilities.signin.checks)};mutate(p);return {...a,postRepairProof:p};}});assert.equal(result.verifiedAfterAct,false);assert.notEqual(result.verification,'PASS');
 }
});
test('ACT cannot drop an older pinned check-level obligation',async()=>{
 const a=enable(fixture());delete a.capabilities.signin.checks.existing_identity_authenticated;const baseline=evaluateAdapter(a);
 a.capabilities.signin.checks.explicit_entry=undefined;
 const result=await executeRepair(a,{capabilityId:'signin',authorization:{authorized:true,productId:a.productId,revision:a.revision,capabilityId:'signin'},baseline,baselineDigest:digest(baseline),requireHistory:true,handlers:new Map([['signin',()=>{}]]),observe:async c=>({...a,postRepairProof:{runId:c.runId,capabilityId:c.capabilityId,revision:c.resultingRevision,observedAt:Date.now(),checks:CAPABILITIES.find(x=>x.id==='signin').checks}})});
 assert.equal(result.verification,'FAIL');assert.equal(result.profile_verification,'FAIL');assert.equal(result.assurance.historical_continuity,'FAIL');
});
