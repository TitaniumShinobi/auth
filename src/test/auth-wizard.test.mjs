import test from 'node:test';
import assert from 'node:assert/strict';
import { CAPABILITIES } from '../../scripts/auth-capability-catalog.mjs';
import { evaluateAdapter, executeRepair } from '../../scripts/auth-wizard.mjs';
const fixture = () => ({schemaVersion:1, productId:'sample-product',revision:'r1',capabilities:Object.fromEntries(CAPABILITIES.map(c => [c.id,{applicability:'FALSE',reason:'Product has not adopted this feature',implementation:'NOT_ESTABLISHED'}]))});
function establish(a,id) { a.capabilities[id]={applicability:'TRUE',implementation:'ESTABLISHED',evidence:['test-run:r1'],checks:Object.fromEntries(CAPABILITIES.find(c=>c.id===id).checks.map(key=>[key,true]))}; }
const declared = checks => ({applicability:'TRUE',implementation:'ESTABLISHED',evidence:['adapter-test:r1'],checks:Object.fromEntries(checks.map(key=>[key,true]))});

test('catalog is immutable and covers all 17 families independently',()=>{
 assert.equal(new Set(CAPABILITIES.map(c=>c.family)).size,17);
 assert.equal(new Set(CAPABILITIES.map(c=>c.id)).size,CAPABILITIES.length);
 assert.ok(CAPABILITIES.every(c=>Object.isFrozen(c)&&Object.isFrozen(c.checks)));
});
test('missing applicability and evidence never passes; explicit exclusions need a reason',()=>{
 const a=fixture(); delete a.capabilities.signin;
 assert.equal(evaluateAdapter(a).verification,'INDETERMINATE');
 establish(a,'signin'); a.capabilities.signin.evidence=[];
 assert.equal(evaluateAdapter(a).capabilities.find(c=>c.id==='signin').implementation,'INDETERMINATE');
 a.capabilities.signin={applicability:'FALSE'};
 assert.equal(evaluateAdapter(a).verification,'INDETERMINATE');
 assert.equal(evaluateAdapter(fixture()).verification,'PASS');
});
test('adding magic email cannot erase signup or established providers, including changing applicability',()=>{
 const a=fixture(); for(const id of ['signin','signup','providers.google','providers.github']) establish(a,id);
 const baseline=evaluateAdapter(a); assert.equal(baseline.verification,'PASS');
 establish(a,'providers.magic_email'); assert.equal(evaluateAdapter(a,{baseline}).verification,'PASS');
 a.capabilities.signup={applicability:'FALSE',reason:'replaced with magic email'};
 delete a.capabilities['providers.github'];
 const after=evaluateAdapter(a,{baseline}); assert.equal(after.verification,'FAIL');
 assert.deepEqual(after.regressions.map(r=>r.id),['signup','providers.github']);
});
test('explicit failures and absent implementation differ from missing evidence',()=>{
 const a=fixture(); establish(a,'session.refresh'); a.capabilities['session.refresh'].checks.token_rotated=false;
 assert.equal(evaluateAdapter(a).verification,'FAIL');
 a.capabilities['session.refresh'].checks.token_rotated=undefined;
 assert.equal(evaluateAdapter(a).verification,'INDETERMINATE');
 a.capabilities['session.refresh'].implementation='NOT_ESTABLISHED'; assert.equal(evaluateAdapter(a).verification,'FAIL');
});
test('each declared counterpart permits decline and reuse without any product-name dispatch',()=>{
 const a=fixture(); establish(a,'cross_product.offer');
 assert.equal(evaluateAdapter(a).verification,'INDETERMINATE');
 a.counterparts=[{productId:'another-product',...declared(['optional_offer','explicit_acceptance','decline_preserves_primary_access','existing_account_reused'])}];
 assert.equal(evaluateAdapter(a).verification,'PASS');
 a.counterparts[0].checks.decline_preserves_primary_access=false;
 assert.equal(evaluateAdapter(a).verification,'FAIL');
});
test('each authentication email is checked; marketing newsletters are outside authority',()=>{
 const a=fixture(); a.emails=[{id:'verification',kind:'verification',...declared(['trigger_defined','recipient_defined','delivery_adapter','template_exists','delivery_result','duplicate_policy_defined','token_url_secrecy','expiry_policy_defined'])}];
 assert.equal(evaluateAdapter(a).verification,'PASS');
 a.emails[0].kind='marketing_newsletter'; assert.equal(evaluateAdapter(a).verification,'FAIL');
 a.emails[0].kind='verification'; a.emails[0].checks.delivery_result=false; assert.equal(evaluateAdapter(a).verification,'FAIL');
});
test('lifecycle evidence participates in verification, not just documentation',()=>{
 const a=fixture(); establish(a,'signin'); a.capabilities.signin.trace={capability:'login',events:[{type:'identity.lookup',exists:false},{type:'identity.create',id:'duplicate'},{type:'identity.authenticate',id:'duplicate'}]};
 assert.equal(evaluateAdapter(a).verification,'FAIL');
});
test('ACT requires exact explicit authorization, a handler and applicability, then verifies regression',async()=>{
 const a=fixture(); establish(a,'signup'); establish(a,'signin');
 a.capabilities.signin.checks.explicit_entry=false;
 let calls=0;
 const authorization={authorized:true,productId:a.productId,revision:a.revision,capabilityId:'signin'};
 const handlers=new Map([['signin',()=>{calls++;a.capabilities.signin.checks.explicit_entry=true;}]]);
 await assert.rejects(executeRepair(a,{capabilityId:'signin',handlers,observe:async c=>({...a,postRepairProof:{runId:c.runId,capabilityId:c.capabilityId,revision:c.resultingRevision,observedAt:Date.now(),checks:CAPABILITIES.find(x=>x.id===c.capabilityId).checks}})}),/authorization/);
 assert.equal(calls,0);
 assert.equal((await executeRepair(a,{capabilityId:'signin',authorization,handlers,observe:async c=>({...a,postRepairProof:{runId:c.runId,capabilityId:c.capabilityId,revision:c.resultingRevision,observedAt:Date.now(),checks:CAPABILITIES.find(x=>x.id===c.capabilityId).checks}})})).verification,'PASS');
 assert.equal(calls,1);
 handlers.set('signin',()=>{a.capabilities.signup.checks.explicit_entry=false;});
 assert.equal((await executeRepair(a,{capabilityId:'signin',authorization,handlers,observe:async c=>({...a,postRepairProof:{runId:c.runId,capabilityId:c.capabilityId,revision:c.resultingRevision,observedAt:Date.now(),checks:CAPABILITIES.find(x=>x.id===c.capabilityId).checks}})})).verification,'FAIL');
});
test('unsupported or stale adapters fail closed',()=>{
 assert.throws(()=>evaluateAdapter({}),/Adapter requires/);
 const a=fixture(); a.capabilities.typo={applicability:'TRUE'}; assert.equal(evaluateAdapter(a).verification,'INDETERMINATE');
 assert.throws(()=>evaluateAdapter(a,{baseline:{productId:'other'}}),/Baseline/);
});

test('supported repair preserves safe machine failure codes without leaking messages',async()=>{
 const a=fixture();establish(a,'signin');
 const authorization={authorized:true,productId:a.productId,revision:a.revision,capabilityId:'signin'};
 for(const [code,expected] of [['HANDSHAKE_REJECTED','HANDSHAKE_REJECTED'],['secret token value','REPAIR_FAILED']]) {
 const result=await executeRepair(a,{capabilityId:'signin',authorization,handlers:new Map([['signin',async()=>{throw Object.assign(new Error('sensitive message'),{code});}]]),observe:async c=>({...a,postRepairProof:{runId:c.runId,capabilityId:c.capabilityId,revision:c.resultingRevision,observedAt:Date.now(),checks:CAPABILITIES.find(x=>x.id===c.capabilityId).checks}})});
 assert.equal(result.error,expected);assert.equal(result.verification,'FAIL');assert.equal(result.profile_verification,'FAIL');assert.ok(!JSON.stringify(result).includes('sensitive message'));
 }
});
