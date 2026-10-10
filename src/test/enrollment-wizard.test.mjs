import test from 'node:test';
import assert from 'node:assert/strict';
import { CAPABILITIES } from '../../scripts/auth-capability-catalog.mjs';
import { evaluateAdapter, executeRepair } from '../../scripts/auth-wizard.mjs';
import { createBlockerHandoffs } from '../../scripts/auth-blocker-handoff.mjs';
const ids = ['signin.returning', 'enrollment.product', 'enrollment.continuation'];
function fixture() {
 return {schemaVersion:1,productId:'synthetic-enrollment-client',revision:'fixture-1',authenticationRole:'RELYING_PARTY',
 identityAuthority:{id:'identity-fixture',revision:'1'},enrollmentAuthority:{id:'enrollment-fixture',revision:'2'},
 capabilities:Object.fromEntries(CAPABILITIES.map(c=>[c.id,ids.includes(c.id)?{applicability:'TRUE',implementation:'ESTABLISHED',evidence:['fixture:controlled-contract-tests'],checks:Object.fromEntries(c.checks.map(k=>[k,true]))}:{applicability:'FALSE',reason:'Outside this isolated contract fixture'}]))};
}
const entry = (r,id)=>r.capabilities.find(c=>c.id===id);
test('catalog distinguishes admission from identity and owner; missing authoritative completion is not PASS',()=>{
 const a=fixture(), r=evaluateAdapter(a);
 const c=entry(r,'enrollment.product');
 assert.equal(c.verification,'INDETERMINATE');
 assert.equal(c.checks.find(x=>x.id==='authority_completion_verified').verification_owner,'EXTERNAL_AUTHORITY');
 assert.ok(c.checks.some(x=>x.id==='owner_binding_not_admission'));
 assert.equal(createBlockerHandoffs(r).find(x=>x.capabilityId==='enrollment.product').nextOwner,'EXTERNAL AUTHORITY');
});
test('identity authority evidence cannot impersonate separately declared enrollment authority',()=>{
 const a=fixture();
 const record={productId:a.productId,revision:a.revision,authority:'identity-fixture',authorityRevision:'1',capabilityId:'enrollment.product',checkId:'authority_completion_verified',verification_owner:'EXTERNAL_AUTHORITY',kind:'CONFORMANCE',result:'PASS',references:['fixture:authority']};
 assert.equal(entry(evaluateAdapter(a,{trustedAuthorityEvidence:[record]}),'enrollment.product').verification,'INDETERMINATE');
 record.authority='enrollment-fixture';record.authorityRevision='2';
 assert.equal(entry(evaluateAdapter(a,{trustedAuthorityEvidence:[record]}),'enrollment.product').verification,'PASS');
 a.capabilities['enrollment.product'].checks.owner_binding_not_admission=false;
 assert.equal(entry(evaluateAdapter(a,{trustedAuthorityEvidence:[record]}),'enrollment.product').verification,'FAIL');
});
test('unknown sign-in admission and mutating resume failures are exposed through existing capabilities',()=>{
 const a=fixture();a.capabilities['signin.returning'].checks.unknown_signin_requires_enrollment=false;
 a.capabilities['enrollment.continuation'].checks.resume_has_no_gate_mutations=false;
 const r=evaluateAdapter(a);
 assert.equal(entry(r,'signin.returning').verification,'FAIL');
 assert.equal(entry(r,'enrollment.continuation').verification,'FAIL');
});
test('contract module does not register a product repair; ACT still needs supported handler and observer',async()=>{
 const a=fixture();await assert.rejects(executeRepair(a,{capabilityId:'enrollment.product',authorization:{authorized:true,productId:a.productId,revision:a.revision,capabilityId:'enrollment.product'},observe:async()=>a}),/No supported repair/);
});
