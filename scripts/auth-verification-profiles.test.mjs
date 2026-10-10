import test from 'node:test';
import assert from 'node:assert/strict';
import { CAPABILITIES } from './auth-capability-catalog.mjs';
import { evaluateAdapter } from './auth-wizard.mjs';

function adapter(requiredChecks) {
  const capabilities=Object.fromEntries(CAPABILITIES.map(row=>[row.id,{applicability:'FALSE',reason:'Outside product-local profile'}]));
  capabilities.signin={applicability:'TRUE',implementation:'ESTABLISHED',evidence:['source:test'],checks:{explicit_entry:true}};
  return {schemaVersion:1,productId:'product-fixture',revision:'revision',authenticationRole:'IDENTITY_AUTHORITY',
    productProfile:{id:'PRODUCT_FIXTURE_AUTH',requiredChecks},productCandidates:[],capabilities};
}

test('PRODUCT_LOCAL evaluates only product-declared generic checks',()=>{
  const report=evaluateAdapter(adapter(['signin/explicit_entry']),{verificationProfile:'PRODUCT_LOCAL'});
  assert.equal(report.profile_verification,'PASS');
  assert.equal(report.productProfile.id,'PRODUCT_FIXTURE_AUTH');
  assert.deepEqual(report.missing_product_checks,[]);
});

test('PRODUCT_LOCAL fails closed for unknown or unresolved required checks',()=>{
  assert.equal(evaluateAdapter(adapter(['signin/not-a-check']),{verificationProfile:'PRODUCT_LOCAL'}).profile_verification,'INDETERMINATE');
  const unresolved=adapter(['signin/explicit_entry']);
  unresolved.capabilities.signin.implementation='INDETERMINATE';
  assert.equal(evaluateAdapter(unresolved,{verificationProfile:'PRODUCT_LOCAL'}).profile_verification,'INDETERMINATE');
});
