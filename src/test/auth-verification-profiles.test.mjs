import { seal, CONFORMANCE_CONTRACT } from '../../scripts/auth-conformance-binding.mjs';
const bound = ({digest: _old, ...record}) => seal({...record,binding:{contractVersion:CONFORMANCE_CONTRACT,configurationDigest:'a'.repeat(64),runtimeDigest:'b'.repeat(64),generatedAt:new Date(Date.now()-1000).toISOString(),expiresAt:new Date(Date.now()+60000).toISOString()}});
import test from 'node:test';
import assert from 'node:assert/strict';
import {CAPABILITIES} from '../../scripts/auth-capability-catalog.mjs';
import {evaluateAdapter} from '../../scripts/auth-wizard.mjs';
import {verificationOwner} from '../../scripts/auth-evidence-ownership.mjs';
import {requiredByProfile} from '../../scripts/auth-verification-profiles.mjs';
function fixture(){
 const adapter={schemaVersion:1,productId:'generic-client',revision:'r1',authenticationRole:'RELYING_PARTY',identityAuthority:{id:'authority',revision:'a1'},capabilities:{}};
 const trustedAuthorityEvidence=[];
 for(const c of CAPABILITIES){
  adapter.capabilities[c.id]={applicability:'TRUE',implementation:'ESTABLISHED',evidence:['test:fixture'],checks:{}};
  for(const id of c.checks)if(requiredByProfile('RELYING_PARTY_CLIENT',c,{id})){
   if(verificationOwner(c.id,id)==='EXTERNAL_AUTHORITY')trustedAuthorityEvidence.push(bound({productId:adapter.productId,revision:'r1',authority:'authority',authorityRevision:'a1',capabilityId:c.id,checkId:id,verification_owner:'EXTERNAL_AUTHORITY',kind:'CONFORMANCE',result:'PASS',references:['test:authority']}));
   else adapter.capabilities[c.id].checks[id]=true;
  }
 }
 // Dynamic declarations are not relevant to this client fixture.
 for(const c of CAPABILITIES.filter(c=>c.family==='auth_email'||c.family==='cross_product'||c.id==='welcome.email'))adapter.capabilities[c.id]={applicability:'FALSE',reason:'not offered by fixture'};
 return {adapter,options:{verificationProfile:'RELYING_PARTY_CLIENT',trustedAuthorityEvidence}};
}
test('client PASS preserves full unknowns and ownership with outside-profile tracking',()=>{
 const {adapter,options}=fixture();const report=evaluateAdapter(adapter,options);
 assert.equal(report.profile_verification,'PASS');assert.equal(report.full_verification,'INDETERMINATE');
 adapter.capabilities['cross_product.offer']={applicability:'TRUE',implementation:'INDETERMINATE'};
 const outside=evaluateAdapter(adapter,options);assert.equal(outside.profile_verification,'PASS');assert.ok(outside.outside_profile_unknowns.includes('counterparts:missing'));
 adapter.capabilities['invented.assertion']={applicability:'TRUE'};assert.equal(evaluateAdapter(adapter,options).profile_verification,'INDETERMINATE');delete adapter.capabilities['invented.assertion'];assert.equal(report.verification,'INDETERMINATE');
 assert.ok(report.outside_profile_unresolved_checks.some(c=>c.checkId==='revocation_persisted'&&c.verification==='INDETERMINATE'&&c.scope==='OUTSIDE_CURRENT_PROFILE'));
 assert.equal(report.capabilities.length,CAPABILITIES.length);
 assert.equal(report.capabilities.find(c=>c.id==='session.refresh').checks.find(c=>c.id==='replay_rejected').verification_owner,'EXTERNAL_AUTHORITY');
 assert.equal(evaluateAdapter(adapter,{...options,verificationProfile:'FULL_AUTHORITY_CONFORMANCE'}).profile_verification,'INDETERMINATE');
 assert.equal(evaluateAdapter(adapter,{...options,verificationProfile:'AUTHORITY_RUNTIME'}).profile_verification,'INDETERMINATE');
});
test('required failure, missing authority proof, or missing implementation prevents client PASS',()=>{
 const {adapter,options}=fixture();
 assert.equal(evaluateAdapter(adapter,{...options,trustedAuthorityEvidence:[]}).profile_verification,'INDETERMINATE');
 adapter.capabilities['relying_party.client_operations'].checks.refresh_response_handled=false;
 assert.equal(evaluateAdapter(adapter,options).profile_verification,'FAIL');
 adapter.capabilities['relying_party.client_operations'].checks.refresh_response_handled=true;
 adapter.capabilities['session.persistence'].implementation='INDETERMINATE';
 assert.equal(evaluateAdapter(adapter,options).profile_verification,'INDETERMINATE');
});
test('profile baseline prevents hiding a previously required passing capability',()=>{
 const {adapter,options}=fixture();const baseline=evaluateAdapter(adapter,options);
 adapter.capabilities['session.persistence']={applicability:'FALSE',reason:'removed'};
 assert.equal(evaluateAdapter(adapter,{...options,baseline}).profile_verification,'FAIL');
 assert.throws(()=>evaluateAdapter(adapter,{verificationProfile:'UNKNOWN'}),/profile/);
});

test('assertion integration separates presenter evidence from validator conformance without OAuth requirements',()=>{
 const adapter={schemaVersion:1,productId:'presenter',revision:'r2',authenticationRole:'RELYING_PARTY',identityAuthority:{id:'issuer',revision:'i2'},resourceAuthority:{id:'validator',revision:'v2'},capabilities:{}};
 const trustedAuthorityEvidence=[];
 for(const c of CAPABILITIES.filter(c=>requiredByProfile('ASSERTION_INTEGRATION',c,{}))){
  adapter.capabilities[c.id]={applicability:'TRUE',implementation:'ESTABLISHED',evidence:['test:bounded-fixture'],checks:{}};
  for(const checkId of c.checks){
   if(verificationOwner(c.id,checkId)==='EXTERNAL_AUTHORITY')trustedAuthorityEvidence.push(bound({productId:'presenter',revision:'r2',authority:c.id==='assertion.issuance'?'issuer':'validator',authorityRevision:c.id==='assertion.issuance'?'i2':'v2',capabilityId:c.id,checkId,verification_owner:'EXTERNAL_AUTHORITY',kind:'CONFORMANCE',result:'PASS',references:['test:validator-negatives']}));
   else adapter.capabilities[c.id].checks[checkId]=true;
  }
 }
 const options={verificationProfile:'ASSERTION_INTEGRATION',trustedAuthorityEvidence};
 const report=evaluateAdapter(adapter,options);
 assert.equal(report.profile_verification,'PASS');assert.equal(report.full_verification,'INDETERMINATE');
 adapter.capabilities['cross_product.offer']={applicability:'TRUE',implementation:'INDETERMINATE'};
 const outside=evaluateAdapter(adapter,options);assert.equal(outside.profile_verification,'PASS');assert.ok(outside.outside_profile_unknowns.includes('counterparts:missing'));
 adapter.capabilities['invented.assertion']={applicability:'TRUE'};assert.equal(evaluateAdapter(adapter,options).profile_verification,'INDETERMINATE');delete adapter.capabilities['invented.assertion'];
 assert.ok(report.outside_profile_unresolved_checks.some(c=>c.capabilityId==='relying_party.pkce'));
 assert.equal(evaluateAdapter(adapter,{...options,trustedAuthorityEvidence:[]}).profile_verification,'INDETERMINATE');
 adapter.capabilities['assertion.validation'].checks=Object.fromEntries(CAPABILITIES.find(c=>c.id==='assertion.validation').checks.map(c=>[c,true]));
 assert.equal(evaluateAdapter(adapter,{...options,trustedAuthorityEvidence:[]}).profile_verification,'INDETERMINATE');
 adapter.capabilities['assertion.validation']={applicability:'FALSE',reason:'skip validation'};
 assert.notEqual(evaluateAdapter(adapter,options).profile_verification,'PASS');
 adapter.capabilities['assertion.integration'].checks.failure_code_preserved=false;
 assert.notEqual(evaluateAdapter(adapter,options).profile_verification,'PASS');
 assert.throws(()=>evaluateAdapter({...adapter,authenticationRole:'IDENTITY_AUTHORITY'},options),/RELYING_PARTY/);
});
