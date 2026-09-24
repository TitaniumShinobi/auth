import test from 'node:test';
import assert from 'node:assert/strict';
import {repairAssertionIssuance} from '../../scripts/auth-assertion-repair.mjs';
const reference='env:AUTH_CANONICAL_OWNER_DATABASE_URL';
function fixture(){
 const adapter={schemaVersion:1,productId:'auth',revision:'r1',capabilities:{'assertion.issuance':{applicability:'TRUE',implementation:'ESTABLISHED',evidence:['synthetic:fixture'],checks:{authenticated_session_required:true,subject_owner_binding_authorized:false,relying_party_scope_authorized:true}}}};
 const expected={revision:'r1',sourceDigest:'source',configurationDigest:'config',accountStorage:'sqlite:existing',refreshStorage:'memory:existing',serviceId:'auth-local',lookupReference:null,lookupReady:false};
 let state={...expected},mutations=0,reloads=0,observations=0;
 const host={observe:async()=>({...state}),inspectProtectedReference:async()=>({reference,authorized:true,targetRevision:'r1',targetService:'auth-local',provenance:'TARGET_OWNED_PROTECTED_REFERENCE',available:true}),
 compareAndSetLookup:async({expected:prior,reference})=>{assert.equal(prior.configurationDigest,state.configurationDigest);mutations++;state={...state,configurationDigest:'changed',lookupReference:reference};return {snapshot:{...state},rollbackHandle:'private-preimage-handle'};},
 reload:async id=>{assert.equal(id,'auth-local');reloads++;state.lookupReady=true;},
 restoreLookup:async()=>{state={...expected};return true;}};
 return {options:{adapter,authorization:{authorized:true,productId:'auth',revision:'r1',capabilityId:'assertion.issuance',datasourceReference:reference},expected,host,observe:async()=>{observations++;return adapter;}},counts:()=>({mutations,reloads,observations}),state:()=>state};
}
test('authorized repair preserves persistence and verifies without claiming end-to-end completion',async()=>{
 const f=fixture();const r=await repairAssertionIssuance(f.options);
 assert.deepEqual(f.counts(),{mutations:1,reloads:1,observations:1});assert.equal(f.state().accountStorage,'sqlite:existing');assert.equal(f.state().refreshStorage,'memory:existing');assert.equal(r.verifiedAfterAct,true);assert.equal(r.verification,'FAIL');
 assert.doesNotMatch(JSON.stringify(r),/private-preimage-handle/);
});
test('missing and unauthorized references mutate nothing and route external prerequisite',async()=>{
 for(const mode of ['authorization','missing']){const f=fixture();if(mode==='authorization')delete f.options.authorization.datasourceReference;else f.options.host.inspectProtectedReference=async()=>null;
 const r=await repairAssertionIssuance(f.options);assert.equal(f.counts().mutations,0);assert.equal(r.error,'AUTHORIZED_OWNER_DATASOURCE_REQUIRED');assert.equal(r.blockerHandoffs.find(b=>b.capabilityId==='assertion.issuance').nextOwner,'EXTERNAL AUTHORITY');}
});
test('revision/source/config drift refuses repair',async()=>{
 for(const key of ['revision','sourceDigest','configurationDigest']){const f=fixture();f.options.expected={...f.options.expected,[key]:'other'};await repairAssertionIssuance(f.options);assert.equal(f.counts().mutations,0);}
});
test('reload failure restores preimage; concurrent changes are preserved',async()=>{
 for(const conflict of [false,true]){const f=fixture();let calls=0;f.options.host.reload=async()=>{if(calls++===0)throw new Error('secret database failure');};if(conflict)f.options.host.restoreLookup=async()=>false;
 const r=await repairAssertionIssuance(f.options);assert.equal(r.repair.rollbackState,conflict?'CONCURRENT_CHANGE_PRESERVED':'RESTORED');assert.equal(r.verifiedAfterAct,true);assert.doesNotMatch(JSON.stringify(r),/secret database failure/);}
});
test('credentials embedded in evidence cannot authorize a repair',async()=>{const f=fixture();delete f.options.authorization.datasourceReference;f.options.adapter.datasource={url:'postgres://fixture-secret'};const r=await repairAssertionIssuance(f.options);assert.equal(f.counts().mutations,0);assert.doesNotMatch(JSON.stringify(r),/fixture-secret/);});
