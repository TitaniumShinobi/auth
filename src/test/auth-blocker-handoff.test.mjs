import test from 'node:test';
import assert from 'node:assert/strict';
import { createBlockerHandoffs } from '../../scripts/auth-blocker-handoff.mjs';
const row = (overrides = {}) => ({ id: 'signin', applicability: 'TRUE', implementation: 'ESTABLISHED', verification: 'FAIL', evidence: ['fixture:test'], checks: [{id:'explicit_entry', result:'FAIL'}], ...overrides });
const report = (rows = [row()], overrides = {}) => ({ schemaVersion:1,catalogVersion:'1',productId:'fixture',operator:'VERIFY',verification:'FAIL',capabilities:rows,unknownCapabilities:[],regressions:[],...overrides });

test('genuine pass has no handoffs, including declared inapplicability', () => {
  assert.deepEqual(createBlockerHandoffs(report([row({verification:'NOT_APPLICABLE',applicability:'FALSE'})],{verification:'PASS'})), []);
});
test('claimed pass cannot conceal failed capabilities', () => {
  assert.equal(createBlockerHandoffs(report(undefined,{verification:'PASS'})).length,1);
});
test('known missing implementation routes product integration', () => {
  const [h] = createBlockerHandoffs(report([row({implementation:'NOT_ESTABLISHED'})]));
  assert.equal(h.nextOwner,'PRODUCT INTEGRATION'); assert.equal(h.reasonCode,'IMPLEMENTATION_NOT_ESTABLISHED');
  assert.equal(h.executionClassification,'AGENT_INTEGRATION_REQUIRED');
  assert.equal(h.mdboLineage.status,'NOT_ESTABLISHED'); assert.equal(h.actAvailability,'UNAVAILABLE');
});
test('unknown capability stops for AUTH development even if operator says authorized', () => {
  const [h] = createBlockerHandoffs(report([],{unknownCapabilities:['future.identity']}),{authorization:true});
  assert.equal(h.nextOwner,'AUTH DEVELOPMENT'); assert.match(h.instruction,/^STOP/);
  assert.equal(h.executionClassification,'AUTH_DEVELOPMENT_REQUIRED');
});
test('unsupported reusable contract stops for AUTH development', () => {
  const [h] = createBlockerHandoffs(report(),{reusableContracts:{signin:false}});
  assert.equal(h.nextOwner,'AUTH DEVELOPMENT'); assert.equal(h.reasonCode,'AUTH_CONTRACT_UNSUPPORTED');
});
test('approval owner requires registered handler and explicitly missing authorization', () => {
  const [h] = createBlockerHandoffs(report(),{registeredCapabilities:['signin'],authorization:false});
  assert.equal(h.nextOwner,'OPERATOR APPROVAL'); assert.equal(h.authorizationRequired,true);
  assert.equal(h.executionClassification,'EXTERNAL_ACTION_REQUIRED');
  assert.equal(createBlockerHandoffs(report(),{authorization:false})[0].nextOwner,'PRODUCT INTEGRATION');
});
test('only established external blockers route to external authority', () => {
  const context = {externalBlockers:{signin:{established:true,reason:'Provider configuration rejected',owner:'provider administrator'}}};
  assert.equal(createBlockerHandoffs(report(),context)[0].nextOwner,'EXTERNAL AUTHORITY');
  assert.equal(createBlockerHandoffs(report(),context)[0].executionClassification,'EXTERNAL_ACTION_REQUIRED');
  assert.equal(createBlockerHandoffs(report(),{externalBlockers:{signin:{reason:'guess'}}})[0].nextOwner,'PRODUCT INTEGRATION');
});
test('regression remains a blocker even when row is now marked inapplicable', () => {
  const [h] = createBlockerHandoffs(report([row({verification:'NOT_APPLICABLE'})],{regressions:[{id:'signin',before:'PASS',after:'NOT_APPLICABLE'}]}));
  assert.equal(h.reasonCode,'CAPABILITY_REGRESSION');
});
test('commands preserved as argument arrays without executing or accepting shell text', () => {
  const context = {repository:'/fixture',reproductionCommand:['node','cli','wizard','--repo','a b'],verificationCommand:'node cli'};
  const [h] = createBlockerHandoffs(report(),context);
  assert.deepEqual(h.reproductionCommand,context.reproductionCommand); assert.equal(h.verificationCommand,null);
  assert.equal(h.target.repository,'/fixture');
});
test('deterministic sorted output does not mutate report', () => {
  const source = report([row(),row({id:'signup'})]); const before=JSON.stringify(source);
  assert.deepEqual(createBlockerHandoffs(source),createBlockerHandoffs(source)); assert.equal(JSON.stringify(source),before);
  assert.deepEqual(createBlockerHandoffs(source).map(h=>h.capabilityId),['signin','signup']);
});
test('unexplained nonpass returns to AUTH development rather than inventing product work', () => {
  const [handoff] = createBlockerHandoffs(report([]));
  assert.equal(handoff.nextOwner,'AUTH DEVELOPMENT');
  assert.equal(handoff.executionClassification,'AUTH_DEVELOPMENT_REQUIRED');
});
test('scoped ACT failure preserves actual capability without inferring handler support', () => {
  const [h] = createBlockerHandoffs({operator:'ACT',verification:'INDETERMINATE',error:'NO_SUPPORTED_REPAIR',productId:'fixture'}, {capabilityId:'signin'});
  assert.equal(h.capabilityId,'signin'); assert.equal(h.nextOwner,'PRODUCT INTEGRATION'); assert.equal(h.actAvailability,'UNAVAILABLE');
});

test('missing collection declarations belong to product integration', () => {
  for (const id of ['welcome-emails:missing','emails:missing','counterparts:missing']) {
    assert.equal(createBlockerHandoffs(report([],{unknownCapabilities:[id]}))[0].nextOwner,'PRODUCT INTEGRATION');
  }
});
test('failed ACT with passing capabilities produces task blocker without fabricated capability', () => {
  const [h] = createBlockerHandoffs(report([row({verification:'PASS'})],{operator:'ACT',error:'REPAIR_FAILED'}));
  assert.equal(h.capabilityId,null); assert.equal(h.reasonCode,'REPAIR_FAILED'); assert.equal(h.nextOwner,'AUTH DEVELOPMENT');
});
test('unscoped ACT authorization error requires approval without inventing available repair', () => {
  const [h] = createBlockerHandoffs({operator:'ACT',verification:'INDETERMINATE',error:'AUTHORIZATION_REQUIRED'}, {authorization:false});
  assert.equal(h.capabilityId,null); assert.equal(h.reasonCode,'AUTHORIZATION_REQUIRED'); assert.equal(h.nextOwner,'OPERATOR APPROVAL'); assert.equal(h.authorizationRequired,true); assert.equal(h.actAvailability,'UNAVAILABLE');
});

test('unknown IDs cannot claim a dynamic contract merely by matching its prefix', () => {
  const [h] = createBlockerHandoffs(report([],{unknownCapabilities:['email-message:undeclared']}));
  assert.equal(h.nextOwner,'AUTH DEVELOPMENT');
});

test('ACT error priority is retained for both task-level and known capability handoffs', () => {
  for (const capabilityId of [undefined, 'signin']) {
    for (const error of ['AUTHORIZATION_REQUIRED', 'NO_SUPPORTED_REPAIR']) {
      const [h] = createBlockerHandoffs({operator:'ACT',verification:'INDETERMINATE',error}, {capabilityId,authorization:false});
      assert.equal(h.reasonCode,error);
      assert.equal(h.nextOwner,error === 'AUTHORIZATION_REQUIRED' ? 'OPERATOR APPROVAL' : capabilityId ? 'PRODUCT INTEGRATION' : 'AUTH DEVELOPMENT');
      assert.equal(h.authorizationRequired,true);
      if (error === 'NO_SUPPORTED_REPAIR') assert.equal(h.executionClassification, capabilityId ? 'AGENT_INTEGRATION_REQUIRED' : 'AUTH_DEVELOPMENT_REQUIRED');
      else assert.match(h.resumeCondition,/supported bounded repair handler is still required/);
    }
  }
});
test('unsupported contract ACT failure goes to AUTH development without overwriting failure reason', () => {
  const [h] = createBlockerHandoffs({operator:'ACT',verification:'INDETERMINATE',error:'NO_SUPPORTED_REPAIR'}, {capabilityId:'signin',reusableContracts:{signin:false},authorization:true});
  assert.equal(h.nextOwner,'AUTH DEVELOPMENT'); assert.equal(h.reasonCode,'NO_SUPPORTED_REPAIR'); assert.match(h.instruction,/^STOP/);
});
test('registered handler is the preferred automatic execution path once authorization is present', () => {
  const [handoff] = createBlockerHandoffs(report(), { registeredCapabilities: ['signin'], authorization: true });
  assert.equal(handoff.executionClassification, 'AUTO_REPAIR_AVAILABLE');
  assert.equal(handoff.actAvailability, 'AVAILABLE');
  assert.match(handoff.instruction, /registered bounded ACT handler/);
});
test('declaration blockers specify concrete expected evidence', () => {
  for (const id of ['counterparts:missing','emails:missing','welcome-emails:missing']) {
    const [h] = createBlockerHandoffs(report([],{unknownCapabilities:[id]}));
    assert.ok(h.expectedEvidence.length); assert.match(h.capabilityGap,/declare_applicable_/);
  }
});
test('known capability gap identifies failed and missing required checks', () => {
  const [h] = createBlockerHandoffs(report());
  assert.match(h.capabilityGap,/explicit_entry/); assert.match(h.capabilityGap,/existing_identity_authenticated/);
});

test('handoffs distinguish authorization knowledge and retain mandatory verification', () => {
  for (const [authorization, expected] of [[true, 'GRANTED'], [false, 'NOT_GRANTED'], [undefined, 'NOT_ESTABLISHED']]) {
    const [handoff] = createBlockerHandoffs(report(), { registeredCapabilities: ['signin'], authorization });
    assert.equal(handoff.authorizationState, expected);
    assert.equal(handoff.verificationRequired, true);
  }
});

test('transferable handoff retains revision and required operating context without invented lineage', () => {
  const [handoff] = createBlockerHandoffs(report(undefined, { revision: 'reviewed-revision' }), {
    repository: '/product', requestedOutcome: 'Confirm successful enrollment',
    reproductionCommand: ['auth', 'wizard', '--operator', 'OBSERVE'],
    verificationCommand: ['auth', 'wizard', '--operator', 'VERIFY'],
  });
  assert.equal(handoff.target.revision, 'reviewed-revision');
  for (const key of ['wizard', 'version', 'catalogVersion', 'target', 'requestedOutcome', 'capabilityId', 'mdboLineage',
    'operator', 'applicability', 'implementation', 'verification', 'reasonCode', 'observedEvidence', 'expectedEvidence',
    'capabilityGap', 'executionClassification', 'actAvailability', 'authorizationRequired', 'nextOwner', 'reproductionCommand', 'verificationCommand', 'resumeCondition']) {
    assert.ok(Object.hasOwn(handoff, key), key);
  }
  assert.equal(handoff.mdboLineage.status, 'NOT_ESTABLISHED');
});
