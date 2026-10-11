import test from 'node:test';
import assert from 'node:assert/strict';
import { evaluateRuntimeAcceptance as evaluate } from './auth-runtime-acceptance.mjs';
const now = Date.parse('2026-09-12T23:10:00-04:00');
const evaluateRuntimeAcceptance = input => evaluate(input, {now});
const base = { target: 'product', environment: 'local', contract: 'ASSERTION_INTEGRATION', source_conformance: { result: 'PASS', checks: 25 } };
const currentCheck = {id:'issuer_signer_available',environment:'local',freshness:'CURRENT_OBSERVATION',observedAt:'2026-09-12T23:05:48-04:00',result:'PASS',evidence:['current observation'],expected:'available',owner:'AUTH'};
test('stale, future, malformed, and contradictory observations cannot establish gates', () => {
  for (const overrides of [{observedAt:'2026-09-10T23:05:48-04:00'}, {observedAt:'2026-09-13T23:05:48-04:00'}, {evidence:'string'}, {evidence:['']}]) {
    const r = evaluateRuntimeAcceptance({...base, configured_runtime:[{...currentCheck,...overrides}]});
    assert.equal(r.configured_runtime.checks[0].result,'INDETERMINATE');
  }
  const r = evaluateRuntimeAcceptance({...base,configured_runtime:[currentCheck,{...currentCheck,result:'FAIL'}]});
  assert.equal(r.configured_runtime.checks[0].result,'INDETERMINATE');
});
test('native completion schema failure does not invent credential rejection', () => {
  const r = evaluateRuntimeAcceptance({...base,contract:'NATIVE_SIGNIN',configured_runtime:[{id:'canonical_enrollment_completion_schema_compatible',environment:'local',freshness:'CURRENT_OBSERVATION',observedAt:'2026-09-12T23:05:48-04:00',result:'FAIL',evidence:['canonical schema vs completion source'],expected:'compatible completion',owner:'native persistence'}]});
  assert.equal(r.configured_runtime.result,'FAIL');
  assert.equal(r.live_acceptance.result,'INDETERMINATE');
});
test('source PASS cannot certify absent runtime evidence', () => {
  const r = evaluateRuntimeAcceptance(base);
  assert.equal(r.source_conformance.result, 'PASS'); assert.equal(r.acceptance, 'INDETERMINATE');
});
test('proven unavailable signer fails configured runtime; live unknown stays unknown', () => {
  const r = evaluateRuntimeAcceptance({...base, configured_runtime: [{id:'issuer_signer_available',environment:'local',freshness:'CURRENT_OBSERVATION',observedAt:'2026-09-12T23:05:48-04:00',result:'FAIL',evidence:['HTTP503 ACCESS_ASSERTION_UNAVAILABLE'],expected:'available signer',owner:'AUTH'}]});
  assert.equal(r.configured_runtime.result, 'FAIL'); assert.equal(r.live_acceptance.result, 'INDETERMINATE'); assert.equal(r.acceptance, 'FAIL');
});
test('foreign environment evidence cannot pass or fail current gate', () => {
  const r = evaluateRuntimeAcceptance({...base,configured_runtime:[{id:'issuer_signer_available',environment:'production',result:'FAIL',evidence:['screenshot'],expected:'available signer',owner:'AUTH'}]});
  assert.equal(r.configured_runtime.result,'INDETERMINATE');
});
