import test from 'node:test';
import assert from 'node:assert/strict';
import { CAPABILITIES, CATALOG_VERSION, COMPATIBLE_BASELINE_VERSIONS } from '../../scripts/auth-capability-catalog.mjs';
import { evaluateAdapter } from '../../scripts/auth-wizard.mjs';
import { verificationOwner } from '../../scripts/auth-evidence-ownership.mjs';

const ids = ['assertion.resource_grant', 'assertion.resource_status'];
function fixture(includeResources = true) {
  const adapter = { schemaVersion: 1, productId: 'fixture-native', revision: 'product-r1', authenticationRole: 'RELYING_PARTY', identityAuthority: { id: 'auth-issuer', revision: 'issuer-r1' }, resourceAuthority: { id: 'resource-validator', revision: 'validator-r1' }, capabilities: {} };
  const trustedAuthorityEvidence = [];
  for (const c of CAPABILITIES.filter(c => c.family === 'assertion' || c.id === 'security.failure' || includeResources && ids.includes(c.id))) {
    adapter.capabilities[c.id] = { applicability: 'TRUE', implementation: 'ESTABLISHED', evidence: ['synthetic:fixture'], checks: {} };
    for (const checkId of c.checks) {
      if (verificationOwner(c.id, checkId) !== 'EXTERNAL_AUTHORITY') adapter.capabilities[c.id].checks[checkId] = true;
      else {
        const authority = ['assertion.validation', 'assertion.resource_status'].includes(c.id) ? adapter.resourceAuthority : adapter.identityAuthority;
        trustedAuthorityEvidence.push({ productId: adapter.productId, revision: adapter.revision, authority: authority.id, authorityRevision: authority.revision, capabilityId: c.id, checkId, verification_owner: 'EXTERNAL_AUTHORITY', kind: 'CONFORMANCE', result: 'PASS', references: ['synthetic:authority-contract-tests'] });
      }
    }
  }
  return { adapter, options: { verificationProfile: 'ASSERTION_INTEGRATION', trustedAuthorityEvidence } };
}
const row = (report, id) => report.capabilities.find(c => c.id === id);

test('catalog is additive and legacy v2 profile does not require undeclared resource authorization', () => {
  assert.equal(CATALOG_VERSION, '1.5'); assert.ok(COMPATIBLE_BASELINE_VERSIONS.includes('1.4'));
  const { adapter, options } = fixture(false); const report = evaluateAdapter(adapter, options);
  assert.equal(report.profile_verification, 'PASS'); assert.equal(report.full_verification, 'INDETERMINATE');
  assert.ok(ids.every(id => report.outside_profile_unresolved_checks.some(c => c.capabilityId === id)));
  assert.equal(row(report, ids[0]).applicability, 'INDETERMINATE');
});

test('declared generic contract requires issuer and resource-validator evidence independently', () => {
  const { adapter, options } = fixture(); const report = evaluateAdapter(adapter, options);
  assert.equal(report.profile_verification, 'PASS');
  assert.equal(report.profile_required_checks.filter(c => ids.includes(c.capabilityId)).length, 10);
  const wrongAuthority = options.trustedAuthorityEvidence.map(e => e.capabilityId === ids[1] ? { ...e, authority: adapter.identityAuthority.id, authorityRevision: adapter.identityAuthority.revision } : e);
  const rejected = evaluateAdapter(adapter, { ...options, trustedAuthorityEvidence: wrongAuthority });
  assert.equal(row(rejected, ids[1]).verification, 'INDETERMINATE');
  assert.equal(row(rejected, ids[0]).verification, 'PASS');
  assert.equal(rejected.profile_verification, 'INDETERMINATE');
});

test('product booleans and missing authority proof cannot satisfy resource checks', () => {
  const { adapter, options } = fixture();
  for (const id of ids) adapter.capabilities[id].checks = Object.fromEntries(CAPABILITIES.find(c => c.id === id).checks.map(check => [check, true]));
  const report = evaluateAdapter(adapter, { ...options, trustedAuthorityEvidence: options.trustedAuthorityEvidence.filter(e => !ids.includes(e.capabilityId)) });
  assert.equal(report.profile_verification, 'INDETERMINATE');
  assert.ok(ids.every(id => row(report, id).verification === 'INDETERMINATE'));
});

test('failed online status check fails applicable profile and cannot be hidden by a PASS', () => {
  const { adapter, options } = fixture();
  options.trustedAuthorityEvidence.push({ ...options.trustedAuthorityEvidence.find(e => e.capabilityId === ids[1] && e.checkId === 'status_failure_fails_closed'), result: 'FAIL' });
  const report = evaluateAdapter(adapter, options);
  assert.equal(report.profile_verification, 'FAIL'); assert.equal(row(report, ids[1]).verification, 'FAIL');
});

test('an established generic requirement cannot disappear from profile by deleting applicability', () => {
  const { adapter, options } = fixture();
  const baseline = evaluateAdapter(adapter, options);
  delete adapter.capabilities['assertion.resource_status'];
  const after = evaluateAdapter(adapter, { ...options, baseline });
  assert.equal(after.profile_verification, 'FAIL');
  assert.equal(after.profile_regressions.filter(c => c.capabilityId === 'assertion.resource_status').length, 5);
});
