import test from 'node:test';
import assert from 'node:assert/strict';
import { CAPABILITIES, CATALOG_VERSION } from '../../scripts/auth-capability-catalog.mjs';
import { evaluateAdapter, executeRepair } from '../../scripts/auth-wizard.mjs';

function adapter() {
  return { schemaVersion: 1, productId: 'example', revision: 'r1', capabilities:
    Object.fromEntries(CAPABILITIES.map(c => [c.id, { applicability: 'FALSE', reason: 'Not adopted by this product' }])) };
}
function established(a, id) {
  a.capabilities[id] = { applicability: 'TRUE', implementation: 'ESTABLISHED', evidence: ['test:current-revision'],
    checks: Object.fromEntries(CAPABILITIES.find(c => c.id === id).checks.map(check => [check, true])) };
}
const result = (a, id) => evaluateAdapter(a).capabilities.find(c => c.id === id);
function message(kind, checks) {
  return { id: kind, kind, applicability: 'TRUE', implementation: 'ESTABLISHED', evidence: ['transport-test:current'],
    checks: Object.fromEntries(checks.map(check => [check, true])) };
}
const welcomeChecks = ['trigger_after_success', 'recipient_defined', 'delivery_adapter', 'template_exists', 'delivery_result', 'duplicate_policy_defined'];
const authChecks = ['trigger_defined', 'recipient_defined', 'delivery_adapter', 'template_exists', 'delivery_result', 'duplicate_policy_defined', 'token_url_secrecy', 'expiry_policy_defined'];

test('welcome confirmation retains all three applicability states; a reasoned exclusion is not forced on products', () => {
  const a = adapter();
  assert.equal(result(a, 'welcome.confirmation').verification, 'NOT_APPLICABLE');
  established(a, 'welcome.confirmation');
  assert.equal(result(a, 'welcome.confirmation').verification, 'PASS');
  a.capabilities['welcome.confirmation'].applicability = 'INDETERMINATE';
  assert.equal(result(a, 'welcome.confirmation').verification, 'INDETERMINATE');
  delete a.capabilities['welcome.confirmation'];
  assert.equal(result(a, 'welcome.confirmation').verification, 'INDETERMINATE');
});

test('applicable welcome requires established implementation and success confirmation evidence', () => {
  const a = adapter();
  a.capabilities['welcome.confirmation'] = { applicability: 'TRUE', implementation: 'NOT_ESTABLISHED' };
  assert.equal(result(a, 'welcome.confirmation').verification, 'FAIL');
  established(a, 'welcome.confirmation');
  a.capabilities['welcome.confirmation'].checks.in_product_confirmation_visible = false;
  assert.equal(result(a, 'welcome.confirmation').verification, 'FAIL');
  delete a.capabilities['welcome.confirmation'].checks.in_product_confirmation_visible;
  assert.equal(result(a, 'welcome.confirmation').verification, 'INDETERMINATE');
});

test('in-product confirmation does not require a welcome email; applicable mail needs its own declaration', () => {
  const a = adapter(); established(a, 'welcome.confirmation');
  assert.equal(evaluateAdapter(a).verification, 'PASS');
  established(a, 'welcome.email');
  a.emails = [message('verification', authChecks)];
  assert.equal(evaluateAdapter(a).verification, 'INDETERMINATE');
  assert.ok(evaluateAdapter(a).unknownCapabilities.includes('welcome-emails:missing'));
  a.emails.push(message('welcome', welcomeChecks));
  assert.equal(evaluateAdapter(a).verification, 'PASS');
  a.emails[1].checks.delivery_result = false;
  assert.equal(evaluateAdapter(a).verification, 'FAIL');
});

test('welcome is onboarding, distinct from verification and magic, and marketing remains outside authority', () => {
  const a = adapter();
  a.emails = [message('welcome', welcomeChecks), message('verification', authChecks), message('magic_link', authChecks)];
  const report = evaluateAdapter(a);
  assert.equal(report.verification, 'PASS');
  const welcome = report.capabilities.find(c => c.id === 'email-message:welcome');
  assert.equal(welcome.family, 'enrollment');
  assert.deepEqual(welcome.checks.map(c => c.id), welcomeChecks);
  assert.equal(report.capabilities.find(c => c.id === 'email-message:verification').family, 'auth_email');
  a.emails.push(message('marketing_newsletter', authChecks));
  assert.equal(evaluateAdapter(a).capabilities.find(c => c.id === 'email-message:marketing_newsletter').error, 'OUTSIDE_AUTH_EMAIL_AUTHORITY');
});

test('welcome checks protect trigger, template, delivery and idempotency independently', () => {
  for (const check of CAPABILITIES.find(c => c.id === 'welcome.email').checks) {
    const a = adapter(); established(a, 'welcome.email'); a.emails = [message('welcome', welcomeChecks)];
    a.capabilities['welcome.email'].checks[check] = false;
    assert.equal(result(a, 'welcome.email').verification, 'FAIL', check);
  }
});

test('additive catalog upgrade keeps old baseline protections and requires new welcome evidence', () => {
  const a = adapter(); established(a, 'signup');
  const baseline = evaluateAdapter(a);
  baseline.catalogVersion = '1';
  baseline.capabilities = baseline.capabilities.filter(c => !c.id.startsWith('welcome.'));
  assert.equal(evaluateAdapter(a).catalogVersion, CATALOG_VERSION);
  a.capabilities.signup.checks.explicit_entry = false;
  const report = evaluateAdapter(a, { baseline });
  assert.equal(report.verification, 'FAIL');
  assert.ok(report.regressions.some(r => r.id === 'signup'));
});

test('supported ACT always observes and verifies; authorization alone cannot grant PASS', async () => {
  const a = adapter(); established(a, 'welcome.confirmation');
  a.capabilities['welcome.confirmation'].checks.in_product_confirmation_visible = false;
  const events = [];
  const report = await executeRepair(a, { capabilityId: 'welcome.confirmation',
    authorization: { authorized: true, productId: 'example', revision: 'r1', capabilityId: 'welcome.confirmation' },
    handlers: new Map([['welcome.confirmation', () => events.push('ACT')]]),
    observe: async () => { events.push('VERIFY'); return a; } });
  assert.deepEqual(events, ['ACT', 'VERIFY']);
  assert.equal(report.verifiedAfterAct, true);
  assert.equal(report.verificationRequired, true);
  assert.equal(report.verification, 'FAIL');
});
