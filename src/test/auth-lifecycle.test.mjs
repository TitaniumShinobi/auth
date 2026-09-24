import test from 'node:test';
import assert from 'node:assert/strict';
import { verifyLifecycle } from '../../scripts/auth-lifecycle.mjs';
const verify = (capability, events) => verifyLifecycle({ capability, events }).verification;
const event = (type, fields = {}) => ({ type, ...fields });
const existing = event('identity.lookup', { exists: true, id: 'one' });
const auth = event('identity.authenticate', { id: 'one' });
const create = event('identity.create', { id: 'one' });

test('login and signup evidence is distinct and prevents duplicate identities', () => {
  assert.equal(verify('login', [existing, auth]), 'PASS');
  assert.equal(verify('signup', [event('identity.lookup', { exists: false }), create, auth]), 'PASS');
  assert.equal(verify('signup', [existing, auth]), 'PASS');
  assert.equal(verify('login', [existing, create, auth]), 'FAIL');
  assert.equal(verify('signup', [existing, create, auth]), 'FAIL');
  assert.equal(verify('login', [existing, event('identity.authenticate', { id: 'different' })]), 'FAIL');
});

test('optional enrollment decline permits completion in either generic direction', () => {
  for (const accepted of [false, true]) {
    const decision = event('enrollment.decision', { optional: true, accepted });
    assert.equal(verify('optional-enrollment', [decision, event('primary.complete')]), 'PASS');
  }
  assert.equal(verify('optional-enrollment', [event('enrollment.decision', { optional: true, accepted: false }), event('primary.blocked')]), 'FAIL');
});

test('existing-account linking reuses identity and relying parties do not own identity', () => {
  const link = event('account.link', { existingId: 'one', linkedId: 'one' });
  assert.equal(verify('account-link', [link]), 'PASS');
  assert.equal(verify('account-link', [link, create]), 'FAIL');
  assert.equal(verify('account-link', [event('account.link', { existingId: 'one', linkedId: 'two' })]), 'FAIL');
  assert.equal(verify('relying-party', [event('relying-party.accept', { identityAuthority: false })]), 'PASS');
  assert.equal(verify('relying-party', [event('relying-party.accept', { identityAuthority: true })]), 'FAIL');
});

test('expired, replayed, or failed delivery magic links cannot authenticate', () => {
  for (const outcome of ['expired', 'replayed', 'delivery-failed']) {
    const consumed = event('magic.consume', { outcome });
    assert.equal(verify('magic-email', [consumed, event('authentication.denied')]), 'PASS');
    assert.equal(verify('magic-email', [consumed, auth]), 'FAIL');
    assert.equal(verify('magic-email', [consumed]), 'INDETERMINATE');
  }
});

test('session operations provide independent evidence', () => {
  for (const operation of ['issue', 'validate', 'refresh', 'logout', 'revoke', 'expire']) {
    assert.equal(verify('session', [event(`session.${operation}`, { sessionId: 's', success: true })]), 'PASS');
    assert.equal(verify('session', [event(`session.${operation}`, { sessionId: 's', success: false })]), 'FAIL');
    assert.equal(verify('session', [event(`session.${operation}`, { sessionId: 's' })]), 'INDETERMINATE');
  }
});

test('missing, malformed, and unrelated evidence never passes vacuously', () => {
  for (const trace of [null, {}, { capability: 'login', events: [] }, { capability: 'login', events: [auth] }, { capability: 'unknown', events: [auth] }, { capability: 'session', events: [event('session.fake')] }]) {
    assert.equal(verifyLifecycle(trace).verification, 'INDETERMINATE');
  }
});

test('identity lookup and valid magic proof precede authentication', () => {
  assert.equal(verify('login', [auth, existing]), 'FAIL');
  assert.equal(verify('magic-email', [auth, event('magic.consume', { outcome: 'valid' })]), 'FAIL');
  assert.equal(verify('magic-email', [event('magic.consume', { outcome: 'valid' }), auth]), 'PASS');
});

test('denied authentication cannot coexist with identity or session success', () => {
  const denied = event('authentication.denied');
  assert.equal(verify('login', [existing, denied, auth]), 'FAIL');
  assert.equal(verify('login', [existing, denied, event('session.issue', { sessionId: 's', success: true })]), 'FAIL');
  assert.equal(verify('login', [existing, denied]), 'PASS');
});
