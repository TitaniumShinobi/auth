import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeVerifiedProviderIdentity } from '../auth/canonicalOwner.js';
import { signProductSessionAssertion, verifyProductSessionAssertionSignature } from '../auth/productSessionFederation.js';
test('optional verified Google contact is bound by federation signature and legacy signatures remain valid', () => {
    const input = { product_id: 'chatty', authorization_request: 'request', subject: 'life', email: 'fixture@example.test', name: 'Fixture', issued_at: 1, expires_at: 60, nonce: 'nonce', provider_identity: { provider: 'google', subject: 'provider', issuer: 'https://accounts.google.com' } };
    const secret = 'fixture-secret-with-at-least-32-bytes';
    const old = signProductSessionAssertion(input, secret);
    assert.equal(verifyProductSessionAssertionSignature(input, old, secret), true);
    const extended = { ...input, provider_identity: { ...input.provider_identity, verifiedEmail: 'fixture@example.test' } };
    assert.equal(verifyProductSessionAssertionSignature(extended, old, secret), false);
    assert.equal(verifyProductSessionAssertionSignature(extended, signProductSessionAssertion(extended, secret), secret), true);
    assert.equal(normalizeVerifiedProviderIdentity({ ...extended.provider_identity, verifiedEmail: 'invalid' }), null);
    assert.equal(normalizeVerifiedProviderIdentity({ ...extended.provider_identity, provider: 'github', issuer: 'https://github.com' }), null);
});
