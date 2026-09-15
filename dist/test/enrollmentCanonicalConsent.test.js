import test from 'node:test';
import assert from 'node:assert/strict';
import { canonicalConsentManifest, acceptedCanonicalConsent } from '../auth/enrollmentCanonicalConsent.js';
const docs = ['terms', 'privacy', 'eeccd'].map(key => ({ key: 'vvault:' + key, version: 'v1', sha256: 'a'.repeat(64), url: '/api/legal/' + key + '.pdf', label: key }));
test('manifest is pinned and exact current acceptance is required', async () => {
    let options;
    const parsed = await canonicalConsentManifest({ AUTH_ENROLLMENT_AUTHORITY_ORIGIN: 'http://localhost:8000' }, async (url, opts) => { assert.equal(String(url), 'http://localhost:8000/api/auth/enrollment/documents'); options = opts; return { ok: true, json: async () => ({ authority: 'vvault', version: 'vvault.enrollment.documents.v1', documents: docs }) }; });
    assert.equal(options.redirect, 'error');
    assert.equal(parsed[0].url, 'http://localhost:8000/api/legal/terms.pdf');
    assert.equal(acceptedCanonicalConsent({}, parsed), null);
    assert.equal(acceptedCanonicalConsent({ canonicalConsent: { accepted: true, documents: [{ ...docs[0], sha256: 'b'.repeat(64) }] } }, parsed), null);
    assert.equal(acceptedCanonicalConsent({ canonicalConsent: { accepted: true, documents: docs } }, parsed, 1000)?.acceptedAt, 1000);
    await assert.rejects(canonicalConsentManifest({ AUTH_ENROLLMENT_AUTHORITY_ORIGIN: 'https://user:password@fixture.test' }, async () => assert.fail('must not fetch')));
    await assert.rejects(canonicalConsentManifest({ AUTH_ENROLLMENT_AUTHORITY_ORIGIN: 'http://localhost:8000' }, async () => ({ ok: true, json: async () => ({ authority: 'vvault', version: 'vvault.enrollment.documents.v1', documents: [{ ...docs[0], url: 'https://other.test/doc' }] }) })));
});
