import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { verifyVvaultSessionProof, verifyChattyConsentManifest } from '../auth/vvaultSessionFederation.js';
test('native VVAULT proof requires exact issuer audience gates owner identity expiry and recorded receipt hashes', async () => {
    const keys = crypto.generateKeyPairSync('ed25519');
    const pem = keys.publicKey.export({ type: 'spki', format: 'pem' }).toString();
    const p = { version: 'auth.vvault-native-session.v1', kind: 'IDENTITY', issuer: 'vvault', audience: 'quantum-auth', product_id: 'chatty', relyingParty: 'chatty', client_id: 'chatty-web-link', issuedAt: 1000, expiresAt: 1060, authorization_request: 'request-'.repeat(5), nonce: 'nonce-'.repeat(5), authoritySessionBinding: 'native-session-'.repeat(2), ownerId: '11111111-1111-4111-8111-111111111111', provider_identity: { provider: 'google', subject: 'google-id', issuer: 'https://accounts.google.com', verifiedEmail: 'fixture@example.test' }, email: 'fixture@example.test', name: 'Fixture', requirements: { enrollment: 'SATISFIED', session: 'SATISFIED', device: 'SATISFIED', policy: 'SATISFIED' }, chattyConsents: ['terms', 'privacy', 'eeccd'].map(k => ({ key: 'chatty:' + k, version: 'v1', sha256: 'a'.repeat(64), acceptedAt: new Date(999000).toISOString() })) };
    const sign = (v) => { const b = Buffer.from(JSON.stringify(v)).toString('base64url'); return b + '.' + crypto.sign(null, Buffer.from(b), keys.privateKey).toString('base64url'); };
    const verify = (v) => verifyVvaultSessionProof(sign(v), { publicKeyPem: pem, audience: 'quantum-auth', now: 1000 });
    assert.equal(verify(p).ownerId, p.ownerId);
    for (const changes of [{ audience: 'other' }, { issuer: 'other' }, { expiresAt: 1000 }, { expiresAt: 1061 }, { client_id: 'other' }, { requirements: { ...p.requirements, device: 'PENDING' } }, { provider_identity: { ...p.provider_identity, verifiedEmail: undefined } }, { chattyConsents: [p.chattyConsents[0], p.chattyConsents[0], p.chattyConsents[2]] }])
        assert.throws(() => verify({ ...p, ...changes }));
    const fetcher = async (_url, opts) => { assert.equal(opts.redirect, 'error'); return { ok: true, json: async () => ({ authority: 'chatty', documents: p.chattyConsents }) }; };
    assert.equal(await verifyChattyConsentManifest(p.chattyConsents, 'http://localhost:5173/login', fetcher), true);
    assert.equal(await verifyChattyConsentManifest(p.chattyConsents.map(d => ({ ...d, sha256: 'b'.repeat(64) })), 'http://localhost:5173/login', fetcher), false);
});
