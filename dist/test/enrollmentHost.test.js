import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { mountEnrollmentHost } from '../auth/enrollmentHost.js';
test('host requires current authenticated bearer and binds durable admission to session and owner', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'enrollment-host-'));
    const previous = { ...process.env };
    const auth = crypto.generateKeyPairSync('ed25519'), authority = crypto.generateKeyPairSync('ed25519');
    process.env.AUTH_ENROLLMENT_STORE_PATH = join(dir, 'tx.sqlite');
    process.env.AUTH_VVAULT_ACCESS_ASSERTION_PRIVATE_KEY_PEM = auth.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    process.env.AUTH_VVAULT_ACCESS_ASSERTION_PUBLIC_KEY_PEM = auth.publicKey.export({ type: 'spki', format: 'pem' }).toString();
    delete process.env.AUTH_VVAULT_ACCESS_ASSERTION_KEY_ID;
    delete process.env.AUTH_VVAULT_ACCOUNT_ASSERTION_KEY_ID;
    process.env.AUTH_ENROLLMENT_AUTHORITY_PUBLIC_KEY_PEM = authority.publicKey.export({ type: 'spki', format: 'pem' }).toString().replace(/\n/g, '\\n');
    process.env.AUTH_JWT_ISSUER = 'quantum-auth';
    process.env.AUTH_ENROLLMENT_AUTHORITY_ISSUER = 'vvault';
    const routes = new Map();
    let sessionId = 'session-a';
    let revoked = false;
    let consentRequired = false;
    let manifestReads = 0;
    const session = { id: 'life-a', sub: 'life-a', vvaultUserId: 'life-a', relyingPartyId: 'chatty', providerIdentity: { provider: 'google', subject: 'google-a', issuer: 'https://accounts.google.com', verifiedEmail: 'fixture@example.test' } };
    mountEnrollmentHost({ post: (p, h) => routes.set(p, h), get: (p, h) => routes.set(p, h) }, async () => revoked ? { error: 'revoked', status: 401 } : { sessionId, session }, async () => ({ required: consentRequired, docs: [{ key: 'chatty:terms', version: 'fixture' }] }), async () => { manifestReads++; return ['terms', 'privacy', 'eeccd'].map(key => ({ key: 'vvault:' + key, version: 'v1', sha256: 'a'.repeat(64), url: 'http://localhost/' + key, label: key })); });
    async function invoke(path, body = {}, cookie) { let status = 200; let data; await routes.get('/api/auth/enrollment/' + path)({ body, headers: { cookie }, get: (k) => k === 'authorization' ? 'Bearer fixture' : k === 'X-Chatty-Auth-Bridge' ? 'auth.enrollment.v1' : null }, { set() { }, status(n) { status = n; return this; }, json(d) { data = d; return this; } }); return { status, data }; }
    try {
        assert.equal((await invoke('start', { intent: 'SIGN_UP' }, 'native=1')).status, 403);
        const started = await invoke('start', { intent: 'SIGN_UP', canonicalConsent: { accepted: true, documents: ['terms', 'privacy', 'eeccd'].map(key => ({ key: 'vvault:' + key, version: 'v1', sha256: 'a'.repeat(64) })) }, ownerId: 'forged', relyingParty: 'vvault' });
        assert.equal(started.status, 200);
        assert.equal(JSON.parse(Buffer.from(started.data.handoff.split('.')[0], 'base64url').toString()).ownerId, null);
        assert.equal((await invoke('admission')).data.ownerResolved, false);
        const moduleUrl = new URL('../../scripts/auth-enrollment-handoff.mjs', import.meta.url).href;
        const { createAuthorityCompletion } = await import(moduleUrl);
        const completed = await createAuthorityCompletion({ handoff: started.data.handoff, authPublicKey: auth.publicKey, authIssuer: 'quantum-auth', authorityIssuer: 'vvault', authoritySigningKey: authority.privateKey, attest: async (h) => ({ enrollment: 'COMPLETED', ownerId: '11111111-1111-4111-8111-111111111111', identity: h.identity, requirements: { session: 'SATISFIED', device: 'SATISFIED', policy: 'SATISFIED' }, policyVersion: '1', authoritySessionBinding: 'authority-a' }) });
        sessionId = 'session-b';
        assert.equal((await invoke('complete', completed)).status, 409);
        sessionId = 'session-a';
        const beforeCompleteReads = manifestReads;
        assert.equal((await invoke('complete', completed)).data.admission, 'AUTHORIZED');
        assert.equal(manifestReads, beforeCompleteReads);
        assert.equal((await invoke('complete', completed)).status, 409);
        assert.equal((await invoke('admission')).data.ownerId, '11111111-1111-4111-8111-111111111111');
        assert.equal(manifestReads, beforeCompleteReads);
        consentRequired = true;
        assert.equal((await invoke('admission')).data.admission, 'ENROLLMENT_REQUIRED');
        assert.equal((await invoke('admission')).data.productConsentRequired, true);
        assert.equal((await invoke('start', { intent: 'SIGN_IN' })).data.errorCode, 'PRODUCT_CONSENT_REQUIRED');
        consentRequired = false;
        sessionId = 'session-b';
        assert.equal((await invoke('admission')).data.admission, 'ENROLLMENT_REQUIRED');
        revoked = true;
        assert.equal((await invoke('admission')).status, 401);
    }
    finally {
        for (const k of Object.keys(process.env))
            if (!(k in previous))
                delete process.env[k];
        Object.assign(process.env, previous);
        rmSync(dir, { recursive: true, force: true });
    }
});
