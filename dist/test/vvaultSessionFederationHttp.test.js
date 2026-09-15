import { signProductSessionAssertion } from '../auth/productSessionFederation.js';
import { spawn } from 'node:child_process';
import { realpathSync } from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { createAuthApp } from '../app.js';
import { MemoryStorageAdapter } from '../persistence/memoryStorage.js';
import { MemoryRefreshTokenStore } from '../auth/refreshTokenStore.js';
const cookie = (r) => r.headers.getSetCookie().map((s) => s.split(';')[0]).join('; ');
test('native authority federation is browser/request bound, one use, imports exact receipts then exchanges PKCE', async (t) => {
    const originalFetch = globalThis.fetch, previous = { ...process.env };
    const keys = crypto.generateKeyPairSync('ed25519');
    process.env.AUTH_ENROLLMENT_AUTHORITY_PUBLIC_KEY_PEM = keys.publicKey.export({ type: 'spki', format: 'pem' }).toString();
    process.env.AUTH_ENROLLMENT_AUTHORITY_ORIGIN = 'http://localhost:8000';
    process.env.AUTH_JWT_ISSUER = 'quantum-auth';
    const owner = '11111111-1111-4111-8111-111111111111';
    const docs = ['terms', 'privacy', 'eeccd'].map(key => ({ key: 'chatty:' + key, version: 'v1', sha256: 'a'.repeat(64), label: key, url: 'http://localhost:5173/legal/' + key, required: true }));
    globalThis.fetch = (async (url, options) => String(url) === 'http://localhost:5173/api/auth/enrollment/documents' ? new Response(JSON.stringify({ authority: 'chatty', documents: docs }), { status: 200 }) : originalFetch(url, options));
    const config = { app: { id: 'chatty', name: 'Chatty' }, allowedOrigins: ['http://localhost:5173', 'http://localhost:8000'], redirects: { postLoginPath: '/', postLogoutPath: '/' }, docs, credentials: { enabled: true }, turnstile: { required: false, enabled: false }, providers: [], publicClients: [{ clientId: 'chatty-web-link', authorizationUiUrl: 'http://localhost:5173/login', redirectUris: ['http://localhost:5173/api/auth/paired/callback'], scopes: ['openid', 'profile', 'email'] }] };
    const storage = new MemoryStorageAdapter();
    const app = await createAuthApp({ storage, configStore: { getConfig: async () => config }, refreshTokenStore: new MemoryRefreshTokenStore(), sessionSecret: 'fixture-session-secret', resolveLifeProfile: async () => ({ lifeUserId: 'life-fixture', supabaseUserId: null, displayName: 'Fixture', source: 'local_only' }), resolveVvaultOwnerId: async () => owner });
    const server = app.listen(0, '127.0.0.1');
    await new Promise(resolve => server.once('listening', resolve));
    const base = 'http://127.0.0.1:' + server.address().port;
    try {
        const emailInput = { product_id: 'chatty', authorization_request: 'fixture-authorization', subject: '33333333-3333-4333-8333-333333333333', email: 'fixture@example.test', name: 'Fixture', issued_at: Math.floor(Date.now() / 1000), expires_at: Math.floor(Date.now() / 1000) + 60, nonce: crypto.randomUUID(), provider_identity: { provider: 'email', subject: '33333333-3333-4333-8333-333333333333', issuer: 'https://vvault.thewreck.org', verifiedEmail: 'fixture@example.test' } };
        const emailHmac = await fetch(base + '/oauth/federation/assertions', { method: 'POST', headers: { 'content-type': 'application/json', 'x-auth-assertion-signature': signProductSessionAssertion(emailInput, 'synthetic-shared-secret-for-fixture-only') }, body: JSON.stringify(emailInput) });
        assert.equal(emailHmac.status, 401);
        const verifier = 'test-verifier-long-enough-for-pkce-fixture-123456';
        const redirect = 'http://localhost:5173/api/auth/paired/callback';
        const query = new URLSearchParams({ app: 'chatty', response_type: 'code', client_id: 'chatty-web-link', redirect_uri: redirect, state: 'fixture-state-long-enough-123456789', code_challenge: crypto.createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256', identity_authority: 'vvault' });
        const start = await fetch(base + '/oauth/authorize?' + query, { redirect: 'manual' });
        assert.equal(start.status, 302);
        const target = new URL(start.headers.get('location'));
        assert.equal(target.origin + target.pathname, 'http://localhost:8000/api/auth/chatty/authorize');
        const now = Math.floor(Date.now() / 1000);
        const proof = { version: 'auth.vvault-native-session.v1', kind: 'IDENTITY', issuer: 'vvault', audience: 'quantum-auth', product_id: 'chatty', relyingParty: 'chatty', client_id: 'chatty-web-link', issuedAt: now, expiresAt: now + 60, authorization_request: target.searchParams.get('authorization_request'), nonce: crypto.randomUUID(), authoritySessionBinding: crypto.randomUUID(), ownerId: owner, provider_identity: { provider: 'google', subject: 'provider-fixture', issuer: 'https://accounts.google.com', verifiedEmail: 'fixture@example.test' }, email: 'fixture@example.test', name: 'Fixture', requirements: { enrollment: 'SATISFIED', session: 'SATISFIED', device: 'SATISFIED', policy: 'SATISFIED' }, chattyConsents: docs.map(d => ({ ...d, acceptedAt: new Date((now - 1) * 1000).toISOString() })) };
        const encoded = Buffer.from(JSON.stringify(proof)).toString('base64url');
        const token = encoded + '.' + crypto.sign(null, Buffer.from(encoded), keys.privateKey).toString('base64url');
        const send = () => fetch(base + '/oauth/federation/assertions', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ authority_proof: token }) });
        const assertion = await send();
        assert.equal(assertion.status, 201);
        assert.equal((await send()).status, 409);
        const id = (await assertion.json()).assertion_id;
        const complete = (cookies) => fetch(base + '/oauth/federation/complete', { method: 'POST', redirect: 'manual', headers: { 'content-type': 'application/json', origin: 'http://localhost:8000', cookie: cookies }, body: JSON.stringify({ assertion_id: id }) });
        assert.equal((await complete('')).status, 400);
        const completed = await complete(cookie(start));
        assert.equal(completed.status, 302);
        assert.equal((await complete(cookie(start))).status, 400);
        const callback = new URL(completed.headers.get('location'));
        const exchange = await fetch(base + '/oauth/token', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ grant_type: 'authorization_code', client_id: 'chatty-web-link', redirect_uri: redirect, code: callback.searchParams.get('code'), code_verifier: verifier }) });
        assert.equal(exchange.status, 200);
        await t.test('actual AUTH profile refresh preserves signed RP for Chatty owner verification', async () => {
            const actualTokens = await exchange.json();
            const actualMe = await fetch(base + '/api/me', { headers: { authorization: 'Bearer ' + actualTokens.access_token } });
            assert.equal(actualMe.status, 200, actualMe.status === 200 ? '' : await actualMe.text());
            const actualSession = await actualMe.json();
            assert.equal(actualSession.ok, true);
            const pairedModule = await Function('url', 'return import(url)')(new URL('file://' + path.join(path.resolve(realpathSync(new URL('../../scripts', import.meta.url)), '../..'), 'chatty-ui/server/lib/pairedSignup.js')).href);
            let native;
            try {
                native = pairedModule.pairedIdentity(actualSession.user, owner);
            }
            catch (error) {
                throw new Error('Actual AUTH session rejected: ' + error.pairedReason);
            }
            assert.equal(native.sub, 'provider-fixture');
            assert.equal(native.identityOnly, true);
        });
        for (const producerProvider of ['google', 'email']) {
            const fresh = await fetch(base + '/oauth/authorize?' + query, { redirect: 'manual' });
            const freshTarget = new URL(fresh.headers.get('location'));
            const scripts = realpathSync(new URL('../../scripts', import.meta.url));
            const root = path.resolve(scripts, '../..');
            const produced = await new Promise((resolve, reject) => {
                const proc = spawn(path.join(root, 'vvault/.venv/bin/python'), [path.join(scripts, 'test-vvault-reverse-producer.py')], { stdio: ['pipe', 'pipe', 'pipe'] });
                let out = '', err = '';
                proc.stdout.on('data', v => out += v);
                proc.stderr.on('data', v => err += v);
                proc.on('error', reject);
                proc.on('close', code => { if (code)
                    reject(new Error('Python producer fixture failed: ' + err.slice(-300)));
                else {
                    try {
                        resolve(JSON.parse(out));
                    }
                    catch {
                        reject(new Error('Invalid producer fixture output'));
                    }
                } });
                proc.stdin.end(JSON.stringify({ repositoryRoot: root, provider: producerProvider, privateKey: keys.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(), documents: docs, ownerId: owner, authOrigin: base, authorizationRequest: freshTarget.searchParams.get('authorization_request') }));
            });
            assert.equal(produced.status, 200, produced.body);
            assert.match(produced.headers['Content-Security-Policy'], /default-src 'none'/);
            assert.match(produced.headers['Content-Security-Policy'], /form-action/);
            assert.equal(produced.headers['Cache-Control'], 'no-store');
            const postedId = /name="assertion_id" value="([^"]+)"/.exec(produced.body)?.[1];
            assert.ok(postedId);
            assert.ok(produced.body.includes('action="' + base + '/oauth/federation/complete"'));
            const producerComplete = await fetch(base + '/oauth/federation/complete', { method: 'POST', redirect: 'manual', headers: { 'content-type': 'application/x-www-form-urlencoded', origin: 'http://localhost:8000', cookie: cookie(fresh) }, body: new URLSearchParams({ assertion_id: postedId }) });
            assert.equal(producerComplete.status, 302);
            const producerCallback = new URL(producerComplete.headers.get('location'));
            const producerExchange = await fetch(base + '/oauth/token', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ grant_type: 'authorization_code', client_id: 'chatty-web-link', redirect_uri: redirect, code: producerCallback.searchParams.get('code'), code_verifier: verifier }) });
            assert.equal(producerExchange.status, 200);
            const producerTokens = await producerExchange.json();
            const producerMe = await fetch(base + '/api/me', { headers: { authorization: 'Bearer ' + producerTokens.access_token } });
            assert.equal(producerMe.status, 200);
            const producerSession = (await producerMe.json()).user;
            const module = await Function('url', 'return import(url)')(new URL('file://' + path.join(root, 'chatty-ui/server/lib/pairedSignup.js')).href);
            const consumerIdentity = module.pairedIdentity(producerSession, owner);
            assert.equal(consumerIdentity.auth_provider, producerProvider);
            if (producerProvider === 'email') {
                assert.equal(consumerIdentity.uid, '33333333-3333-4333-8333-333333333333');
                assert.equal(consumerIdentity.email_identity_verified, true);
            }
        }
        const user = await storage.findUserByLifeUserId('life-fixture');
        assert.ok(user);
        assert.equal(await storage.hasAcceptedConsentDocs(user.id, 'chatty', docs), true);
    }
    finally {
        await new Promise(resolve => server.close(() => resolve()));
        globalThis.fetch = originalFetch;
        for (const k of Object.keys(process.env))
            if (!(k in previous))
                delete process.env[k];
        Object.assign(process.env, previous);
    }
});
