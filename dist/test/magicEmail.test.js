import assert from 'node:assert/strict';
import test from 'node:test';
import { createAuthApp } from '../app.js';
import { MemoryStorageAdapter } from '../persistence/memoryStorage.js';
import { MemoryRefreshTokenStore } from '../auth/refreshTokenStore.js';
import { MemoryEphemeralAuthStore } from '../auth/ephemeralStore.js';
import { createPostalMagicDelivery, sendMagicChallenge, consumeMagicChallenge } from '../auth/magicEmail.js';
test('Postal accepts only successful HTTP and Postal status; unconfigured sends fail', async () => {
    const env = { AUTH_POSTAL_URL: 'https://postal.example', AUTH_POSTAL_API_KEY: 'test', AUTH_MAGIC_EMAIL_FROM: 'test@example.com' };
    let options;
    const adapter = createPostalMagicDelivery(env, (async (_url, init) => { options = init; return new Response(JSON.stringify({ status: 'success' })); }));
    await adapter.send({ email: 'recipient@example.com', url: 'https://product.example/#magic_token=test', appName: 'Test' });
    assert.equal(options?.redirect, 'error');
    assert.ok(options?.signal);
    const failed = createPostalMagicDelivery(env, (async () => new Response(JSON.stringify({ status: 'error' }))));
    await assert.rejects(failed.send({ email: 'recipient@example.com', url: 'https://product.example', appName: 'Test' }));
    assert.equal(createPostalMagicDelivery({}).isConfigured(), false);
});
test('magic challenge is app/origin bound, single use and failed delivery stores nothing', async () => {
    const store = new MemoryEphemeralAuthStore();
    let token = '';
    const delivery = { isConfigured: () => true, send: async ({ url }) => { token = new URLSearchParams(new URL(url).hash.slice(1)).get('magic_token'); } };
    const record = { email: 'test@example.com', appId: 'chatty', origin: 'http://localhost:5173', intent: 'login' };
    await sendMagicChallenge(store, delivery, record, 'Chatty');
    assert.equal(await consumeMagicChallenge(store, token, 'vvault', record.origin), null);
    assert.equal(await consumeMagicChallenge(store, token, record.appId, 'https://evil.example'), null);
    const results = await Promise.all([consumeMagicChallenge(store, token, record.appId, record.origin), consumeMagicChallenge(store, token, record.appId, record.origin)]);
    assert.equal(results.filter(Boolean).length, 1);
    await assert.rejects(sendMagicChallenge(store, { ...delivery, send: async (input) => { await delivery.send(input); throw new Error('failed'); } }, record, 'Chatty'));
    assert.equal(await consumeMagicChallenge(store, token, record.appId, record.origin), null);
});
test('magic request unavailable is explicit; signup keeps enrollment gate and providers remain recoverable', async () => {
    let token = '';
    let configured = false;
    let appId = 'chatty';
    const delivery = { isConfigured: () => configured, send: async ({ url }) => { token = new URLSearchParams(new URL(url).hash.slice(1)).get('magic_token'); } };
    const storage = new MemoryStorageAdapter();
    await storage.createCredentialUser({ email: 'existing@example.com', displayName: 'Test', passwordHash: 'unused' });
    const app = await createAuthApp({ storage, refreshTokenStore: new MemoryRefreshTokenStore(), ephemeralStore: new MemoryEphemeralAuthStore(), magicEmailDelivery: delivery,
        resolveLifeProfile: async () => ({ lifeUserId: 'test-life', supabaseUserId: null, source: 'local_only' }), resolveVvaultOwnerId: async () => null,
        configStore: { getConfig: async () => ({ app: { id: appId, name: 'Test' }, allowedOrigins: ['http://localhost:5173'], redirects: { postLoginPath: '/', postLogoutPath: '/' }, credentials: { enabled: true }, docs: [], turnstile: { enabled: false, required: false }, providers: [] }) }, sessionSecret: 'test-only-secret' });
    const server = app.listen(0, '127.0.0.1');
    await new Promise(resolve => server.once('listening', resolve));
    const address = server.address();
    const base = `http://127.0.0.1:${address.port}`;
    const post = (path, body) => fetch(base + path, { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: 'http://localhost:5173' }, body: JSON.stringify({ ...body, origin: 'http://localhost:5173' }) });
    try {
        let response = await post('/api/auth/magic/request', { email: 'existing@example.com', intent: 'login' });
        assert.equal(response.status, 503);
        assert.equal((await response.json()).code, 'MAGIC_EMAIL_NOT_CONFIGURED');
        configured = true;
        response = await post('/api/auth/magic/request', { email: 'new@example.com', intent: 'signup' });
        assert.equal(response.status, 403);
        assert.equal((await response.json()).code, 'ENROLLMENT_REQUIRED');
        assert.equal(response.headers.get('set-cookie'), null);
        assert.equal(token, '');
        response = await post('/api/auth/magic/request', { email: 'unknown@example.com', intent: 'login' });
        assert.equal(response.status, 403);
        assert.equal(token, '');
        assert.equal((await post('/api/auth/magic/request', { email: 'existing@example.com', intent: 'login' })).status, 202);
        response = await post('/api/auth/magic/consume', { token });
        assert.equal(response.status, 200);
        assert.match(response.headers.get('set-cookie') || '', /HttpOnly/);
        assert.equal((await response.json()).intent, 'login');
        assert.equal((await post('/api/auth/magic/consume', { token })).status, 400);
        for (const provider of ['google', 'github', 'apple', 'microsoft'])
            assert.equal((await fetch(`${base}/api/auth/${provider}`)).status, 503);
        assert.equal((await fetch(`${base}/api/auth/unknown`)).status, 404);
        const previous = process.env.AUTH_MAGIC_DELIVERY_SECRET;
        process.env.AUTH_MAGIC_DELIVERY_SECRET = 'test-service-only-'.repeat(3);
        try {
            const send = (url, authorization) => fetch(`${base}/api/auth/magic/deliver`, { method: 'POST', headers: { 'Content-Type': 'application/json', ...(authorization ? { authorization } : {}) }, body: JSON.stringify({ email: 'test@example.com', url }) });
            const bearer = `Bearer ${process.env.AUTH_MAGIC_DELIVERY_SECRET}`;
            assert.equal((await send('http://localhost:5173/#magic_link=abc')).status, 401);
            assert.equal((await send('http://localhost:5173/#magic_link=abc', bearer)).status, 400);
            appId = 'vvault';
            assert.equal((await send('https://evil.example/#magic_link=abc', bearer)).status, 400);
            assert.equal((await send('http://localhost:5173/#magic_link=abc', bearer)).status, 202);
        }
        finally {
            if (previous === undefined)
                delete process.env.AUTH_MAGIC_DELIVERY_SECRET;
            else
                process.env.AUTH_MAGIC_DELIVERY_SECRET = previous;
        }
    }
    finally {
        await new Promise(resolve => server.close(() => resolve()));
    }
});
