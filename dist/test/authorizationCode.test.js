import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { createAuthApp } from '../app.js';
import { MemoryRefreshTokenStore, PostgresRefreshTokenStore, } from '../auth/refreshTokenStore.js';
import { MemoryStorageAdapter } from '../persistence/memoryStorage.js';
import { validateRedirectUri, verifyS256 } from '../auth/authorizationCode.js';
import { signProductSessionAssertion } from '../auth/productSessionFederation.js';
import { resolveJwtTokenConfig, verifyAccessToken, verifyRefreshToken } from '../auth/jwtTokens.js';
const FEDERATION_SECRET = 'fixture-federation-secret-that-is-distinct';
process.env.FIXTURE_FEDERATION_SECRET = FEDERATION_SECRET;
test('Chatty browser-link registration accepts only its exact product callback', () => {
    const config = JSON.parse(readFileSync(new URL('../../config/chatty.json', import.meta.url), 'utf8'));
    const client = config.publicClients.find(client => client.clientId === 'chatty-web-link');
    assert.ok(client);
    assert.equal(validateRedirectUri(client, 'http://localhost:5173/auth/connect-callback'), 'http://localhost:5173/auth/connect-callback');
    assert.equal(validateRedirectUri(client, 'http://localhost:5173/auth/connect-callback?next=https://evil.example'), null);
    assert.equal(validateRedirectUri(client, 'http://evil.example/auth/connect-callback'), null);
    assert.equal(validateRedirectUri(client, 'http://localhost:5999/auth/connect-callback'), null);
    assert.ok(config.publicClients.some(client => client.clientId === 'chatty-cli'));
});
test('Chatty public client uses the canonical localhost browser origins', () => {
    const chattyConfig = JSON.parse(readFileSync(new URL('../../config/chatty.json', import.meta.url), 'utf8'));
    const cliClient = chattyConfig.publicClients?.find(client => client.clientId === 'chatty-cli');
    assert.deepEqual(chattyConfig.allowedOrigins, [
        'http://localhost:5173',
        'http://localhost:5050',
    ]);
    assert.equal(cliClient?.authorizationUiUrl, 'http://localhost:5173/login');
});
const config = {
    app: { id: 'fixture', name: 'Fixture' },
    allowedOrigins: ['http://localhost:4100'],
    redirects: { postLoginPath: '/', postLogoutPath: '/' },
    credentials: { enabled: true },
    docs: [],
    turnstile: { required: false, enabled: false },
    providers: [],
    sessionFederation: { enabled: true, assertionSecretEnv: 'FIXTURE_FEDERATION_SECRET' },
    publicClients: [{
            clientId: 'fixture-native',
            authorizationUiUrl: 'http://localhost:4100/login',
            loopback: { hosts: ['127.0.0.1', '::1'], path: '/callback', allowDynamicPorts: true },
            scopes: ['openid', 'profile', 'email'],
        }],
};
class ConfigStore {
    async getConfig() { return config; }
}
async function withServer(fn, refreshTokenStore) {
    const app = await createAuthApp({
        storage: new MemoryStorageAdapter(),
        configStore: new ConfigStore(),
        refreshTokenStore,
        sessionSecret: 'authorization-test-secret',
        cookieName: 'auth_sid',
        resolveLifeProfile: async ({ email, displayName }) => ({
            lifeUserId: `life:${email}`,
            supabaseUserId: null,
            displayName,
            source: 'local_only',
        }),
        isEmailInLifeRegistry: async () => true,
    });
    const server = app.listen(0, '127.0.0.1');
    await new Promise((resolve) => server.once('listening', resolve));
    const address = server.address();
    if (!address || typeof address === 'string')
        throw new Error('missing address');
    try {
        await fn(`http://127.0.0.1:${address.port}`);
    }
    finally {
        await new Promise((resolve) => server.close(() => resolve()));
    }
}
class FailingRotationStore extends MemoryRefreshTokenStore {
    failRotation = false;
    async rotateRefreshToken(...args) {
        if (this.failRotation)
            throw new Error('fixture refresh store unavailable');
        return super.rotateRefreshToken(...args);
    }
}
test('Postgres refresh rotation inserts the replacement before assigning its immediate FK', async () => {
    const statements = [];
    const sessionId = '11111111-1111-4111-8111-111111111111';
    const oldTokenId = '22222222-2222-4222-8222-222222222222';
    const newTokenId = '33333333-3333-4333-8333-333333333333';
    const tx = {
        async $queryRawUnsafe(sql) {
            if (sql.includes('FROM auth.auth_sessions')) {
                return [{ id: sessionId, user_id: 'life:user', current_refresh_token_id: oldTokenId, revoked_at: null, expires_at: new Date(Date.now() + 60_000) }];
            }
            return [{ id: oldTokenId, session_id: sessionId, user_id: 'life:user', token_jti: 'old-jti', status: 'active', generation: 0, expires_at: new Date(Date.now() + 60_000) }];
        },
        async $executeRawUnsafe(sql) {
            statements.push(sql.replace(/\s+/g, ' ').trim());
            return 1;
        },
    };
    const prisma = {
        async $transaction(callback) { return callback(tx); },
    };
    const store = new PostgresRefreshTokenStore(prisma);
    const result = await store.rotateRefreshToken({
        sessionId,
        userId: 'life:user',
        presentedTokenJti: 'old-jti',
        presentedTokenHash: 'old-hash',
        newRefreshTokenId: newTokenId,
        newRefreshTokenJti: 'new-jti',
        newRefreshTokenHash: 'new-hash',
        newRefreshExpiresAt: new Date(Date.now() + 120_000),
    });
    assert.deepEqual(result, { ok: true });
    const insertIndex = statements.findIndex(statement => statement.startsWith('INSERT INTO auth.refresh_tokens'));
    const replacementIndex = statements.findIndex(statement => statement.includes('SET replaced_by_token_id'));
    assert.ok(insertIndex >= 0);
    assert.ok(replacementIndex > insertIndex);
});
function cookies(response) {
    return (response.headers.getSetCookie?.() || [response.headers.get('set-cookie')])
        .filter(Boolean).map((value) => value.split(';')[0]).join('; ');
}
function setCookieHeaders(response) {
    return (response.headers.getSetCookie?.() || [response.headers.get('set-cookie')])
        .filter(Boolean);
}
test('loopback callback validation is exact and PKCE is S256', () => {
    const client = config.publicClients[0];
    assert.equal(validateRedirectUri(client, 'http://127.0.0.1:49152/callback'), 'http://127.0.0.1:49152/callback');
    assert.equal(validateRedirectUri(client, 'http://127.0.0.1:49152/other'), null);
    assert.equal(validateRedirectUri(client, 'https://127.0.0.1:49152/callback'), null);
    assert.equal(validateRedirectUri(client, 'http://example.com:49152/callback'), null);
    const verifier = 'a'.repeat(64);
    const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
    assert.equal(verifyS256(verifier, challenge), true);
    assert.equal(verifyS256('b'.repeat(64), challenge), false);
});
test('authorization code is PKCE-bound, single-use, refreshable, revocable, and token-free in callback', async () => {
    await withServer(async (baseUrl) => {
        const register = await fetch(`${baseUrl}/api/auth/register`, {
            method: 'POST', headers: { 'content-type': 'application/json', origin: 'http://localhost:4100' },
            body: JSON.stringify({ email: 'native@example.com', name: 'Native User', password: 'StrongPassword!123', confirmPassword: 'StrongPassword!123' }),
        });
        assert.equal(register.status, 201);
        const cookie = cookies(register);
        const verifier = crypto.randomBytes(48).toString('base64url');
        const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
        const state = crypto.randomBytes(32).toString('base64url');
        const redirectUri = 'http://127.0.0.1:49152/callback';
        const authorize = new URL('/oauth/authorize', baseUrl);
        authorize.search = new URLSearchParams({ response_type: 'code', client_id: 'fixture-native', redirect_uri: redirectUri, state, code_challenge: challenge, code_challenge_method: 'S256' }).toString();
        const response = await fetch(authorize, { headers: { cookie }, redirect: 'manual' });
        assert.equal(response.status, 302);
        const callback = new URL(response.headers.get('location'));
        assert.equal(callback.origin + callback.pathname, redirectUri);
        assert.equal(callback.searchParams.get('state'), state);
        assert.equal(callback.searchParams.has('access_token'), false);
        assert.equal(callback.searchParams.has('refresh_token'), false);
        const code = callback.searchParams.get('code');
        const badExchange = await fetch(`${baseUrl}/oauth/token`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ grant_type: 'authorization_code', client_id: 'fixture-native', redirect_uri: redirectUri, code, code_verifier: 'x'.repeat(64) }) });
        assert.equal(badExchange.status, 400);
        const replayAfterBadPkce = await fetch(`${baseUrl}/oauth/token`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ grant_type: 'authorization_code', client_id: 'fixture-native', redirect_uri: redirectUri, code, code_verifier: verifier }) });
        assert.equal(replayAfterBadPkce.status, 400);
        const second = await fetch(authorize, { headers: { cookie }, redirect: 'manual' });
        const secondCode = new URL(second.headers.get('location')).searchParams.get('code');
        const exchange = await fetch(`${baseUrl}/oauth/token`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ grant_type: 'authorization_code', client_id: 'fixture-native', redirect_uri: redirectUri, code: secondCode, code_verifier: verifier }) });
        assert.equal(exchange.status, 200);
        const tokens = await exchange.json();
        const info = await fetch(`${baseUrl}/oauth/userinfo`, { headers: { authorization: `Bearer ${tokens.access_token}` } });
        assert.equal(info.status, 200);
        assert.equal((await info.json()).uid, 'life:native@example.com');
        const refresh = await fetch(`${baseUrl}/oauth/token`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ grant_type: 'refresh_token', client_id: 'fixture-native', refresh_token: tokens.refresh_token }) });
        assert.equal(refresh.status, 200);
        const rotated = await refresh.json();
        const rotatedInfo = await fetch(`${baseUrl}/oauth/userinfo`, { headers: { authorization: `Bearer ${rotated.access_token}` } });
        assert.equal(rotatedInfo.status, 200);
        assert.equal((await rotatedInfo.json()).uid, 'life:native@example.com');
        const replay = await fetch(`${baseUrl}/oauth/token`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ grant_type: 'refresh_token', client_id: 'fixture-native', refresh_token: tokens.refresh_token }) });
        assert.equal(replay.status, 400);
        const revokedFamily = await fetch(`${baseUrl}/oauth/userinfo`, { headers: { authorization: `Bearer ${rotated.access_token}` } });
        assert.equal(revokedFamily.status, 401);
    });
});
test('native refresh reports a recoverable 503 without consuming the reusable token', async () => {
    const refreshTokenStore = new FailingRotationStore();
    await withServer(async (baseUrl) => {
        const register = await fetch(`${baseUrl}/api/auth/register`, {
            method: 'POST',
            headers: {
                'content-type': 'application/json',
                origin: 'http://localhost:4100',
            },
            body: JSON.stringify({
                email: 'recoverable-refresh@example.com',
                name: 'Recoverable Refresh',
                password: 'StrongPassword!123',
                confirmPassword: 'StrongPassword!123',
            }),
        });
        assert.equal(register.status, 201);
        const verifier = crypto.randomBytes(48).toString('base64url');
        const redirectUri = 'http://127.0.0.1:49153/callback';
        const authorize = new URL('/oauth/authorize', baseUrl);
        authorize.search = new URLSearchParams({
            response_type: 'code',
            client_id: 'fixture-native',
            redirect_uri: redirectUri,
            state: crypto.randomBytes(32).toString('base64url'),
            code_challenge: crypto.createHash('sha256').update(verifier).digest('base64url'),
            code_challenge_method: 'S256',
        }).toString();
        const authorization = await fetch(authorize, {
            headers: { cookie: cookies(register) },
            redirect: 'manual',
        });
        const code = new URL(authorization.headers.get('location')).searchParams.get('code');
        const exchange = await fetch(`${baseUrl}/oauth/token`, {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({
                grant_type: 'authorization_code',
                client_id: 'fixture-native',
                redirect_uri: redirectUri,
                code,
                code_verifier: verifier,
            }),
        });
        assert.equal(exchange.status, 200);
        const tokens = await exchange.json();
        refreshTokenStore.failRotation = true;
        const unavailable = await fetch(`${baseUrl}/oauth/token`, {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({
                grant_type: 'refresh_token',
                client_id: 'fixture-native',
                refresh_token: tokens.refresh_token,
            }),
        });
        assert.equal(unavailable.status, 503);
        assert.deepEqual(await unavailable.json(), {
            error: 'temporarily_unavailable',
            error_description: 'Refresh session is temporarily unavailable',
        });
        refreshTokenStore.failRotation = false;
        const recovered = await fetch(`${baseUrl}/oauth/token`, {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({
                grant_type: 'refresh_token',
                client_id: 'fixture-native',
                refresh_token: tokens.refresh_token,
            }),
        });
        assert.equal(recovered.status, 200);
    }, refreshTokenStore);
});
test('unauthenticated authorization redirects only an opaque request to product UI', async () => {
    await withServer(async (baseUrl) => {
        const verifier = crypto.randomBytes(48).toString('base64url');
        const url = new URL('/oauth/authorize', baseUrl);
        url.search = new URLSearchParams({ response_type: 'code', client_id: 'fixture-native', redirect_uri: 'http://127.0.0.1:50001/callback', state: crypto.randomBytes(32).toString('base64url'), code_challenge: crypto.createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256' }).toString();
        const response = await fetch(url, { redirect: 'manual' });
        assert.equal(response.status, 302);
        const login = new URL(response.headers.get('location'));
        assert.equal(login.origin + login.pathname, 'http://localhost:4100/login');
        assert.equal(login.searchParams.get('authorization_return'), 'http://localhost:1111/oauth/authorize/complete');
        assert.ok(login.searchParams.get('authorization_request'));
        assert.equal(login.searchParams.has('code'), false);
        assert.equal(login.searchParams.has('state'), false);
        assert.equal(login.searchParams.has('code_challenge'), false);
        const requestId = login.searchParams.get('authorization_request');
        const register = await fetch(`${baseUrl}/api/auth/register`, {
            method: 'POST', headers: { 'content-type': 'application/json', origin: 'http://localhost:4100' },
            body: JSON.stringify({ email: 'resume@example.com', name: 'Resume User', password: 'StrongPassword!123', confirmPassword: 'StrongPassword!123' }),
        });
        assert.equal(register.status, 201);
        const completion = await fetch(`${baseUrl}/oauth/authorize/complete?authorization_request=${encodeURIComponent(requestId)}`, { headers: { cookie: cookies(register) }, redirect: 'manual' });
        assert.equal(completion.status, 302);
        const callback = new URL(completion.headers.get('location'));
        assert.equal(callback.origin + callback.pathname, 'http://127.0.0.1:50001/callback');
        assert.ok(callback.searchParams.get('code'));
        assert.equal(callback.searchParams.has('access_token'), false);
        assert.equal(callback.searchParams.has('refresh_token'), false);
    });
});
test('authorization continuation stays on the canonical authority origin for either loopback request host', async () => {
    await withServer(async (baseUrl) => {
        const createAuthorizeUrl = (authorityOrigin) => {
            const verifier = crypto.randomBytes(48).toString('base64url');
            const url = new URL('/oauth/authorize', authorityOrigin);
            url.search = new URLSearchParams({
                response_type: 'code',
                client_id: 'fixture-native',
                redirect_uri: 'http://127.0.0.1:50009/callback',
                state: crypto.randomBytes(32).toString('base64url'),
                code_challenge: crypto.createHash('sha256').update(verifier).digest('base64url'),
                code_challenge_method: 'S256',
            }).toString();
            return url;
        };
        const direct = await fetch(createAuthorizeUrl(baseUrl), { redirect: 'manual' });
        const canonical = await fetch(createAuthorizeUrl(baseUrl), {
            headers: { host: `localhost:${new URL(baseUrl).port}` },
            redirect: 'manual',
        });
        for (const response of [direct, canonical]) {
            assert.equal(response.status, 302);
            const login = new URL(response.headers.get('location'));
            assert.equal(login.origin + login.pathname, 'http://localhost:4100/login');
            assert.equal(login.searchParams.get('authorization_return'), 'http://localhost:1111/oauth/authorize/complete');
        }
    });
});
test('product session assertion establishes authority session and completes PKCE authorization once', async () => {
    await withServer(async (baseUrl) => {
        const verifier = crypto.randomBytes(48).toString('base64url');
        const state = crypto.randomBytes(32).toString('base64url');
        const redirectUri = 'http://127.0.0.1:50002/callback';
        const authorize = new URL('/oauth/authorize', baseUrl);
        authorize.search = new URLSearchParams({
            response_type: 'code', client_id: 'fixture-native', redirect_uri: redirectUri, state,
            code_challenge: crypto.createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256',
        }).toString();
        const start = await fetch(authorize, { redirect: 'manual' });
        const productUi = new URL(start.headers.get('location'));
        const requestId = productUi.searchParams.get('authorization_request');
        const browserBindingCookie = cookies(start);
        const browserBindingSetCookie = setCookieHeaders(start)[0];
        assert.match(browserBindingCookie, /^auth_fed_pending_[A-Za-z0-9_-]{22}=[A-Za-z0-9_-]{43}$/);
        assert.match(browserBindingSetCookie, /Path=\/oauth\/federation\/complete/);
        assert.match(browserBindingSetCookie, /HttpOnly/);
        assert.match(browserBindingSetCookie, /SameSite=Strict/);
        assert.match(browserBindingSetCookie, /Max-Age=600/);
        assert.equal(productUi.toString().includes(browserBindingCookie), false);
        const now = Math.floor(Date.now() / 1000);
        const assertion = {
            product_id: 'fixture', authorization_request: requestId, subject: 'product-user-123',
            email: 'federated@example.com', name: 'Federated User', issued_at: now, expires_at: now + 45,
            nonce: crypto.randomBytes(24).toString('base64url'),
        };
        const create = await fetch(`${baseUrl}/oauth/federation/assertions`, {
            method: 'POST', headers: { 'content-type': 'application/json', 'x-auth-assertion-signature': signProductSessionAssertion(assertion, FEDERATION_SECRET) },
            body: JSON.stringify(assertion),
        });
        assert.equal(create.status, 201);
        const created = await create.json();
        assert.match(created.assertion_id, /^[A-Za-z0-9_-]+$/);
        assert.equal(JSON.stringify(created).includes('federated@example.com'), false);
        assert.equal(JSON.stringify(created).includes(FEDERATION_SECRET), false);
        const replayCreate = await fetch(`${baseUrl}/oauth/federation/assertions`, {
            method: 'POST', headers: { 'content-type': 'application/json', 'x-auth-assertion-signature': signProductSessionAssertion(assertion, FEDERATION_SECRET) },
            body: JSON.stringify(assertion),
        });
        assert.equal(replayCreate.status, 409);
        const missingOrigin = await fetch(`${baseUrl}/oauth/federation/complete`, {
            method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ assertion_id: created.assertion_id }), redirect: 'manual',
        });
        assert.equal(missingOrigin.status, 403);
        assert.deepEqual(await missingOrigin.json(), { error: 'invalid_federation_origin' });
        const untrustedOrigin = await fetch(`${baseUrl}/oauth/federation/complete`, {
            method: 'POST', headers: { 'content-type': 'application/json', origin: 'https://attacker.example' }, body: JSON.stringify({ assertion_id: created.assertion_id }), redirect: 'manual',
        });
        assert.equal(untrustedOrigin.status, 403);
        assert.deepEqual(await untrustedOrigin.json(), { error: 'invalid_federation_origin' });
        const unbound = await fetch(`${baseUrl}/oauth/federation/complete`, {
            method: 'POST', headers: { 'content-type': 'application/json', origin: 'http://localhost:4100' }, body: JSON.stringify({ assertion_id: created.assertion_id }), redirect: 'manual',
        });
        assert.equal(unbound.status, 400);
        assert.deepEqual(await unbound.json(), { error: 'invalid_browser_binding' });
        const complete = await fetch(`${baseUrl}/oauth/federation/complete`, {
            method: 'POST', headers: { 'content-type': 'application/json', cookie: browserBindingCookie, origin: 'http://localhost:4100' }, body: JSON.stringify({ assertion_id: created.assertion_id }), redirect: 'manual',
        });
        assert.equal(complete.status, 302);
        assert.match(complete.headers.get('set-cookie') || '', /auth_sid=/);
        assert.match(complete.headers.get('set-cookie') || '', /auth_fed_pending_[A-Za-z0-9_-]{22}=;[^,]*Max-Age=0/);
        const callback = new URL(complete.headers.get('location'));
        assert.equal(callback.origin + callback.pathname, redirectUri);
        assert.equal(callback.searchParams.get('state'), state);
        assert.equal(callback.searchParams.has('access_token'), false);
        assert.equal(callback.searchParams.has('refresh_token'), false);
        assert.equal(callback.searchParams.has('assertion_id'), false);
        const reused = await fetch(`${baseUrl}/oauth/federation/complete`, {
            method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ assertion_id: created.assertion_id }), redirect: 'manual',
        });
        assert.equal(reused.status, 400);
        const code = callback.searchParams.get('code');
        const exchange = await fetch(`${baseUrl}/oauth/token`, {
            method: 'POST', headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ grant_type: 'authorization_code', client_id: 'fixture-native', redirect_uri: redirectUri, code, code_verifier: verifier }),
        });
        assert.equal(exchange.status, 200);
    });
});
test('federation browser bindings are request-bound and support concurrent authorization starts', async () => {
    await withServer(async (baseUrl) => {
        const startAuthorization = async (port) => {
            const verifier = crypto.randomBytes(48).toString('base64url');
            const authorize = new URL('/oauth/authorize', baseUrl);
            authorize.search = new URLSearchParams({
                response_type: 'code',
                client_id: 'fixture-native',
                redirect_uri: `http://127.0.0.1:${port}/callback`,
                state: crypto.randomBytes(32).toString('base64url'),
                code_challenge: crypto.createHash('sha256').update(verifier).digest('base64url'),
                code_challenge_method: 'S256',
            }).toString();
            const response = await fetch(authorize, { redirect: 'manual' });
            return {
                requestId: new URL(response.headers.get('location')).searchParams.get('authorization_request'),
                cookie: cookies(response),
            };
        };
        const createAssertion = async (requestId, suffix) => {
            const now = Math.floor(Date.now() / 1000);
            const assertion = {
                product_id: 'fixture',
                authorization_request: requestId,
                subject: `product-user-${suffix}`,
                email: `federated-${suffix}@example.com`,
                name: `Federated ${suffix}`,
                issued_at: now,
                expires_at: now + 45,
                nonce: crypto.randomBytes(24).toString('base64url'),
            };
            const response = await fetch(`${baseUrl}/oauth/federation/assertions`, {
                method: 'POST',
                headers: {
                    'content-type': 'application/json',
                    'x-auth-assertion-signature': signProductSessionAssertion(assertion, FEDERATION_SECRET),
                },
                body: JSON.stringify(assertion),
            });
            assert.equal(response.status, 201);
            return (await response.json()).assertion_id;
        };
        const complete = (assertionId, cookie) => fetch(`${baseUrl}/oauth/federation/complete`, {
            method: 'POST',
            headers: { 'content-type': 'application/json', cookie, origin: 'http://localhost:4100' },
            body: JSON.stringify({ assertion_id: assertionId }),
            redirect: 'manual',
        });
        const [first, second] = await Promise.all([
            startAuthorization(50003),
            startAuthorization(50004),
        ]);
        assert.notEqual(first.requestId, second.requestId);
        assert.notEqual(first.cookie.split('=')[0], second.cookie.split('=')[0]);
        const [firstAssertion, secondAssertion] = await Promise.all([
            createAssertion(first.requestId, 'one'),
            createAssertion(second.requestId, 'two'),
        ]);
        const crossed = await complete(secondAssertion, first.cookie);
        assert.equal(crossed.status, 400);
        assert.deepEqual(await crossed.json(), { error: 'invalid_browser_binding' });
        assert.equal((await complete(secondAssertion, second.cookie)).status, 302);
        assert.equal((await complete(firstAssertion, first.cookie)).status, 302);
    });
});
test('federation assertion endpoint rejects weak and example signing secrets', async () => {
    const previous = process.env.FIXTURE_FEDERATION_SECRET;
    try {
        await withServer(async (baseUrl) => {
            const postAssertion = () => fetch(`${baseUrl}/oauth/federation/assertions`, {
                method: 'POST',
                headers: { 'content-type': 'application/json' },
                body: JSON.stringify({ product_id: 'fixture' }),
            });
            for (const invalidSecret of [
                'too-short',
                'change-me-to-a-distinct-random-secret',
            ]) {
                process.env.FIXTURE_FEDERATION_SECRET = invalidSecret;
                const response = await postAssertion();
                assert.equal(response.status, 503);
                assert.deepEqual(await response.json(), { error: 'federation_unavailable' });
            }
            process.env.FIXTURE_FEDERATION_SECRET = '🔐'.repeat(8);
            const utf8Boundary = await postAssertion();
            assert.equal(utf8Boundary.status, 401);
            assert.deepEqual(await utf8Boundary.json(), { error: 'invalid_assertion' });
        });
    }
    finally {
        if (previous === undefined)
            delete process.env.FIXTURE_FEDERATION_SECRET;
        else
            process.env.FIXTURE_FEDERATION_SECRET = previous;
    }
});
test('product session assertions reject expiration, wrong product, and wrong authorization request', async () => {
    await withServer(async (baseUrl) => {
        const now = Math.floor(Date.now() / 1000);
        const base = {
            product_id: 'fixture', authorization_request: crypto.randomBytes(32).toString('base64url'), subject: 'user-1',
            email: 'invalid@example.com', name: 'Invalid User', issued_at: now, expires_at: now + 30,
            nonce: crypto.randomBytes(24).toString('base64url'),
        };
        const send = (assertion) => fetch(`${baseUrl}/oauth/federation/assertions`, {
            method: 'POST', headers: { 'content-type': 'application/json', 'x-auth-assertion-signature': signProductSessionAssertion(assertion, FEDERATION_SECRET) },
            body: JSON.stringify(assertion),
        });
        assert.equal((await send(base)).status, 400);
        const expired = { ...base, issued_at: now - 90, expires_at: now - 30, nonce: crypto.randomBytes(24).toString('base64url') };
        assert.equal((await send(expired)).status, 401);
        const wrongProduct = { ...base, product_id: 'other-product', nonce: crypto.randomBytes(24).toString('base64url') };
        assert.equal((await send(wrongProduct)).status, 403);
    });
});
test('v2 federation provider proof survives code exchange and refresh without unsigned overrides', async () => {
    await withServer(async (baseUrl) => {
        const verifier = crypto.randomBytes(48).toString('base64url');
        const redirectUri = 'http://127.0.0.1:50002/callback';
        const authorize = new URL('/oauth/authorize', baseUrl);
        authorize.search = new URLSearchParams({ response_type: 'code', client_id: 'fixture-native', redirect_uri: redirectUri, state: crypto.randomBytes(32).toString('base64url'), code_challenge: crypto.createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256' }).toString();
        const start = await fetch(authorize, { redirect: 'manual' });
        assert.equal(start.status, 302);
        const requestId = new URL(start.headers.get('location')).searchParams.get('authorization_request');
        const now = Math.floor(Date.now() / 1000);
        const proof = { provider: 'google', subject: 'synthetic-verified-provider-subject', issuer: 'https://accounts.google.com', verifiedEmail: 'v2-fixture@example.test' };
        const assertion = {
            product_id: 'fixture', authorization_request: requestId, subject: 'synthetic-product-subject',
            email: 'v2-fixture@example.test', name: 'Fixture', issued_at: now, expires_at: now + 45,
            nonce: crypto.randomBytes(24).toString('base64url'), provider_identity: proof,
        };
        const signature = signProductSessionAssertion(assertion, FEDERATION_SECRET);
        assert.ok(signature.startsWith('v2='));
        const create = await fetch(`${baseUrl}/oauth/federation/assertions`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-auth-assertion-signature': signature }, body: JSON.stringify(assertion) });
        assert.equal(create.status, 201);
        const created = await create.json();
        const complete = await fetch(`${baseUrl}/oauth/federation/complete`, { method: 'POST', headers: { 'content-type': 'application/json', cookie: cookies(start), origin: 'http://localhost:4100' }, body: JSON.stringify({ assertion_id: created.assertion_id, provider_identity: { ...proof, subject: 'unsigned-forgery' } }), redirect: 'manual' });
        assert.equal(complete.status, 302);
        const callback = new URL(complete.headers.get('location'));
        assert.equal(callback.origin + callback.pathname, redirectUri);
        assert.equal(callback.searchParams.has('provider_identity'), false);
        const exchange = await fetch(`${baseUrl}/oauth/token`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ grant_type: 'authorization_code', client_id: 'fixture-native', redirect_uri: redirectUri, code: callback.searchParams.get('code'), code_verifier: verifier, provider_identity: { ...proof, subject: 'unsigned-forgery' } }) });
        assert.equal(exchange.status, 200);
        const tokens = await exchange.json();
        const tokenConfig = resolveJwtTokenConfig('authorization-test-secret');
        const access = await verifyAccessToken(tokens.access_token, tokenConfig);
        assert.ok(access);
        assert.deepEqual(access.session.providerIdentity, proof);
        assert.notEqual(access.session.sub, proof.subject);
        assert.deepEqual((await verifyRefreshToken(tokens.refresh_token, tokenConfig))?.providerIdentity, proof);
        const refresh = await fetch(`${baseUrl}/oauth/token`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ grant_type: 'refresh_token', client_id: 'fixture-native', refresh_token: tokens.refresh_token, provider_identity: { ...proof, subject: 'unsigned-forgery' } }) });
        assert.equal(refresh.status, 200);
        const rotated = await refresh.json();
        assert.notEqual(rotated.refresh_token, tokens.refresh_token);
        assert.deepEqual((await verifyAccessToken(rotated.access_token, tokenConfig))?.session.providerIdentity, proof);
        assert.deepEqual((await verifyRefreshToken(rotated.refresh_token, tokenConfig))?.providerIdentity, proof);
    }, new MemoryRefreshTokenStore());
});
test('prompt login cannot reuse an older authenticated identity at authorization or completion', async () => {
    await withServer(async (baseUrl) => {
        const register = await fetch(`${baseUrl}/api/auth/register`, { method: 'POST', headers: { 'content-type': 'application/json', origin: 'http://localhost:4100' }, body: JSON.stringify({ email: 'old-identity@example.com', name: 'Old Identity', password: 'StrongPassword!123', confirmPassword: 'StrongPassword!123' }) });
        assert.equal(register.status, 201);
        const url = new URL('/oauth/authorize', baseUrl);
        url.search = new URLSearchParams({ response_type: 'code', client_id: 'fixture-native', redirect_uri: 'http://127.0.0.1:50001/callback', state: crypto.randomBytes(32).toString('base64url'), code_challenge: crypto.createHash('sha256').update('fresh-verifier').digest('base64url'), code_challenge_method: 'S256', prompt: 'login' }).toString();
        const first = await fetch(url, { headers: { cookie: cookies(register) }, redirect: 'manual' });
        const redirect = new URL(first.headers.get('location'));
        assert.equal(redirect.origin + redirect.pathname, 'http://localhost:4100/login');
        const next = await fetch(`${baseUrl}/oauth/authorize/complete?authorization_request=${encodeURIComponent(redirect.searchParams.get('authorization_request'))}`, { headers: { cookie: cookies(register) }, redirect: 'manual' });
        const nextUrl = new URL(next.headers.get('location'));
        assert.equal(nextUrl.origin + nextUrl.pathname, 'http://localhost:4100/login');
        assert.equal(nextUrl.searchParams.has('code'), false);
    });
});
