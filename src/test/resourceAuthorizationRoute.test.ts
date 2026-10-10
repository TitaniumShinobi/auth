import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { createAuthApp } from '../app.js';
import { MemoryStorageAdapter } from '../persistence/memoryStorage.js';
import { MemoryRefreshTokenStore } from '../auth/refreshTokenStore.js';
import { createAccessToken, resolveJwtTokenConfig, verifyAccessToken, verifyRefreshToken } from '../auth/jwtTokens.js';
import { RESOURCE_CONTRACT } from '../auth/resourceAuthorization.js';
import type { ResourceGrantRecord, ResourceGrantStore } from '../auth/resourceGrantStore.js';
import type { AuthAppConfig } from '../types.js';

const secret = 'synthetic-resource-route-secret';
const jwt = resolveJwtTokenConfig(secret);
const audience = 'https://resource.example.test';
const binding = { clientId: 'fixture-native', applicationId: 'fixture' };
const owner = '11111111-1111-4111-8111-111111111111';
const fixtureConfig = (): AuthAppConfig => ({ app: { id: 'fixture', name: 'Fixture' }, allowedOrigins: ['http://localhost:4100'], redirects: { postLoginPath: '/' }, credentials: { enabled: true }, docs: [], turnstile: { enabled: false, required: false }, providers: [], publicClients: [{ clientId: binding.clientId, authorizationUiUrl: 'http://localhost:4100/login', loopback: { hosts: ['127.0.0.1'], path: '/callback', allowDynamicPorts: true }, scopes: ['openid', 'profile', 'email'] }] });
class FixtureStore implements ResourceGrantStore {
  rows = new Map<string, ResourceGrantRecord & { revoked: boolean }>();
  async initialize() {}
  async put(record: ResourceGrantRecord) { if (this.rows.has(record.id)) throw new Error('duplicate'); this.rows.set(record.id, { ...record, revoked: false }); }
  async get(id: string) { return this.rows.get(id) || null; }
  async revoke(id: string) { const row = this.rows.get(id); if (row) row.revoked = true; }
}
function cookies(response: Response) { return ((response.headers as any).getSetCookie?.() || []).map((s: string) => s.split(';')[0]).join('; '); }
async function post(base: string, path: string, body: unknown, headers = {}) { return fetch(base + path, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body) }); }
async function withServer(configured: boolean, fn: (base: string, config: AuthAppConfig, store: FixtureStore) => Promise<void>) {
  const config = fixtureConfig(); const store = new FixtureStore();
  const key = crypto.generateKeyPairSync('ed25519').privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
  const app = await createAuthApp({ storage: new MemoryStorageAdapter(), refreshTokenStore: new MemoryRefreshTokenStore(), configStore: { getConfig: async () => config }, sessionSecret: secret, cookieName: 'auth_sid', resolveLifeProfile: async ({ email, displayName }) => ({ lifeUserId: `life:${email}`, supabaseUserId: null, displayName, source: 'local_only' }), resolveVvaultOwnerId: async () => owner, isEmailInLifeRegistry: async () => true,
    ...(configured ? { resourceAuthorization: { issuer: 'fixture-issuer', keyId: 'fixture-key', privateKeyPem: key, store, workloads: [{ audience, fingerprint256: 'a'.repeat(64) }], resolvePolicy: async session => ({ enabled: true, contract: RESOURCE_CONTRACT, wireContract: 'synthetic-wire/v1', clientId: session.clientId, applicationId: session.applicationId, audience, capabilities: ['fixture:read'] }), resolveAdmission: async session => ({ admitted: true, subject: session.subject, sessionId: session.sessionId, clientId: session.clientId, applicationId: session.applicationId, audience, ownerId: owner, capabilities: ['fixture:read'], expiresAt: Math.floor(Date.now() / 1000) + 120, policyVersion: 'synthetic-admission/v1' }) } } : {}),
  });
  const server = app.listen(0, '127.0.0.1'); await new Promise<void>(resolve => server.once('listening', resolve));
  try { await fn(`http://127.0.0.1:${(server.address() as any).port}`, config, store); }
  finally { await new Promise<void>(resolve => server.close(() => resolve())); }
}
async function nativeLogin(base: string) {
  const registration = await post(base, '/api/auth/register', { email: 'fixture@example.test', name: 'Fixture', password: 'StrongPassword!123', confirmPassword: 'StrongPassword!123' }, { origin: 'http://localhost:4100' });
  assert.equal(registration.status, 201);
  const verifier = crypto.randomBytes(48).toString('base64url'); const redirect = 'http://127.0.0.1:49152/callback';
  const url = new URL('/oauth/authorize', base); url.search = new URLSearchParams({ response_type: 'code', client_id: binding.clientId, redirect_uri: redirect, state: crypto.randomBytes(32).toString('base64url'), code_challenge: crypto.createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256' }).toString();
  const authorization = await fetch(url, { headers: { cookie: cookies(registration) }, redirect: 'manual' }); assert.equal(authorization.status, 302);
  const code = new URL(authorization.headers.get('location')!).searchParams.get('code');
  const exchange = await post(base, '/oauth/token', { grant_type: 'authorization_code', client_id: binding.clientId, redirect_uri: redirect, code, code_verifier: verifier }); assert.equal(exchange.status, 200);
  return await exchange.json() as any;
}
const request = { audience, capabilities: ['fixture:read'] };

test('native binding survives code exchange, native refresh, cookie refresh and profile rebuilding', async () => {
  await withServer(true, async base => {
    const first = await nativeLogin(base);
    assert.deepEqual((await verifyAccessToken(first.access_token, jwt))?.session.nativeClient, binding);
    assert.deepEqual((await verifyRefreshToken(first.refresh_token, jwt))?.nativeClient, binding);
    const refresh = await post(base, '/oauth/token', { grant_type: 'refresh_token', client_id: binding.clientId, refresh_token: first.refresh_token }); assert.equal(refresh.status, 200);
    const rotated = await refresh.json() as any;
    assert.deepEqual((await verifyAccessToken(rotated.access_token, jwt))?.session.nativeClient, binding);
    const browser = await post(base, '/api/auth/refresh', {}, { cookie: `auth_rid=${rotated.refresh_token}` }); assert.equal(browser.status, 200);
    assert.deepEqual((await browser.json() as any).user.nativeClient, binding);
    const me = await fetch(base + '/api/me', { headers: { cookie: cookies(browser) } }); assert.equal(me.status, 200);
    assert.deepEqual((await me.json() as any).user.nativeClient, binding);
  });
});

test('stale native registration rejects both refresh entrypoints', async () => {
  await withServer(true, async (base, config) => {
    const tokens = await nativeLogin(base); config.publicClients = [];
    assert.equal((await post(base, '/oauth/token', { grant_type: 'refresh_token', client_id: binding.clientId, refresh_token: tokens.refresh_token })).status, 400);
    assert.equal((await post(base, '/api/auth/refresh', {}, { cookie: `auth_rid=${tokens.refresh_token}` })).status, 401);
  });
});

test('resource host defaults disabled and never treats readiness as configured authorization', async () => {
  await withServer(false, async base => { assert.equal((await post(base, '/api/auth/resource-authorization', request)).status, 503); });
});

test('resource issuance requires bound bearer, refuses selectors/cookies and supports owner-scoped revocation', async () => {
  await withServer(true, async (base, _config, store) => {
    const tokens = await nativeLogin(base); const headers = { authorization: `Bearer ${tokens.access_token}` };
    const issued = await post(base, '/api/auth/resource-authorization', request, headers); assert.equal(issued.status, 200); assert.equal(issued.headers.get('cache-control'), 'no-store');
    const grant = await issued.json() as any; assert.equal(store.rows.size, 1);
    assert.equal((await post(base, '/api/auth/resource-authorization', { ...request, owner_id: owner }, headers)).status, 400);
    assert.equal((await post(base, '/api/auth/resource-authorization', request, { ...headers, cookie: `auth_sid=${tokens.access_token}` })).status, 401);
    const verified = (await verifyAccessToken(tokens.access_token, jwt))!;
    const old = await createAccessToken({ ...verified.session, nativeClient: undefined }, verified.sessionId, jwt);
    assert.equal((await post(base, '/api/auth/resource-authorization', request, { authorization: `Bearer ${old.token}` })).status, 401);
    const revoked = await post(base, '/api/auth/resource-revoke', { grant_id: grant.grant_id }, headers); assert.equal(revoked.status, 200);
    assert.equal((await store.get(grant.grant_id))?.revoked, true);
    await post(base, '/oauth/revoke', { token: tokens.refresh_token, client_id: binding.clientId });
    assert.equal((await post(base, '/api/auth/resource-authorization', request, headers)).status, 401);
  });
});

test('resource status requires real mutual TLS and rejects spoofed proxy certificate headers', async () => {
  await withServer(true, async base => {
    const response = await post(base, '/api/auth/resource-status', { assertion: 'synthetic-never-a-real-token' }, { 'x-forwarded-proto': 'https', 'x-ssl-client-verify': 'SUCCESS', 'x-ssl-client-fingerprint': 'a'.repeat(64) });
    assert.equal(response.status, 401); assert.equal((await response.json() as any).errorCode, 'RESOURCE_WORKLOAD_REQUIRED');
  });
});
