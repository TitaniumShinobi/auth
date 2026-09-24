import assert from 'node:assert/strict';
import test from 'node:test';
import { createAuthApp } from '../app.js';
import { MemoryStorageAdapter } from '../persistence/memoryStorage.js';
import { MemoryRefreshTokenStore } from '../auth/refreshTokenStore.js';
import { MemoryEphemeralAuthStore } from '../auth/ephemeralStore.js';
import type { AuthAppConfig, OAuthProviderClient } from '../types.js';

const owner = 'aaaaaaaa-bbbb-4ccc-9ddd-eeeeeeeeeeee';
const life = 'fixture_life_subject';
const proof = { provider: 'google', subject: 'verified-google-subject', issuer: 'https://accounts.google.com' };
const config: AuthAppConfig = {
  app: { id: 'fixture', name: 'Fixture', brandTagline: 'Synthetic owner proof' },
  allowedOrigins: ['http://localhost:2048'], redirects: { postLoginPath: '/', postLogoutPath: '/' },
  credentials: { enabled: true }, turnstile: { required: false, enabled: false },
  docs: [{ product: 'fixture', docType: 'terms', key: 'fixture:terms', version: '1', label: 'Terms', url: 'https://example.test/terms', required: true }],
  providers: [{ provider: 'google', label: 'Google', enabled: true }],
};
const provider: OAuthProviderClient = {
  provider: 'google', label: 'Google', isConfigured: () => true,
  buildAuthorizationUrl: ({ state }) => `https://accounts.google.test/auth?state=${encodeURIComponent(state)}`,
  exchangeCodeForProfile: async () => ({ providerUserId: proof.subject, email: 'fixture@example.test', displayName: 'Fixture', raw: { sub: proof.subject } }),
};
function cookies(response: Response): string {
  return (response.headers as unknown as { getSetCookie(): string[] }).getSetCookie().map(value => value.split(';')[0]).join('; ');
}

test('verified OAuth owner proof survives consent and refresh without changing LIFE subject', async () => {
  const calls: Array<{ email: string; identity: unknown }> = [];
  const storage = new MemoryStorageAdapter();
  const app = await createAuthApp({
    storage, refreshTokenStore: new MemoryRefreshTokenStore(), ephemeralStore: new MemoryEphemeralAuthStore(),
    configStore: { getConfig: async () => config }, providers: { google: provider }, sessionSecret: 'synthetic-owner-flow-secret', cookieName: 'auth_sid',
    resolveLifeProfile: async () => ({ lifeUserId: life, supabaseUserId: null, source: 'local_only' }),
    resolveVvaultOwnerId: async (email, identity) => { calls.push({ email, identity }); return owner; },
  });
  const server = app.listen(0, '127.0.0.1');
  await new Promise<void>((resolve, reject) => { server.once('listening', resolve); server.once('error', reject); });
  try {
    const address = server.address();
    assert.ok(address && typeof address !== 'string');
    const base = `http://127.0.0.1:${address.port}`;
    const start = await fetch(`${base}/api/auth/google`, { headers: { Origin: 'http://localhost:2048' }, redirect: 'manual' });
    assert.equal(start.status, 302);
    const state = new URL(start.headers.get('location')!).searchParams.get('state');
    assert.ok(state);
    const callback = await fetch(`${base}/api/auth/google/callback?code=synthetic&state=${encodeURIComponent(state)}&owner=forged&providerUserId=forged&subject=forged`, { redirect: 'manual' });
    assert.equal(callback.status, 403);
    assert.equal((await callback.json() as { state: string }).state, 'ENROLLMENT_REQUIRED');
    assert.equal(callback.headers.get('location'), null);
    assert.deepEqual(calls, [{ email: 'fixture@example.test', identity: proof }]);
    const initialCookies = cookies(callback);
    assert.ok(initialCookies.includes('auth_sid='));
    const consent = await fetch(`${base}/api/auth/consent`, { method: 'POST', headers: { 'Content-Type': 'application/json', Cookie: initialCookies }, body: JSON.stringify({ consent: { 'fixture:terms': true }, providerIdentity: { subject: 'forged' }, vvaultUserId: 'forged' }) });
    assert.equal(consent.status, 200);
    const me = await fetch(`${base}/api/me`, { headers: { Cookie: initialCookies } });
    assert.equal(me.status, 200);
    const payload = await me.json() as { user: { id: string; sub: string; vvaultUserId: string } };
    assert.equal(payload.user.id, life);
    assert.equal(payload.user.sub, life);
    assert.equal(payload.user.vvaultUserId, owner);
    const beforeRefresh = calls.length;
    const refreshed = await fetch(`${base}/api/auth/refresh`, { method: 'POST', headers: { Cookie: initialCookies, 'Content-Type': 'application/json' }, body: JSON.stringify({ providerIdentity: { subject: 'forged' }, vvaultUserId: 'forged' }) });
    assert.equal(refreshed.status, 200);
    assert.ok(calls.length > beforeRefresh, 'refresh must re-attest owner');
    assert.ok(calls.every(call => JSON.stringify(call.identity) === JSON.stringify(proof)));
    const restored = await fetch(`${base}/api/me`, { headers: { Cookie: cookies(refreshed) } });
    assert.equal(restored.status, 200);
    const restoredPayload = await restored.json() as { user: { sub: string; vvaultUserId: string } };
    assert.equal(restoredPayload.user.sub, life);
    assert.equal(restoredPayload.user.vvaultUserId, owner);
    assert.equal((await storage.findUserByEmail('fixture@example.test'))?.email, 'fixture@example.test');
  } finally {
    server.closeAllConnections();
    await new Promise<void>(resolve => server.close(() => resolve()));
  }
});
