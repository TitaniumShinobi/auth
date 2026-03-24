import assert from 'node:assert/strict';
import test from 'node:test';

import type { AppConfigStore, AuthAppConfig, OAuthProviderClient } from '../types.js';
import type { LifeProfileResult, ResolveLifeProfileInput } from '../lifeProfile.js';
import { createAuthApp } from '../app.js';
import { hashPassword } from '../auth/passwords.js';
import { MemoryStorageAdapter } from '../persistence/memoryStorage.js';

const TEST_CONFIG: AuthAppConfig = {
  app: {
    id: 'code',
    name: 'Code',
    brandTagline: 'Test auth',
  },
  allowedOrigins: ['http://localhost:2048'],
  redirects: {
    postLoginPath: '/',
    postLogoutPath: '/',
  },
  credentials: {
    enabled: true,
  },
  docs: [
    {
      product: 'code',
      docType: 'terms',
      key: 'code:terms',
      version: '1',
      label: 'Code Terms',
      url: 'https://example.com/terms',
      required: true,
    },
  ],
  turnstile: {
    required: false,
    enabled: false,
  },
  providers: [
    { provider: 'google', label: 'Continue with Google', enabled: true },
    { provider: 'github', label: 'Continue with GitHub', enabled: true },
  ],
};

class StaticConfigStore implements AppConfigStore {
  constructor(private readonly config: AuthAppConfig) {}

  async getConfig() {
    return this.config;
  }
}

async function withServer(
  options: {
    config?: AuthAppConfig;
    providers?: Record<string, OAuthProviderClient>;
    turnstileVerifier?: (token: string) => Promise<boolean>;
    resolveLifeProfile?: (input: ResolveLifeProfileInput) => Promise<LifeProfileResult>;
    isEmailInLifeRegistry?: (email: string) => Promise<boolean>;
    seedStorage?: (storage: MemoryStorageAdapter) => void | Promise<void>;
  },
  fn: (context: { baseUrl: string }) => Promise<void>,
) {
  const storage = new MemoryStorageAdapter();
  const app = await createAuthApp({
    storage,
    configStore: new StaticConfigStore(options.config || TEST_CONFIG),
    providers: options.providers,
    turnstileVerifier: options.turnstileVerifier as any,
    resolveLifeProfile: options.resolveLifeProfile,
    isEmailInLifeRegistry: options.isEmailInLifeRegistry,
    sessionSecret: 'test-secret',
    cookieName: 'auth_sid',
  });
  await options.seedStorage?.(storage);

  const server = app.listen(0, '127.0.0.1');
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.once('listening', () => resolve());
  });
  const address = server.address();
  if (!address || typeof address === 'string') {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    throw new Error('Unable to resolve test server address');
  }
  try {
    await fn({ baseUrl: `http://127.0.0.1:${address.port}` });
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

test('registers a user and rejects duplicate email', async () => {
  await withServer({}, async ({ baseUrl }) => {
    const createResponse = await fetch(`${baseUrl}/api/auth/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Origin: 'http://localhost:2048',
      },
      body: JSON.stringify({
        name: 'Devon',
        email: 'devon@example.com',
        password: 'secret123',
        confirmPassword: 'secret123',
        consent: { 'code:terms': true },
      }),
    });
    assert.equal(createResponse.status, 201);
    const createPayload = await createResponse.json() as { ok: boolean; user?: { email: string } };
    assert.equal(createPayload.ok, true);
    assert.equal(createPayload.user?.email, 'devon@example.com');
    const setCookie = (createResponse.headers as any).getSetCookie?.()[0] || createResponse.headers.get('set-cookie');
    assert.ok(setCookie);
    assert.equal(createResponse.headers.get('access-control-allow-origin'), 'http://localhost:2048');
    assert.equal(createResponse.headers.get('access-control-allow-credentials'), 'true');

    const duplicateResponse = await fetch(`${baseUrl}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: 'Devon',
        email: 'devon@example.com',
        password: 'secret123',
        confirmPassword: 'secret123',
        consent: { 'code:terms': true },
      }),
    });
    assert.equal(duplicateResponse.status, 409);
  });
});

test('rejects invalid login and returns signed-in / signed-out session states', async () => {
  await withServer({}, async ({ baseUrl }) => {
    await fetch(`${baseUrl}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: 'Devon',
        email: 'devon@example.com',
        password: 'secret123',
        confirmPassword: 'secret123',
        consent: { 'code:terms': true },
      }),
    });

    const badLogin = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'devon@example.com', password: 'wrong' }),
    });
    assert.equal(badLogin.status, 401);

    const goodLogin = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'devon@example.com', password: 'secret123' }),
    });
    assert.equal(goodLogin.status, 200);
    const setCookie = (goodLogin.headers as any).getSetCookie?.()[0] || goodLogin.headers.get('set-cookie');
    assert.ok(setCookie);

    const meSignedIn = await fetch(`${baseUrl}/api/me`, {
      headers: { Cookie: setCookie },
    });
    assert.equal(meSignedIn.status, 200);
    const mePayload = await meSignedIn.json() as { ok: boolean; user?: { email: string } };
    assert.equal(mePayload.user?.email, 'devon@example.com');

    const meSignedOut = await fetch(`${baseUrl}/api/me`);
    assert.equal(meSignedOut.status, 401);
  });
});

test('login returns lifeRegistryMatch when email is in LIFE registry but not in local auth DB', async () => {
  await withServer(
    {
      isEmailInLifeRegistry: async (e) => e.toLowerCase() === 'legacy@example.com',
    },
    async ({ baseUrl }) => {
      const response = await fetch(`${baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Origin: 'http://localhost:2048' },
        body: JSON.stringify({ email: 'legacy@example.com', password: 'any-password' }),
      });
      assert.equal(response.status, 401);
      const payload = await response.json() as { ok: boolean; lifeRegistryMatch?: boolean; error?: string };
      assert.equal(payload.ok, false);
      assert.equal(payload.lifeRegistryMatch, true);
      assert.match(payload.error || '', /LIFE Technology user registry/i);
    },
  );
});

test('login returns oauthOnly when local user exists with no password (OAuth-only)', async () => {
  await withServer(
    {
      seedStorage: async (s) => {
        await s.upsertOAuthUser({
          provider: 'google',
          providerUserId: 'google-sub-99',
          email: 'oauthonly@example.com',
          displayName: 'OAuth Only',
          profile: {},
        });
      },
    },
    async ({ baseUrl }) => {
      const response = await fetch(`${baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Origin: 'http://localhost:2048' },
        body: JSON.stringify({ email: 'oauthonly@example.com', password: 'any-password' }),
      });
      assert.equal(response.status, 401);
      const payload = await response.json() as {
        ok: boolean;
        oauthOnly?: boolean;
        credentialLoginUnavailable?: boolean;
        authProvider?: string;
        lifeRegistryMatch?: boolean;
        error?: string;
      };
      assert.equal(payload.ok, false);
      assert.equal(payload.oauthOnly, true);
      assert.equal(payload.credentialLoginUnavailable, true);
      assert.equal(payload.authProvider, 'google');
      assert.equal(payload.lifeRegistryMatch, undefined);
      assert.match(payload.error || '', /Google sign-in/i);
    },
  );
});

test('/api/me returns Chatty-shaped id sub and Supabase uid when life resolver is fixed', async () => {
  const fixedLife = 'devon_woodson_1762969514958';
  const fixedSb = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
  await withServer(
    {
      resolveLifeProfile: async () => ({
        lifeUserId: fixedLife,
        supabaseUserId: fixedSb,
        source: 'cache',
      }),
    },
    async ({ baseUrl }) => {
      await fetch(`${baseUrl}/api/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: 'Devon',
          email: 'parity@example.com',
          password: 'secret123',
          confirmPassword: 'secret123',
          consent: { 'code:terms': true },
        }),
      });

      const login = await fetch(`${baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: 'parity@example.com', password: 'secret123' }),
      });
      assert.equal(login.status, 200);
      const setCookie = (login.headers as any).getSetCookie?.()[0] || login.headers.get('set-cookie');
      assert.ok(setCookie);

      const meSignedIn = await fetch(`${baseUrl}/api/me`, {
        headers: { Cookie: setCookie },
      });
      assert.equal(meSignedIn.status, 200);
      const mePayload = await meSignedIn.json() as {
        ok: boolean;
        user?: { id: string; sub: string; uid: string; email: string };
      };
      assert.equal(mePayload.user?.id, fixedLife);
      assert.equal(mePayload.user?.sub, fixedLife);
      assert.equal(mePayload.user?.uid, fixedSb);
      assert.equal(mePayload.user?.email, 'parity@example.com');
    },
  );
});

test('answers credentialed CORS preflight for allowed origins', async () => {
  await withServer({}, async ({ baseUrl }) => {
    const response = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'OPTIONS',
      headers: {
        Origin: 'http://localhost:2048',
        'Access-Control-Request-Method': 'POST',
      },
    });
    assert.equal(response.status, 204);
    assert.equal(response.headers.get('access-control-allow-origin'), 'http://localhost:2048');
    assert.equal(response.headers.get('access-control-allow-credentials'), 'true');
  });
});

test('returns dynamic auth config and provider availability', async () => {
  const providers = {
    google: {
      provider: 'google',
      label: 'Continue with Google',
      isConfigured: () => true,
      buildAuthorizationUrl: () => 'https://accounts.google.test',
      exchangeCodeForProfile: async () => {
        throw new Error('not used');
      },
    },
    github: {
      provider: 'github',
      label: 'Continue with GitHub',
      isConfigured: () => false,
      buildAuthorizationUrl: () => 'https://github.test',
      exchangeCodeForProfile: async () => {
        throw new Error('not used');
      },
    },
  } satisfies Record<string, OAuthProviderClient>;

  await withServer({ providers }, async ({ baseUrl }) => {
    const response = await fetch(`${baseUrl}/api/auth/config`);
    assert.equal(response.status, 200);
    const payload = await response.json() as {
      app: { name: string };
      credentials: { enabled: boolean };
      docs: Array<{ key: string }>;
      providers: Array<{ provider: string; available: boolean }>;
    };
    assert.equal(payload.app.name, 'Code');
    assert.equal(payload.credentials.enabled, true);
    assert.deepEqual(payload.docs.map((doc) => doc.key), ['code:terms']);
    assert.deepEqual(payload.providers, [
      {
        provider: 'google',
        label: 'Continue with Google',
        enabled: true,
        available: true,
      },
      {
        provider: 'github',
        label: 'Continue with GitHub',
        enabled: true,
        available: false,
        reason: 'Provider is not configured',
      },
    ]);
  });
});

test('enforces turnstile when required', async () => {
  await withServer({
    config: {
      ...TEST_CONFIG,
      turnstile: {
        required: true,
        enabled: true,
        siteKey: 'turnstile-site-key',
      },
    },
    turnstileVerifier: async (token) => token === 'valid-turnstile-token',
  }, async ({ baseUrl }) => {
    const badResponse = await fetch(`${baseUrl}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: 'Devon',
        email: 'devon@example.com',
        password: 'secret123',
        confirmPassword: 'secret123',
        consent: { 'code:terms': true },
        turnstileToken: 'wrong',
      }),
    });
    assert.equal(badResponse.status, 400);

    const goodResponse = await fetch(`${baseUrl}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: 'Devon',
        email: 'devon@example.com',
        password: 'secret123',
        confirmPassword: 'secret123',
        consent: { 'code:terms': true },
        turnstileToken: 'valid-turnstile-token',
      }),
    });
    assert.equal(goodResponse.status, 201);
  });
});

test('blocks credential login when product consent is missing', async () => {
  const storage = new MemoryStorageAdapter();
  const passwordHash = await hashPassword('secret123');
  await storage.createCredentialUser({
    email: 'existing@example.com',
    displayName: 'Existing User',
    passwordHash,
  });

  const app = await createAuthApp({
    storage,
    configStore: new StaticConfigStore(TEST_CONFIG),
    sessionSecret: 'test-secret',
    cookieName: 'auth_sid',
  });

  const server = app.listen(0, '127.0.0.1');
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.once('listening', resolve);
  });
  const address = server.address();
  if (!address || typeof address === 'string') {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    throw new Error('Unable to resolve test server address');
  }

  try {
    const response = await fetch(`http://127.0.0.1:${address.port}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'existing@example.com', password: 'secret123' }),
    });
    assert.equal(response.status, 403);
    const payload = await response.json() as { ok: boolean; requiresProductSignup?: boolean };
    assert.equal(payload.ok, false);
    assert.equal(payload.requiresProductSignup, true);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

test('redirects OAuth callback to signup when product consent is missing', async () => {
  const provider: OAuthProviderClient = {
    provider: 'google',
    label: 'Continue with Google',
    isConfigured: () => true,
    buildAuthorizationUrl: ({ state, callbackUrl }) => `https://accounts.google.test/auth?state=${encodeURIComponent(state)}&redirect_uri=${encodeURIComponent(callbackUrl)}`,
    exchangeCodeForProfile: async ({ code }) => ({
      providerUserId: `google-${code}`,
      email: 'oauth-missing-consent@example.com',
      displayName: 'OAuth No Consent',
      avatarUrl: 'https://example.com/avatar.png',
      raw: { sub: `google-${code}` },
    }),
  };

  await withServer({ providers: { google: provider } }, async ({ baseUrl }) => {
    const start = await fetch(`${baseUrl}/api/auth/google`, {
      headers: { Origin: 'http://localhost:2048' },
      redirect: 'manual',
    });
    assert.equal(start.status, 302);
    const location = start.headers.get('location');
    assert.ok(location);
    const state = new URL(location).searchParams.get('state');
    assert.ok(state);

    const callback = await fetch(
      `${baseUrl}/api/auth/google/callback?code=test-code&state=${encodeURIComponent(state as string)}`,
      {
        headers: { Origin: 'http://localhost:2048' },
        redirect: 'manual',
      },
    );
    assert.equal(callback.status, 302);
    assert.equal(callback.headers.get('location'), 'http://localhost:2048/?authModal=signup&reason=missing_consent');
    const setCookie = (callback.headers as any).getSetCookie?.()[0] || callback.headers.get('set-cookie');
    assert.equal(setCookie, null);
  });
});
