import assert from 'node:assert/strict';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import type { AppConfigStore, AuthAppConfig, OAuthProviderClient } from '../types.js';
import type { LifeProfileResult, ResolveLifeProfileInput } from '../lifeProfile.js';
import { createAuthApp } from '../app.js';
import { FileAppConfigStore } from '../config.js';
import { hashPassword } from '../auth/passwords.js';
import { MemoryStorageAdapter } from '../persistence/memoryStorage.js';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

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
    configStore?: AppConfigStore;
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
    configStore: options.configStore || new StaticConfigStore(options.config || TEST_CONFIG),
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

// bf60e5e moved Code execution out of AUTH. These are compatibility-boundary tests.
for (const [label, route, method] of [
  ['thread', '/api/code/ask/thread', 'GET'],
  ['status', '/api/code/ask/status', 'GET'],
  ['messages', '/api/code/ask/messages', 'POST'],
] as const) {
  test(`Ask Hydro ${label} is absent by default and explicitly moved when opted in`, async () => {
    const previous = process.env.AUTH_ENABLE_LEGACY_CODE_ROUTES;
    const originalFetch = globalThis.fetch;
    let unexpectedCalls = 0;
    // No provider/transcript request is allowed from the compatibility route.
    globalThis.fetch = async (input: Parameters<typeof fetch>[0], init?: Parameters<typeof fetch>[1]) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
      if (!url.startsWith('http://127.0.0.1:')) {
        unexpectedCalls++;
        throw new Error('Unexpected external request');
      }
      return originalFetch(input, init);
    };
    try {
      delete process.env.AUTH_ENABLE_LEGACY_CODE_ROUTES;
      await withServer({}, async ({ baseUrl }) => {
        assert.equal((await fetch(`${baseUrl}${route}`, { method })).status, 404);
      });
      process.env.AUTH_ENABLE_LEGACY_CODE_ROUTES = '1';
      await withServer({}, async ({ baseUrl }) => {
        const response = await fetch(`${baseUrl}${route}`, { method });
        assert.equal(response.status, 501);
        const body = await response.json() as { ok?: boolean; code?: string; movedTo?: string; canonicalTranscriptPath?: string };
        assert.equal(body.ok, false);
        assert.equal(body.code, 'CODE_ASK_MOVED_TO_CODE_RUNTIME');
        assert.equal(body.movedTo, 'code-runtime');
        assert.equal(body.canonicalTranscriptPath, undefined);
      });
      assert.equal(unexpectedCalls, 0);
    } finally {
      globalThis.fetch = originalFetch;
      if (previous === undefined) delete process.env.AUTH_ENABLE_LEGACY_CODE_ROUTES;
      else process.env.AUTH_ENABLE_LEGACY_CODE_ROUTES = previous;
    }
  });
}

test('scratch compatibility is opt-in, authenticated, and returns metadata without Ask execution', async () => {
  const previous = process.env.AUTH_ENABLE_LEGACY_CODE_ROUTES;
  try {
    delete process.env.AUTH_ENABLE_LEGACY_CODE_ROUTES;
    await withServer({}, async ({ baseUrl }) => {
      assert.equal((await fetch(`${baseUrl}/api/code/projects/scratch`, { method: 'POST' })).status, 404);
    });
    process.env.AUTH_ENABLE_LEGACY_CODE_ROUTES = '1';
    await withServer({}, async ({ baseUrl }) => {
      const endpoint = `${baseUrl}/api/code/projects/scratch`;
      assert.equal((await fetch(endpoint, { method: 'POST' })).status, 401);
      const registration = await fetch(`${baseUrl}/api/auth/register`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'Fixture', email: 'scratch@example.test', password: 'secret123', confirmPassword: 'secret123', consent: { 'code:terms': true } }),
      });
      assert.equal(registration.status, 201);
      const cookie = registration.headers.getSetCookie().map(value => value.split(';')[0]).join('; ');
      assert.ok(cookie);
      const headers = { 'Content-Type': 'application/json', Cookie: cookie };
      assert.equal((await fetch(endpoint, { method: 'POST', headers, body: '{}' })).status, 400);
      const response = await fetch(endpoint, { method: 'POST', headers, body: JSON.stringify({ name: 'craft-world', initialPrompt: 'prototype a sandbox' }) });
      assert.equal(response.status, 201);
      const body = await response.json() as { project: { name: string; rootPath: string; starterIntent: string }; ask?: unknown };
      assert.equal(body.project.name, 'craft-world');
      assert.equal(body.project.rootPath, '/workspaces/craft-world');
      assert.equal(body.project.starterIntent, 'prototype a sandbox');
      assert.equal(body.ask, undefined);
    });
  } finally {
    if (previous === undefined) delete process.env.AUTH_ENABLE_LEGACY_CODE_ROUTES;
    else process.env.AUTH_ENABLE_LEGACY_CODE_ROUTES = previous;
  }
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

test('OAuth missing consent exposes enrollment and an authenticated consent continuation', async () => {
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
    assert.equal(callback.status, 403);
    assert.equal(callback.headers.get('location'), null);
    assert.equal(callback.headers.get('cache-control'), 'no-store');
    const body = await callback.json() as { state: string; requiresProductSignup: boolean; reason: string; consent: { method: string; url: string }; continuation: string };
    assert.equal(body.state, 'ENROLLMENT_REQUIRED');
    assert.equal(body.requiresProductSignup, true);
    assert.equal(body.reason, 'missing_consent');
    assert.equal(body.consent.method, 'POST');
    assert.equal(body.consent.url, '/api/auth/consent?app=code');
    assert.equal(body.continuation, 'http://localhost:2048/');
    const cookie = callback.headers.getSetCookie().map(value => value.split(';')[0]).join('; ');
    assert.ok(cookie);
    const consent = await fetch(`${baseUrl}${body.consent.url}`, {
      method: 'POST', headers: { 'Content-Type': 'application/json', Cookie: cookie },
      body: JSON.stringify({ consent: { 'code:terms': true } }),
    });
    assert.equal(consent.status, 200);
  });
});

test('live-lineage GRID routing and hosted native authorization preserve existing selectors', async () => {
  const configStore = new FileAppConfigStore([
    'code.json',
    'chatty.json',
    'vvault.json',
    'grid.json',
  ].map((name) => path.join(repoRoot, 'config', name)));
  const github: OAuthProviderClient = {
    provider: 'github',
    label: 'Continue with GitHub',
    isConfigured: () => true,
    buildAuthorizationUrl: ({ callbackUrl, state }) => {
      const url = new URL('https://github.com/login/oauth/authorize');
      url.searchParams.set('redirect_uri', callbackUrl);
      url.searchParams.set('state', state);
      return url.toString();
    },
    exchangeCodeForProfile: async () => ({
      providerUserId: 'grid-github-user',
      email: 'grid@example.test',
      displayName: 'GRID Test User',
      raw: { id: 'grid-github-user' },
    }),
  };

  await withServer({ configStore, providers: { github } }, async ({ baseUrl }) => {
    const responseFor = async (pathName: string, headers: Record<string, string>) => {
      const response = await fetch(`${baseUrl}${pathName}`, { headers, redirect: 'manual' });
      return { response, body: await response.json() as { app?: { id?: string }; error?: string } };
    };

    const trustedProxyWins = await responseFor('/api/auth/config?app=chatty', {
      'X-Auth-App-Id': 'grid',
      Origin: 'https://grid.thewreck.org',
    });
    assert.equal(trustedProxyWins.response.status, 200);
    assert.equal(trustedProxyWins.body.app?.id, 'grid');

    const chatty = await responseFor('/api/auth/config?app=chatty', {});
    assert.equal(chatty.response.status, 200);
    assert.equal(chatty.body.app?.id, 'chatty');

    const vvault = await responseFor('/api/auth/config', { Origin: 'http://localhost:7784' });
    assert.equal(vvault.response.status, 200);
    assert.equal(vvault.body.app?.id, 'vvault');

    const unknown = await responseFor('/api/auth/config?app=not-a-product', {});
    assert.equal(unknown.response.status, 403);
    assert.equal(unknown.body.error, 'AUTH_CONFIG_NOT_FOUND');

    const providerStart = await fetch(`${baseUrl}/api/auth/github`, {
      headers: { 'X-Auth-App-Id': 'grid', Origin: 'https://grid.thewreck.org' },
      redirect: 'manual',
    });
    assert.equal(providerStart.status, 302);
    assert.equal(
      new URL(providerStart.headers.get('location') || '').searchParams.get('redirect_uri'),
      'https://grid.thewreck.org/api/auth/github/callback',
    );

    const authorize = new URL('/oauth/authorize', baseUrl);
    authorize.searchParams.set('response_type', 'code');
    authorize.searchParams.set('client_id', 'grid-windows');
    authorize.searchParams.set('redirect_uri', 'http://127.0.0.1:49152/grid-natives-callback');
    authorize.searchParams.set('state', 's'.repeat(32));
    authorize.searchParams.set('code_challenge', 'c'.repeat(43));
    authorize.searchParams.set('code_challenge_method', 'S256');
    const authorizeResponse = await fetch(authorize, {
      headers: { 'X-Auth-App-Id': 'grid' },
      redirect: 'manual',
    });
    assert.equal(authorizeResponse.status, 302);
    const signinUrl = new URL(authorizeResponse.headers.get('location') || '');
    const signin = await fetch(`${baseUrl}${signinUrl.pathname}${signinUrl.search}`, {
      headers: { 'X-Auth-App-Id': 'grid' },
    });
    assert.equal(signin.status, 200);
    assert.equal(signin.headers.get('cache-control'), 'no-store');
    assert.match(signin.headers.get('content-security-policy') || '', /default-src 'none'/);
    assert.match(await signin.text(), /GRID Terms of Service/);

    const providerForAuthorization = await fetch(
      `${baseUrl}/api/auth/github?authorization_request=${encodeURIComponent(signinUrl.searchParams.get('authorization_request') || '')}&authorization_return=${encodeURIComponent('http://localhost:1111/oauth/authorize/complete')}`,
      { headers: { 'X-Auth-App-Id': 'grid' }, redirect: 'manual' },
    );
    const providerState = new URL(providerForAuthorization.headers.get('location') || '').searchParams.get('state');
    assert.ok(providerState);
    const providerCallback = await fetch(
      `${baseUrl}/api/auth/github/callback?code=grid-test-code&state=${encodeURIComponent(providerState as string)}`,
      { headers: { 'X-Auth-App-Id': 'grid' }, redirect: 'manual' },
    );
    assert.equal(providerCallback.status, 302);
    const loopback = new URL(providerCallback.headers.get('location') || '');
    assert.equal(loopback.origin, 'http://127.0.0.1:49152');
    assert.equal(loopback.pathname, '/grid-natives-callback');
    assert.equal(loopback.searchParams.get('error'), 'enrollment_required');
    assert.equal(loopback.searchParams.get('state'), 's'.repeat(32));
    assert.equal(loopback.searchParams.get('code'), null);
    assert.equal(providerCallback.headers.get('set-cookie'), null);

    // Explicit signup acceptance is snapshotted by the authority, not inferred from sign-in.
    authorize.searchParams.set('accept_required_consent', 'true');
    authorize.searchParams.set('provider', 'github');
    const signupStart = await fetch(authorize, { headers: { 'X-Auth-App-Id': 'grid' }, redirect: 'manual' });
    const signupProviderUrl = new URL(signupStart.headers.get('location') || '');
    const signupProvider = await fetch(`${baseUrl}${signupProviderUrl.pathname}${signupProviderUrl.search}`, { headers: { 'X-Auth-App-Id': 'grid' }, redirect: 'manual' });
    const signupState = new URL(signupProvider.headers.get('location') || '').searchParams.get('state');
    assert.ok(signupState);
    const signupCallback = await fetch(`${baseUrl}/api/auth/github/callback?code=signup&state=${encodeURIComponent(signupState)}`, { headers: { 'X-Auth-App-Id': 'grid' }, redirect: 'manual' });
    assert.equal(signupCallback.status, 302);
    const continuationUrl = new URL(signupCallback.headers.get('location') || '');
    assert.equal(continuationUrl.pathname, '/oauth/authorize/complete');
    const cookie = signupCallback.headers.getSetCookie().map(value => value.split(';')[0]).join('; ');
    assert.ok(cookie);
    const completed = await fetch(`${baseUrl}${continuationUrl.pathname}${continuationUrl.search}`, { headers: { 'X-Auth-App-Id': 'grid', Cookie: cookie }, redirect: 'manual' });
    const signupResult = new URL(completed.headers.get('location') || '');
    assert.equal(signupResult.pathname, '/grid-natives-callback');
    assert.ok(signupResult.searchParams.get('code'));
    assert.equal(signupResult.searchParams.get('state'), 's'.repeat(32));
    assert.equal(signupResult.searchParams.get('error'), null);
  });
});

// Recovered from the pre-snapshot test contract at 3fe8da9^.
test('rotates refresh tokens and revokes the token family on replay', async () => {
  await withServer({}, async ({ baseUrl }) => {
    const register = await fetch(`${baseUrl}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: 'Devon',
        email: 'rotate-test@example.com',
        password: 'secret123',
        confirmPassword: 'secret123',
        consent: { 'code:terms': true },
      }),
    });
    assert.equal(register.status, 201);
    const initialCookies = register.headers.getSetCookie();
    assert.equal(initialCookies.length, 2);
    assert.ok(initialCookies.some((cookie) => /^auth_sid=/.test(cookie) && /Max-Age=900/.test(cookie) && /HttpOnly/i.test(cookie)));
    assert.ok(initialCookies.some((cookie) => /^auth_rid=/.test(cookie) && /Max-Age=2592000/.test(cookie) && /HttpOnly/i.test(cookie)));
    const initialCookieHeader = initialCookies.map(value => value.split(';')[0]).join('; ');

    const meSignedIn = await fetch(`${baseUrl}/api/me`, {
      headers: { Cookie: initialCookieHeader },
    });
    assert.equal(meSignedIn.status, 200);

    const refresh = await fetch(`${baseUrl}/api/auth/refresh`, {
      method: 'POST',
      headers: { Cookie: initialCookieHeader },
    });
    assert.equal(refresh.status, 200);
    const rotatedCookies = refresh.headers.getSetCookie();
    assert.equal(rotatedCookies.length, 2);
    const rotatedCookieHeader = rotatedCookies.map(value => value.split(';')[0]).join('; ');
    assert.notEqual(rotatedCookieHeader, initialCookieHeader);

    const replay = await fetch(`${baseUrl}/api/auth/refresh`, {
      method: 'POST',
      headers: { Cookie: initialCookieHeader },
    });
    assert.equal(replay.status, 401);
    const replayPayload = await replay.json() as { ok: boolean; errorCode?: string };
    assert.equal(replayPayload.ok, false);
    assert.equal(replayPayload.errorCode, 'REFRESH_TOKEN_REPLAY');

    const meAfterReplay = await fetch(`${baseUrl}/api/me`, {
      headers: { Cookie: rotatedCookieHeader },
    });
    assert.equal(meAfterReplay.status, 401);
  });
});
