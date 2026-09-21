import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import type { AppConfigStore, AuthAppConfig, OAuthProviderClient } from '../types.js';
import { resolveLifeProfile, type LifeProfileResult, type ResolveLifeProfileInput } from '../lifeProfile.js';
import { createAuthApp } from '../app.js';
import { hashPassword } from '../auth/passwords.js';
import { MemoryEphemeralAuthStore, type EphemeralAuthStore } from '../auth/ephemeralStore.js';
import { MemoryRefreshTokenStore } from '../auth/refreshTokenStore.js';
import { AuthConfigSelectionError, FileAppConfigStore } from '../config.js';
import { MemoryStorageAdapter } from '../persistence/memoryStorage.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, '..', '..');
type FetchInput = Parameters<typeof fetch>[0];
const ACCOUNT_CONTEXT_KEY_PAIR = crypto.generateKeyPairSync('ed25519');
const ACCOUNT_CONTEXT_PRIVATE_KEY_PEM = ACCOUNT_CONTEXT_KEY_PAIR.privateKey
  .export({ type: 'pkcs8', format: 'pem' }).toString();

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
    resolveVvaultOwnerId?: (email: string) => Promise<string | null>;
    isEmailInLifeRegistry?: (email: string) => Promise<boolean>;
    seedStorage?: (storage: MemoryStorageAdapter) => void | Promise<void>;
    storage?: MemoryStorageAdapter;
    ephemeralStore?: EphemeralAuthStore;
    configStore?: AppConfigStore;
  },
  fn: (context: { baseUrl: string }) => Promise<void>,
) {
  const storage = options.storage || new MemoryStorageAdapter();
  const app = await createAuthApp({
    storage,
    refreshTokenStore: new MemoryRefreshTokenStore(),
    configStore: options.configStore || new StaticConfigStore(options.config || TEST_CONFIG),
    providers: options.providers,
    turnstileVerifier: options.turnstileVerifier as any,
    resolveLifeProfile: options.resolveLifeProfile,
    resolveVvaultOwnerId: options.resolveVvaultOwnerId,
    isEmailInLifeRegistry: options.isEmailInLifeRegistry,
    sessionSecret: 'test-secret',
    cookieName: 'auth_sid',
    ephemeralStore: options.ephemeralStore || new MemoryEphemeralAuthStore(),
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

test('routes config and oauth callback base by request origin', async () => {
  const vvaultConfig: AuthAppConfig = {
    ...TEST_CONFIG,
    app: {
      id: 'vvault',
      name: 'VVAULT',
      brandTagline: 'Vault auth',
    },
    oauth: {
      envPrefix: 'VVAULT',
    },
    allowedOrigins: ['http://localhost:7784'],
    docs: [
      {
        product: 'vvault',
        docType: 'terms',
        key: 'vvault:terms',
        version: '1',
        label: 'VVAULT Terms',
        url: 'https://example.com/vvault/terms',
        required: true,
      },
    ],
  };

  class RequestAwareConfigStore implements AppConfigStore {
    async getConfig(req?: any) {
      const origin = req?.get?.('origin') || req?.headers?.origin || req?.query?.origin;
      return origin === 'http://localhost:7784' ? vvaultConfig : TEST_CONFIG;
    }
  }

  const provider: OAuthProviderClient = {
    provider: 'google',
    label: 'Continue with Google',
    isConfigured: () => true,
    buildAuthorizationUrl: ({ state, callbackUrl }) => `https://accounts.google.test/auth?state=${encodeURIComponent(state)}&redirect_uri=${encodeURIComponent(callbackUrl)}`,
    exchangeCodeForProfile: async () => {
      throw new Error('not used');
    },
  };

  await withEnv({
    VVAULT_GOOGLE_CALLBACK_URL: undefined,
    VVAULT_GOOGLE_CALLBACK: undefined,
    VVAULT_PUBLIC_CALLBACK_BASE: undefined,
    VVAULT_GOOGLE_CALLBACK_PATH: undefined,
    VVAULT_CALLBACK_PATH: undefined,
    GOOGLE_CALLBACK_URL: undefined,
    GOOGLE_CALLBACK: undefined,
    PUBLIC_CALLBACK_BASE: undefined,
    GOOGLE_CALLBACK_PATH: undefined,
    CALLBACK_PATH: undefined,
  }, async () => {
    await withServer({
      configStore: new RequestAwareConfigStore(),
      providers: { google: provider },
    }, async ({ baseUrl }) => {
      const vvaultConfigResponse = await fetch(`${baseUrl}/api/auth/config`, {
        headers: { Origin: 'http://localhost:7784' },
      });
      assert.equal(vvaultConfigResponse.status, 200);
      const vvaultPayload = await vvaultConfigResponse.json() as { app: { id: string } };
      assert.equal(vvaultPayload.app.id, 'vvault');

      const codeConfigResponse = await fetch(`${baseUrl}/api/auth/config`, {
        headers: { Origin: 'http://localhost:2048' },
      });
      assert.equal(codeConfigResponse.status, 200);
      const codePayload = await codeConfigResponse.json() as { app: { id: string } };
      assert.equal(codePayload.app.id, 'code');

      const oauthStart = await fetch(`${baseUrl}/api/auth/google`, {
        headers: { Origin: 'http://localhost:7784' },
        redirect: 'manual',
      });
      assert.equal(oauthStart.status, 302);
      const location = oauthStart.headers.get('location');
      assert.ok(location);
      const authUrl = new URL(location);
      assert.equal(authUrl.searchParams.get('redirect_uri'), 'http://localhost:7784/api/auth/google/callback');
    });
  });
});

test('multiple file configs reject unknown origins instead of falling back to the first app', async () => {
  const tempDir = await mkdtemp(path.join(tmpdir(), 'auth-config-selection-'));
  const firstConfigPath = path.join(tempDir, 'first.json');
  const secondConfigPath = path.join(tempDir, 'second.json');
  await writeFile(firstConfigPath, JSON.stringify({
    ...TEST_CONFIG,
    app: { id: 'first', name: 'First App' },
    allowedOrigins: ['http://localhost:3001'],
    providers: [],
    docs: [],
  }));
  await writeFile(secondConfigPath, JSON.stringify({
    ...TEST_CONFIG,
    app: { id: 'second', name: 'Second App' },
    allowedOrigins: ['http://localhost:3002'],
    providers: [],
    docs: [],
  }));

  await withServer(
    {
      configStore: new FileAppConfigStore([firstConfigPath, secondConfigPath]),
    },
    async ({ baseUrl }) => {
      const known = await fetch(`${baseUrl}/api/auth/config`, {
        headers: { Origin: 'http://localhost:3002' },
      });
      assert.equal(known.status, 200);
      const knownPayload = await known.json() as { app?: { id?: string } };
      assert.equal(knownPayload.app?.id, 'second');

      const unknown = await fetch(`${baseUrl}/api/auth/config`, {
        headers: { Origin: 'http://localhost:3999' },
      });
      assert.equal(unknown.status, 403);
      const unknownPayload = await unknown.json() as { ok: boolean; error?: string };
      assert.equal(unknownPayload.ok, false);
      assert.equal(unknownPayload.error, 'AUTH_CONFIG_NOT_FOUND');
    },
  );
});

test('/health bypasses consumer config selection for unknown origins', async () => {
  await withServer(
    {
      configStore: new FileAppConfigStore([
        path.join(repoRoot, 'config', 'example-app.json'),
        path.join(repoRoot, 'config', 'code.json'),
      ]),
    },
    async ({ baseUrl }) => {
      const response = await fetch(`${baseUrl}/health`, {
        headers: { Origin: 'http://localhost:3999' },
      });
      assert.equal(response.status, 200);
      const payload = await response.json() as { ok?: boolean; service?: string };
      assert.equal(payload.ok, true);
      assert.equal(payload.service, 'auth');
    },
  );
});

test('supports VVAULT start on frontend origin and callback on backend origin', async () => {
  const vvaultConfig: AuthAppConfig = {
    ...TEST_CONFIG,
    app: {
      id: 'vvault',
      name: 'VVAULT',
      brandTagline: 'Vault auth',
    },
    oauth: {
      envPrefix: 'VVAULT',
    },
    allowedOrigins: ['http://localhost:7784', 'http://localhost:8000'],
    docs: [],
  };
  const exchanges: Array<{ code: string; callbackUrl: string }> = [];

  const provider: OAuthProviderClient = {
    provider: 'google',
    label: 'Continue with Google',
    isConfigured: () => true,
    buildAuthorizationUrl: ({ state, callbackUrl }) => `https://accounts.google.test/auth?state=${encodeURIComponent(state)}&redirect_uri=${encodeURIComponent(callbackUrl)}`,
    exchangeCodeForProfile: async ({ code, callbackUrl }) => {
      exchanges.push({ code, callbackUrl });
      return {
        providerUserId: `google-${code}`,
        email: 'vvault-oauth@example.com',
        displayName: 'VVAULT OAuth',
        raw: { sub: `google-${code}` },
      };
    },
  };

  await withEnv({
    VVAULT_GOOGLE_CALLBACK_URL: 'http://localhost:8000/api/auth/google/callback',
  }, async () => {
    await withServer({
      config: vvaultConfig,
      providers: { google: provider },
    }, async ({ baseUrl }) => {
      const oauthStart = await fetch(`${baseUrl}/api/auth/google`, {
        headers: { Origin: 'http://localhost:7784' },
        redirect: 'manual',
      });
      assert.equal(oauthStart.status, 302);
      const location = oauthStart.headers.get('location');
      assert.ok(location);
      const authUrl = new URL(location);
      assert.equal(authUrl.searchParams.get('redirect_uri'), 'http://localhost:8000/api/auth/google/callback');
      const state = authUrl.searchParams.get('state');
      assert.ok(state);

      const callback = await fetch(`${baseUrl}/api/auth/google/callback?code=vvault-code&state=${encodeURIComponent(state)}`, {
        headers: { Host: 'localhost:8000' },
        redirect: 'manual',
      });
      assert.equal(callback.status, 302);
      const callbackLocation = callback.headers.get('location') || '';
      assert.match(callbackLocation, /^http:\/\/localhost:7784\/api\/auth\/set-session\?code=/);
      assert.deepEqual(exchanges, [
        {
          code: 'vvault-code',
          callbackUrl: 'http://localhost:8000/api/auth/google/callback',
        },
      ]);
    });
  });
});

test('OAuth start fails closed for an origin outside the active config', async () => {
  const provider: OAuthProviderClient = {
    provider: 'google',
    label: 'Continue with Google',
    isConfigured: () => true,
    buildAuthorizationUrl: () => {
      throw new Error('not used');
    },
    exchangeCodeForProfile: async () => {
      throw new Error('not used');
    },
  };

  await withEnv({
    CODE_GOOGLE_CALLBACK_URL: 'http://localhost:8000/api/auth/google/callback',
    CODE_PUBLIC_CALLBACK_BASE: undefined,
    GOOGLE_CALLBACK_URL: undefined,
    PUBLIC_CALLBACK_BASE: undefined,
  }, async () => {
    await withServer({ providers: { google: provider } }, async ({ baseUrl }) => {
      const response = await fetch(`${baseUrl}/api/auth/google`, {
        headers: { Origin: 'http://localhost:7784' },
        redirect: 'manual',
      });
      assert.equal(response.status, 403);
      const payload = await response.json() as { ok?: boolean; error?: string };
      assert.equal(payload.ok, false);
      assert.equal(payload.error, 'AUTH_ORIGIN_NOT_ALLOWED');
    });
  });
});

async function withEnv(vars: Record<string, string | undefined>, fn: () => Promise<void>) {
  const previous: Record<string, string | undefined> = {};
  for (const [key, value] of Object.entries(vars)) {
    previous[key] = process.env[key];
    if (value === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = value;
    }
  }
  try {
    await fn();
  } finally {
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = value;
      }
    }
  }
}

function decodeJwtSegment<T>(token: string, index: number): T {
  const segment = token.split('.')[index];
  assert.ok(segment);
  return JSON.parse(Buffer.from(segment, 'base64url').toString('utf8')) as T;
}

function signJwtInput(input: string, secret: string) {
  return crypto.createHmac('sha256', secret).update(input).digest('base64url');
}

function getSetCookies(headers: Headers): string[] {
  const getSetCookie = (headers as any).getSetCookie;
  if (typeof getSetCookie === 'function') {
    return getSetCookie.call(headers);
  }
  const single = headers.get('set-cookie');
  return single ? [single] : [];
}

function cookieHeaderFromSetCookies(setCookies: string[]): string {
  return setCookies.map((cookie) => cookie.split(';')[0]).join('; ');
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

test('README presents auth as setup tooling and runtime authorization authority', async () => {
  const readme = await readFile(path.join(repoRoot, 'README.md'), 'utf8');
  const exampleConfig = JSON.parse(
    await readFile(path.join(repoRoot, 'config', 'example-app.json'), 'utf8'),
  ) as { app?: { id?: string } };

  assert.equal(exampleConfig.app?.id, 'example-app');
  assert.match(readme, /reusable authentication and authorization authority/i);
  assert.match(readme, /shared runtime protocol authority for registered public clients/i);
  assert.match(readme, /bin\/auth setup --repo/i);
  assert.match(readme, /bin\/auth validate --repo/i);
  assert.match(readme, /copied, forked, or adapted/i);
  assert.match(readme, /What Auth Is/);
  assert.match(readme, /What Auth Is Not/);
  assert.match(readme, /does not own:[\s\S]*sibling-service discovery/i);
  assert.match(readme, /`?config\/example-app\.json`? is the primary onboarding example/i);
  assert.doesNotMatch(readme, /shared auth for the WRECK stack/i);
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
    const initialCookies = getSetCookies(register.headers);
    assert.equal(initialCookies.length, 2);
    assert.ok(initialCookies.some((cookie) => /^auth_sid=/.test(cookie) && /Max-Age=900/.test(cookie) && /HttpOnly/i.test(cookie)));
    assert.ok(initialCookies.some((cookie) => /^auth_rid=/.test(cookie) && /Max-Age=2592000/.test(cookie) && /HttpOnly/i.test(cookie)));
    const initialCookieHeader = cookieHeaderFromSetCookies(initialCookies);

    const meSignedIn = await fetch(`${baseUrl}/api/me`, {
      headers: { Cookie: initialCookieHeader },
    });
    assert.equal(meSignedIn.status, 200);

    const refresh = await fetch(`${baseUrl}/api/auth/refresh`, {
      method: 'POST',
      headers: { Cookie: initialCookieHeader },
    });
    assert.equal(refresh.status, 200);
    const rotatedCookies = getSetCookies(refresh.headers);
    assert.equal(rotatedCookies.length, 2);
    const rotatedCookieHeader = cookieHeaderFromSetCookies(rotatedCookies);
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

test('refresh lock contention returns retry without revoking the active session', async () => {
  class LockedRefreshStore extends MemoryEphemeralAuthStore {
    override async setIfNotExists(key: string, value: string, ttlSeconds: number) {
      if (key.startsWith('auth:refresh:lock:')) return false;
      return super.setIfNotExists(key, value, ttlSeconds);
    }
  }

  await withServer({ ephemeralStore: new LockedRefreshStore() }, async ({ baseUrl }) => {
    const register = await fetch(`${baseUrl}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: 'Devon',
        email: 'lock-test@example.com',
        password: 'secret123',
        confirmPassword: 'secret123',
        consent: { 'code:terms': true },
      }),
    });
    assert.equal(register.status, 201);
    const cookieHeader = cookieHeaderFromSetCookies(getSetCookies(register.headers));

    const refresh = await fetch(`${baseUrl}/api/auth/refresh`, {
      method: 'POST',
      headers: { Cookie: cookieHeader },
    });
    assert.equal(refresh.status, 409);
    const payload = await refresh.json() as { ok: boolean; errorCode?: string };
    assert.equal(payload.ok, false);
    assert.equal(payload.errorCode, 'REFRESH_IN_PROGRESS');
    assert.deepEqual(getSetCookies(refresh.headers), []);

    const me = await fetch(`${baseUrl}/api/me`, {
      headers: { Cookie: cookieHeader },
    });
    assert.equal(me.status, 200);
  });
});

test('refresh falls back to the session store when Redis-style cache operations fail', async () => {
  class FailingEphemeralStore extends MemoryEphemeralAuthStore {
    override async setIfNotExists(key: string, value: string, ttlSeconds: number) {
      if (key.startsWith('auth:refresh:lock:')) {
        throw new Error('redis unavailable');
      }
      return super.setIfNotExists(key, value, ttlSeconds);
    }

    override async isAccessRevoked(_jti: string): Promise<boolean> {
      throw new Error('redis unavailable');
    }

    override async isSessionRevoked(_sessionId: string): Promise<boolean> {
      throw new Error('redis unavailable');
    }
  }

  const originalWarn = console.warn;
  const warnCalls: Array<unknown[]> = [];
  console.warn = (...args: unknown[]) => {
    warnCalls.push(args);
  };

  try {
    await withServer({ ephemeralStore: new FailingEphemeralStore() }, async ({ baseUrl }) => {
      const register = await fetch(`${baseUrl}/api/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: 'Devon',
          email: 'redis-fallback@example.com',
          password: 'secret123',
          confirmPassword: 'secret123',
          consent: { 'code:terms': true },
        }),
      });
      assert.equal(register.status, 201);
      const initialCookieHeader = cookieHeaderFromSetCookies(getSetCookies(register.headers));

      const refresh = await fetch(`${baseUrl}/api/auth/refresh`, {
        method: 'POST',
        headers: { Cookie: initialCookieHeader },
      });
      assert.equal(refresh.status, 200);
      const rotatedCookieHeader = cookieHeaderFromSetCookies(getSetCookies(refresh.headers));
      assert.ok(rotatedCookieHeader.includes('auth_sid='));
      assert.ok(rotatedCookieHeader.includes('auth_rid='));

      const me = await fetch(`${baseUrl}/api/me`, {
        headers: { Cookie: rotatedCookieHeader },
      });
      assert.equal(me.status, 200);
    });
  } finally {
    console.warn = originalWarn;
  }

  assert.equal(warnCalls[0]?.[0], '⚠️ [Auth] refresh lock unavailable; falling back to session store');
  assert.equal(warnCalls[1]?.[0], '⚠️ [Auth] revocation cache unavailable; falling back to session store');
});

test('issues a PostgREST JWT from an existing auth cookie when uid is a Supabase UUID', async () => {
  const fixedLife = 'devon_woodson_1762969514958';
  const fixedSb = 'aaaaaaaa-bbbb-4ccc-9ddd-eeeeeeeeeeee';
  const jwtSecret = 'test-postgrest-secret';

  await withEnv(
    {
      AUTH_POSTGREST_JWT_SECRET: jwtSecret,
      AUTH_POSTGREST_JWT_TTL_SECONDS: '900',
    },
    async () => {
      await withServer(
        {
          resolveLifeProfile: async () => ({
            lifeUserId: fixedLife,
            supabaseUserId: fixedSb,
            source: 'supabase_found',
          }),
        },
        async ({ baseUrl }) => {
          const register = await fetch(`${baseUrl}/api/auth/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              name: 'Devon',
              email: 'postgrest@example.com',
              password: 'secret123',
              confirmPassword: 'secret123',
              consent: { 'code:terms': true },
            }),
          });
          assert.equal(register.status, 201);
          const cookie = (register.headers as any).getSetCookie?.()[0] || register.headers.get('set-cookie');
          assert.ok(cookie);

          const tokenResponse = await fetch(`${baseUrl}/api/auth/postgrest-token`, {
            method: 'POST',
            headers: { Cookie: cookie },
          });
          assert.equal(tokenResponse.status, 200);
          const tokenPayload = await tokenResponse.json() as {
            ok: boolean;
            token?: string;
            exp?: number;
            expiresIn?: number;
            tokenType?: string;
          };
          assert.equal(tokenPayload.ok, true);
          assert.equal(tokenPayload.tokenType, 'Bearer');
          assert.equal(tokenPayload.expiresIn, 900);
          const issuedToken = tokenPayload.token;
          assert.ok(issuedToken);

          const [header, payload, signature] = issuedToken.split('.');
          assert.ok(header && payload && signature);
          assert.equal(signature, signJwtInput(`${header}.${payload}`, jwtSecret));
          const decodedHeader = decodeJwtSegment<{ alg: string; typ: string }>(issuedToken, 0);
          const claims = decodeJwtSegment<{ sub: string; role: string; email: string; iat: number; exp: number }>(issuedToken, 1);
          assert.equal(decodedHeader.alg, 'HS256');
          assert.equal(decodedHeader.typ, 'JWT');
          assert.equal(claims.sub, fixedSb);
          assert.equal(claims.role, 'authenticated');
          assert.equal(claims.email, 'postgrest@example.com');
          assert.equal(claims.exp - claims.iat, 900);
          assert.equal(tokenPayload.exp, claims.exp);
        },
      );
    },
  );
});

test('refuses PostgREST JWT issuance when the session uid is not a Supabase UUID', async () => {
  await withEnv({ AUTH_POSTGREST_JWT_SECRET: 'test-postgrest-secret' }, async () => {
    await withServer(
      {
        resolveLifeProfile: async () => ({
          lifeUserId: 'local_only_user_123',
          supabaseUserId: null,
          source: 'local_only',
        }),
      },
      async ({ baseUrl }) => {
        const register = await fetch(`${baseUrl}/api/auth/register`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            name: 'Local Only',
            email: 'local-only@example.com',
            password: 'secret123',
            confirmPassword: 'secret123',
            consent: { 'code:terms': true },
          }),
        });
        assert.equal(register.status, 201);
        const cookie = (register.headers as any).getSetCookie?.()[0] || register.headers.get('set-cookie');
        assert.ok(cookie);

        const tokenResponse = await fetch(`${baseUrl}/api/auth/postgrest-token`, {
          method: 'POST',
          headers: { Cookie: cookie },
        });
        assert.equal(tokenResponse.status, 409);
        const payload = await tokenResponse.json() as { ok: boolean; token?: string; errorCode?: string };
        assert.equal(payload.ok, false);
        assert.equal(payload.errorCode, 'SUPABASE_UID_REQUIRED');
        assert.equal(payload.token, undefined);
      },
    );
  });
});

test('VVAULT account assertion endpoint signs only canonical owner account context', async () => {
  const subject = 'canary_assertion_owner_1770000000000';
  const supabaseUserId = 'cccccccc-dddd-4eee-8fff-aaaaaaaaaaaa';
  await withEnv({
    AUTH_VVAULT_ACCOUNT_ASSERTION_PRIVATE_KEY_PEM: ACCOUNT_CONTEXT_PRIVATE_KEY_PEM,
  }, async () => {
    await withServer({
      resolveLifeProfile: async () => ({
        lifeUserId: subject,
        supabaseUserId,
        source: 'supabase_found',
      }),
      resolveVvaultOwnerId: async () => supabaseUserId,
    }, async ({ baseUrl }) => {
      const register = await fetch(`${baseUrl}/api/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: 'Canary Assertion Owner',
          email: 'canary-assertion@example.com',
          password: 'secret123',
          confirmPassword: 'secret123',
          consent: { 'code:terms': true },
        }),
      });
      assert.equal(register.status, 201);
      const registerPayload = await register.json() as {
        user?: {
          actorAttestation?: { vvaultOwnerId?: string };
          accountContextReadiness?: { ready?: boolean; vvaultOwnerId?: string };
        };
      };
      assert.equal(registerPayload.user?.actorAttestation?.vvaultOwnerId, supabaseUserId);
      assert.equal(registerPayload.user?.accountContextReadiness?.ready, true);
      assert.equal(registerPayload.user?.accountContextReadiness?.vvaultOwnerId, supabaseUserId);
      const cookie = (register.headers as any).getSetCookie?.()[0] || register.headers.get('set-cookie');
      assert.ok(cookie);

      const response = await fetch(`${baseUrl}/api/auth/vvault-account-assertion`, {
        method: 'POST',
        headers: { Cookie: cookie },
      });
      assert.equal(response.status, 200);
      const body = await response.json() as { assertion?: string; accountContext?: Record<string, unknown> };
      assert.ok(body.assertion);
      assert.deepEqual(body.accountContext, { displayName: 'Canary Assertion Owner' });
      const claims = decodeJwtSegment<Record<string, unknown>>(body.assertion, 1);
      assert.equal(claims.sub, subject);
      assert.equal(claims.vvault_owner_id, supabaseUserId);
      assert.equal(claims.aud, 'vvault');
      assert.deepEqual(claims.account_context, { displayName: 'Canary Assertion Owner' });
      assert.equal(JSON.stringify(claims).includes('canary-assertion@example.com'), false);

      const accessToken = decodeURIComponent(String(cookie).split(';', 1)[0].split('=').slice(1).join('='));
      const bearerResponse = await fetch(`${baseUrl}/api/auth/vvault-account-assertion`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      assert.equal(bearerResponse.status, 200);
      const bearerBody = await bearerResponse.json() as { assertion?: string };
      assert.ok(bearerBody.assertion);
    });
  });
});

test('local-only sessions expose unverified readiness and cannot mint VVAULT account assertions', async () => {
  await withEnv({
    AUTH_VVAULT_ACCOUNT_ASSERTION_PRIVATE_KEY_PEM: ACCOUNT_CONTEXT_PRIVATE_KEY_PEM,
  }, async () => {
    await withServer({
      resolveLifeProfile: async () => ({
        lifeUserId: 'canary_local_only_1770000000000',
        supabaseUserId: null,
        source: 'local_only',
      }),
    }, async ({ baseUrl }) => {
      const register = await fetch(`${baseUrl}/api/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: 'Canary Local Only',
          email: 'canary-local-only@example.com',
          password: 'secret123',
          confirmPassword: 'secret123',
          consent: { 'code:terms': true },
        }),
      });
      assert.equal(register.status, 201);
      const registerPayload = await register.json() as {
        user?: {
          actorAttestation?: unknown;
          accountContextReadiness?: { ready?: boolean; reason?: string };
        };
      };
      assert.equal(registerPayload.user?.actorAttestation, undefined);
      assert.deepEqual(registerPayload.user?.accountContextReadiness, {
        version: 'life-auth-account-context-readiness/v1',
        ready: false,
        subject: 'canary_local_only_1770000000000',
        reason: 'canonical_owner_unverified',
      });
      const cookie = (register.headers as any).getSetCookie?.()[0] || register.headers.get('set-cookie');
      assert.ok(cookie);

      const response = await fetch(`${baseUrl}/api/auth/vvault-account-assertion`, {
        method: 'POST',
        headers: { Cookie: cookie },
      });
      assert.equal(response.status, 409);
      const body = await response.json() as { assertion?: string; errorCode?: string };
      assert.equal(body.errorCode, 'CANONICAL_OWNER_UNVERIFIED');
      assert.equal(body.assertion, undefined);
    });
  });
});

test('leaves normal sessions working when PostgREST JWT secret is missing', async () => {
  const fixedLife = 'devon_woodson_1762969514958';
  const fixedSb = 'aaaaaaaa-bbbb-4ccc-9ddd-eeeeeeeeeeee';

  await withEnv({ AUTH_POSTGREST_JWT_SECRET: undefined }, async () => {
    await withServer(
      {
        resolveLifeProfile: async () => ({
          lifeUserId: fixedLife,
          supabaseUserId: fixedSb,
          source: 'supabase_found',
        }),
      },
      async ({ baseUrl }) => {
        const register = await fetch(`${baseUrl}/api/auth/register`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            name: 'Devon',
            email: 'missing-secret@example.com',
            password: 'secret123',
            confirmPassword: 'secret123',
            consent: { 'code:terms': true },
          }),
        });
        assert.equal(register.status, 201);
        const cookie = (register.headers as any).getSetCookie?.()[0] || register.headers.get('set-cookie');
        assert.ok(cookie);

        const me = await fetch(`${baseUrl}/api/me`, { headers: { Cookie: cookie } });
        assert.equal(me.status, 200);

        const tokenResponse = await fetch(`${baseUrl}/api/auth/postgrest-token`, {
          method: 'POST',
          headers: { Cookie: cookie },
        });
        assert.equal(tokenResponse.status, 503);
        const payload = await tokenResponse.json() as { ok: boolean; errorCode?: string };
        assert.equal(payload.ok, false);
        assert.equal(payload.errorCode, 'POSTGREST_JWT_SECRET_MISSING');
      },
    );
  });
});

test('refuses PostgREST JWT issuance when the JWT secret reuses the auth session secret', async () => {
  const fixedLife = 'devon_woodson_1762969514958';
  const fixedSb = 'aaaaaaaa-bbbb-4ccc-9ddd-eeeeeeeeeeee';

  await withEnv({ AUTH_POSTGREST_JWT_SECRET: 'test-secret' }, async () => {
    await withServer(
      {
        resolveLifeProfile: async () => ({
          lifeUserId: fixedLife,
          supabaseUserId: fixedSb,
          source: 'supabase_found',
        }),
      },
      async ({ baseUrl }) => {
        const register = await fetch(`${baseUrl}/api/auth/register`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            name: 'Devon',
            email: 'reused-secret@example.com',
            password: 'secret123',
            confirmPassword: 'secret123',
            consent: { 'code:terms': true },
          }),
        });
        assert.equal(register.status, 201);
        const cookie = (register.headers as any).getSetCookie?.()[0] || register.headers.get('set-cookie');
        assert.ok(cookie);

        const tokenResponse = await fetch(`${baseUrl}/api/auth/postgrest-token`, {
          method: 'POST',
          headers: { Cookie: cookie },
        });
        assert.equal(tokenResponse.status, 503);
        const payload = await tokenResponse.json() as { ok: boolean; errorCode?: string };
        assert.equal(payload.ok, false);
        assert.equal(payload.errorCode, 'POSTGREST_JWT_SECRET_REUSES_SESSION_SECRET');
      },
    );
  });
});

test('/api/me skips refresh work when the signed session already has a Supabase uid', async () => {
  class CountingStorage extends MemoryStorageAdapter {
    findUserByEmailCalls = 0;
    updateUserLifeAnchorsCalls = 0;

    override async findUserByEmail(email: string) {
      this.findUserByEmailCalls += 1;
      return super.findUserByEmail(email);
    }

    override async updateUserLifeAnchors(userId: string, lifeUserId: string, supabaseUserId: string | null) {
      this.updateUserLifeAnchorsCalls += 1;
      return super.updateUserLifeAnchors(userId, lifeUserId, supabaseUserId);
    }
  }

  const storage = new CountingStorage();
  const fixedLife = 'devon_woodson_1762969514958';
  const fixedSb = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
  let resolveCalls = 0;

  await withServer(
    {
      storage,
      resolveLifeProfile: async () => {
        resolveCalls += 1;
        return {
          lifeUserId: fixedLife,
          supabaseUserId: fixedSb,
          source: 'cache',
        };
      },
    },
    async ({ baseUrl }) => {
      const register = await fetch(`${baseUrl}/api/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: 'Devon',
          email: 'fastpath@example.com',
          password: 'secret123',
          confirmPassword: 'secret123',
          consent: { 'code:terms': true },
        }),
      });
      assert.equal(register.status, 201);
      const signedCookie = (register.headers as any).getSetCookie?.()[0] || register.headers.get('set-cookie');
      assert.ok(signedCookie);

      resolveCalls = 0;
      storage.findUserByEmailCalls = 0;
      storage.updateUserLifeAnchorsCalls = 0;

      const me = await fetch(`${baseUrl}/api/me`, {
        headers: { Cookie: signedCookie },
      });
      assert.equal(me.status, 200);
      assert.equal(me.headers.get('set-cookie'), null);

      const mePayload = await me.json() as {
        ok: boolean;
        user?: { id?: string; sub?: string; uid?: string; email?: string };
      };
      assert.equal(mePayload.ok, true);
      assert.equal(mePayload.user?.id, fixedLife);
      assert.equal(mePayload.user?.sub, fixedLife);
      assert.equal(mePayload.user?.uid, fixedSb);
      assert.equal(mePayload.user?.email, 'fastpath@example.com');
      assert.equal(resolveCalls, 0);
      assert.equal(storage.findUserByEmailCalls, 0);
      assert.equal(storage.updateUserLifeAnchorsCalls, 0);
    },
  );
});

test('/api/me diagnostics logs both session keys for a Supabase-ready session without leaking cookies', async () => {
  const originalInfo = console.info;
  const infoCalls: any[] = [];
  console.info = (...args: any[]) => {
    infoCalls.push(args);
  };
  process.env.VVAULT_IDENTITY_DIAGNOSTICS = 'true';
  process.env.VVAULT_IDENTITY_DIAGNOSTICS_SALT = 'atlas-local-salt';
  process.env.COOKIE_NAME = 'sid';

  try {
    await withServer(
      {
        resolveLifeProfile: async () => ({
          lifeUserId: 'devon_woodson_1762969514958',
          supabaseUserId: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
          source: 'cache',
        }),
      },
      async ({ baseUrl }) => {
        const register = await fetch(`${baseUrl}/api/auth/register`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            name: 'Devon',
            email: 'diag-ready@example.com',
            password: 'secret123',
            confirmPassword: 'secret123',
            consent: { 'code:terms': true },
          }),
        });
        assert.equal(register.status, 201);
        const setCookie = (register.headers as any).getSetCookie?.()[0] || register.headers.get('set-cookie');
        assert.ok(setCookie);

        const me = await fetch(`${baseUrl}/api/me`, {
          headers: { Cookie: `${setCookie}; sid=chatty-session-token` },
        });
        assert.equal(me.status, 200);
      },
    );

    const diagCall = infoCalls.find((entry) => entry?.[0] === 'ℹ️ [VvaultIdentityDiagnostics]');
    assert.ok(diagCall);
    assert.equal(diagCall[1]?.label, 'auth_api_me');
    assert.equal(diagCall[1]?.uid, 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee');
    assert.equal(diagCall[1]?.uidState, 'supabase_uuid');
    assert.equal(diagCall[1]?.life_user_id_present, true);
    assert.equal(diagCall[1]?.supabase_user_id_present, true);
    assert.equal(diagCall[1]?.refreshRan, false);
    assert.equal(diagCall[1]?.refreshChanged, false);
    assert.equal(diagCall[1]?.authSessionKey?.length, 12);
    assert.equal(diagCall[1]?.chattySessionKey?.length, 12);
    assert.equal(String(diagCall[1]).includes('auth_sid='), false);
    assert.equal(String(diagCall[1]).includes('chatty-session-token'), false);
  } finally {
    console.info = originalInfo;
    delete process.env.VVAULT_IDENTITY_DIAGNOSTICS;
    delete process.env.VVAULT_IDENTITY_DIAGNOSTICS_SALT;
    delete process.env.COOKIE_NAME;
  }
});

test('/api/me diagnostics logs LIFE fallback before refresh and marks refresh changed when session upgrades', async () => {
  const originalInfo = console.info;
  const infoCalls: any[] = [];
  console.info = (...args: any[]) => {
    infoCalls.push(args);
  };
  process.env.VVAULT_IDENTITY_DIAGNOSTICS = 'true';
  process.env.VVAULT_IDENTITY_DIAGNOSTICS_SALT = 'atlas-local-salt';
  process.env.COOKIE_NAME = 'sid';

  try {
    let resolveCount = 0;
    await withServer(
      {
        resolveLifeProfile: async () => {
          resolveCount += 1;
          return resolveCount === 1
            ? {
                lifeUserId: 'devon_woodson_1762969514958',
                supabaseUserId: null,
                source: 'local_only',
              }
            : {
                lifeUserId: 'devon_woodson_1762969514958',
                supabaseUserId: 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
                source: 'cache',
              };
        },
      },
      async ({ baseUrl }) => {
        const register = await fetch(`${baseUrl}/api/auth/register`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            name: 'Devon',
            email: 'diag-refresh@example.com',
            password: 'secret123',
            confirmPassword: 'secret123',
            consent: { 'code:terms': true },
          }),
        });
        assert.equal(register.status, 201);
        const cookies = getSetCookies(register.headers);
        assert.ok(cookies.length >= 2);

        const me = await fetch(`${baseUrl}/api/me`, {
          headers: {
            Cookie: `${cookieHeaderFromSetCookies(cookies)}; sid=chatty-session-token`,
          },
        });
        assert.equal(me.status, 200);
        const payload = await me.json() as { ok: boolean; user?: { uid?: string } };
        assert.equal(payload.ok, true);
        assert.equal(payload.user?.uid, 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee');
      },
    );

    const diagCall = infoCalls.find((entry) => entry?.[0] === 'ℹ️ [VvaultIdentityDiagnostics]');
    assert.ok(diagCall);
    assert.equal(diagCall[1]?.label, 'auth_api_me');
    assert.equal(diagCall[1]?.uid, 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee');
    assert.equal(diagCall[1]?.uidState, 'supabase_uuid');
    assert.equal(diagCall[1]?.life_user_id_present, true);
    assert.equal(diagCall[1]?.supabase_user_id_present, true);
    assert.equal(diagCall[1]?.refreshRan, true);
    assert.equal(diagCall[1]?.refreshChanged, true);
    assert.equal(diagCall[1]?.authSessionKey?.length, 12);
    assert.equal(diagCall[1]?.chattySessionKey?.length, 12);
  } finally {
    console.info = originalInfo;
    delete process.env.VVAULT_IDENTITY_DIAGNOSTICS;
    delete process.env.VVAULT_IDENTITY_DIAGNOSTICS_SALT;
    delete process.env.COOKIE_NAME;
  }
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

async function assertCodeAskMovedResponse(baseUrl: string, path: string, init?: RequestInit) {
  const response = await fetch(`${baseUrl}${path}`, init);
  assert.equal(response.status, 501);
  const payload = await response.json() as {
    ok: boolean;
    code: string;
    movedTo: string;
    message: string;
  };
  assert.equal(payload.ok, false);
  assert.equal(payload.code, 'CODE_ASK_MOVED_TO_CODE_RUNTIME');
  assert.equal(payload.movedTo, 'code-runtime');
  assert.match(payload.message, /moved out of auth/i);
}

test('Ask Hydro thread endpoint fails closed with an explicit moved response', async () => {
  await withEnv({ AUTH_ENABLE_LEGACY_CODE_ROUTES: '1' }, async () => {
    await withServer({}, async ({ baseUrl }) => {
      await assertCodeAskMovedResponse(
        baseUrl,
        '/api/code/ask/thread?projectName=demo&rootPath=%2Ftmp%2Fdemo',
      );
    });
  });
});

test('Ask Hydro status endpoint fails closed with an explicit moved response', async () => {
  await withEnv({ AUTH_ENABLE_LEGACY_CODE_ROUTES: '1' }, async () => {
    await withServer({}, async ({ baseUrl }) => {
      await assertCodeAskMovedResponse(
        baseUrl,
        '/api/code/ask/status?projectName=demo&rootPath=%2Ftmp%2Fdemo',
      );
    });
  });
});

test('scratch project creation stays inside auth metadata without Ask runtime bootstrap', async () => {
  const originalFetch = globalThis.fetch;
  const upstreamCalls: string[] = [];

  globalThis.fetch = (async (input: FetchInput | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
    if (url.startsWith('https://vvault.example')) {
      upstreamCalls.push(url);
      return new Response(JSON.stringify({ messages: [] }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }
    return originalFetch(input as any, init);
  }) as typeof fetch;

  try {
    await withEnv(
      {
        AUTH_ENABLE_LEGACY_CODE_ROUTES: '1',
        VVAULT_API_BASE_URL: 'https://vvault.example',
        OPENAI_API_KEY: 'test-openai-key',
      },
      async () => {
        await withServer({}, async ({ baseUrl }) => {
          const register = await fetch(`${baseUrl}/api/auth/register`, {
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
          const cookie = (register.headers as any).getSetCookie?.()[0] || register.headers.get('set-cookie');
          assert.ok(cookie);

          const response = await fetch(`${baseUrl}/api/code/projects/scratch`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              Cookie: cookie,
            },
            body: JSON.stringify({
              name: 'craft-world',
              initialPrompt: 'prototype a survival sandbox',
            }),
          });
          assert.equal(response.status, 201);
          const payload = await response.json() as {
            project: { name: string; rootPath: string; starterIntent: string | null };
            ask?: unknown;
          };
          assert.equal(payload.project.name, 'craft-world');
          assert.equal(payload.project.rootPath, '/workspaces/craft-world');
          assert.equal(payload.project.starterIntent, 'prototype a survival sandbox');
          assert.equal(payload.ask, undefined);
          assert.deepEqual(upstreamCalls, []);
        });
      },
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('Ask Hydro message endpoint fails closed with an explicit moved response', async () => {
  await withEnv({ AUTH_ENABLE_LEGACY_CODE_ROUTES: '1' }, async () => {
    await withServer({}, async ({ baseUrl }) => {
      await assertCodeAskMovedResponse(baseUrl, '/api/code/ask/messages', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          content: 'hello',
          projectName: 'demo',
          rootPath: '/tmp/demo',
        }),
      });
    });
  });
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
        user?: {
          id: string;
          sub: string;
          uid: string;
          lifeUserId?: string;
          vvaultUserId?: string;
          supabaseUserId?: string;
          email: string;
        };
      };
      assert.equal(mePayload.user?.id, fixedLife);
      assert.equal(mePayload.user?.sub, fixedLife);
      assert.equal(mePayload.user?.uid, fixedSb);
      assert.equal(mePayload.user?.lifeUserId, fixedLife);
      assert.equal(mePayload.user?.vvaultUserId, undefined);
      assert.equal(mePayload.user?.supabaseUserId, fixedSb);
      assert.equal(mePayload.user?.email, 'parity@example.com');
    },
  );
});

test('/api/me refreshes stale sessions once a Supabase uid is available', async () => {
  const fixedLife = 'devon_woodson_1762969514958';
  const fixedSb = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
  let resolveCount = 0;

  await withServer(
    {
      resolveLifeProfile: async () => {
        resolveCount += 1;
        return resolveCount === 1
          ? {
              lifeUserId: fixedLife,
              supabaseUserId: null,
              source: 'local_only',
            }
          : {
              lifeUserId: fixedLife,
              supabaseUserId: fixedSb,
              source: 'supabase_found',
            };
      },
    },
    async ({ baseUrl }) => {
      const register = await fetch(`${baseUrl}/api/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: 'Devon',
          email: 'stale-session@example.com',
          password: 'secret123',
          confirmPassword: 'secret123',
          consent: { 'code:terms': true },
        }),
      });
      assert.equal(register.status, 201);
      const staleCookie = (register.headers as any).getSetCookie?.()[0] || register.headers.get('set-cookie');
      assert.ok(staleCookie);
      const registerPayload = await register.json() as { user?: { uid?: string } };
      assert.equal(registerPayload.user?.uid, fixedLife);

      const me = await fetch(`${baseUrl}/api/me`, {
        headers: { Cookie: staleCookie },
      });
      assert.equal(me.status, 200);
      const refreshedCookie = (me.headers as any).getSetCookie?.()[0] || me.headers.get('set-cookie');
      assert.ok(refreshedCookie);
      const mePayload = await me.json() as { user?: { id?: string; sub?: string; uid?: string } };
      assert.equal(mePayload.user?.id, fixedLife);
      assert.equal(mePayload.user?.sub, fixedLife);
      assert.equal(mePayload.user?.uid, fixedSb);
    },
  );
});

test('canonical owner registration resolves local Supabase anchor without remote lookup', async () => {
  const canaryEmail = 'canary-owner@example.com';
  const canaryLifeId = 'canary_owner_1770000000000';
  const canarySupabaseId = 'aaaaaaaa-bbbb-4ccc-9ddd-eeeeeeeeeeee';
  const realFetch = globalThis.fetch;
  let remoteLookupCalls = 0;

  globalThis.fetch = (async (input: FetchInput | URL, init?: RequestInit) => {
    const url = typeof input === 'string'
      ? input
      : input instanceof URL
        ? input.toString()
        : input.url;
    if (String(url).includes('/rest/v1/users')) {
      remoteLookupCalls += 1;
      throw new Error('unexpected_remote_lookup');
    }
    return realFetch(input, init);
  }) as typeof globalThis.fetch;

  try {
    await withEnv({
      AUTH_CANONICAL_EMAIL_LIFE_IDS: `${canaryEmail}=${canaryLifeId}`,
      AUTH_CANONICAL_EMAIL_SUPABASE_IDS: `${canaryEmail}=${canarySupabaseId}`,
    }, async () => {
      await withServer({}, async ({ baseUrl }) => {
        const register = await realFetch(`${baseUrl}/api/auth/register`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            name: 'Canary Owner',
            email: canaryEmail,
            password: 'secret123',
            confirmPassword: 'secret123',
            consent: { 'code:terms': true },
          }),
        });
        assert.equal(register.status, 201);
        const registerPayload = await register.json() as {
          ok: boolean;
          user?: { id?: string; sub?: string; uid?: string };
        };
        assert.equal(registerPayload.user?.id, canaryLifeId);
        assert.equal(registerPayload.user?.sub, canaryLifeId);
        assert.equal(registerPayload.user?.uid, canarySupabaseId);

        const cookie = (register.headers as any).getSetCookie?.()[0] || register.headers.get('set-cookie');
        assert.ok(cookie);

        const me = await realFetch(`${baseUrl}/api/me`, {
          headers: { Cookie: cookie },
        });
        assert.equal(me.status, 200);
        const mePayload = await me.json() as {
          ok: boolean;
          user?: { id?: string; sub?: string; uid?: string };
        };
        assert.equal(mePayload.user?.id, canaryLifeId);
        assert.equal(mePayload.user?.sub, canaryLifeId);
        assert.equal(mePayload.user?.uid, canarySupabaseId);
      });
    });
  } finally {
    globalThis.fetch = realFetch;
  }

  assert.equal(remoteLookupCalls, 0);
});

test('resolveLifeProfile returns the canonical local registry mapping before any remote lookup', async () => {
  const canaryEmail = 'canary-profile@example.com';
  const canaryLifeId = 'canary_profile_1770000000000';
  const canarySupabaseId = 'bbbbbbbb-cccc-4ddd-8eee-ffffffffffff';
  const realFetch = globalThis.fetch;
  let remoteLookupCalls = 0;

  globalThis.fetch = (async (input: FetchInput | URL, init?: RequestInit) => {
    const url = typeof input === 'string'
      ? input
      : input instanceof URL
        ? input.toString()
        : input.url;
    if (String(url).includes('/rest/v1/users')) {
      remoteLookupCalls += 1;
      throw new Error('unexpected_remote_lookup');
    }
    return realFetch(input, init);
  }) as typeof globalThis.fetch;

  try {
    await withEnv({
      AUTH_CANONICAL_EMAIL_LIFE_IDS: `${canaryEmail}=${canaryLifeId}`,
      AUTH_CANONICAL_EMAIL_SUPABASE_IDS: `${canaryEmail}=${canarySupabaseId}`,
    }, async () => {
      const resolved = await resolveLifeProfile({
        email: canaryEmail,
        displayName: 'Canary Profile',
        cachedLifeUserId: null,
        cachedSupabaseUserId: null,
      });
      assert.deepEqual(resolved, {
        lifeUserId: canaryLifeId,
        supabaseUserId: canarySupabaseId,
        source: 'local_registry',
      });
    });
  } finally {
    globalThis.fetch = realFetch;
  }

  assert.equal(remoteLookupCalls, 0);
});

test('/api/me falls back to the signed session and logs refresh exceptions', async () => {
  class FailingRefreshStorage extends MemoryStorageAdapter {
    failFindUserByEmail = false;

    override async findUserByEmail(email: string) {
      if (this.failFindUserByEmail && email === 'refresh-fallback@example.com') {
        throw new Error('storage temporarily unavailable');
      }
      return super.findUserByEmail(email);
    }
  }

  const storage = new FailingRefreshStorage();
  const fixedLife = 'devon_woodson_1762969514958';
  const fixedSb = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
  let resolveCount = 0;
  const originalWarn = console.warn;
  const warnCalls: Array<unknown[]> = [];
  console.warn = (...args: unknown[]) => {
    warnCalls.push(args);
  };

  try {
    await withServer(
      {
        storage,
        resolveLifeProfile: async () => {
          resolveCount += 1;
          return resolveCount === 1
            ? {
                lifeUserId: fixedLife,
                supabaseUserId: null,
                source: 'local_only',
              }
            : {
                lifeUserId: fixedLife,
                supabaseUserId: fixedSb,
                source: 'supabase_found',
              };
        },
      },
      async ({ baseUrl }) => {
        const register = await fetch(`${baseUrl}/api/auth/register`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            name: 'Devon',
            email: 'refresh-fallback@example.com',
            password: 'secret123',
            confirmPassword: 'secret123',
            consent: { 'code:terms': true },
          }),
        });
        assert.equal(register.status, 201);
        const staleCookie = (register.headers as any).getSetCookie?.()[0] || register.headers.get('set-cookie');
        assert.ok(staleCookie);

        storage.failFindUserByEmail = true;

        const me = await fetch(`${baseUrl}/api/me`, {
          headers: { Cookie: staleCookie },
        });
        assert.equal(me.status, 200);
        assert.equal(me.headers.get('set-cookie'), null);

        const mePayload = await me.json() as { user?: { id?: string; sub?: string; uid?: string } };
        assert.equal(mePayload.user?.id, fixedLife);
        assert.equal(mePayload.user?.sub, fixedLife);
        assert.equal(mePayload.user?.uid, fixedLife);
      },
    );
  } finally {
    console.warn = originalWarn;
  }

  assert.equal(warnCalls.length, 1);
  assert.equal(warnCalls[0]?.[0], '⚠️ [Auth] /api/me refresh fallback');
  assert.equal((warnCalls[0]?.[1] as any)?.requestPath, '/api/me');
  assert.equal((warnCalls[0]?.[1] as any)?.failureClass, 'refresh_exception');
  assert.equal((warnCalls[0]?.[1] as any)?.sessionUidState, 'life_fallback');
  assert.equal((warnCalls[0]?.[1] as any)?.errorClass, 'Error');
  assert.equal((warnCalls[0]?.[1] as any)?.errorMessage, 'storage temporarily unavailable');
  assert.equal(typeof (warnCalls[0]?.[1] as any)?.elapsedMs, 'number');
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

test('does not serve a hosted auth frontend from the auth origin', async () => {
  await withServer({}, async ({ baseUrl }) => {
    const response = await fetch(`${baseUrl}/?origin=http%3A%2F%2Flocalhost%3A2048&mode=signup`);
    assert.equal(response.status, 410);
    assert.match(response.headers.get('content-type') || '', /application\/json/);
    const payload = await response.json() as {
      ok: boolean;
      error: string;
      message: string;
      consumerOrigin: string;
      useTheseApiSurfaces: string[];
    };
    assert.equal(payload.ok, false);
    assert.equal(payload.error, 'auth_frontend_removed');
    assert.match(payload.message, /AUTH HAS NO FRONTEND/);
    assert.equal(payload.consumerOrigin, 'http://localhost:2048');
    assert.ok(payload.useTheseApiSurfaces.includes('/api/auth/config'));
    assert.ok(payload.useTheseApiSurfaces.includes('/api/me'));
  });
});

test('hosted logout clears auth cookie and redirects to the allowed consumer logout path', async () => {
  await withServer(
    {
      config: {
        ...TEST_CONFIG,
        redirects: {
          ...TEST_CONFIG.redirects,
          postLogoutPath: '/signed-out',
        },
      },
    },
    async ({ baseUrl }) => {
      const response = await fetch(`${baseUrl}/api/auth/logout?origin=http%3A%2F%2Flocalhost%3A2048`, {
        redirect: 'manual',
      });
      assert.equal(response.status, 302);
      assert.equal(response.headers.get('location'), 'http://localhost:2048/signed-out');
      const setCookie = getSetCookies(response.headers)[0];
      assert.match(setCookie || '', /auth_sid=/);
      assert.match(setCookie || '', /Max-Age=0/);
    },
  );
});

test('hosted logout clears both host-only and configured-domain auth cookies', async () => {
  await withEnv({ AUTH_COOKIE_DOMAIN: '.thewreck.org' }, async () => {
    await withServer(
      {
        config: {
          ...TEST_CONFIG,
          redirects: {
            ...TEST_CONFIG.redirects,
            postLogoutPath: '/signed-out',
          },
        },
      },
      async ({ baseUrl }) => {
        const response = await fetch(`${baseUrl}/api/auth/logout?origin=http%3A%2F%2Flocalhost%3A2048`, {
          headers: {
            host: 'auth.thewreck.org',
            'x-forwarded-proto': 'https',
          },
          redirect: 'manual',
        });
        assert.equal(response.status, 302);
        assert.equal(response.headers.get('location'), 'http://localhost:2048/signed-out');
        const setCookies = getSetCookies(response.headers);
        assert.equal(setCookies.length, 4);
        assert.ok(setCookies.some((cookie) => /^auth_sid=/.test(cookie) && /Max-Age=0/.test(cookie) && !/Domain=/i.test(cookie)));
        assert.ok(setCookies.some((cookie) => /^auth_sid=/.test(cookie) && /Max-Age=0/.test(cookie) && /Domain=\.thewreck\.org/i.test(cookie)));
        assert.ok(setCookies.some((cookie) => /^auth_rid=/.test(cookie) && /Max-Age=0/.test(cookie) && !/Domain=/i.test(cookie)));
        assert.ok(setCookies.some((cookie) => /^auth_rid=/.test(cookie) && /Max-Age=0/.test(cookie) && /Domain=\.thewreck\.org/i.test(cookie)));
      },
    );
  });
});

test('json auth logout clears production domain auth cookie from Chatty origin behind proxy', async () => {
  await withEnv(
    {
      AUTH_COOKIE_DOMAIN: '.thewreck.org',
      AUTH_PUBLIC_ORIGIN: 'https://auth.thewreck.org',
    },
    async () => {
      await withServer(
        {
          config: {
            ...TEST_CONFIG,
            allowedOrigins: ['https://chatty.thewreck.org'],
          },
        },
        async ({ baseUrl }) => {
          const response = await fetch(`${baseUrl}/api/auth/logout`, {
            method: 'POST',
            headers: {
              host: 'auth.thewreck.org',
              Origin: 'https://chatty.thewreck.org',
            },
            redirect: 'manual',
          });

          assert.equal(response.status, 200);
          assert.equal(response.headers.get('access-control-allow-origin'), 'https://chatty.thewreck.org');
          assert.equal(response.headers.get('access-control-allow-credentials'), 'true');
          assert.equal(response.headers.get('location'), null);
          const setCookies = getSetCookies(response.headers);
          assert.equal(setCookies.length, 4);
          assert.ok(setCookies.some((cookie) => /^auth_sid=/.test(cookie) && /Max-Age=0/.test(cookie) && /Secure/i.test(cookie) && !/Domain=/i.test(cookie)));
          assert.ok(setCookies.some((cookie) => /^auth_sid=/.test(cookie) && /Max-Age=0/.test(cookie) && /Secure/i.test(cookie) && /Domain=\.thewreck\.org/i.test(cookie)));
          assert.ok(setCookies.some((cookie) => /^auth_rid=/.test(cookie) && /Max-Age=0/.test(cookie) && /Secure/i.test(cookie) && !/Domain=/i.test(cookie)));
          assert.ok(setCookies.some((cookie) => /^auth_rid=/.test(cookie) && /Max-Age=0/.test(cookie) && /Secure/i.test(cookie) && /Domain=\.thewreck\.org/i.test(cookie)));
        },
      );
    },
  );
});

test('hosted logout does not redirect to an unknown origin', async () => {
  await withServer({}, async ({ baseUrl }) => {
    const response = await fetch(`${baseUrl}/api/auth/logout?origin=https%3A%2F%2Fevil.example`, {
      redirect: 'manual',
    });
    assert.equal(response.status, 302);
    assert.equal(response.headers.get('location'), 'http://localhost:2048/');
  });
});

test('json logout endpoints clear auth cookie without hosted redirect', async () => {
  await withServer({}, async ({ baseUrl }) => {
    for (const path of ['/api/logout', '/api/auth/logout']) {
      const response = await fetch(`${baseUrl}${path}`, { method: 'POST', redirect: 'manual' });
      assert.equal(response.status, 200);
      assert.equal(response.headers.get('location'), null);
      const payload = await response.json() as { ok: boolean };
      assert.equal(payload.ok, true);
      const setCookie = getSetCookies(response.headers)[0];
      assert.match(setCookie || '', /auth_sid=/);
      assert.match(setCookie || '', /Max-Age=0/);
    }
  });
});

test('json auth logout honors allowed-origin CORS while clearing auth cookie', async () => {
  await withServer({}, async ({ baseUrl }) => {
    const response = await fetch(`${baseUrl}/api/auth/logout`, {
      method: 'POST',
      headers: {
        Origin: 'http://localhost:2048',
      },
      redirect: 'manual',
    });

    assert.equal(response.status, 200);
    assert.match(response.headers.get('content-type') || '', /application\/json/);
    assert.equal(response.headers.get('access-control-allow-origin'), 'http://localhost:2048');
    assert.equal(response.headers.get('access-control-allow-credentials'), 'true');
    assert.equal(response.headers.get('location'), null);

    const payload = await response.json() as { ok: boolean };
    assert.equal(payload.ok, true);
    const setCookie = getSetCookies(response.headers)[0];
    assert.match(setCookie || '', /auth_sid=/);
    assert.match(setCookie || '', /Max-Age=0/);
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

for (const providerId of ['google', 'github'] as const) {
test(`${providerId} returns explicit enrollment, completes consent, and links returning identity`, async () => {
  const provider: OAuthProviderClient = {
    provider: providerId,
    label: `Continue with ${providerId}`,
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

  const storage = new MemoryStorageAdapter();
  const existing = await storage.createCredentialUser({
    email: 'oauth-missing-consent@example.com', displayName: 'Existing identity',
    passwordHash: await hashPassword('secret123'),
  });
  await withServer({
    storage,
    providers: { [providerId]: provider },
    resolveLifeProfile: async () => ({ lifeUserId: 'fixture_identity', supabaseUserId: null, source: 'local_only' }),
    resolveVvaultOwnerId: async () => null,
  }, async ({ baseUrl }) => {
    const start = await fetch(`${baseUrl}/api/auth/${providerId}`, {
      headers: { Origin: 'http://localhost:2048' },
      redirect: 'manual',
    });
    assert.equal(start.status, 302);
    const location = start.headers.get('location');
    assert.ok(location);
    const state = new URL(location).searchParams.get('state');
    assert.ok(state);

    const callback = await fetch(
      `${baseUrl}/api/auth/${providerId}/callback?code=test-code&state=${encodeURIComponent(state as string)}`,
      {
        headers: { Origin: 'http://localhost:2048' },
        redirect: 'manual',
      },
    );
    assert.equal(callback.status, 403);
    assert.equal(callback.headers.get('location'), null);
    assert.match(callback.headers.get('content-type') || '', /application\/json/);
    const enrollment = await callback.json() as { state: string };
    assert.equal(enrollment.state, 'ENROLLMENT_REQUIRED');
    const setCookie = (callback.headers as any).getSetCookie?.()[0] || callback.headers.get('set-cookie');
    assert.match(setCookie || '', /auth_sid=/);
    assert.equal((await storage.findUserByEmail(existing.email))?.id, existing.id);
    assert.equal((await storage.findProviderAccount(existing.id, providerId))?.providerUserId, 'google-test-code');
    const cookie = setCookie.split(';')[0];
    const consent = await fetch(`${baseUrl}/api/auth/consent`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Cookie: cookie },
      body: JSON.stringify({ consent: { 'code:terms': true } }),
    });
    assert.equal(consent.status, 200);
    const me = await fetch(`${baseUrl}/api/me`, { headers: { Cookie: cookie } });
    assert.equal(me.status, 200);
    assert.equal((await me.json() as { user: { email: string } }).user.email, existing.email);
  });
});
}

test('OAuth callback fails closed when stored state origin no longer matches a config', async () => {
  let rejectStoredOrigin = false;
  class MutableConfigStore implements AppConfigStore {
    async getConfig(req?: any) {
      const origin = req?.query?.origin;
      if (rejectStoredOrigin && origin === 'http://localhost:2048') {
        throw new AuthConfigSelectionError('No auth app config allows the requested origin');
      }
      return TEST_CONFIG;
    }
  }

  const provider: OAuthProviderClient = {
    provider: 'google',
    label: 'Continue with Google',
    isConfigured: () => true,
    buildAuthorizationUrl: ({ state, callbackUrl }) => `https://accounts.google.test/auth?state=${encodeURIComponent(state)}&redirect_uri=${encodeURIComponent(callbackUrl)}`,
    exchangeCodeForProfile: async () => {
      throw new Error('not used');
    },
  };

  await withServer(
    {
      configStore: new MutableConfigStore(),
      providers: { google: provider },
    },
    async ({ baseUrl }) => {
      const start = await fetch(`${baseUrl}/api/auth/google`, {
        headers: { Origin: 'http://localhost:2048' },
        redirect: 'manual',
      });
      assert.equal(start.status, 302);
      const location = start.headers.get('location');
      assert.ok(location);
      const state = new URL(location).searchParams.get('state');
      assert.ok(state);

      rejectStoredOrigin = true;
      const callback = await fetch(
        `${baseUrl}/api/auth/google/callback?code=test-code&state=${encodeURIComponent(state)}`,
        { redirect: 'manual' },
      );
      assert.equal(callback.status, 403);
      const payload = await callback.json() as { ok?: boolean; error?: string };
      assert.equal(payload.ok, false);
      assert.equal(payload.error, 'AUTH_CONFIG_NOT_FOUND');
    },
  );
});

test('records consent for an authenticated session through the hosted auth surface', async () => {
  await withServer({}, async ({ baseUrl }) => {
    const register = await fetch(`${baseUrl}/api/auth/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Origin: 'http://localhost:2048',
      },
      body: JSON.stringify({
        name: 'Devon',
        email: 'consent@example.com',
        password: 'secret123',
        confirmPassword: 'secret123',
        consent: { 'code:terms': true },
      }),
    });
    assert.equal(register.status, 201);
    const setCookie = (register.headers as any).getSetCookie?.()[0] || register.headers.get('set-cookie');
    assert.ok(setCookie);

    const consent = await fetch(`${baseUrl}/api/auth/consent`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Cookie: setCookie.split(';')[0],
      },
      body: JSON.stringify({ consent: { 'code:terms': true } }),
    });
    assert.equal(consent.status, 200);
    const payload = await consent.json() as { ok: boolean; user?: { email: string } };
    assert.equal(payload.ok, true);
    assert.equal(payload.user?.email, 'consent@example.com');
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
    exchangeCodeForProfile: async () => { throw new Error('not used'); },
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
  });
});
