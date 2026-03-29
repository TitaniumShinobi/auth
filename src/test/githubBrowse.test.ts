import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import { rm } from 'node:fs/promises';
import test from 'node:test';

import { createAuthApp } from '../app.js';
import { decryptProviderToken, encryptProviderToken } from '../auth/providerTokens.js';
import {
  extractGitHubNextPage,
  normalizeGitHubRepoRecord,
  parseGitHubLinkHeader,
} from '../github/api.js';
import { GitHubRepoSessionStore } from '../github/repoSession.js';
import type { AppConfigStore, AuthAppConfig, OAuthProviderClient, StorageAdapter } from '../types.js';
import { MemoryStorageAdapter } from '../persistence/memoryStorage.js';
import { SqliteStorageAdapter } from '../persistence/sqliteStorage.js';
import { querySql, execSql } from '../persistence/sqliteCli.js';

const CONFIG: AuthAppConfig = {
  app: {
    id: 'code',
    name: 'Code',
  },
  oauth: {
    envPrefix: 'CODE',
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
    providers?: Record<string, OAuthProviderClient>;
    githubFetchImpl?: typeof fetch;
    githubRepoSessions?: GitHubRepoSessionStore;
    storage?: StorageAdapter;
    seedStorage?: (storage: StorageAdapter) => void | Promise<void>;
  },
  fn: (context: { baseUrl: string; registerAndGetCookie: () => Promise<string> }) => Promise<void>,
) {
  const storage = options.storage || new MemoryStorageAdapter();
  const app = await createAuthApp({
    storage,
    configStore: new StaticConfigStore(CONFIG),
    providers: options.providers,
    githubFetchImpl: options.githubFetchImpl,
    githubRepoSessions: options.githubRepoSessions,
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

  const baseUrl = `http://127.0.0.1:${address.port}`;
  const registerAndGetCookie = async () => {
    const response = await fetch(`${baseUrl}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Origin: 'http://localhost:2048' },
      body: JSON.stringify({
        name: 'Devon',
        email: 'devon@example.com',
        password: 'secret123',
        confirmPassword: 'secret123',
        consent: { 'code:terms': true },
      }),
    });
    assert.equal(response.status, 201);
    const setCookie = (response.headers as any).getSetCookie?.()[0] || response.headers.get('set-cookie');
    assert.ok(setCookie);
    return setCookie;
  };

  try {
    await fn({ baseUrl, registerAndGetCookie });
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

function withGitHubEnv(fn: () => Promise<void> | void) {
  const original = {
    CODE_GITHUB_CLIENT_ID: process.env.CODE_GITHUB_CLIENT_ID,
    CODE_GITHUB_CLIENT_SECRET: process.env.CODE_GITHUB_CLIENT_SECRET,
    CODE_GITHUB_CALLBACK_URL: process.env.CODE_GITHUB_CALLBACK_URL,
  };

  process.env.CODE_GITHUB_CLIENT_ID = 'code-github-client';
  process.env.CODE_GITHUB_CLIENT_SECRET = 'code-github-secret';
  process.env.CODE_GITHUB_CALLBACK_URL = 'http://localhost:2048/api/auth/github/callback';

  return Promise.resolve(fn()).finally(() => {
    for (const [key, value] of Object.entries(original)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  });
}

async function loginAndGetCookie(baseUrl: string, email: string, password: string) {
  const response = await fetch(`${baseUrl}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Origin: 'http://localhost:2048' },
    body: JSON.stringify({ email, password }),
  });
  assert.equal(response.status, 200);
  const setCookie = (response.headers as any).getSetCookie?.()[0] || response.headers.get('set-cookie');
  assert.ok(setCookie);
  return setCookie;
}

function createGoogleProvider(profile: {
  providerUserId?: string;
  email?: string;
  displayName?: string;
  avatarUrl?: string;
} = {}): OAuthProviderClient {
  return {
    provider: 'google',
    label: 'Continue with Google',
    isConfigured: () => true,
    buildAuthorizationUrl: ({ state, callbackUrl }) => `https://accounts.google.test/auth?state=${encodeURIComponent(state)}&redirect_uri=${encodeURIComponent(callbackUrl)}`,
    exchangeCodeForProfile: async ({ code }) => ({
      providerUserId: profile.providerUserId ?? `google-${code}`,
      email: profile.email ?? 'google-user@example.com',
      displayName: profile.displayName ?? 'Google User',
      avatarUrl: profile.avatarUrl ?? 'https://example.com/google-avatar.png',
      raw: { sub: profile.providerUserId ?? `google-${code}` },
    }),
  };
}

async function connectGitHubForCookie(baseUrl: string, cookie: string) {
  const connect = await fetch(`${baseUrl}/api/github/connect`, {
    method: 'POST',
    headers: { Cookie: cookie, Origin: 'http://localhost:2048', 'Content-Type': 'application/json' },
    body: '{}',
  });
  assert.equal(connect.status, 200);
  const connectPayload = await connect.json() as { url: string };
  const state = new URL(connectPayload.url).searchParams.get('state');
  assert.ok(state);

  const callback = await fetch(
    `${baseUrl}/api/auth/github/callback?code=test-code&state=${encodeURIComponent(state as string)}`,
    {
      headers: { Cookie: cookie, Origin: 'http://localhost:2048' },
      redirect: 'manual',
    },
  );
  assert.equal(callback.status, 302);
  assert.equal(callback.headers.get('location'), 'http://localhost:2048/');
  return callback;
}

test('github browse status returns disconnected when app session exists but github is not connected', async () => {
  await withGitHubEnv(async () => {
    await withServer({}, async ({ baseUrl, registerAndGetCookie }) => {
      const cookie = await registerAndGetCookie();
      const response = await fetch(`${baseUrl}/api/github/status`, {
        headers: { Cookie: cookie, Origin: 'http://localhost:2048' },
      });
      assert.equal(response.status, 200);
      assert.deepEqual(await response.json(), { connected: false });
    });
  });
});

test('github connect returns a repo-scope authorization url', async () => {
  await withGitHubEnv(async () => {
    await withServer({}, async ({ baseUrl, registerAndGetCookie }) => {
      const cookie = await registerAndGetCookie();
      const response = await fetch(`${baseUrl}/api/github/connect`, {
        method: 'POST',
        headers: { Cookie: cookie, Origin: 'http://localhost:2048', 'Content-Type': 'application/json' },
        body: '{}',
      });
      assert.equal(response.status, 200);
      const payload = await response.json() as { url: string };
      const authUrl = new URL(payload.url);
      assert.equal(authUrl.origin, 'https://github.com');
      assert.equal(authUrl.pathname, '/login/oauth/authorize');
      assert.equal(authUrl.searchParams.get('client_id'), 'code-github-client');
      assert.equal(authUrl.searchParams.get('redirect_uri'), 'http://localhost:2048/api/auth/github/callback');
      assert.equal(authUrl.searchParams.get('scope'), 'repo read:org');
      assert.ok(authUrl.searchParams.get('state'));
    });
  });
});

test('github repo-connect callback persists per user across logout/login and supports owners/repos/disconnect', async () => {
  await withGitHubEnv(async () => {
    const githubFetchImpl: typeof fetch = async (input, init) => {
      const url = String(input);
      if (url === 'https://github.com/login/oauth/access_token') {
        return new Response(JSON.stringify({ access_token: 'gho_test_token', scope: 'repo,read:org' }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      if (url === 'https://api.github.com/user') {
        return new Response(JSON.stringify({
          id: 42,
          login: 'TitaniumShinobi',
          name: 'Devon',
          avatar_url: 'https://example.com/avatar.png',
        }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      if (url === 'https://api.github.com/user/orgs?per_page=100') {
        return new Response(JSON.stringify([
          { login: 'code-team', avatar_url: 'https://example.com/org.png' },
        ]), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      if (url.includes('https://api.github.com/user/repos?')) {
        assert.equal(init?.headers && (init.headers as Record<string, string>).Authorization, 'Bearer gho_test_token');
        return new Response(JSON.stringify([
          {
            id: 1,
            name: 'WRECK',
            full_name: 'TitaniumShinobi/WRECK',
            private: true,
            html_url: 'https://github.com/TitaniumShinobi/WRECK',
            clone_url: 'https://github.com/TitaniumShinobi/WRECK.git',
            ssh_url: 'git@github.com:TitaniumShinobi/WRECK.git',
            default_branch: 'main',
            updated_at: '2026-03-26T12:00:00Z',
            pushed_at: '2026-03-26T12:00:00Z',
            owner: { login: 'TitaniumShinobi' },
          },
          {
            id: 2,
            name: 'demo',
            full_name: 'TitaniumShinobi/demo',
            private: false,
            html_url: 'https://github.com/TitaniumShinobi/demo',
            clone_url: 'https://github.com/TitaniumShinobi/demo.git',
            ssh_url: 'git@github.com:TitaniumShinobi/demo.git',
            default_branch: 'main',
            updated_at: '2026-03-25T12:00:00Z',
            pushed_at: '2026-03-25T12:00:00Z',
            owner: { login: 'TitaniumShinobi' },
          },
        ]), {
          status: 200,
          headers: {
            'Content-Type': 'application/json',
            link: '<https://api.github.com/user/repos?page=2>; rel="next"',
          },
        });
      }
      throw new Error(`Unexpected GitHub fetch: ${url}`);
    };

    await withServer({ githubFetchImpl }, async ({ baseUrl, registerAndGetCookie }) => {
      const cookie = await registerAndGetCookie();

      const callback = await connectGitHubForCookie(baseUrl, cookie);
      const callbackSetCookie = (callback.headers as any).getSetCookie?.()[0] || callback.headers.get('set-cookie');
      assert.equal(callbackSetCookie, null);

      const status = await fetch(`${baseUrl}/api/github/status`, {
        headers: { Cookie: cookie, Origin: 'http://localhost:2048' },
      });
      assert.equal(status.status, 200);
      assert.deepEqual(await status.json(), {
        connected: true,
        login: 'TitaniumShinobi',
        name: 'Devon',
        avatarUrl: 'https://example.com/avatar.png',
      });

      const owners = await fetch(`${baseUrl}/api/github/owners`, {
        headers: { Cookie: cookie, Origin: 'http://localhost:2048' },
      });
      assert.equal(owners.status, 200);
      assert.deepEqual(await owners.json(), [
        {
          login: 'TitaniumShinobi',
          name: 'Devon',
          avatarUrl: 'https://example.com/avatar.png',
          type: 'user',
        },
        {
          login: 'code-team',
          name: 'code-team',
          avatarUrl: 'https://example.com/org.png',
          type: 'org',
        },
      ]);

      const repos = await fetch(`${baseUrl}/api/github/repos?owner=TitaniumShinobi&query=wre&page=1&perPage=20`, {
        headers: { Cookie: cookie, Origin: 'http://localhost:2048' },
      });
      assert.equal(repos.status, 200);
      assert.deepEqual(await repos.json(), {
        repos: [
          {
            id: 1,
            name: 'WRECK',
            fullName: 'TitaniumShinobi/WRECK',
            ownerLogin: 'TitaniumShinobi',
            private: true,
            htmlUrl: 'https://github.com/TitaniumShinobi/WRECK',
            cloneUrl: 'https://github.com/TitaniumShinobi/WRECK.git',
            sshUrl: 'git@github.com:TitaniumShinobi/WRECK.git',
            defaultBranch: 'main',
            updatedAt: '2026-03-26T12:00:00Z',
            pushedAt: '2026-03-26T12:00:00Z',
          },
        ],
        nextPage: 2,
      });

      const logout = await fetch(`${baseUrl}/api/logout`, {
        method: 'POST',
        headers: { Cookie: cookie, Origin: 'http://localhost:2048' },
      });
      assert.equal(logout.status, 200);

      const reloginCookie = await loginAndGetCookie(baseUrl, 'devon@example.com', 'secret123');

      const persistedStatus = await fetch(`${baseUrl}/api/github/status`, {
        headers: { Cookie: reloginCookie, Origin: 'http://localhost:2048' },
      });
      assert.equal(persistedStatus.status, 200);
      assert.deepEqual(await persistedStatus.json(), {
        connected: true,
        login: 'TitaniumShinobi',
        name: 'Devon',
        avatarUrl: 'https://example.com/avatar.png',
      });

      const disconnect = await fetch(`${baseUrl}/api/github/disconnect`, {
        method: 'POST',
        headers: { Cookie: reloginCookie, Origin: 'http://localhost:2048', 'Content-Type': 'application/json' },
        body: '{}',
      });
      assert.equal(disconnect.status, 200);
      assert.deepEqual(await disconnect.json(), { ok: true });

      const disconnectedStatus = await fetch(`${baseUrl}/api/github/status`, {
        headers: { Cookie: reloginCookie, Origin: 'http://localhost:2048' },
      });
      assert.equal(disconnectedStatus.status, 200);
      assert.deepEqual(await disconnectedStatus.json(), { connected: false });
    });
  });
});

test('github disconnect clears repo access without changing /api/me identity', async () => {
  await withGitHubEnv(async () => {
    const githubFetchImpl: typeof fetch = async (input) => {
      const url = String(input);
      if (url === 'https://github.com/login/oauth/access_token') {
        return new Response(JSON.stringify({ access_token: 'gho_test_token', scope: 'repo,read:org' }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      if (url === 'https://api.github.com/user') {
        return new Response(JSON.stringify({
          id: 42,
          login: 'TitaniumShinobi',
          name: 'Devon',
          avatar_url: 'https://example.com/avatar.png',
        }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      if (url === 'https://api.github.com/user/orgs?per_page=100') {
        return new Response(JSON.stringify([]), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      throw new Error(`Unexpected GitHub fetch: ${url}`);
    };

    await withServer(
      {
        providers: {
          google: createGoogleProvider({
            providerUserId: 'google-session-user',
            email: 'google-user@example.com',
            displayName: 'Google User',
            avatarUrl: 'https://example.com/google-avatar.png',
          }),
        },
        githubFetchImpl,
        seedStorage: async (storage) => {
          const user = await storage.upsertOAuthUser({
            provider: 'google',
            providerUserId: 'google-session-user',
            email: 'google-user@example.com',
            displayName: 'Google User',
            avatarUrl: 'https://example.com/google-avatar.png',
            profile: {},
          });
          await storage.replaceConsentAcceptances(user.id, CONFIG.app.id, [
            {
              key: 'code:terms',
              version: '1',
              label: 'Code Terms',
              url: 'https://example.com/terms',
              acceptedAt: new Date().toISOString(),
            },
          ]);
        },
      },
      async ({ baseUrl }) => {
        const start = await fetch(`${baseUrl}/api/auth/google`, {
          headers: { Origin: 'http://localhost:2048' },
          redirect: 'manual',
        });
        assert.equal(start.status, 302);
        const startLocation = start.headers.get('location');
        assert.ok(startLocation);
        const state = new URL(startLocation).searchParams.get('state');
        assert.ok(state);

        const callback = await fetch(
          `${baseUrl}/api/auth/google/callback?code=google-code&state=${encodeURIComponent(state as string)}`,
          {
            headers: { Origin: 'http://localhost:2048' },
            redirect: 'manual',
          },
        );
        assert.equal(callback.status, 302);
        const cookie = (callback.headers as any).getSetCookie?.()[0] || callback.headers.get('set-cookie');
        assert.ok(cookie);

        const meBefore = await fetch(`${baseUrl}/api/me`, {
          headers: { Cookie: cookie, Origin: 'http://localhost:2048' },
        });
        assert.equal(meBefore.status, 200);
        const meBeforePayload = await meBefore.json();

        const repoCallback = await connectGitHubForCookie(baseUrl, cookie);
        assert.equal(repoCallback.status, 302);
        assert.equal(repoCallback.headers.get('location'), 'http://localhost:2048/');
        const repoCallbackSetCookie = (repoCallback.headers as any).getSetCookie?.()[0] || repoCallback.headers.get('set-cookie');
        assert.equal(repoCallbackSetCookie, null);

        const meAfterConnect = await fetch(`${baseUrl}/api/me`, {
          headers: { Cookie: cookie, Origin: 'http://localhost:2048' },
        });
        assert.equal(meAfterConnect.status, 200);
        assert.deepEqual(await meAfterConnect.json(), meBeforePayload);

        const disconnect = await fetch(`${baseUrl}/api/github/disconnect`, {
          method: 'POST',
          headers: { Cookie: cookie, Origin: 'http://localhost:2048', 'Content-Type': 'application/json' },
          body: '{}',
        });
        assert.equal(disconnect.status, 200);
        assert.deepEqual(await disconnect.json(), { ok: true });
        const disconnectSetCookie = (disconnect.headers as any).getSetCookie?.()[0] || disconnect.headers.get('set-cookie');
        assert.equal(disconnectSetCookie, null);

        const meAfterDisconnect = await fetch(`${baseUrl}/api/me`, {
          headers: { Cookie: cookie, Origin: 'http://localhost:2048' },
        });
        assert.equal(meAfterDisconnect.status, 200);
        assert.deepEqual(await meAfterDisconnect.json(), meBeforePayload);

        const status = await fetch(`${baseUrl}/api/github/status`, {
          headers: { Cookie: cookie, Origin: 'http://localhost:2048' },
        });
        assert.equal(status.status, 200);
        assert.deepEqual(await status.json(), { connected: false });

        const owners = await fetch(`${baseUrl}/api/github/owners`, {
          headers: { Cookie: cookie, Origin: 'http://localhost:2048' },
        });
        assert.equal(owners.status, 401);
      },
    );
  });
});

test('github connection persists across auth restart for the same user and remains user-scoped', async () => {
  await withGitHubEnv(async () => {
    const dbPath = path.join(os.tmpdir(), `auth-github-${Date.now()}-${Math.random().toString(16).slice(2)}.sqlite`);
    const githubFetchImpl: typeof fetch = async (input) => {
      const url = String(input);
      if (url === 'https://github.com/login/oauth/access_token') {
        return new Response(JSON.stringify({ access_token: 'gho_restart_token', scope: 'repo,read:org' }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      if (url === 'https://api.github.com/user') {
        return new Response(JSON.stringify({
          id: 77,
          login: 'persisted-dev',
          name: 'Persisted Devon',
          avatar_url: 'https://example.com/persisted-avatar.png',
        }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      if (url === 'https://api.github.com/user/orgs?per_page=100') {
        return new Response(JSON.stringify([]), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      throw new Error(`Unexpected GitHub fetch: ${url}`);
    };

    try {
      await withServer(
        {
          storage: new SqliteStorageAdapter(dbPath),
          githubFetchImpl,
        },
        async ({ baseUrl, registerAndGetCookie }) => {
          const cookie = await registerAndGetCookie();
          await connectGitHubForCookie(baseUrl, cookie);
        },
      );

      await withServer(
        {
          storage: new SqliteStorageAdapter(dbPath),
          githubFetchImpl,
        },
        async ({ baseUrl }) => {
          const reloginCookie = await loginAndGetCookie(baseUrl, 'devon@example.com', 'secret123');
          const persistedStatus = await fetch(`${baseUrl}/api/github/status`, {
            headers: { Cookie: reloginCookie, Origin: 'http://localhost:2048' },
          });
          assert.equal(persistedStatus.status, 200);
          assert.deepEqual(await persistedStatus.json(), {
            connected: true,
            login: 'persisted-dev',
            name: 'Persisted Devon',
            avatarUrl: 'https://example.com/persisted-avatar.png',
          });

          const otherUser = await fetch(`${baseUrl}/api/auth/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', Origin: 'http://localhost:2048' },
            body: JSON.stringify({
              name: 'Different User',
              email: 'other@example.com',
              password: 'secret123',
              confirmPassword: 'secret123',
              consent: { 'code:terms': true },
            }),
          });
          assert.equal(otherUser.status, 201);
          const otherCookie = (otherUser.headers as any).getSetCookie?.()[0] || otherUser.headers.get('set-cookie');
          assert.ok(otherCookie);

          const otherStatus = await fetch(`${baseUrl}/api/github/status`, {
            headers: { Cookie: otherCookie, Origin: 'http://localhost:2048' },
          });
          assert.equal(otherStatus.status, 200);
          assert.deepEqual(await otherStatus.json(), { connected: false });
        },
      );
    } finally {
      await rm(dbPath, { force: true }).catch(() => undefined);
      await rm(`${dbPath}-shm`, { force: true }).catch(() => undefined);
      await rm(`${dbPath}-wal`, { force: true }).catch(() => undefined);
    }
  });
});

test('revoked github tokens clear the persisted connection', async () => {
  await withGitHubEnv(async () => {
    const storage = new MemoryStorageAdapter();
    const githubFetchImpl: typeof fetch = async (input) => {
      const url = String(input);
      if (url === 'https://github.com/login/oauth/access_token') {
        return new Response(JSON.stringify({ access_token: 'gho_revoked_token', scope: 'repo,read:org' }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      if (url === 'https://api.github.com/user') {
        return new Response(JSON.stringify({
          id: 91,
          login: 'revoked-dev',
          name: 'Revoked Devon',
          avatar_url: 'https://example.com/revoked-avatar.png',
        }), {
          status: 200,
          headers: { 'Content-Type': 'application/json' },
        });
      }
      if (url === 'https://api.github.com/user/orgs?per_page=100') {
        return new Response('revoked', { status: 403 });
      }
      throw new Error(`Unexpected GitHub fetch: ${url}`);
    };

    await withServer({ storage, githubFetchImpl }, async ({ baseUrl, registerAndGetCookie }) => {
      const cookie = await registerAndGetCookie();
      await connectGitHubForCookie(baseUrl, cookie);

      const owners = await fetch(`${baseUrl}/api/github/owners`, {
        headers: { Cookie: cookie, Origin: 'http://localhost:2048' },
      });
      assert.equal(owners.status, 401);

      const status = await fetch(`${baseUrl}/api/github/status`, {
        headers: { Cookie: cookie, Origin: 'http://localhost:2048' },
      });
      assert.equal(status.status, 200);
      assert.deepEqual(await status.json(), { connected: false });

      const user = await storage.findUserByEmail('devon@example.com');
      assert.ok(user);
      const account = await storage.findProviderAccount(user.id, 'github');
      assert.ok(account);
      assert.equal(account.accessTokenEncrypted, null);
    });
  });
});

test('provider token encryption round-trips and storage keeps only encrypted values', async () => {
  const storage = new MemoryStorageAdapter();
  await storage.initialize();
  const user = await storage.createCredentialUser({
    email: 'encrypted@example.com',
    displayName: 'Encrypted User',
    passwordHash: 'hash',
  });
  const encrypted = encryptProviderToken('gho_plaintext', 'provider-secret');
  await storage.upsertProviderAccountConnection({
    userId: user.id,
    provider: 'github',
    providerUserId: '42',
    displayName: 'Encrypted User',
    avatarUrl: 'https://example.com/avatar.png',
    profile: { login: 'encrypted-user' },
    accessTokenEncrypted: encrypted,
    accessTokenScope: 'repo,read:org',
  });

  const account = await storage.findProviderAccount(user.id, 'github');
  assert.ok(account);
  assert.notEqual(account.accessTokenEncrypted, 'gho_plaintext');
  assert.equal(decryptProviderToken(account.accessTokenEncrypted as string, 'provider-secret'), 'gho_plaintext');
});

test('sqlite storage migration adds persisted github connection columns', async () => {
  const dbPath = path.join(os.tmpdir(), `auth-github-migrate-${Date.now()}-${Math.random().toString(16).slice(2)}.sqlite`);
  try {
    execSql(
      dbPath,
      `
      CREATE TABLE IF NOT EXISTS provider_accounts (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        provider TEXT NOT NULL,
        provider_user_id TEXT NOT NULL,
        email TEXT,
        display_name TEXT,
        avatar_url TEXT,
        profile_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        UNIQUE(provider, provider_user_id)
      );
      `,
    );

    const storage = new SqliteStorageAdapter(dbPath);
    await storage.initialize();
    const columns = querySql<{ name: string }>(dbPath, 'PRAGMA table_info(provider_accounts);');
    const names = new Set(columns.map((column) => column.name));
    assert.ok(names.has('access_token_encrypted'));
    assert.ok(names.has('access_token_scope'));
    assert.ok(names.has('connected_at'));
    assert.ok(names.has('connection_updated_at'));
  } finally {
    await rm(dbPath, { force: true }).catch(() => undefined);
    await rm(`${dbPath}-shm`, { force: true }).catch(() => undefined);
    await rm(`${dbPath}-wal`, { force: true }).catch(() => undefined);
  }
});

test('github helper utilities normalize pagination and repos', () => {
  assert.deepEqual(
    parseGitHubLinkHeader('<https://api.github.com/user/repos?page=2>; rel="next", <https://api.github.com/user/repos?page=4>; rel="last"'),
    {
      next: 'https://api.github.com/user/repos?page=2',
      last: 'https://api.github.com/user/repos?page=4',
    },
  );
  assert.equal(
    extractGitHubNextPage('<https://api.github.com/user/repos?page=2>; rel="next"'),
    2,
  );
  assert.deepEqual(
    normalizeGitHubRepoRecord({
      id: 7,
      name: 'wreck',
      full_name: 'TitaniumShinobi/WRECK',
      private: true,
      html_url: 'https://github.com/TitaniumShinobi/WRECK',
      clone_url: 'https://github.com/TitaniumShinobi/WRECK.git',
      ssh_url: 'git@github.com:TitaniumShinobi/WRECK.git',
      default_branch: 'main',
      updated_at: '2026-03-26T12:00:00Z',
      pushed_at: '2026-03-26T12:00:00Z',
      owner: { login: 'TitaniumShinobi' },
    }),
    {
      id: 7,
      name: 'wreck',
      fullName: 'TitaniumShinobi/WRECK',
      ownerLogin: 'TitaniumShinobi',
      private: true,
      htmlUrl: 'https://github.com/TitaniumShinobi/WRECK',
      cloneUrl: 'https://github.com/TitaniumShinobi/WRECK.git',
      sshUrl: 'git@github.com:TitaniumShinobi/WRECK.git',
      defaultBranch: 'main',
      updatedAt: '2026-03-26T12:00:00Z',
      pushedAt: '2026-03-26T12:00:00Z',
    },
  );
});
