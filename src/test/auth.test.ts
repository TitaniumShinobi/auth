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

test('Ask Hydro thread resolves to the canonical per-project Hydro singleton transcript', async () => {
  const previousBaseUrl = process.env.VVAULT_API_BASE_URL;
  process.env.VVAULT_API_BASE_URL = 'https://vvault.example';
  const originalFetch = globalThis.fetch;
  const upstreamCalls: string[] = [];

  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
    if (url.startsWith('https://vvault.example')) {
      upstreamCalls.push(url);
      return new Response(JSON.stringify({
        messages: [
          {
            id: 'msg-1',
            role: 'assistant',
            content: 'Hello from Hydro.',
            timestamp: '2026-03-28T12:00:00.000Z',
            metadata: {
              modelKey: 'gpt-4o-mini',
              modelLabel: 'GPT-4o mini',
            },
          },
        ],
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }
    return originalFetch(input as any, init);
  }) as typeof fetch;

  try {
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

      const response = await fetch(`${baseUrl}/api/code/ask/thread?projectName=demo&rootPath=%2Ftmp%2Fdemo`, {
        headers: { Cookie: cookie },
      });
      assert.equal(response.status, 200);
      const payload = await response.json() as {
        id: string;
        constructId: string;
        title: string;
        storageMode: string;
      };
      assert.equal(payload.id, 'hydro-001_demo_hydro_chat');
      assert.equal(payload.constructId, 'hydro-001');
      assert.equal(payload.title, 'demo Hydro');
      assert.equal(payload.storageMode, 'canonical');
      assert.equal(
        upstreamCalls[0],
        'https://vvault.example/api/chatty/transcript/hydro-001?projectName=demo&rootPath=%2Ftmp%2Fdemo',
      );
    });
  } finally {
    globalThis.fetch = originalFetch;
    if (previousBaseUrl === undefined) {
      delete process.env.VVAULT_API_BASE_URL;
    } else {
      process.env.VVAULT_API_BASE_URL = previousBaseUrl;
    }
  }
});

test('Ask Hydro status reports canonical readiness without leaking relay errors into the UI contract', async () => {
  const previousBaseUrl = process.env.VVAULT_API_BASE_URL;
  const previousOpenAiKey = process.env.OPENAI_API_KEY;
  process.env.VVAULT_API_BASE_URL = 'https://vvault.example';
  process.env.OPENAI_API_KEY = 'test-openai-key';

  try {
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

      const response = await fetch(`${baseUrl}/api/code/ask/status?projectName=demo&rootPath=%2Ftmp%2Fdemo`, {
        headers: { Cookie: cookie },
      });
      assert.equal(response.status, 200);
      const payload = await response.json() as {
        configured: boolean;
        relayConfigured: boolean;
        openAiConfigured: boolean;
        canonicalTranscriptPath: string;
        threadId: string;
      };
      assert.equal(payload.configured, true);
      assert.equal(payload.relayConfigured, true);
      assert.equal(payload.openAiConfigured, true);
      assert.equal(payload.threadId, 'hydro-001_demo_hydro_chat');
      assert.match(payload.canonicalTranscriptPath, /\/vvault_files\/users\/shard_0000\/.+\/instances\/hydro-001\/code\/demo_hydro_chat\.md$/);
    });
  } finally {
    if (previousBaseUrl === undefined) {
      delete process.env.VVAULT_API_BASE_URL;
    } else {
      process.env.VVAULT_API_BASE_URL = previousBaseUrl;
    }
    if (previousOpenAiKey === undefined) {
      delete process.env.OPENAI_API_KEY;
    } else {
      process.env.OPENAI_API_KEY = previousOpenAiKey;
    }
  }
});

test('scratch project creation returns canonical project metadata and Ask readiness', async () => {
  const previousBaseUrl = process.env.VVAULT_API_BASE_URL;
  const previousOpenAiKey = process.env.OPENAI_API_KEY;
  process.env.VVAULT_API_BASE_URL = 'https://vvault.example';
  process.env.OPENAI_API_KEY = 'test-openai-key';
  const originalFetch = globalThis.fetch;
  const upstreamCalls: string[] = [];

  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
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
        ask: { configured: boolean; canonicalTranscriptPath: string };
      };
      assert.equal(payload.project.name, 'craft-world');
      assert.equal(payload.project.rootPath, '/workspaces/craft-world');
      assert.equal(payload.project.starterIntent, 'prototype a survival sandbox');
      assert.equal(payload.ask.configured, true);
      assert.match(payload.ask.canonicalTranscriptPath, /\/vvault_files\/users\/shard_0000\/.+\/instances\/hydro-001\/code\/craft_world_hydro_chat\.md$/);
      assert.equal(
        upstreamCalls[0],
        'https://vvault.example/api/chatty/transcript/hydro-001?projectName=craft-world&rootPath=%2Fworkspaces%2Fcraft-world',
      );
    });
  } finally {
    globalThis.fetch = originalFetch;
    if (previousBaseUrl === undefined) {
      delete process.env.VVAULT_API_BASE_URL;
    } else {
      process.env.VVAULT_API_BASE_URL = previousBaseUrl;
    }
    if (previousOpenAiKey === undefined) {
      delete process.env.OPENAI_API_KEY;
    } else {
      process.env.OPENAI_API_KEY = previousOpenAiKey;
    }
  }
});

test('Ask Hydro message relay forwards attachments, grouping metadata, and canonical transcript path', async () => {
  const previousBaseUrl = process.env.VVAULT_API_BASE_URL;
  const previousOpenAiKey = process.env.OPENAI_API_KEY;
  process.env.VVAULT_API_BASE_URL = 'https://vvault.example';
  process.env.OPENAI_API_KEY = 'test-openai-key';
  const originalFetch = globalThis.fetch;
  let openAiBody: Record<string, unknown> | null = null;
  const appendedMessages: Array<Record<string, unknown>> = [];

  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
    if (url === 'https://api.openai.com/v1/responses') {
      openAiBody = JSON.parse(String(init?.body ?? '{}')) as Record<string, unknown>;
      return new Response(JSON.stringify({
        id: 'resp_123',
        output_text: 'Hydro is here.',
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }
    if (url === 'https://vvault.example/api/chatty/transcript/hydro-001/message') {
      appendedMessages.push(JSON.parse(String(init?.body ?? '{}')) as Record<string, unknown>);
      return new Response(JSON.stringify({ success: true }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }
    if (url.startsWith('https://vvault.example/api/chatty/transcript/hydro-001')) {
      const assistantMetadata = appendedMessages.find((entry) => entry.role === 'assistant')?.metadata as Record<string, unknown> | undefined;
      return new Response(JSON.stringify({
        messages: [
          {
            id: 'msg-user-1',
            role: 'user',
            content: '<!-- hydro_message {"taskId":"task-existing","taskTitle":"Earlier request","taskKind":"regular","taskMode":"hydro","taskStartedAt":1711627200000,"taskCompleted":true,"checkpointSaved":true} -->\n### You\nhello',
            timestamp: '2026-03-28T12:00:00.000Z',
            attachments: [
              {
                id: 'att-1',
                name: 'hello.txt',
                mimeType: 'text/plain',
                size: 5,
                category: 'document',
                storagePath: 'instances/hydro-001/documents/demo_hello.txt',
              },
            ],
          },
          {
            id: 'msg-assistant-1',
            role: 'assistant',
            content: '<!-- hydro_message {"taskId":"task-existing","taskTitle":"Earlier request","taskKind":"regular","taskMode":"hydro","taskStartedAt":1711627200000,"taskCompleted":true,"checkpointSaved":true,"workDurationMs":12000} -->\n### Hydro\nHydro is here.',
            timestamp: '2026-03-28T12:00:01.000Z',
            metadata: assistantMetadata ?? {
              provider: 'openai',
              model: 'gpt-4o-mini',
              modelKey: 'gpt-4o-mini',
              modelLabel: 'GPT-4o mini',
              askMode: 'hydro',
              modeLabel: 'Hydro',
              agentLabel: 'Hydro',
            },
          },
        ],
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }
    return originalFetch(input as any, init);
  }) as typeof fetch;

  try {
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

      const response = await fetch(`${baseUrl}/api/code/ask/messages`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Cookie: cookie,
        },
        body: JSON.stringify({
          content: 'hello',
          projectName: 'demo',
          rootPath: '/tmp/demo',
          attachments: [
            {
              id: 'att-1',
              name: 'hello.txt',
              mimeType: 'text/plain',
              size: 5,
              category: 'document',
              textContent: 'hello',
            },
          ],
        }),
      });
      assert.equal(response.status, 200);
      const payload = await response.json() as {
        thread: {
          id: string;
          storageMode: string;
          messages: Array<{
            content: string;
            taskTitle?: string;
            taskKind?: string;
            checkpointSaved?: boolean;
          }>;
        };
      };
      assert.equal(payload.thread.id, 'hydro-001_demo_hydro_chat');
      assert.equal(payload.thread.storageMode, 'canonical');
      assert.equal(openAiBody?.model, 'gpt-4o-mini');
      assert.match(String(openAiBody?.instructions || ''), /Hydro/i);
      assert.equal(appendedMessages.length, 2);
      assert.equal(appendedMessages[0]?.transcriptPath, 'instances/hydro-001/code/demo_hydro_chat.md');
      assert.equal(((appendedMessages[0]?.attachments as unknown[]) || []).length, 1);
      assert.equal((appendedMessages[1]?.metadata as Record<string, unknown> | undefined)?.provider, 'openai');
      assert.equal((appendedMessages[1]?.metadata as Record<string, unknown> | undefined)?.model, 'gpt-4o-mini');
      assert.equal((appendedMessages[0]?.metadata as Record<string, unknown> | undefined)?.taskKind, 'regular');
      assert.equal(typeof (appendedMessages[0]?.metadata as Record<string, unknown> | undefined)?.taskId, 'string');
      assert.equal((appendedMessages[1]?.metadata as Record<string, unknown> | undefined)?.checkpointSaved, true);
      assert.equal(typeof (appendedMessages[1]?.metadata as Record<string, unknown> | undefined)?.workDurationMs, 'number');
      assert.equal(payload.thread.messages[0]?.content, 'hello');
      assert.equal(payload.thread.messages[1]?.content, 'Hydro is here.');
      assert.equal(payload.thread.messages[1]?.taskTitle, 'hello');
      assert.equal(payload.thread.messages[1]?.taskKind, 'regular');
      assert.equal(payload.thread.messages[1]?.checkpointSaved, true);
    });
  } finally {
    globalThis.fetch = originalFetch;
    if (previousBaseUrl === undefined) {
      delete process.env.VVAULT_API_BASE_URL;
    } else {
      process.env.VVAULT_API_BASE_URL = previousBaseUrl;
    }
    if (previousOpenAiKey === undefined) {
      delete process.env.OPENAI_API_KEY;
    } else {
      process.env.OPENAI_API_KEY = previousOpenAiKey;
    }
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
