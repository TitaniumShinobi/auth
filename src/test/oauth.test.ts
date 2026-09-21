import assert from 'node:assert/strict';
import test from 'node:test';

import type { AppConfigStore, AuthAppConfig, OAuthProviderClient } from '../types.js';
import { createAuthApp } from '../app.js';
import { createGoogleProviderClient, resolveOAuthCallbackUrl, resolveProviderCredentials } from '../auth/oauth.js';
import { MemoryStorageAdapter } from '../persistence/memoryStorage.js';

const CONFIG: AuthAppConfig = {
  app: { id: 'code', name: 'Code' },
  oauth: { envPrefix: 'CODE' },
  allowedOrigins: ['http://localhost:2048'],
  redirects: {
    postLoginPath: '/',
    postLogoutPath: '/',
  },
  credentials: { enabled: true },
  docs: [],
  turnstile: { required: false, enabled: false },
  providers: [
    { provider: 'google', label: 'Continue with Google', enabled: true },
  ],
};

class StaticConfigStore implements AppConfigStore {
  constructor(private readonly config: AuthAppConfig = CONFIG) {}

  async getConfig() {
    return this.config;
  }
}

async function withServer(
  provider: OAuthProviderClient,
  fn: (baseUrl: string) => Promise<void>,
  config: AuthAppConfig = CONFIG,
) {
  const app = await createAuthApp({
    storage: new MemoryStorageAdapter(),
    configStore: new StaticConfigStore(config),
    providers: { google: provider },
    sessionSecret: 'oauth-secret',
    cookieName: 'auth_sid',
  });

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
    await fn(`http://127.0.0.1:${address.port}`);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

test('prefers app-scoped OAuth env vars before generic shared vars', () => {
  const original = {
    CODE_GOOGLE_CLIENT_ID: process.env.CODE_GOOGLE_CLIENT_ID,
    CODE_GOOGLE_CLIENT_SECRET: process.env.CODE_GOOGLE_CLIENT_SECRET,
    CODE_GOOGLE_CALLBACK_URL: process.env.CODE_GOOGLE_CALLBACK_URL,
    GOOGLE_CLIENT_ID: process.env.GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET: process.env.GOOGLE_CLIENT_SECRET,
    GOOGLE_CALLBACK_URL: process.env.GOOGLE_CALLBACK_URL,
  };

  process.env.CODE_GOOGLE_CLIENT_ID = 'code-client';
  process.env.CODE_GOOGLE_CLIENT_SECRET = 'code-secret';
  process.env.CODE_GOOGLE_CALLBACK_URL = 'http://localhost:2048/api/auth/google/callback';
  process.env.GOOGLE_CLIENT_ID = 'shared-client';
  process.env.GOOGLE_CLIENT_SECRET = 'shared-secret';
  process.env.GOOGLE_CALLBACK_URL = 'http://localhost:5173/api/auth/google/callback';

  try {
    assert.deepEqual(resolveProviderCredentials('google', CONFIG), {
      clientId: 'code-client',
      clientSecret: 'code-secret',
      callbackUrl: 'http://localhost:2048/api/auth/google/callback',
    });
  } finally {
    for (const [key, value] of Object.entries(original)) {
      if (value === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = value;
      }
    }
  }
});

test('does not configure Google OAuth when the secret is a placeholder', () => {
  const original = {
    CODE_GOOGLE_CLIENT_ID: process.env.CODE_GOOGLE_CLIENT_ID,
    CODE_GOOGLE_CLIENT_SECRET: process.env.CODE_GOOGLE_CLIENT_SECRET,
    CODE_GOOGLE_CALLBACK_URL: process.env.CODE_GOOGLE_CALLBACK_URL,
  };

  process.env.CODE_GOOGLE_CLIENT_ID = '936875376345-s7g9j45opr1jsog24l5gpnobj0278n3c.apps.googleusercontent.com';
  process.env.CODE_GOOGLE_CLIENT_SECRET = 'abc';
  process.env.CODE_GOOGLE_CALLBACK_URL = 'http://localhost:2048/api/auth/google/callback';

  try {
    const provider = createGoogleProviderClient(CONFIG);
    assert.equal(provider.isConfigured(), false);
  } finally {
    for (const [key, value] of Object.entries(original)) {
      if (value === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = value;
      }
    }
  }
});

test('falls back to existing callback base env vars when explicit callback url is unset', () => {
  const original = {
    CODE_GOOGLE_CLIENT_ID: process.env.CODE_GOOGLE_CLIENT_ID,
    CODE_GOOGLE_CLIENT_SECRET: process.env.CODE_GOOGLE_CLIENT_SECRET,
    CODE_GOOGLE_CALLBACK_URL: process.env.CODE_GOOGLE_CALLBACK_URL,
    CODE_PUBLIC_CALLBACK_BASE: process.env.CODE_PUBLIC_CALLBACK_BASE,
    CODE_CALLBACK_PATH: process.env.CODE_CALLBACK_PATH,
    GOOGLE_CLIENT_ID: process.env.GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET: process.env.GOOGLE_CLIENT_SECRET,
    GOOGLE_CALLBACK_URL: process.env.GOOGLE_CALLBACK_URL,
    PUBLIC_CALLBACK_BASE: process.env.PUBLIC_CALLBACK_BASE,
    CALLBACK_PATH: process.env.CALLBACK_PATH,
  };

  process.env.CODE_GOOGLE_CLIENT_ID = 'code-client';
  process.env.CODE_GOOGLE_CLIENT_SECRET = 'code-secret';
  delete process.env.CODE_GOOGLE_CALLBACK_URL;
  process.env.CODE_PUBLIC_CALLBACK_BASE = 'http://localhost:2048/';
  process.env.CODE_CALLBACK_PATH = '/api/auth/google/callback';
  process.env.GOOGLE_CLIENT_ID = 'shared-client';
  process.env.GOOGLE_CLIENT_SECRET = 'shared-secret';
  process.env.GOOGLE_CALLBACK_URL = '';
  process.env.PUBLIC_CALLBACK_BASE = 'http://localhost:5050';
  process.env.CALLBACK_PATH = '/api/auth/google/callback';

  try {
    assert.deepEqual(resolveProviderCredentials('google', CONFIG), {
      clientId: 'code-client',
      clientSecret: 'code-secret',
      callbackUrl: 'http://localhost:2048/api/auth/google/callback',
    });
  } finally {
    for (const [key, value] of Object.entries(original)) {
      if (value === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = value;
      }
    }
  }
});

test('starts OAuth, completes callback, and sets a session cookie', async () => {
  const original = {
    CODE_GOOGLE_CALLBACK_URL: process.env.CODE_GOOGLE_CALLBACK_URL,
    CODE_PUBLIC_CALLBACK_BASE: process.env.CODE_PUBLIC_CALLBACK_BASE,
    CODE_CALLBACK_PATH: process.env.CODE_CALLBACK_PATH,
    GOOGLE_CALLBACK_URL: process.env.GOOGLE_CALLBACK_URL,
    PUBLIC_CALLBACK_BASE: process.env.PUBLIC_CALLBACK_BASE,
    CALLBACK_PATH: process.env.CALLBACK_PATH,
  };

  delete process.env.CODE_GOOGLE_CALLBACK_URL;
  delete process.env.CODE_PUBLIC_CALLBACK_BASE;
  delete process.env.CODE_CALLBACK_PATH;
  delete process.env.GOOGLE_CALLBACK_URL;
  delete process.env.PUBLIC_CALLBACK_BASE;
  delete process.env.CALLBACK_PATH;

  const provider: OAuthProviderClient = {
    provider: 'google',
    label: 'Continue with Google',
    isConfigured: () => true,
    buildAuthorizationUrl: ({ state, callbackUrl }) => `https://accounts.google.test/auth?state=${encodeURIComponent(state)}&redirect_uri=${encodeURIComponent(callbackUrl)}`,
    exchangeCodeForProfile: async ({ code }) => ({
      providerUserId: `google-${code}`,
      email: 'oauth@example.com',
      displayName: 'OAuth Devon',
      avatarUrl: 'https://example.com/avatar.png',
      raw: { sub: `google-${code}` },
    }),
  };

  try {
    await withServer(provider, async (baseUrl) => {
      const start = await fetch(`${baseUrl}/api/auth/google`, {
        headers: { Origin: 'http://localhost:2048' },
        redirect: 'manual',
      });
      assert.equal(start.status, 302);
      const location = start.headers.get('location');
      assert.ok(location);
      const authUrl = new URL(location);
      const state = authUrl.searchParams.get('state');
      assert.ok(state);
      assert.equal(authUrl.searchParams.get('redirect_uri'), 'http://localhost:2048/api/auth/google/callback');

      const callback = await fetch(`${baseUrl}/api/auth/google/callback?code=test-code&state=${encodeURIComponent(state)}`, {
        headers: { Origin: 'http://localhost:2048' },
        redirect: 'manual',
      });
      assert.equal(callback.status, 302);
      const callbackLocation = callback.headers.get('location');
      assert.equal(callbackLocation, 'http://localhost:2048/');
      const setCookie = (callback.headers as any).getSetCookie?.()[0] || callback.headers.get('set-cookie');
      assert.match(setCookie || '', /^auth_sid=/);
    });
  } finally {
    for (const [key, value] of Object.entries(original)) {
      if (value === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = value;
      }
    }
  }
});

test('starts OAuth with the configured callback base when legacy callback env vars are present', async () => {
  const original = {
    CODE_GOOGLE_CLIENT_ID: process.env.CODE_GOOGLE_CLIENT_ID,
    CODE_GOOGLE_CLIENT_SECRET: process.env.CODE_GOOGLE_CLIENT_SECRET,
    CODE_GOOGLE_CALLBACK_URL: process.env.CODE_GOOGLE_CALLBACK_URL,
    CODE_PUBLIC_CALLBACK_BASE: process.env.CODE_PUBLIC_CALLBACK_BASE,
    CODE_CALLBACK_PATH: process.env.CODE_CALLBACK_PATH,
  };

  process.env.CODE_GOOGLE_CLIENT_ID = 'code-client';
  process.env.CODE_GOOGLE_CLIENT_SECRET = 'code-secret';
  delete process.env.CODE_GOOGLE_CALLBACK_URL;
  process.env.CODE_PUBLIC_CALLBACK_BASE = 'http://localhost:2048';
  process.env.CODE_CALLBACK_PATH = '/api/auth/google/callback';

  const provider: OAuthProviderClient = {
    provider: 'google',
    label: 'Continue with Google',
    isConfigured: () => true,
    buildAuthorizationUrl: ({ state, callbackUrl }) => `https://accounts.google.test/auth?state=${encodeURIComponent(state)}&redirect_uri=${encodeURIComponent(callbackUrl)}`,
    exchangeCodeForProfile: async () => {
      throw new Error('not used');
    },
  };

  try {
    await withServer(provider, async (baseUrl) => {
      const start = await fetch(`${baseUrl}/api/auth/google`, {
        redirect: 'manual',
      });
      assert.equal(start.status, 302);
      const location = start.headers.get('location');
      assert.ok(location);
      const authUrl = new URL(location);
      assert.equal(authUrl.searchParams.get('redirect_uri'), 'http://localhost:2048/api/auth/google/callback');
    });
  } finally {
    for (const [key, value] of Object.entries(original)) {
      if (value === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = value;
      }
    }
  }
});

test('starts OAuth with request origin when explicit callback env points at backend origin', async () => {
  const original = {
    CODE_GOOGLE_CLIENT_ID: process.env.CODE_GOOGLE_CLIENT_ID,
    CODE_GOOGLE_CLIENT_SECRET: process.env.CODE_GOOGLE_CLIENT_SECRET,
    CODE_GOOGLE_CALLBACK_URL: process.env.CODE_GOOGLE_CALLBACK_URL,
    CODE_PUBLIC_CALLBACK_BASE: process.env.CODE_PUBLIC_CALLBACK_BASE,
    CODE_CALLBACK_PATH: process.env.CODE_CALLBACK_PATH,
  };

  process.env.CODE_GOOGLE_CLIENT_ID = 'code-client';
  process.env.CODE_GOOGLE_CLIENT_SECRET = 'code-secret';
  process.env.CODE_GOOGLE_CALLBACK_URL = 'http://localhost:8000/api/auth/google/callback';
  process.env.CODE_PUBLIC_CALLBACK_BASE = 'http://localhost:5173';
  process.env.CODE_CALLBACK_PATH = '/api/auth/google/callback';

  const provider: OAuthProviderClient = {
    provider: 'google',
    label: 'Continue with Google',
    isConfigured: () => true,
    buildAuthorizationUrl: ({ state, callbackUrl }) => `https://accounts.google.test/auth?state=${encodeURIComponent(state)}&redirect_uri=${encodeURIComponent(callbackUrl)}`,
    exchangeCodeForProfile: async () => {
      throw new Error('not used');
    },
  };

  try {
    await withServer(provider, async (baseUrl) => {
      const start = await fetch(`${baseUrl}/api/auth/google`, {
        headers: { Origin: 'http://localhost:2048' },
        redirect: 'manual',
      });
      assert.equal(start.status, 302);
      const location = start.headers.get('location');
      assert.ok(location);
      const authUrl = new URL(location);
      assert.equal(authUrl.searchParams.get('redirect_uri'), 'http://localhost:2048/api/auth/google/callback');
    });
  } finally {
    for (const [key, value] of Object.entries(original)) {
      if (value === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = value;
      }
    }
  }
});

test('starts OAuth with backend callback only when the callback origin is explicitly allowed', async () => {
  const original = {
    CODE_GOOGLE_CLIENT_ID: process.env.CODE_GOOGLE_CLIENT_ID,
    CODE_GOOGLE_CLIENT_SECRET: process.env.CODE_GOOGLE_CLIENT_SECRET,
    CODE_GOOGLE_CALLBACK_URL: process.env.CODE_GOOGLE_CALLBACK_URL,
    CODE_PUBLIC_CALLBACK_BASE: process.env.CODE_PUBLIC_CALLBACK_BASE,
    CODE_CALLBACK_PATH: process.env.CODE_CALLBACK_PATH,
  };

  process.env.CODE_GOOGLE_CLIENT_ID = 'code-client';
  process.env.CODE_GOOGLE_CLIENT_SECRET = 'code-secret';
  process.env.CODE_GOOGLE_CALLBACK_URL = 'http://localhost:8000/api/auth/google/callback';
  delete process.env.CODE_PUBLIC_CALLBACK_BASE;
  delete process.env.CODE_CALLBACK_PATH;

  const provider: OAuthProviderClient = {
    provider: 'google',
    label: 'Continue with Google',
    isConfigured: () => true,
    buildAuthorizationUrl: ({ state, callbackUrl }) => `https://accounts.google.test/auth?state=${encodeURIComponent(state)}&redirect_uri=${encodeURIComponent(callbackUrl)}`,
    exchangeCodeForProfile: async () => {
      throw new Error('not used');
    },
  };

  try {
    await withServer(
      provider,
      async (baseUrl) => {
        const start = await fetch(`${baseUrl}/api/auth/google`, {
          headers: { Origin: 'http://localhost:2048' },
          redirect: 'manual',
        });
        assert.equal(start.status, 302);
        const location = start.headers.get('location');
        assert.ok(location);
        const authUrl = new URL(location);
        assert.equal(authUrl.searchParams.get('redirect_uri'), 'http://localhost:8000/api/auth/google/callback');
      },
      {
        ...CONFIG,
        allowedOrigins: ['http://localhost:2048', 'http://localhost:8000'],
      },
    );
  } finally {
    for (const [key, value] of Object.entries(original)) {
      if (value === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = value;
      }
    }
  }
});

test('rejects OAuth start from an unknown origin instead of falling back to the hosted backend', async () => {
  const original = {
    CODE_GOOGLE_CALLBACK_URL: process.env.CODE_GOOGLE_CALLBACK_URL,
    CODE_PUBLIC_CALLBACK_BASE: process.env.CODE_PUBLIC_CALLBACK_BASE,
    GOOGLE_CALLBACK_URL: process.env.GOOGLE_CALLBACK_URL,
    PUBLIC_CALLBACK_BASE: process.env.PUBLIC_CALLBACK_BASE,
  };

  process.env.CODE_GOOGLE_CALLBACK_URL = 'http://localhost:8000/api/auth/google/callback';
  delete process.env.CODE_PUBLIC_CALLBACK_BASE;
  delete process.env.GOOGLE_CALLBACK_URL;
  delete process.env.PUBLIC_CALLBACK_BASE;

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

  try {
    await withServer(provider, async (baseUrl) => {
      const start = await fetch(`${baseUrl}/api/auth/google`, {
        headers: { Origin: 'http://localhost:7784' },
        redirect: 'manual',
      });
      assert.equal(start.status, 403);
      const payload = await start.json() as { ok?: boolean; error?: string };
      assert.equal(payload.ok, false);
      assert.equal(payload.error, 'AUTH_ORIGIN_NOT_ALLOWED');
    });
  } finally {
    for (const [key, value] of Object.entries(original)) {
      if (value === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = value;
      }
    }
  }
});

test('rejects OAuth start without origin evidence when no allowed callback is configured', async () => {
  const original = {
    CODE_GOOGLE_CALLBACK_URL: process.env.CODE_GOOGLE_CALLBACK_URL,
    CODE_PUBLIC_CALLBACK_BASE: process.env.CODE_PUBLIC_CALLBACK_BASE,
    GOOGLE_CALLBACK_URL: process.env.GOOGLE_CALLBACK_URL,
    PUBLIC_CALLBACK_BASE: process.env.PUBLIC_CALLBACK_BASE,
  };

  process.env.CODE_GOOGLE_CALLBACK_URL = 'http://localhost:8000/api/auth/google/callback';
  delete process.env.CODE_PUBLIC_CALLBACK_BASE;
  delete process.env.GOOGLE_CALLBACK_URL;
  delete process.env.PUBLIC_CALLBACK_BASE;

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

  try {
    await withServer(provider, async (baseUrl) => {
      const start = await fetch(`${baseUrl}/api/auth/google`, {
        redirect: 'manual',
      });
      assert.equal(start.status, 503);
      const payload = await start.json() as { ok?: boolean; error?: string };
      assert.equal(payload.ok, false);
      assert.equal(payload.error, 'OAUTH_CALLBACK_NOT_ALLOWED');
    });
  } finally {
    for (const [key, value] of Object.entries(original)) {
      if (value === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = value;
      }
    }
  }
});

test('callback resolver reports stale generic callback conflicts without selecting them', () => {
  const original = {
    CODE_GOOGLE_CALLBACK_URL: process.env.CODE_GOOGLE_CALLBACK_URL,
    CODE_PUBLIC_CALLBACK_BASE: process.env.CODE_PUBLIC_CALLBACK_BASE,
    GOOGLE_CALLBACK_URL: process.env.GOOGLE_CALLBACK_URL,
    PUBLIC_CALLBACK_BASE: process.env.PUBLIC_CALLBACK_BASE,
  };

  delete process.env.CODE_GOOGLE_CALLBACK_URL;
  delete process.env.CODE_PUBLIC_CALLBACK_BASE;
  process.env.GOOGLE_CALLBACK_URL = 'http://localhost:8000/api/auth/google/callback';
  process.env.PUBLIC_CALLBACK_BASE = 'http://localhost:5050';

  try {
    const resolution = resolveOAuthCallbackUrl('google', CONFIG, {
      requestOrigin: 'http://localhost:2048',
    });
    assert.equal(resolution.callbackUrl, 'http://localhost:2048/api/auth/google/callback');
    assert.equal(resolution.source, 'request_origin');
  } finally {
    for (const [key, value] of Object.entries(original)) {
      if (value === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = value;
      }
    }
  }
});

test('rejects OAuth callback with invalid state', async () => {
  const provider: OAuthProviderClient = {
    provider: 'google',
    label: 'Continue with Google',
    isConfigured: () => true,
    buildAuthorizationUrl: () => 'https://accounts.google.test/auth',
    exchangeCodeForProfile: async () => {
      throw new Error('not used');
    },
  };

  await withServer(provider, async (baseUrl) => {
    const callback = await fetch(`${baseUrl}/api/auth/google/callback?code=test-code&state=wrong`, {
      headers: { Origin: 'http://localhost:2048' },
      redirect: 'manual',
    });
    assert.equal(callback.status, 302);
    assert.equal(callback.headers.get('location'), 'http://localhost:2048/?error=invalid_state');
  });
});
