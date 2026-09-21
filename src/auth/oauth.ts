import crypto from 'node:crypto';

import '../env.js';
import type {
  AuthAppConfig,
  OAuthExchangeContext,
  OAuthProviderClient,
  OAuthStartContext,
  ProviderProfile,
} from '../types.js';

type OAuthStateRecord = {
  origin: string;
  callbackUrl: string;
  provider: string;
  createdAt: number;
  mode: 'identity_login' | 'repo_connect';
};

const STATE_TTL_MS = 10 * 60 * 1000;

export class OAuthStateStore {
  private readonly pending = new Map<string, OAuthStateRecord>();

  issue(
    provider: string,
    origin: string,
    callbackUrl: string,
    options: { mode?: 'identity_login' | 'repo_connect' } = {},
  ) {
    const state = crypto.randomBytes(18).toString('base64url');
    this.pending.set(state, {
      provider,
      origin,
      callbackUrl,
      createdAt: Date.now(),
      mode: options.mode ?? 'identity_login',
    });
    return state;
  }

  consume(provider: string, state: string) {
    const record = this.pending.get(state);
    if (!record) return null;
    this.pending.delete(state);
    if (record.provider !== provider) return null;
    if (Date.now() - record.createdAt > STATE_TTL_MS) return null;
    return record;
  }
}

async function postForm(url: string, body: URLSearchParams) {
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Accept: 'application/json',
    },
    body,
  });
  if (!response.ok) {
    const text = await response.text();
    let providerError = '';
    try {
      const payload = JSON.parse(text) as { error?: unknown; error_description?: unknown };
      const code = typeof payload.error === 'string' ? payload.error : '';
      const description = typeof payload.error_description === 'string' ? payload.error_description : '';
      providerError = [code, description].filter(Boolean).join(': ');
    } catch {
      providerError = text.slice(0, 160);
    }
    throw new Error(
      providerError
        ? `OAuth token exchange failed (${response.status}): ${providerError}`
        : `OAuth token exchange failed (${response.status})`,
    );
  }
  return response.json() as Promise<Record<string, unknown>>;
}

async function getJson<T>(url: string, headers: Record<string, string>) {
  const response = await fetch(url, {
    headers,
  });
  if (!response.ok) {
    throw new Error(`OAuth profile fetch failed (${response.status})`);
  }
  return response.json() as Promise<T>;
}

function candidateKeys(prefix: string | undefined, suffixes: string[]) {
  const keys: string[] = [];
  if (prefix) {
    for (const suffix of suffixes) {
      keys.push(`${prefix}_${suffix}`);
    }
  }
  keys.push(...suffixes);
  return keys;
}

function firstEnvValue(keys: string[]) {
  for (const key of keys) {
    const value = process.env[key];
    if (typeof value === 'string' && value.trim()) return value.trim();
  }
  return '';
}

function firstEnvEntry(keys: string[]) {
  for (const key of keys) {
    const value = process.env[key];
    if (typeof value === 'string' && value.trim()) {
      return { key, value: value.trim() };
    }
  }
  return null;
}

function normalizeBaseUrl(value: string) {
  return value.replace(/\/+$/, '');
}

function normalizeCallbackPath(value: string) {
  if (!value) return '';
  return value.startsWith('/') ? value : `/${value}`;
}

function adaptCallbackPathForProvider(path: string, provider: string) {
  return path.replace(/\/api\/auth\/[^/]+\/callback(?=$|[?#])/i, `/api/auth/${provider}/callback`);
}

export function resolveOAuthEnvPrefix(config?: AuthAppConfig) {
  return config?.oauth?.envPrefix?.trim() || config?.app?.id?.toUpperCase?.() || '';
}

function trimTrailingSlash(value: string) {
  return value.replace(/\/+$/, '');
}

function allowedOrigins(config?: AuthAppConfig) {
  return new Set((config?.allowedOrigins || []).map(trimTrailingSlash));
}

function allowedCallbackUrl(url: string, config?: AuthAppConfig) {
  if (!url) return false;
  const allowed = allowedOrigins(config);
  if (allowed.size === 0) return false;
  try {
    return allowed.has(trimTrailingSlash(new URL(url).origin));
  } catch {
    return false;
  }
}

function callbackFromBase(provider: string, base: string, path = '') {
  const rawCallbackPath = path || `/api/auth/${provider}/callback`;
  const callbackPath = adaptCallbackPathForProvider(normalizeCallbackPath(rawCallbackPath), provider);
  return `${normalizeBaseUrl(base)}${callbackPath}`;
}

export type OAuthCallbackResolution = {
  callbackUrl: string;
  source: string;
  envKey?: string;
  conflicts: string[];
};

export function resolveOAuthCallbackUrl(
  provider: string,
  config?: AuthAppConfig,
  options: { requestOrigin?: string } = {},
): OAuthCallbackResolution {
  const prefix = resolveOAuthEnvPrefix(config);
  const upperProvider = provider.toUpperCase();

  const conflicts: string[] = [];
  const appSpecificCallback = firstEnvEntry(prefix ? [
    `${upperProvider}_CALLBACK_URL`,
    `${upperProvider}_CALLBACK`,
  ].map((suffix) => `${prefix}_${suffix}`) : []);
  if (appSpecificCallback) {
    if (allowedCallbackUrl(appSpecificCallback.value, config)) {
      return {
        callbackUrl: appSpecificCallback.value,
        source: 'app_specific_callback_env',
        envKey: appSpecificCallback.key,
        conflicts,
      };
    }
    conflicts.push(`${appSpecificCallback.key} does not match an allowed app origin`);
  }

  const appSpecificBase = firstEnvEntry(prefix ? [`${prefix}_PUBLIC_CALLBACK_BASE`] : []);
  if (appSpecificBase) {
    const appSpecificPath = firstEnvValue(prefix ? [
      `${prefix}_${upperProvider}_CALLBACK_PATH`,
      `${prefix}_CALLBACK_PATH`,
    ] : []);
    const callbackUrl = callbackFromBase(provider, appSpecificBase.value, appSpecificPath);
    if (allowedCallbackUrl(callbackUrl, config)) {
      return {
        callbackUrl,
        source: 'app_specific_public_callback_base',
        envKey: appSpecificBase.key,
        conflicts,
      };
    }
    conflicts.push(`${appSpecificBase.key} builds a callback outside allowed app origins`);
  }

  const requestOrigin = trimTrailingSlash(options.requestOrigin || '');
  if (requestOrigin && allowedOrigins(config).has(requestOrigin)) {
    return {
      callbackUrl: `${requestOrigin}/api/auth/${provider}/callback`,
      source: 'request_origin',
      conflicts,
    };
  }

  const genericCallback = firstEnvEntry([
    `${upperProvider}_CALLBACK_URL`,
    `${upperProvider}_CALLBACK`,
  ]);
  if (genericCallback) {
    if (allowedCallbackUrl(genericCallback.value, config)) {
      return {
        callbackUrl: genericCallback.value,
        source: 'generic_callback_env',
        envKey: genericCallback.key,
        conflicts,
      };
    }
    conflicts.push(`${genericCallback.key} does not match an allowed app origin`);
  }

  const genericBase = firstEnvEntry(['PUBLIC_CALLBACK_BASE']);
  if (genericBase) {
    const genericPath = firstEnvValue([
    `${upperProvider}_CALLBACK_PATH`,
    'CALLBACK_PATH',
    ]);
    const callbackUrl = callbackFromBase(provider, genericBase.value, genericPath);
    if (allowedCallbackUrl(callbackUrl, config)) {
      return {
        callbackUrl,
        source: 'generic_public_callback_base',
        envKey: genericBase.key,
        conflicts,
      };
    }
    conflicts.push(`${genericBase.key} builds a callback outside allowed app origins`);
  }

  const backendCallback = firstEnvEntry(prefix ? [
    `${prefix}_BACKEND_CALLBACK_URL`,
    `${prefix}_${upperProvider}_BACKEND_CALLBACK_URL`,
  ] : []);
  if (backendCallback) {
    if (allowedCallbackUrl(backendCallback.value, config)) {
      return {
        callbackUrl: backendCallback.value,
        source: 'backend_callback_env',
        envKey: backendCallback.key,
        conflicts,
      };
    }
    conflicts.push(`${backendCallback.key} is backend/internal and does not match an allowed app origin`);
  }

  return { callbackUrl: '', source: 'unconfigured', conflicts };
}

export function resolveProviderCallbackUrl(provider: string, config?: AuthAppConfig) {
  return resolveOAuthCallbackUrl(provider, config).callbackUrl;
}

export function resolveProviderCredentials(provider: string, config?: AuthAppConfig) {
  const prefix = resolveOAuthEnvPrefix(config);
  const upperProvider = provider.toUpperCase();
  const clientId = firstEnvValue(candidateKeys(prefix, [
    `${upperProvider}_CLIENT_ID`,
    `${upperProvider}_OAUTH_CLIENT_ID`,
  ]));
  const clientSecret = firstEnvValue(candidateKeys(prefix, [
    `${upperProvider}_CLIENT_SECRET`,
    `${upperProvider}_OAUTH_CLIENT_SECRET`,
  ]));
  const callbackUrl = resolveProviderCallbackUrl(provider, config);
  return { clientId, clientSecret, callbackUrl };
}

function hasUsableGoogleCredentials(clientId: string, clientSecret: string) {
  const normalizedClientId = clientId.trim();
  const normalizedClientSecret = clientSecret.trim();
  return (
    normalizedClientId.endsWith('.apps.googleusercontent.com')
    && normalizedClientSecret.startsWith('GOCSPX-')
    && normalizedClientSecret.length >= 30
  );
}

export function resolveProviderCredentialEnv(provider: string, config?: AuthAppConfig) {
  const prefix = resolveOAuthEnvPrefix(config);
  const upperProvider = provider.toUpperCase();
  const clientId = firstEnvEntry(candidateKeys(prefix, [
    `${upperProvider}_CLIENT_ID`,
    `${upperProvider}_OAUTH_CLIENT_ID`,
  ]));
  const clientSecret = firstEnvEntry(candidateKeys(prefix, [
    `${upperProvider}_CLIENT_SECRET`,
    `${upperProvider}_OAUTH_CLIENT_SECRET`,
  ]));
  const callback = resolveOAuthCallbackUrl(provider, config);
  return {
    clientId: { present: Boolean(clientId), key: clientId?.key },
    clientSecret: { present: Boolean(clientSecret), key: clientSecret?.key },
    callback: {
      present: Boolean(callback.callbackUrl),
      source: callback.source,
      envKey: callback.envKey,
    },
  };
}

export function createGoogleProviderClient(config?: AuthAppConfig): OAuthProviderClient {
  const resolve = () => resolveProviderCredentials('google', config);

  return {
    provider: 'google',
    label: 'Continue with Google',
    isConfigured: () => {
      const { clientId, clientSecret } = resolve();
      return hasUsableGoogleCredentials(clientId, clientSecret);
    },
    buildAuthorizationUrl: ({ callbackUrl, state }: OAuthStartContext) => {
      const { clientId } = resolve();
      const url = new URL('https://accounts.google.com/o/oauth2/v2/auth');
      url.searchParams.set('client_id', clientId);
      url.searchParams.set('redirect_uri', callbackUrl);
      url.searchParams.set('response_type', 'code');
      url.searchParams.set('scope', 'openid email profile');
      url.searchParams.set('state', state);
      url.searchParams.set('access_type', 'offline');
      url.searchParams.set('include_granted_scopes', 'true');
      return url.toString();
    },
    exchangeCodeForProfile: async ({ code, callbackUrl }: OAuthExchangeContext): Promise<ProviderProfile> => {
      const { clientId, clientSecret } = resolve();
      const tokenPayload = await postForm(
        'https://oauth2.googleapis.com/token',
        new URLSearchParams({
          client_id: clientId,
          client_secret: clientSecret,
          code,
          redirect_uri: callbackUrl,
          grant_type: 'authorization_code',
        }),
      );
      const accessToken = typeof tokenPayload.access_token === 'string' ? tokenPayload.access_token : '';
      if (!accessToken) throw new Error('Google OAuth did not return an access token');
      const profile = await getJson<Record<string, unknown>>(
        'https://www.googleapis.com/oauth2/v3/userinfo',
        { Authorization: `Bearer ${accessToken}` },
      );
      if (typeof profile.sub !== 'string' || typeof profile.email !== 'string') {
        throw new Error('Google OAuth profile is missing required identity fields');
      }
      return {
        providerUserId: profile.sub,
        email: profile.email,
        displayName: typeof profile.name === 'string' ? profile.name : profile.email,
        avatarUrl: typeof profile.picture === 'string' ? profile.picture : undefined,
        raw: profile,
      };
    },
  };
}

export function createGitHubProviderClient(config?: AuthAppConfig): OAuthProviderClient {
  const resolve = () => resolveProviderCredentials('github', config);

  return {
    provider: 'github',
    label: 'Continue with GitHub',
    isConfigured: () => {
      const { clientId, clientSecret } = resolve();
      return Boolean(clientId && clientSecret);
    },
    buildAuthorizationUrl: ({ callbackUrl, state }: OAuthStartContext) => {
      const { clientId } = resolve();
      const url = new URL('https://github.com/login/oauth/authorize');
      url.searchParams.set('client_id', clientId);
      url.searchParams.set('redirect_uri', callbackUrl);
      url.searchParams.set('scope', 'read:user user:email');
      url.searchParams.set('state', state);
      return url.toString();
    },
    exchangeCodeForProfile: async ({ code, callbackUrl }: OAuthExchangeContext): Promise<ProviderProfile> => {
      const { clientId, clientSecret } = resolve();
      const tokenPayload = await postForm(
        'https://github.com/login/oauth/access_token',
        new URLSearchParams({
          client_id: clientId,
          client_secret: clientSecret,
          code,
          redirect_uri: callbackUrl,
        }),
      );
      const accessToken = typeof tokenPayload.access_token === 'string' ? tokenPayload.access_token : '';
      if (!accessToken) throw new Error('GitHub OAuth did not return an access token');
      const profile = await getJson<Record<string, unknown>>(
        'https://api.github.com/user',
        {
          Authorization: `Bearer ${accessToken}`,
          Accept: 'application/vnd.github+json',
          'User-Agent': 'quantum-auth',
        },
      );
      const emails = await getJson<Array<Record<string, unknown>>>(
        'https://api.github.com/user/emails',
        {
          Authorization: `Bearer ${accessToken}`,
          Accept: 'application/vnd.github+json',
          'User-Agent': 'quantum-auth',
        },
      );
      const primaryEmail = emails.find((entry) => entry.primary === true && typeof entry.email === 'string')
        || emails.find((entry) => typeof entry.email === 'string');
      if (typeof profile.id !== 'number' || typeof primaryEmail?.email !== 'string') {
        throw new Error('GitHub OAuth profile is missing a verified email');
      }
      return {
        providerUserId: String(profile.id),
        email: primaryEmail.email,
        displayName: typeof profile.name === 'string'
          ? profile.name
          : typeof profile.login === 'string'
            ? profile.login
            : primaryEmail.email,
        avatarUrl: typeof profile.avatar_url === 'string' ? profile.avatar_url : undefined,
        raw: {
          profile,
          emails,
        },
      };
    },
  };
}
