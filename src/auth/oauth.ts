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
};

const STATE_TTL_MS = 10 * 60 * 1000;

export class OAuthStateStore {
  private readonly pending = new Map<string, OAuthStateRecord>();

  issue(provider: string, origin: string, callbackUrl: string) {
    const state = crypto.randomBytes(18).toString('base64url');
    this.pending.set(state, { provider, origin, callbackUrl, createdAt: Date.now() });
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
    throw new Error(`OAuth token exchange failed (${response.status})`);
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

export function resolveProviderCallbackUrl(provider: string, config?: AuthAppConfig) {
  const prefix = resolveOAuthEnvPrefix(config);
  const upperProvider = provider.toUpperCase();
  const explicitCallbackUrl = firstEnvValue(candidateKeys(prefix, [
    `${upperProvider}_CALLBACK_URL`,
    `${upperProvider}_CALLBACK`,
  ]));
  if (explicitCallbackUrl) return explicitCallbackUrl;

  const callbackBase = firstEnvValue(candidateKeys(prefix, ['PUBLIC_CALLBACK_BASE']));
  if (!callbackBase) return '';

  const rawCallbackPath = firstEnvValue(candidateKeys(prefix, [
    `${upperProvider}_CALLBACK_PATH`,
    'CALLBACK_PATH',
  ])) || `/api/auth/${provider}/callback`;
  const callbackPath = adaptCallbackPathForProvider(normalizeCallbackPath(rawCallbackPath), provider);
  return `${normalizeBaseUrl(callbackBase)}${callbackPath}`;
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

export function createGoogleProviderClient(config?: AuthAppConfig): OAuthProviderClient {
  const resolve = () => resolveProviderCredentials('google', config);

  return {
    provider: 'google',
    label: 'Continue with Google',
    isConfigured: () => {
      const { clientId, clientSecret } = resolve();
      return Boolean(clientId && clientSecret);
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
