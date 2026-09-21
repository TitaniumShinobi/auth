import crypto from 'node:crypto';

import '../env.js';
import type { VerifiedProviderIdentity } from './canonicalOwner.js';
import type {
  AuthAppConfig,
  AuthProviderDefinition,
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

export type ProviderAdapterOptions = {
  env?: Record<string, string | undefined>;
  fetchImpl?: typeof fetch;
};

export const BUILTIN_PROVIDER_IDS = ['google', 'github', 'microsoft'] as const;
export const IDENTITY_CAPABLE_PROVIDER_IDS = new Set<string>([...BUILTIN_PROVIDER_IDS, 'email']);

/** Authentication/account-link providers recognized by AUTH that have no built-in adapter yet. */
export const RECOGNIZED_PROVIDER_IDS = new Set<string>(['apple']);

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

async function postForm(url: string, body: URLSearchParams, fetchImpl: typeof fetch = fetch.bind(globalThis)) {
  const response = await fetchImpl(url, {
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

async function getJson<T>(url: string, headers: Record<string, string>, fetchImpl: typeof fetch = fetch.bind(globalThis)) {
  const response = await fetchImpl(url, {
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

function envSource(options?: ProviderAdapterOptions): Record<string, string | undefined> {
  return options?.env ?? process.env;
}

function firstEnvValue(keys: string[], options?: ProviderAdapterOptions) {
  const env = envSource(options);
  for (const key of keys) {
    const value = env[key];
    if (typeof value === 'string' && value.trim()) return value.trim();
  }
  return '';
}

function firstEnvEntry(keys: string[], options?: ProviderAdapterOptions) {
  const env = envSource(options);
  for (const key of keys) {
    const value = env[key];
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
  const configuredCallbackUrl = config?.providers
    .find((candidate) => candidate.provider.toLowerCase() === provider.toLowerCase())
    ?.callbackUrl;
  if (configuredCallbackUrl) {
    if (allowedCallbackUrl(configuredCallbackUrl, config)) {
      return { callbackUrl: configuredCallbackUrl, source: 'app_config', conflicts };
    }
    conflicts.push('Configured provider callback does not match an allowed app origin');
  }

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

export function resolveProviderCredentials(provider: string, config?: AuthAppConfig, options: ProviderAdapterOptions = {}) {
  const prefix = resolveOAuthEnvPrefix(config);
  const upperProvider = provider.toUpperCase();
  const clientId = firstEnvValue(candidateKeys(prefix, [
    `${upperProvider}_CLIENT_ID`,
    `${upperProvider}_OAUTH_CLIENT_ID`,
  ]), options);
  const clientSecret = firstEnvValue(candidateKeys(prefix, [
    `${upperProvider}_CLIENT_SECRET`,
    `${upperProvider}_OAUTH_CLIENT_SECRET`,
  ]), options);
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

export function createGoogleProviderClient(config?: AuthAppConfig, options: ProviderAdapterOptions = {}): OAuthProviderClient {
  const fetchImpl = options.fetchImpl ?? fetch.bind(globalThis);
  const resolve = () => resolveProviderCredentials('google', config, options);

  return {
    provider: 'google',
    label: 'Continue with Google',
    issuer: 'https://accounts.google.com',
    identityCapable: true,
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
        fetchImpl,
      );
      const accessToken = typeof tokenPayload.access_token === 'string' ? tokenPayload.access_token : '';
      if (!accessToken) throw new Error('Google OAuth did not return an access token');
      const profile = await getJson<Record<string, unknown>>(
        'https://www.googleapis.com/oauth2/v3/userinfo',
        { Authorization: `Bearer ${accessToken}` },
        fetchImpl,
      );
      if (typeof profile.sub !== 'string' || typeof profile.email !== 'string') {
        throw new Error('Google OAuth profile is missing required identity fields');
      }
      return {
        providerUserId: profile.sub,
        email: profile.email,
        displayName: typeof profile.name === 'string' ? profile.name : profile.email,
        ...(profile.email_verified === true ? { emailVerified: true } : {}),
        avatarUrl: typeof profile.picture === 'string' ? profile.picture : undefined,
        raw: profile,
      };
    },
  };
}

export function createGitHubProviderClient(config?: AuthAppConfig, options: ProviderAdapterOptions = {}): OAuthProviderClient {
  const fetchImpl = options.fetchImpl ?? fetch.bind(globalThis);
  const resolve = () => resolveProviderCredentials('github', config, options);

  return {
    provider: 'github',
    label: 'Continue with GitHub',
    issuer: 'https://github.com',
    identityCapable: true,
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
        fetchImpl,
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
        fetchImpl,
      );
      const emails = await getJson<Array<Record<string, unknown>>>(
        'https://api.github.com/user/emails',
        {
          Authorization: `Bearer ${accessToken}`,
          Accept: 'application/vnd.github+json',
          'User-Agent': 'quantum-auth',
        },
        fetchImpl,
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
        emailVerified: true,
        avatarUrl: typeof profile.avatar_url === 'string' ? profile.avatar_url : undefined,
        raw: {
          profile,
          emails,
        },
      };
    },
  };
}

const MICROSOFT_DEFAULT_AUTHORITY = 'https://login.microsoftonline.com/common';
/** Entra multi-tenant (common) is the canonical identity issuer AUTH recognizes for Microsoft. */
export const MICROSOFT_IDENTITY_ISSUER = `${MICROSOFT_DEFAULT_AUTHORITY}/oauth2/v2.0`;
const MICROSOFT_AVATAR_MAX_BYTES = 24 * 1024;

const KNOWN_IDENTITY_ISSUERS: Record<string, string> = {
  google: 'https://accounts.google.com',
  github: 'https://github.com',
  microsoft: MICROSOFT_IDENTITY_ISSUER,
};

function isUsableCredential(value: string) {
  const normalized = value.trim();
  return Boolean(normalized) && !normalized.startsWith('<');
}

async function fetchMicrosoftAvatar(
  accessToken: string,
  fetchImpl: typeof fetch = fetch.bind(globalThis),
): Promise<string | undefined> {
  try {
    const response = await fetchImpl('https://graph.microsoft.com/v1.0/me/photo/$value', {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    if (!response.ok) return undefined;
    const contentType = response.headers.get('content-type') || '';
    if (!contentType.toLowerCase().startsWith('image/')) return undefined;
    const buffer = Buffer.from(await response.arrayBuffer());
    if (buffer.byteLength === 0 || buffer.byteLength > MICROSOFT_AVATAR_MAX_BYTES) return undefined;
    return `data:${contentType};base64,${buffer.toString('base64')}`;
  } catch {
    return undefined;
  }
}

export function createMicrosoftProviderClient(
  config?: AuthAppConfig,
  options: ProviderAdapterOptions = {},
): OAuthProviderClient {
  const fetchImpl = options.fetchImpl ?? fetch.bind(globalThis);
  const resolve = () => ({
    ...resolveProviderCredentials('microsoft', config, options),
    authority: firstEnvValue(['MICROSOFT_AUTHORITY', `${(resolveOAuthEnvPrefix(config) || 'AUTH').toUpperCase()}_MICROSOFT_AUTHORITY`], options) || MICROSOFT_DEFAULT_AUTHORITY,
  });

  return {
    provider: 'microsoft',
    label: 'Continue with Microsoft',
    issuer: MICROSOFT_IDENTITY_ISSUER,
    identityCapable: true,
    isConfigured: () => {
      const { clientId, clientSecret } = resolve();
      return isUsableCredential(clientId) && isUsableCredential(clientSecret);
    },
    buildAuthorizationUrl: ({ callbackUrl, state }: OAuthStartContext) => {
      const { clientId, authority } = resolve();
      const url = new URL(`${authority.replace(/\/+$/, '')}/oauth2/v2.0/authorize`);
      url.searchParams.set('client_id', clientId);
      url.searchParams.set('redirect_uri', callbackUrl);
      url.searchParams.set('response_type', 'code');
      url.searchParams.set('scope', 'openid email profile');
      url.searchParams.set('state', state);
      url.searchParams.set('prompt', 'select_account');
      return url.toString();
    },
    exchangeCodeForProfile: async ({ code, callbackUrl }: OAuthExchangeContext): Promise<ProviderProfile> => {
      const { clientId, clientSecret, authority } = resolve();
      const tokenPayload = await postForm(
        `${authority.replace(/\/+$/, '')}/oauth2/v2.0/token`,
        new URLSearchParams({
          client_id: clientId,
          client_secret: clientSecret,
          code,
          redirect_uri: callbackUrl,
          grant_type: 'authorization_code',
        }),
        fetchImpl,
      );
      const accessToken = typeof tokenPayload.access_token === 'string' ? tokenPayload.access_token : '';
      if (!accessToken) throw new Error('Microsoft OAuth did not return an access token');
      const profile = await getJson<Record<string, unknown>>(
        'https://graph.microsoft.com/v1.0/me',
        { Authorization: `Bearer ${accessToken}` },
        fetchImpl,
      );
      if (typeof profile.id !== 'string' || !profile.id) {
        throw new Error('Microsoft OAuth profile is missing required identity fields');
      }
      const otherMails = Array.isArray(profile.otherMails) ? profile.otherMails : [];
      const authoritativeEmail = typeof profile.mail === 'string'
        ? profile.mail
        : otherMails.find((entry): entry is string => typeof entry === 'string');
      const upn = typeof profile.userPrincipalName === 'string' ? profile.userPrincipalName : '';
      const email = authoritativeEmail || (upn.includes('@') ? upn : '');
      if (!email) throw new Error('Microsoft OAuth profile is missing a verified email');
      const givenName = typeof profile.givenName === 'string' ? profile.givenName : '';
      const surname = typeof profile.surname === 'string' ? profile.surname : '';
      const displayName = typeof profile.displayName === 'string' && profile.displayName
        ? profile.displayName
        : [givenName, surname].filter(Boolean).join(' ') || email.split('@')[0];
      const avatarUrl = await fetchMicrosoftAvatar(accessToken, fetchImpl);
      return {
        providerUserId: profile.id,
        email,
        displayName,
        emailVerified: true,
        avatarUrl,
        raw: { ...profile, avatarPresent: avatarUrl ? true : undefined },
      };
    },
  };
}

const DEFAULT_PROFILE_MAP = {
  subject: 'sub',
  email: 'email',
  displayName: 'name',
  avatarUrl: 'picture',
  emailVerified: 'email_verified',
};

export function createConfiguredIdentityProviderClient(
  config: AuthAppConfig | undefined,
  definition: AuthProviderDefinition,
  options: ProviderAdapterOptions = {},
): OAuthProviderClient {
  const fetchImpl = options.fetchImpl ?? fetch.bind(globalThis);
  const resolve = () => {
    const prefix = resolveOAuthEnvPrefix(config);
    const upperProvider = definition.provider.toUpperCase();
    const clientId = firstEnvValue(definition.clientIdEnv
      ? [definition.clientIdEnv]
      : candidateKeys(prefix, [`${upperProvider}_CLIENT_ID`, `${upperProvider}_OAUTH_CLIENT_ID`]), options);
    const clientSecret = firstEnvValue(definition.clientSecretEnv
      ? [definition.clientSecretEnv]
      : candidateKeys(prefix, [`${upperProvider}_CLIENT_SECRET`, `${upperProvider}_OAUTH_CLIENT_SECRET`]), options);
    const callbackUrl = resolveProviderCallbackUrl(definition.provider, config);
    return { clientId, clientSecret, callbackUrl };
  };
  const scopes = definition.scopes?.join(' ') || 'openid profile email';
  const prompt = definition.prompt || 'select_account';
  const identityCapable = definition.identityCapable === true;
  const profileMap = { ...DEFAULT_PROFILE_MAP, ...(definition.profileMap || {}) };

  return {
    provider: definition.provider,
    label: definition.label,
    identityCapable,
    isConfigured: () => {
      const { clientId, clientSecret } = resolve();
      return isUsableCredential(clientId) && isUsableCredential(clientSecret);
    },
    buildAuthorizationUrl: ({ callbackUrl, state }: OAuthStartContext) => {
      if (!definition.authorizationEndpoint) throw new Error(`${definition.provider} provider authorization endpoint is not configured`);
      const { clientId } = resolve();
      const url = new URL(definition.authorizationEndpoint);
      url.searchParams.set('client_id', clientId);
      url.searchParams.set('redirect_uri', callbackUrl);
      url.searchParams.set('response_type', 'code');
      url.searchParams.set('scope', scopes);
      url.searchParams.set('state', state);
      if (prompt) url.searchParams.set('prompt', prompt);
      if (definition.type === 'oidc') url.searchParams.set('nonce', crypto.randomBytes(12).toString('base64url'));
      return url.toString();
    },
    exchangeCodeForProfile: async ({ code, callbackUrl }: OAuthExchangeContext): Promise<ProviderProfile> => {
      if (!definition.tokenEndpoint) throw new Error(`${definition.provider} provider token endpoint is not configured`);
      if (!definition.userinfoEndpoint) throw new Error(`${definition.provider} provider userinfo endpoint is not configured`);
      const { clientId, clientSecret } = resolve();
      const tokenPayload = await postForm(
        definition.tokenEndpoint,
        new URLSearchParams({
          client_id: clientId,
          client_secret: clientSecret,
          code,
          redirect_uri: callbackUrl,
          grant_type: 'authorization_code',
          ...(scopes ? { scope: scopes } : {}),
        }),
        fetchImpl,
      );
      const accessToken = typeof tokenPayload.access_token === 'string' ? tokenPayload.access_token : '';
      if (!accessToken) throw new Error(`${definition.provider} OAuth did not return an access token`);
      const claims = await getJson<Record<string, unknown>>(
        definition.userinfoEndpoint,
        { Authorization: `Bearer ${accessToken}` },
        fetchImpl,
      );
      const subject = claims[profileMap.subject];
      const email = claims[profileMap.email];
      if (typeof subject !== 'string' || !subject || typeof email !== 'string' || !email) {
        throw new Error(`${definition.provider} OAuth profile is missing required identity fields`);
      }
      const displayName = typeof claims[profileMap.displayName] === 'string'
        ? (claims[profileMap.displayName] as string)
        : email.split('@')[0];
      const avatarUrl = typeof claims[profileMap.avatarUrl] === 'string'
        ? (claims[profileMap.avatarUrl] as string)
        : undefined;
      const emailVerified = claims[profileMap.emailVerified] === true;
      return {
        providerUserId: subject,
        email,
        displayName,
        ...(emailVerified ? { emailVerified: true } : {}),
        avatarUrl,
        raw: claims,
      };
    },
  };
}

/**
 * AUTH-owned provider registry.
 *
 * - Every built-in adapter (google/github/microsoft) is always available as a
 *   client; app config `providers[].enabled` decides expose/availability.
 * - Any config-declared `type: 'oauth2' | 'oidc'` provider gets a generic
 *   adapter and is treated as an account-link/login provider that NEVER
 *   establishes a primary LIFE identity (identityCapable requires a vetted
 *   built-in adapter). This keeps the identity authority boundary intact.
 * - Tests override the whole map via `options.providers`.
 */
export function createProviderClients(
  config: AuthAppConfig | undefined,
  options: ProviderAdapterOptions = {},
): Record<string, OAuthProviderClient> {
  const clients: Record<string, OAuthProviderClient> = {};
  for (const definition of config?.providers || []) {
    if (!definition?.provider) continue;
    if (definition.type === 'oauth2' || definition.type === 'oidc') {
      clients[definition.provider] = createConfiguredIdentityProviderClient(config, definition, options);
    }
  }
  for (const provider of BUILTIN_PROVIDER_IDS) {
    if (!clients[provider]) {
      clients[provider] = (provider === 'microsoft'
        ? createMicrosoftProviderClient(config, options)
        : provider === 'github'
          ? createGitHubProviderClient(config, options)
          : createGoogleProviderClient(config, options));
    }
  }
  return clients;
}

/**
 * Derives the AUTH-verified identity proof for a completed OAuth exchange.
 * Identity-capable built-in providers always yield subject+issuer (the code
 * exchange already proves them); `verifiedEmail` is only attached when the
 * provider authoritatively verified the mailbox and the identity chain is
 * allowed to carry one. Generic configured providers return undefined and
 * therefore cannot fabricate a LIFE identity.
 */
export function createVerifiedProviderIdentity(
  client: OAuthProviderClient,
  profile: ProviderProfile,
): VerifiedProviderIdentity | undefined {
  if (client.identityCapable === false) return undefined;
  const identityProviders = new Set(IDENTITY_CAPABLE_PROVIDER_IDS);
  if (!identityProviders.has(client.provider)) return undefined;
  const issuer = KNOWN_IDENTITY_ISSUERS[client.provider] || client.issuer || '';
  const verifiedEmail = profile.emailVerified === true && !['github'].includes(client.provider)
    ? profile.email
    : undefined;
  return {
    provider: client.provider as VerifiedProviderIdentity['provider'],
    subject: profile.providerUserId,
    issuer,
    ...(verifiedEmail ? { verifiedEmail } : {}),
  };
}
