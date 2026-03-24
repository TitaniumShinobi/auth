import crypto from 'node:crypto';
import express from 'express';

import { FileAppConfigStore, getCookieName, getDbPath, getPublicOriginFallback, getSessionSecret } from './config.js';
import {
  createGoogleProviderClient,
  createGitHubProviderClient,
  OAuthStateStore,
  resolveProviderCredentials,
} from './auth/oauth.js';
import { hashPassword, validatePasswordStrength, verifyPassword } from './auth/passwords.js';
import {
  createClearCookieHeader,
  createSessionToken,
  createSetCookieHeader,
  parseCookieHeader,
  verifySessionToken,
} from './auth/session.js';
import { verifyTurnstileToken } from './auth/turnstile.js';
import { MemoryStorageAdapter } from './persistence/memoryStorage.js';
import { SqliteStorageAdapter } from './persistence/sqliteStorage.js';
import {
  isEmailInLifeRegistry as defaultIsEmailInLifeRegistry,
  resolveLifeProfile as defaultResolveLifeProfile,
  type LifeProfileResult,
  type ResolveLifeProfileInput,
} from './lifeProfile.js';
import type {
  AppConfigStore,
  AuthAppConfig,
  AuthProviderConfig,
  ConsentAcceptance,
  OAuthProviderClient,
  SessionUser,
  StoredUser,
  StorageAdapter,
  TurnstileVerifier,
} from './types.js';

const SESSION_MAX_AGE_SECONDS = 60 * 60 * 24 * 30;
const EXCHANGE_CODE_TTL_MS = 2 * 60 * 1000;

type ExchangeCodeRecord = {
  token: string;
  origin: string;
  createdAt: number;
};

function trimTrailingSlash(value: string) {
  return value.replace(/\/+$/, '');
}

function resolveRequestOrigin(req: any, config: AuthAppConfig) {
  const originHeader = typeof req.get === 'function' ? req.get('origin') : undefined;
  if (originHeader && config.allowedOrigins.includes(trimTrailingSlash(originHeader))) {
    return trimTrailingSlash(originHeader);
  }

  const refererHeader = typeof req.get === 'function' ? req.get('referer') : undefined;
  if (refererHeader) {
    try {
      const refererOrigin = new URL(refererHeader).origin;
      if (config.allowedOrigins.includes(trimTrailingSlash(refererOrigin))) {
        return trimTrailingSlash(refererOrigin);
      }
    } catch {
      // ignore invalid referer
    }
  }

  const protoHeader = typeof req.get === 'function' ? req.get('x-forwarded-proto') : undefined;
  const forwardedProto = protoHeader ? String(protoHeader).split(',')[0].trim() : '';
  const proto = forwardedProto || (req.secure ? 'https' : 'http');
  const host = typeof req.get === 'function' ? req.get('host') : undefined;
  const hostOrigin = host ? `${proto}://${host}` : getPublicOriginFallback();
  const normalizedHostOrigin = trimTrailingSlash(hostOrigin);
  if (config.allowedOrigins.includes(normalizedHostOrigin)) return normalizedHostOrigin;
  return config.allowedOrigins[0] || normalizedHostOrigin;
}

function getClientIp(req: any) {
  const forwarded = typeof req.get === 'function' ? req.get('x-forwarded-for') : '';
  return forwarded?.split(',')[0]?.trim() || req.socket?.remoteAddress || null;
}

function resolveCallbackUrl(req: any, config: AuthAppConfig, providerId: string) {
  const explicitCallback = resolveProviderCredentials(providerId, config).callbackUrl;
  if (explicitCallback) return explicitCallback;
  const origin = resolveRequestOrigin(req, config);
  return `${origin}/api/auth/${providerId}/callback`;
}

function applyCorsHeaders(req: any, res: any, config: AuthAppConfig) {
  const originHeader = typeof req.get === 'function' ? req.get('origin') : undefined;
  if (!originHeader) return false;

  const origin = trimTrailingSlash(originHeader);
  if (!config.allowedOrigins.includes(origin)) return false;

  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Vary', 'Origin');
  return true;
}

function requiredConsentDocs(config: AuthAppConfig) {
  return config.docs.filter((doc) => doc.required);
}

function buildAcceptedConsentDocs(config: AuthAppConfig, consent: Record<string, boolean>) {
  return requiredConsentDocs(config).map<ConsentAcceptance>((doc) => ({
    key: doc.key,
    version: doc.version,
    label: doc.label,
    url: doc.url,
    acceptedAt: new Date().toISOString(),
  })).filter((doc) => consent[doc.key] === true);
}

function missingRequiredConsent(config: AuthAppConfig, consent: Record<string, boolean>) {
  return requiredConsentDocs(config).find((doc) => consent[doc.key] !== true) ?? null;
}

/** User-facing copy when a Code user exists but has no password (OAuth-only). Not used for LIFE registry hint. */
function credentialLoginUnavailableMessage(authProvider: string | null | undefined): string {
  const p = String(authProvider || '').toLowerCase();
  if (p === 'google') {
    return 'This account uses Google sign-in. Use the Google button to continue.';
  }
  if (p === 'github') {
    return 'This account uses GitHub sign-in. Use the GitHub button to continue.';
  }
  return 'This account does not use email and password. Sign in with your linked sign-in provider.';
}

async function hasRequiredConsentForApp(
  storage: StorageAdapter,
  config: AuthAppConfig,
  userId: string,
) {
  const requiredKeys = requiredConsentDocs(config).map((doc) => doc.key);
  return storage.hasAcceptedConsentKeys(userId, config.app.id, requiredKeys);
}

type CreateAuthAppOptions = {
  storage?: StorageAdapter;
  configStore?: AppConfigStore;
  providers?: Record<string, OAuthProviderClient>;
  turnstileVerifier?: TurnstileVerifier;
  sessionSecret?: string;
  cookieName?: string;
  resolveLifeProfile?: (input: ResolveLifeProfileInput) => Promise<LifeProfileResult>;
  /** Override for tests; default checks Supabase `users` by email. */
  isEmailInLifeRegistry?: (email: string) => Promise<boolean>;
};

export function createDefaultStorage() {
  return process.env.AUTH_STORAGE_ADAPTER === 'memory'
    ? new MemoryStorageAdapter()
    : new SqliteStorageAdapter(getDbPath());
}

function resolveProviderClients(config: AuthAppConfig, overrides?: Record<string, OAuthProviderClient>) {
  if (overrides) return overrides;
  return {
    google: createGoogleProviderClient(config),
    github: createGitHubProviderClient(config),
  };
}

export async function createAuthApp(options: CreateAuthAppOptions = {}) {
  const storage = options.storage || createDefaultStorage();
  const configStore = options.configStore || new FileAppConfigStore();
  const turnstileVerifier = options.turnstileVerifier || verifyTurnstileToken;
  const sessionSecret = options.sessionSecret || getSessionSecret();
  const cookieName = options.cookieName || getCookieName();
  const resolveProfile = options.resolveLifeProfile ?? defaultResolveLifeProfile;
  const checkLifeRegistry = options.isEmailInLifeRegistry ?? defaultIsEmailInLifeRegistry;
  const oauthState = new OAuthStateStore();
  const exchangeCodes = new Map<string, ExchangeCodeRecord>();

  await storage.initialize();

  async function buildSessionForUser(user: StoredUser): Promise<SessionUser> {
    const resolved = await resolveProfile({
      email: user.email,
      displayName: user.displayName,
      cachedLifeUserId: user.lifeUserId,
      cachedSupabaseUserId: user.supabaseUserId,
    });
    await storage.updateUserLifeAnchors(user.id, resolved.lifeUserId, resolved.supabaseUserId);
    const uid = resolved.supabaseUserId || resolved.lifeUserId;
    return {
      id: resolved.lifeUserId,
      sub: resolved.lifeUserId,
      uid,
      email: user.email,
      name: user.displayName,
      picture: user.avatarUrl || undefined,
      auth_provider: user.authProvider,
    };
  }

  const app = express();
  app.disable('x-powered-by');
  app.use(express.json({ limit: '1mb' }));
  app.use(async (req, res, next) => {
    const config = await configStore.getConfig();
    applyCorsHeaders(req, res, config);
    if (req.method === 'OPTIONS') {
      return res.sendStatus(204);
    }
    return next();
  });

  app.get('/health', (_req, res) => {
    res.json({ ok: true, service: 'auth' });
  });

  app.get('/api/me', async (req, res) => {
    const cookies = parseCookieHeader(req.headers.cookie);
    const token = cookies[cookieName];
    if (!token) {
      return res.status(401).json({ ok: false, error: 'No active session' });
    }
    const session = verifySessionToken(token, sessionSecret);
    if (!session) {
      return res.status(401).json({ ok: false, error: 'Session expired' });
    }
    return res.json({ ok: true, user: session });
  });

  app.get('/api/auth/config', async (_req, res) => {
    const config = await configStore.getConfig();
    const providers = resolveProviderClients(config, options.providers);
    const providerStatuses: AuthProviderConfig[] = config.providers.map((provider) => {
      const client = providers[provider.provider];
      const available = provider.enabled && Boolean(client?.isConfigured());
      return {
        provider: provider.provider,
        label: provider.label,
        enabled: provider.enabled,
        available,
        reason: available ? undefined : client ? 'Provider is not configured' : 'Provider is not implemented',
      };
    });

    return res.json({
      ok: true,
      app: config.app,
      credentials: config.credentials,
      docs: config.docs,
      turnstile: config.turnstile,
      providers: providerStatuses,
    });
  });

  app.get('/api/auth/providers/:provider/status', async (req, res) => {
    const config = await configStore.getConfig();
    const providers = resolveProviderClients(config, options.providers);
    const providerId = String(req.params.provider || '').toLowerCase();
    const configuredProvider = config.providers.find((provider) => provider.provider === providerId);
    if (!configuredProvider) {
      return res.status(404).json({ ok: false, error: 'Unknown auth provider' });
    }

    const client = providers[providerId];
    const available = configuredProvider.enabled && Boolean(client?.isConfigured());
    return res.json({
      ok: true,
      provider: providerId,
      label: configuredProvider.label,
      enabled: configuredProvider.enabled,
      available,
      reason: available ? undefined : client ? 'Provider is not configured' : 'Provider is not implemented',
    });
  });

  app.post('/api/auth/login', async (req, res) => {
    const config = await configStore.getConfig();
    const email = String(req.body?.email || '').trim().toLowerCase();
    const password = String(req.body?.password || '');
    if (!email || !password) {
      return res.status(400).json({ ok: false, error: 'Email and password are required' });
    }

    const user = await storage.findUserByEmail(email);
    if (!user?.passwordHash) {
      if (!user && (await checkLifeRegistry(email))) {
        return res.status(401).json({
          ok: false,
          error:
            'This email was found in the LIFE Technology user registry. Finish Code sign-up below and your account will be connected.',
          lifeRegistryMatch: true,
        });
      }
      if (user && !user.passwordHash) {
        const authProvider = user.authProvider?.trim() || undefined;
        return res.status(401).json({
          ok: false,
          error: credentialLoginUnavailableMessage(authProvider),
          oauthOnly: true,
          credentialLoginUnavailable: true,
          ...(authProvider ? { authProvider } : {}),
        });
      }
      return res.status(401).json({ ok: false, error: 'Invalid email or password' });
    }

    const passwordOk = await verifyPassword(password, user.passwordHash);
    if (!passwordOk) {
      return res.status(401).json({ ok: false, error: 'Invalid email or password' });
    }

    const hasRequiredConsent = await hasRequiredConsentForApp(storage, config, user.id);
    if (!hasRequiredConsent) {
      return res.status(403).json({
        ok: false,
        error: `Please complete ${config.app.name} signup before continuing.`,
        requiresProductSignup: true,
      });
    }

    await storage.updateUserLogin(user.id);
    const sessionUser = await buildSessionForUser(user);
    res.setHeader('Set-Cookie', createSetCookieHeader(cookieName, createSessionToken(sessionUser, sessionSecret, SESSION_MAX_AGE_SECONDS), SESSION_MAX_AGE_SECONDS, false));
    return res.json({ ok: true, user: sessionUser });
  });

  app.post('/api/auth/register', async (req, res) => {
    const config = await configStore.getConfig();
    if (!config.credentials.enabled) {
      return res.status(403).json({ ok: false, error: 'Credential sign-up is disabled for this app' });
    }

    const name = String(req.body?.name || '').trim();
    const email = String(req.body?.email || '').trim().toLowerCase();
    const password = String(req.body?.password || '');
    const confirmPassword = String(req.body?.confirmPassword || '');
    const turnstileToken = String(req.body?.turnstileToken || '').trim();
    const consent = (req.body?.consent && typeof req.body.consent === 'object') ? req.body.consent as Record<string, boolean> : {};

    if (!name || !email || !password || !confirmPassword) {
      return res.status(400).json({ ok: false, error: 'Name, email, password, and password confirmation are required' });
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ ok: false, error: 'Enter a valid email address' });
    }
    if (password !== confirmPassword) {
      return res.status(400).json({ ok: false, error: 'Passwords do not match' });
    }
    const passwordError = validatePasswordStrength(password);
    if (passwordError) {
      return res.status(400).json({ ok: false, error: passwordError });
    }

    const missingConsent = missingRequiredConsent(config, consent);
    if (missingConsent) {
      return res.status(400).json({ ok: false, error: `Please accept ${missingConsent.label}` });
    }

    if (config.turnstile.required) {
      if (!config.turnstile.enabled) {
        return res.status(503).json({ ok: false, error: 'Turnstile is required but not configured' });
      }
      if (!turnstileToken) {
        return res.status(400).json({ ok: false, error: 'Turnstile verification is required' });
      }
      const turnstileOk = await turnstileVerifier(turnstileToken, getClientIp(req));
      if (!turnstileOk) {
        return res.status(400).json({ ok: false, error: 'Turnstile verification failed' });
      }
    }

    const existing = await storage.findUserByEmail(email);
    if (existing) {
      return res.status(409).json({ ok: false, error: 'Email already in use' });
    }

    const passwordHash = await hashPassword(password);
    const user = await storage.createCredentialUser({
      email,
      displayName: name,
      passwordHash,
    });
    await storage.replaceConsentAcceptances(user.id, config.app.id, buildAcceptedConsentDocs(config, consent));
    const sessionUser = await buildSessionForUser(user);
    res.setHeader(
      'Set-Cookie',
      createSetCookieHeader(
        cookieName,
        createSessionToken(sessionUser, sessionSecret, SESSION_MAX_AGE_SECONDS),
        SESSION_MAX_AGE_SECONDS,
        false,
      ),
    );
    return res.status(201).json({ ok: true, user: sessionUser });
  });

  const logoutHandler = (_req: any, res: any) => {
    res.setHeader('Set-Cookie', createClearCookieHeader(cookieName, false));
    return res.json({ ok: true });
  };
  app.post('/api/logout', logoutHandler);
  // Aliases for clients that expect `/api/auth/*` (matches sign-out fallbacks in Code host).
  app.post('/api/auth/logout', logoutHandler);
  app.get('/api/auth/logout', logoutHandler);

  app.get('/api/auth/set-session', async (req, res) => {
    const code = String(req.query.code || '');
    const config = await configStore.getConfig();
    const entry = exchangeCodes.get(code);
    if (!code || !entry) {
      return res.redirect(`${config.allowedOrigins[0] || getPublicOriginFallback()}${config.redirects.postLoginPath}?error=invalid_or_expired_code`);
    }
    exchangeCodes.delete(code);
    if (Date.now() - entry.createdAt > EXCHANGE_CODE_TTL_MS) {
      return res.redirect(`${entry.origin}${config.redirects.postLoginPath}?error=expired_code`);
    }
    res.setHeader('Set-Cookie', createSetCookieHeader(cookieName, entry.token, SESSION_MAX_AGE_SECONDS, false));
    return res.redirect(`${entry.origin}${config.redirects.postLoginPath}`);
  });

  app.get('/api/auth/:provider', async (req, res) => {
    const config = await configStore.getConfig();
    const providers = resolveProviderClients(config, options.providers);
    const providerId = String(req.params.provider || '').toLowerCase();
    const configuredProvider = config.providers.find((provider) => provider.provider === providerId);
    const client = providers[providerId];
    if (!configuredProvider || !configuredProvider.enabled || !client) {
      return res.status(404).json({ ok: false, error: 'Unknown auth provider' });
    }
    if (!client.isConfigured()) {
      return res.status(503).json({ ok: false, error: `${providerId} sign-in is not configured yet.` });
    }

    const origin = resolveRequestOrigin(req, config);
    const callbackUrl = resolveCallbackUrl(req, config, providerId);
    const state = oauthState.issue(providerId, origin, callbackUrl);
    return res.redirect(client.buildAuthorizationUrl({ origin, callbackUrl, state }));
  });

  app.get('/api/auth/:provider/callback', async (req, res) => {
    const config = await configStore.getConfig();
    const providers = resolveProviderClients(config, options.providers);
    const providerId = String(req.params.provider || '').toLowerCase();
    const oauthError = String(req.query.error || '');
    const code = String(req.query.code || '');
    const state = String(req.query.state || '');
    const fallbackOrigin = resolveRequestOrigin(req, config);
    if (oauthError) {
      return res.redirect(`${fallbackOrigin}${config.redirects.postLoginPath}?error=${encodeURIComponent(oauthError)}`);
    }

    const stateRecord = oauthState.consume(providerId, state);
    if (!stateRecord) {
      return res.redirect(`${fallbackOrigin}${config.redirects.postLoginPath}?error=invalid_state`);
    }
    const client = providers[providerId];
    if (!client) {
      return res.redirect(`${stateRecord.origin}${config.redirects.postLoginPath}?error=unsupported_provider`);
    }
    if (!code) {
      return res.redirect(`${stateRecord.origin}${config.redirects.postLoginPath}?error=missing_code`);
    }

    try {
      const profile = await client.exchangeCodeForProfile({
        code,
        callbackUrl: stateRecord.callbackUrl,
      });
      const user = await storage.upsertOAuthUser({
        provider: providerId,
        providerUserId: profile.providerUserId,
        email: profile.email,
        displayName: profile.displayName,
        avatarUrl: profile.avatarUrl || null,
        profile: profile.raw,
      });
      const hasRequiredConsent = await hasRequiredConsentForApp(storage, config, user.id);
      if (!hasRequiredConsent) {
        const query = new URLSearchParams({ authModal: 'signup', reason: 'missing_consent' });
        return res.redirect(`${stateRecord.origin}${config.redirects.postLoginPath}?${query.toString()}`);
      }
      await storage.updateUserLogin(user.id);
      const sessionUser = await buildSessionForUser(user);
      const sessionToken = createSessionToken(sessionUser, sessionSecret, SESSION_MAX_AGE_SECONDS);
      const callbackOrigin = new URL(stateRecord.callbackUrl).origin;
      if (callbackOrigin !== stateRecord.origin) {
        const exchangeCode = crypto.randomUUID();
        exchangeCodes.set(exchangeCode, {
          token: sessionToken,
          origin: stateRecord.origin,
          createdAt: Date.now(),
        });
        return res.redirect(`${stateRecord.origin}/api/auth/set-session?code=${encodeURIComponent(exchangeCode)}`);
      }
      res.setHeader('Set-Cookie', createSetCookieHeader(cookieName, sessionToken, SESSION_MAX_AGE_SECONDS, false));
      return res.redirect(`${stateRecord.origin}${config.redirects.postLoginPath}`);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'oauth_failed';
      return res.redirect(`${stateRecord.origin}${config.redirects.postLoginPath}?error=${encodeURIComponent(message)}`);
    }
  });

  return app;
}
