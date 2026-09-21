import { verifyVvaultSessionProof, verifyChattyConsentManifest } from './auth/vvaultSessionFederation.js';
import { createEnrollmentConsent } from './auth/enrollmentConsent.js';
import { mountEnrollmentHost } from './auth/enrollmentHost.js';
import { renderHostedAuthorizationPage } from './auth/hostedAuthorizationPage.js';
import crypto from 'node:crypto';
import path from 'node:path';
import express from 'express';
import { createPostalMagicDelivery, sendMagicChallenge, consumeMagicChallenge, type MagicEmailDelivery } from './auth/magicEmail.js';

import {
  AuthConfigSelectionError,
  FileAppConfigStore,
  getCookieName,
  getDbPath,
  getProviderTokenSecret,
  getPublicOriginFallback,
  getRefreshCookieName,
  getSessionSecret,
} from './config.js';
import {
  createGoogleProviderClient,
  createGitHubProviderClient,
  resolveOAuthCallbackUrl,
  resolveProviderCredentialEnv,
  resolveProviderCredentials,
} from './auth/oauth.js';
import {
  buildGitHubAuthorizationUrl,
  exchangeGitHubCodeForAccessToken,
  fetchGitHubViewer,
  listGitHubOwners,
  listGitHubRepos,
  resolveGitHubOAuthCredentials,
} from './github/api.js';
import { decryptProviderToken, encryptProviderToken } from './auth/providerTokens.js';
import { GitHubRepoSessionStore } from './github/repoSession.js';
import { hashPassword, validatePasswordStrength, verifyPassword } from './auth/passwords.js';
import {
  createClearCookieHeader,
  createSetCookieHeader,
  parseCookieHeader,
} from './auth/session.js';
import {
  accountContextProfileForSession,
  createAccountContextAssertion,
  resolveAccountContextAssertionConfig,
} from './auth/accountContextAssertion.js';
import {
  createVvaultAccessAssertion,
  resolveVvaultAccessAssertionConfig,
} from './auth/vvaultAccessAssertion.js';
import {
  createAccessToken,
  createRefreshToken,
  hashRefreshToken,
  hashRequestMetadata,
  resolveJwtTokenConfig,
  verifyAccessToken,
  verifyRefreshToken,
  type JwtTokenConfig,
} from './auth/jwtTokens.js';
import {
  createDefaultEphemeralAuthStore,
  type EphemeralAuthStore,
} from './auth/ephemeralStore.js';
import {
  MemoryRefreshTokenStore,
  PostgresRefreshTokenStore,
  type RefreshTokenStore,
} from './auth/refreshTokenStore.js';
import { createPostgrestJwt } from './auth/postgrestJwt.js';
import { verifyTurnstileToken } from './auth/turnstile.js';
import {
  AUTHORIZATION_CODE_TTL_SECONDS,
  AUTHORIZATION_REQUEST_TTL_SECONDS,
  appendAuthorizationResult,
  findPublicClient,
  isValidOpaqueState,
  isValidS256Challenge,
  validateRedirectUri,
  verifyS256,
  type AuthorizationCodeRecord,
  type AuthorizationRequestRecord,
} from './auth/authorizationCode.js';
import {
  FEDERATION_ASSERTION_TTL_SECONDS,
  isValidProductSessionFederationSecret,
  validateProductSessionAssertion,
  verifyProductSessionAssertionSignature,
  type ProductSessionAssertionInput,
  type ProductSessionAssertionRecord,
} from './auth/productSessionFederation.js';
import { MemoryStorageAdapter } from './persistence/memoryStorage.js';
import { resolveCanonicalOwner, type VerifiedProviderIdentity } from './auth/canonicalOwner.js';
import { getAuthPrismaClient, getCanonicalOwnerPrismaClient } from './persistence/prismaClient.js';
import { PostgresStorageAdapter } from './persistence/postgresStorage.js';
import { SqliteStorageAdapter } from './persistence/sqliteStorage.js';
import { logAuthApiMeIdentityDiagnostics } from './identityDiagnostics.js';
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

const EXCHANGE_CODE_TTL_MS = 2 * 60 * 1000;
const OAUTH_STATE_TTL_MS = 10 * 60 * 1000;
const DEFAULT_POSTGREST_JWT_TTL_SECONDS = 15 * 60;
const SUPABASE_UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

type ExchangeCodeRecord = {
  accessToken: string;
  refreshToken: string;
  origin: string;
  createdAt: number;
};

type OAuthStateRecord = {
  origin: string;
  callbackUrl: string;
  provider: string;
  createdAt: number;
  mode: 'identity_login' | 'repo_connect';
  authorizationRequestId?: string;
};

type AuthenticatedSession = {
  token: string;
  session: SessionUser;
  sessionId: string;
  accessJti: string;
  accessExp: number;
};

type AuthenticatedUserContext = AuthenticatedSession & {
  user: StoredUser;
};

type NativeAuthorizationRequestRecord = AuthorizationRequestRecord & {
  nativeProvider?: string;
  acceptedRequiredConsentDocs?: ConsentAcceptance[];
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

function resolveConsumerOrigin(req: any, config: AuthAppConfig) {
  const queryOrigin = typeof req?.query?.origin === 'string' ? trimTrailingSlash(req.query.origin) : '';
  if (queryOrigin && config.allowedOrigins.includes(queryOrigin)) {
    return queryOrigin;
  }
  return resolveRequestOrigin(req, config);
}

function resolveRequestedConsumerOrigin(req: any, config: AuthAppConfig) {
  const queryOrigin = typeof req?.query?.origin === 'string' ? trimTrailingSlash(req.query.origin) : '';
  if (queryOrigin && config.allowedOrigins.includes(queryOrigin)) {
    return queryOrigin;
  }

  const originHeader = typeof req.get === 'function' ? req.get('origin') : undefined;
  if (originHeader && config.allowedOrigins.includes(trimTrailingSlash(originHeader))) {
    return trimTrailingSlash(originHeader);
  }

  const refererHeader = typeof req.get === 'function' ? req.get('referer') : undefined;
  if (!refererHeader) return '';
  try {
    const refererOrigin = new URL(refererHeader).origin;
    return config.allowedOrigins.includes(trimTrailingSlash(refererOrigin)) ? trimTrailingSlash(refererOrigin) : '';
  } catch {
    return '';
  }
}

function resolveStrictOAuthStartOrigin(req: any, config: AuthAppConfig) {
  const allowed = new Set(config.allowedOrigins.map(trimTrailingSlash));
  const queryOrigin = typeof req?.query?.origin === 'string' ? trimTrailingSlash(req.query.origin) : '';
  if (queryOrigin) {
    return allowed.has(queryOrigin)
      ? { origin: queryOrigin }
      : { error: 'AUTH_ORIGIN_NOT_ALLOWED', origin: queryOrigin };
  }

  const originHeader = typeof req.get === 'function' ? req.get('origin') : undefined;
  if (originHeader) {
    const origin = trimTrailingSlash(originHeader);
    return allowed.has(origin)
      ? { origin }
      : { error: 'AUTH_ORIGIN_NOT_ALLOWED', origin };
  }

  const refererHeader = typeof req.get === 'function' ? req.get('referer') : undefined;
  if (refererHeader) {
    try {
      const origin = trimTrailingSlash(new URL(refererHeader).origin);
      return allowed.has(origin)
        ? { origin }
        : { error: 'AUTH_ORIGIN_NOT_ALLOWED', origin };
    } catch {
      return { error: 'AUTH_ORIGIN_NOT_ALLOWED', origin: refererHeader };
    }
  }

  return { origin: '' };
}

function resolveHostedOrigin(req: any) {
  const protoHeader = typeof req.get === 'function' ? req.get('x-forwarded-proto') : undefined;
  const forwardedProto = protoHeader ? String(protoHeader).split(',')[0].trim() : '';
  const proto = forwardedProto || (req.secure ? 'https' : 'http');
  const host = typeof req.get === 'function' ? req.get('host') : undefined;
  return trimTrailingSlash(host ? `${proto}://${host}` : getPublicOriginFallback());
}

function resolveAuthorizationOrigin() {
  // Native authorization is a browser protocol flow. Its continuation must use
  // one configured authority origin instead of inheriting whichever loopback
  // spelling (localhost or 127.0.0.1) an API client happened to call.
  return trimTrailingSlash(getPublicOriginFallback());
}

function cookieIsSecure(req: any) {
  return resolveHostedOrigin(req).startsWith('https://') || getPublicOriginFallback().startsWith('https://');
}

function getCookieDomain(req: any) {
  if (!cookieIsSecure(req)) return null;
  const configured = String(process.env.AUTH_COOKIE_DOMAIN || '').trim();
  return configured || null;
}

function createHostedCookie(req: any, name: string, value: string, maxAgeSeconds: number) {
  return createSetCookieHeader(
    name,
    value,
    maxAgeSeconds,
    cookieIsSecure(req),
    getCookieDomain(req),
  );
}

const FEDERATION_BROWSER_BINDING_COOKIE_PREFIX = 'auth_fed_pending_';

function federationBrowserBindingCookieName(requestId: string) {
  const requestDigest = crypto.createHash('sha256').update(requestId).digest('base64url').slice(0, 22);
  return `${FEDERATION_BROWSER_BINDING_COOKIE_PREFIX}${requestDigest}`;
}

function hashFederationBrowserBinding(requestId: string, binding: string) {
  return crypto.createHash('sha256').update(`${requestId}.${binding}`).digest('base64url');
}

function createFederationBrowserBindingCookie(
  req: any,
  requestId: string,
  binding: string,
  maxAgeSeconds = AUTHORIZATION_REQUEST_TTL_SECONDS,
) {
  const secure = cookieIsSecure(req);
  const parts = [
    `${federationBrowserBindingCookieName(requestId)}=${encodeURIComponent(binding)}`,
    'Path=/oauth/federation/complete',
    'HttpOnly',
    secure ? 'SameSite=None' : 'SameSite=Strict',
    `Max-Age=${maxAgeSeconds}`,
  ];
  if (secure) parts.push('Secure');
  return parts.join('; ');
}

function verifyFederationBrowserBinding(req: any, requestId: string, expectedHash?: string) {
  if (!expectedHash || !/^[A-Za-z0-9_-]{43}$/.test(expectedHash)) return false;
  const binding = parseCookieHeader(req.headers.cookie)[federationBrowserBindingCookieName(requestId)];
  if (!binding || !/^[A-Za-z0-9_-]{43}$/.test(binding)) return false;
  const actualHash = hashFederationBrowserBinding(requestId, binding);
  const expected = Buffer.from(expectedHash);
  const actual = Buffer.from(actualHash);
  return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
}

function federationCompletionOriginMatches(req: any, authorizationUiUrl: string) {
  const rawOrigin = String(req.get?.('origin') || '');
  if (!rawOrigin || rawOrigin === 'null') return false;
  try {
    const origin = new URL(rawOrigin);
    const authorizationUi = new URL(authorizationUiUrl);
    return rawOrigin === origin.origin && origin.origin === authorizationUi.origin;
  } catch {
    return false;
  }
}

function createHostedSessionCookie(req: any, name: string, value: string, tokenConfig: JwtTokenConfig) {
  return createHostedCookie(req, name, value, tokenConfig.accessTtlSeconds);
}

function createHostedRefreshCookie(req: any, name: string, value: string, tokenConfig: JwtTokenConfig) {
  return createHostedCookie(req, name, value, tokenConfig.refreshTtlSeconds);
}

function createHostedTokenCookies(
  req: any,
  accessCookieName: string,
  refreshCookieName: string,
  tokens: { accessToken: string; refreshToken: string },
  tokenConfig: JwtTokenConfig,
) {
  return [
    createHostedSessionCookie(req, accessCookieName, tokens.accessToken, tokenConfig),
    createHostedRefreshCookie(req, refreshCookieName, tokens.refreshToken, tokenConfig),
  ];
}

function createHostedClearCookies(req: any, names: string[]) {
  const secure = cookieIsSecure(req);
  const domain = getCookieDomain(req);
  const cookies: string[] = [];
  for (const name of names) {
    cookies.push(createClearCookieHeader(name, secure, null));
    if (domain) {
      cookies.push(createClearCookieHeader(name, secure, domain));
    }
  }
  return cookies;
}

function getClientIp(req: any) {
  const forwarded = typeof req.get === 'function' ? req.get('x-forwarded-for') : '';
  return forwarded?.split(',')[0]?.trim() || req.socket?.remoteAddress || null;
}

async function readAuthSession(
  req: any,
  cookieName: string,
  tokenConfig: JwtTokenConfig,
  refreshTokenStore: RefreshTokenStore,
  ephemeralStore: EphemeralAuthStore,
): Promise<AuthenticatedSession | { status: number; error: string }> {
  const cookies = parseCookieHeader(req.headers.cookie);
  const authorization = String(req.get?.('authorization') || req.headers.authorization || '').trim();
  const bearerMatch = /^Bearer\s+([^\s]+)$/i.exec(authorization);
  const token = cookies[cookieName] || bearerMatch?.[1];
  if (!token) {
    return { status: 401, error: 'No active session' } as const;
  }
  const verified = await verifyAccessToken(token, tokenConfig);
  if (!verified) {
    return { status: 401, error: 'Session expired' } as const;
  }
  try {
    if (await ephemeralStore.isAccessRevoked(verified.jti)) {
      return { status: 401, error: 'Session revoked' } as const;
    }
    if (await ephemeralStore.isSessionRevoked(verified.sessionId)) {
      return { status: 401, error: 'Session revoked' } as const;
    }
  } catch (error) {
    console.warn('⚠️ [Auth] revocation cache unavailable; falling back to session store', {
      requestPath: req.path || req.originalUrl || 'unknown',
      failureClass: 'revocation_cache_unavailable',
      errorClass: error instanceof Error ? error.name || 'Error' : typeof error,
      errorMessage: error instanceof Error ? error.message : String(error),
    });
  }
  const status = await refreshTokenStore.getSessionStatus(verified.sessionId);
  if (status !== 'active') {
    return { status: 401, error: status === 'missing' ? 'Session expired' : 'Session revoked' } as const;
  }
  return {
    token,
    session: verified.session,
    sessionId: verified.sessionId,
    accessJti: verified.jti,
    accessExp: verified.exp,
  } satisfies AuthenticatedSession;
}

function isSupabaseUuid(value: string | null | undefined) {
  if (typeof value !== 'string') return false;
  const trimmed = value.trim();
  if (!trimmed) return false;
  return SUPABASE_UUID_RE.test(trimmed);
}

function getPostgrestJwtSecret() {
  return (process.env.AUTH_POSTGREST_JWT_SECRET || '').trim();
}

function getPostgrestJwtTtlSeconds() {
  const raw = Number.parseInt(process.env.AUTH_POSTGREST_JWT_TTL_SECONDS || '', 10);
  return Number.isFinite(raw) && raw > 0 ? raw : DEFAULT_POSTGREST_JWT_TTL_SECONDS;
}

function sessionNeedsRefresh(session: SessionUser) {
  const id = typeof session.id === 'string' ? session.id.trim() : '';
  const sub = typeof session.sub === 'string' ? session.sub.trim() : '';
  const uid = typeof session.uid === 'string' ? session.uid.trim() : '';

  const readiness = session.accountContextReadiness;
  return !(
    id
    && sub
    && isSupabaseUuid(uid)
    && readiness?.version === 'life-auth-account-context-readiness/v1'
    && readiness.subject === sub
    && readiness.ready
    && typeof session.vvaultUserId === 'string'
    && isSupabaseUuid(session.vvaultUserId)
    && readiness.vvaultOwnerId === session.vvaultUserId
  );
}

function describeSessionUidState(session: SessionUser) {
  const uid = typeof session.uid === 'string' ? session.uid.trim() : '';
  if (!uid) return 'missing';
  if (isSupabaseUuid(uid)) return 'supabase_uuid';
  if (uid === session.id || uid === session.sub) return 'life_fallback';
  return 'non_uuid';
}

function oauthStateKey(state: string) {
  return `auth:oauth:state:${state}`;
}

function exchangeCodeKey(code: string) {
  return `auth:exchange:${code}`;
}

async function issueOAuthState(
  ephemeralStore: EphemeralAuthStore,
  provider: string,
  origin: string,
  callbackUrl: string,
  options: { mode?: 'identity_login' | 'repo_connect'; authorizationRequestId?: string } = {},
) {
  const state = crypto.randomBytes(18).toString('base64url');
  const record: OAuthStateRecord = {
    provider,
    origin,
    callbackUrl,
    createdAt: Date.now(),
    mode: options.mode ?? 'identity_login',
    authorizationRequestId: options.authorizationRequestId,
  };
  await ephemeralStore.setJson(oauthStateKey(state), record, Math.floor(OAUTH_STATE_TTL_MS / 1000));
  return state;
}

async function consumeOAuthState(ephemeralStore: EphemeralAuthStore, provider: string, state: string) {
  const key = oauthStateKey(state);
  const record = await ephemeralStore.getJson<OAuthStateRecord>(key);
  await ephemeralStore.delete(key);
  if (!record) return null;
  if (record.provider !== provider) return null;
  if (Date.now() - record.createdAt > OAUTH_STATE_TTL_MS) return null;
  return record;
}

function requestMetadataHashes(req: any, tokenConfig: JwtTokenConfig) {
  const userAgent = typeof req.get === 'function' ? req.get('user-agent') : '';
  return {
    ipHash: hashRequestMetadata(getClientIp(req), tokenConfig.refreshTokenHashSecret),
    userAgentHash: hashRequestMetadata(userAgent || null, tokenConfig.refreshTokenHashSecret),
  };
}

function resolveCallbackUrl(req: any, config: AuthAppConfig, providerId: string, requestOrigin?: string) {
  const requestedConsumerOrigin = requestOrigin ?? resolveRequestedConsumerOrigin(req, config);
  const resolution = resolveOAuthCallbackUrl(providerId, config, {
    requestOrigin: requestedConsumerOrigin,
  });
  if (resolution.callbackUrl) return resolution.callbackUrl;
  const detail = resolution.conflicts.length > 0
    ? `OAuth callback env conflict: ${resolution.conflicts.join('; ')}`
    : 'OAuth callback is not configured for an allowed app origin';
  throw Object.assign(new Error(detail), {
    status: 503,
    code: 'OAUTH_CALLBACK_NOT_ALLOWED',
  });
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

async function readAuthenticatedUser(
  req: any,
  storage: StorageAdapter,
  cookieName: string,
  tokenConfig: JwtTokenConfig,
  refreshTokenStore: RefreshTokenStore,
  ephemeralStore: EphemeralAuthStore,
): Promise<AuthenticatedUserContext | { status: number; error: string }> {
  const authSession = await readAuthSession(req, cookieName, tokenConfig, refreshTokenStore, ephemeralStore);
  if ('error' in authSession) return authSession;
  const user = await storage.findUserByEmail(authSession.session.email);
  if (!user) {
    return { status: 401, error: 'Session user was not found' } as const;
  }
  return {
    ...authSession,
    user,
  } satisfies AuthenticatedUserContext;
}

function parseProviderProfile(profileJson: string) {
  try {
    const parsed = JSON.parse(profileJson) as Record<string, unknown>;
    return parsed && typeof parsed === 'object' ? parsed : {};
  } catch {
    return {};
  }
}

function githubConnectionPayload(account: {
  displayName: string | null;
  avatarUrl: string | null;
  profileJson: string;
}) {
  const profile = parseProviderProfile(account.profileJson);
  const login = typeof profile.login === 'string' ? profile.login : undefined;
  return {
    connected: true as const,
    login,
    name: account.displayName || (typeof profile.name === 'string' ? profile.name : undefined),
    avatarUrl: account.avatarUrl || undefined,
  };
}

function getHydroConstructId() {
  return (process.env.CODE_HYDRO_CONSTRUCT_ID || 'hydro-001').trim();
}

function getHydroRuntimeSelection() {
  return {
    provider: 'openai',
    model: 'gpt-4o-mini',
  };
}

function getHydroModelLabel() {
  return 'GPT-4o mini';
}

function getHydroCanonicalModeLabel(mode: string) {
  if (mode === 'chat') return 'Chat';
  if (mode === 'plan') return 'Plan';
  if (mode === 'custom') return 'Custom';
  return 'Hydro';
}

const HYDRO_TASK_COMMENT_RE = /<!--\s*hydro_task\s+({[\s\S]*?})\s*-->/i;
const HYDRO_MESSAGE_COMMENT_RE = /<!--\s*hydro_message\s+({[\s\S]*?})\s*-->/i;

function parseJsonObject(value: string) {
  try {
    const parsed = JSON.parse(value) as Record<string, unknown>;
    return parsed && typeof parsed === 'object' ? parsed : {};
  } catch {
    return {};
  }
}

function normalizeAskTaskKind(value: unknown) {
  return value === 'chat' || value === 'plan' || value === 'regular'
    ? value
    : undefined;
}

function askTaskKindForMode(mode: string) {
  if (mode === 'chat') return 'chat';
  if (mode === 'plan') return 'plan';
  return 'regular';
}

function deriveAskTaskTitle(content: string) {
  const normalized = String(content || '')
    .replace(/```[\s\S]*?```/g, ' ')
    .replace(/`[^`]+`/g, ' ')
    .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '$1')
    .replace(/[#>*_~-]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  if (!normalized) return 'New request';
  const sentence = normalized.split(/[.!?](?:\s|$)/).map((part) => part.trim()).find(Boolean) || normalized;
  return sentence.length > 72 ? `${sentence.slice(0, 69).trimEnd()}...` : sentence;
}

function createAskTaskId(startedAt: number, title: string) {
  const slug = slugifyHydroProjectName(title || 'request').slice(0, 32) || 'request';
  return `task_${startedAt}_${slug}_${crypto.randomBytes(3).toString('hex')}`;
}

function parseDecoratedTranscriptContent(content: string) {
  const taskMetadata = content.match(HYDRO_TASK_COMMENT_RE)?.[1]
    ? parseJsonObject(content.match(HYDRO_TASK_COMMENT_RE)![1]!)
    : {};
  const messageMetadata = content.match(HYDRO_MESSAGE_COMMENT_RE)?.[1]
    ? parseJsonObject(content.match(HYDRO_MESSAGE_COMMENT_RE)![1]!)
    : {};
  let stripped = String(content || '').trim();
  if (HYDRO_TASK_COMMENT_RE.test(stripped)) {
    stripped = stripped.replace(HYDRO_TASK_COMMENT_RE, '').trimStart();
    stripped = stripped.replace(/^##\s+.+$/m, '').trimStart();
  }
  if (HYDRO_MESSAGE_COMMENT_RE.test(stripped)) {
    stripped = stripped.replace(HYDRO_MESSAGE_COMMENT_RE, '').trimStart();
    stripped = stripped.replace(/^###\s+.+$/m, '').trimStart();
  }
  return {
    content: stripped.trim(),
    taskMetadata,
    messageMetadata,
  };
}

function roleHeadingForTranscript(role: 'user' | 'assistant' | 'system') {
  if (role === 'assistant') return 'Hydro';
  if (role === 'system') return 'Worklog';
  return 'You';
}

function buildTranscriptMessageContent(params: {
  role: 'user' | 'assistant' | 'system';
  content: string;
  taskId: string;
  taskTitle: string;
  taskKind: string;
  taskMode: string;
  taskStartedAt: number;
  startNewTask: boolean;
  taskCompleted?: boolean;
  workDurationMs?: number;
  checkpointSaved?: boolean;
}) {
  const lines: string[] = [];
  if (params.startNewTask) {
    lines.push(`<!-- hydro_task ${JSON.stringify({
      id: params.taskId,
      title: params.taskTitle,
      kind: params.taskKind,
      mode: params.taskMode,
      startedAt: params.taskStartedAt,
    })} -->`);
    lines.push(`## ${params.taskTitle}`);
  }
  lines.push(`<!-- hydro_message ${JSON.stringify({
    taskId: params.taskId,
    taskTitle: params.taskTitle,
    taskKind: params.taskKind,
    taskMode: params.taskMode,
    taskStartedAt: params.taskStartedAt,
    ...(typeof params.taskCompleted === 'boolean' ? { taskCompleted: params.taskCompleted } : {}),
    ...(typeof params.workDurationMs === 'number' ? { workDurationMs: params.workDurationMs } : {}),
    ...(typeof params.checkpointSaved === 'boolean' ? { checkpointSaved: params.checkpointSaved } : {}),
  })} -->`);
  lines.push(`### ${roleHeadingForTranscript(params.role)}`);
  lines.push(params.content.trim());
  return lines.join('\n');
}

function resolveStoredTaskMetadata(message: any) {
  const metadata = parseAskMetadata(message?.metadata);
  const decorated = parseDecoratedTranscriptContent(String(message?.content || ''));
  const merged = { ...decorated.taskMetadata, ...decorated.messageMetadata, ...metadata };
  return {
    taskId: typeof merged.taskId === 'string' && merged.taskId.trim() ? merged.taskId.trim() : undefined,
    taskTitle: typeof merged.taskTitle === 'string' && merged.taskTitle.trim() ? merged.taskTitle.trim() : typeof merged.title === 'string' && merged.title.trim() ? merged.title.trim() : undefined,
    taskKind: normalizeAskTaskKind(merged.taskKind ?? merged.kind),
    taskMode: typeof merged.taskMode === 'string' && merged.taskMode.trim() ? merged.taskMode.trim() : typeof merged.mode === 'string' && merged.mode.trim() ? merged.mode.trim() : undefined,
    taskStartedAt: Number.isFinite(merged.taskStartedAt) ? Number(merged.taskStartedAt) : Number.isFinite(merged.startedAt) ? Number(merged.startedAt) : undefined,
    taskCompleted: typeof merged.taskCompleted === 'boolean' ? merged.taskCompleted : undefined,
    workDurationMs: Number.isFinite(merged.workDurationMs) ? Number(merged.workDurationMs) : undefined,
    checkpointSaved: typeof merged.checkpointSaved === 'boolean' ? merged.checkpointSaved : undefined,
    displayContent: decorated.content,
  };
}

function resolveTaskAssignment(params: { transcriptPayload: any; content: string; askMode: string; now: number }) {
  const history = Array.isArray(params.transcriptPayload?.messages) ? params.transcriptPayload.messages : [];
  const lastMessage = [...history]
    .reverse()
    .find((message) => String(resolveStoredTaskMetadata(message).displayContent || '').trim().length > 0 || String(message?.content || '').trim().length > 0);
  const lastMetadata = lastMessage ? resolveStoredTaskMetadata(lastMessage) : null;
  const shouldStartNewTask = !lastMessage || lastMetadata?.taskCompleted !== false && lastMessage?.role === 'assistant';
  if (!shouldStartNewTask && lastMetadata?.taskId && lastMetadata.taskTitle) {
    return {
      taskId: lastMetadata.taskId,
      taskTitle: lastMetadata.taskTitle,
      taskKind: lastMetadata.taskKind || askTaskKindForMode(params.askMode),
      taskMode: lastMetadata.taskMode || params.askMode,
      taskStartedAt: lastMetadata.taskStartedAt || params.now,
      startNewTask: false,
    };
  }
  const taskTitle = deriveAskTaskTitle(params.content);
  return {
    taskId: createAskTaskId(params.now, taskTitle),
    taskTitle,
    taskKind: askTaskKindForMode(params.askMode),
    taskMode: params.askMode,
    taskStartedAt: params.now,
    startNewTask: true,
  };
}

function isClarifyingAssistantResponse(content: string) {
  const trimmed = String(content || '').trim();
  if (!trimmed) return false;
  if (/<hydro_question_card>/i.test(trimmed)) return true;
  if (/<proposed_plan>/i.test(trimmed)) return false;
  if (/\?$/.test(trimmed)) return true;
  return /\b(could you clarify|which option|what should|what would you like|tell hydro|tell codex|before i plan|before i answer)\b/i.test(trimmed);
}

function normalizeAskMode(value: unknown, chatMode?: unknown, planMode?: unknown) {
  if (value === 'hydro' || value === 'chat' || value === 'plan' || value === 'custom') {
    return value;
  }
  if (planMode === true) return 'plan';
  if (chatMode === true) return 'chat';
  return 'hydro';
}

function slugifyHydroProjectName(value: string) {
  const slug = value
    .trim()
    .replace(/[^a-zA-Z0-9]+/g, '_')
    .replace(/_+/g, '_')
    .replace(/^_+|_+$/g, '');
  return slug || 'workspace';
}

function inferProjectName(rootPath: string | null | undefined) {
  if (!rootPath) return null;
  const trimmed = rootPath.trim().replace(/\/+$/, '');
  if (!trimmed) return null;
  const basename = path.posix.basename(trimmed);
  return basename && basename !== '.' && basename !== '/' ? basename : null;
}

function resolveAskProjectName(source?: { projectName?: unknown; rootPath?: unknown }) {
  if (typeof source?.projectName === 'string' && source.projectName.trim()) {
    return source.projectName.trim();
  }
  if (typeof source?.rootPath === 'string' && source.rootPath.trim()) {
    return inferProjectName(source.rootPath) || source.rootPath.trim();
  }
  return null;
}

type HydroAskTarget = {
  constructId: string;
  threadId: string;
  filename: string;
  storagePath: string;
  title: string;
  projectName: string | null;
  projectSlug: string | null;
};

type AskAttachmentPayload = {
  id: string;
  name: string;
  mimeType: string;
  size: number;
  category: 'image' | 'document';
  storagePath?: string;
  sha256?: string;
  dataUrl?: string;
  textContent?: string;
};

function parseAskAttachments(value: unknown) {
  if (!Array.isArray(value)) return [] as AskAttachmentPayload[];
  return value
    .map((entry, index) => {
      if (!entry || typeof entry !== 'object') return null;
      const raw = entry as Record<string, unknown>;
      const name = typeof raw.name === 'string' && raw.name.trim() ? raw.name.trim() : `attachment-${index + 1}`;
      const mimeType = typeof raw.mimeType === 'string' && raw.mimeType.trim() ? raw.mimeType.trim() : 'application/octet-stream';
      const size = Number.isFinite(raw.size) ? Number(raw.size) : 0;
      return {
        id: typeof raw.id === 'string' && raw.id.trim() ? raw.id.trim() : `${Date.now()}-${index + 1}`,
        name,
        mimeType,
        size,
        category: raw.category === 'image' || raw.category === 'document'
          ? raw.category
          : mimeType.startsWith('image/')
            ? 'image'
            : 'document',
        storagePath: typeof raw.storagePath === 'string' && raw.storagePath.trim() ? raw.storagePath.trim() : undefined,
        sha256: typeof raw.sha256 === 'string' && raw.sha256.trim() ? raw.sha256.trim() : undefined,
        dataUrl: typeof raw.dataUrl === 'string' && raw.dataUrl.trim() ? raw.dataUrl.trim() : undefined,
        textContent: typeof raw.textContent === 'string' ? raw.textContent : undefined,
      } satisfies AskAttachmentPayload;
    })
    .filter(Boolean) as AskAttachmentPayload[];
}

function parseAskMetadata(value: unknown) {
  if (!value || typeof value !== 'object') return {} as Record<string, unknown>;
  return value as Record<string, unknown>;
}

function extractResponseText(payload: any) {
  if (typeof payload?.output_text === 'string' && payload.output_text.trim()) {
    return payload.output_text.trim();
  }
  const parts: string[] = [];
  if (Array.isArray(payload?.output)) {
    payload.output.forEach((item: any) => {
      if (!Array.isArray(item?.content)) return;
      item.content.forEach((content: any) => {
        if (typeof content?.text === 'string' && content.text.trim()) {
          parts.push(content.text.trim());
          return;
        }
        if (typeof content?.refusal === 'string' && content.refusal.trim()) {
          parts.push(content.refusal.trim());
        }
      });
    });
  }
  return parts.join('\n\n').trim();
}

function sanitizeAskAttachment(entry: AskAttachmentPayload | Record<string, unknown>, index: number) {
  const raw = entry as Record<string, unknown>;
  const mimeType = typeof raw.mimeType === 'string' && raw.mimeType.trim() ? raw.mimeType.trim() : 'application/octet-stream';
  return {
    id: typeof raw.id === 'string' && raw.id.trim() ? raw.id.trim() : `attachment-${index + 1}`,
    name: typeof raw.name === 'string' && raw.name.trim() ? raw.name.trim() : `attachment-${index + 1}`,
    mimeType,
    size: Number.isFinite(raw.size) ? Number(raw.size) : 0,
    category: raw.category === 'image' || raw.category === 'document'
      ? raw.category
      : mimeType.startsWith('image/')
        ? 'image'
        : 'document',
    storagePath: typeof raw.storagePath === 'string' && raw.storagePath.trim() ? raw.storagePath.trim() : undefined,
    sha256: typeof raw.sha256 === 'string' && raw.sha256.trim() ? raw.sha256.trim() : undefined,
  };
}

function buildHydroSystemWrapper() {
  return [
    'You are Hydro, the automated software team inside Code.',
    'Speak in one unified Hydro voice with the Project Manager as the primary conversational surface.',
    'Stay honest, calm, and collaborative.',
    'Do not claim edits, commands, file writes, delegation, or completed implementation unless those actions truly happened.',
    'Treat Ask as conversational-first and non-mutating unless explicit write behavior is actually implemented.',
    'If a request is ambiguous, conflicting, or high-impact, ask clarifying follow-up questions before you answer or propose a plan.',
    'Keep clarification inside the same ongoing task until you have enough context to respond well.',
  ].join(' ');
}

function buildModeInstruction(mode: string, modeLabel?: unknown, modePrompt?: unknown) {
  const customPrompt = typeof modePrompt === 'string' ? modePrompt.trim() : '';
  if (mode === 'plan') {
    return 'Mode: Plan. First clarify anything underspecified or risky. Once you have enough context, respond with a concise implementation plan, key risks, and recommended next steps. Do not pretend work has already been done.';
  }
  if (mode === 'chat') {
    return 'Mode: Chat. Keep the response conversational, helpful, and read-only unless the user explicitly asks for implementation details.';
  }
  if (mode === 'custom' && customPrompt) {
    const customLabel = typeof modeLabel === 'string' && modeLabel.trim() ? modeLabel.trim() : 'Custom';
    return `Mode: ${customLabel}. Follow this extra instruction layer while staying on the same OpenAI runtime: ${customPrompt}`;
  }
  return 'Mode: Hydro. Act as the Project Manager front door for Hydro, routing specialist thinking internally without asking the user to shuttle prompts between team members. Answer simple clear asks directly, but clarify first when the request is underspecified.';
}

function buildWorkerInstruction(agentLabel?: unknown, agentPrompt?: unknown) {
  const label = typeof agentLabel === 'string' && agentLabel.trim() ? agentLabel.trim() : null;
  const prompt = typeof agentPrompt === 'string' && agentPrompt.trim() ? agentPrompt.trim() : null;
  if (prompt) {
    return `Focused worker guidance${label ? ` for ${label}` : ''}: ${prompt}`;
  }
  if (!label || label.toLowerCase() === 'code' || label.toLowerCase() === 'hydro') return '';
  return `Focused worker guidance: emphasize ${label} expertise while still responding as Hydro.`;
}

function buildWorkspaceContextText(source: {
  projectName?: string | null;
  rootPath?: unknown;
  workspaceSummary?: unknown;
}) {
  const lines: string[] = ['Workspace context:'];
  if (source.projectName) lines.push(`Project: ${source.projectName}`);
  if (typeof source.rootPath === 'string' && source.rootPath.trim()) lines.push(`Root path: ${source.rootPath.trim()}`);
  if (source.workspaceSummary && typeof source.workspaceSummary === 'object') {
    lines.push(`Workspace summary: ${JSON.stringify(source.workspaceSummary)}`);
  } else if (typeof source.workspaceSummary === 'string' && source.workspaceSummary.trim()) {
    lines.push(`Workspace summary: ${source.workspaceSummary.trim()}`);
  }
  return lines.join('\n');
}

function buildUserInputParts(content: string, attachments: AskAttachmentPayload[]) {
  const textSections: string[] = [];
  if (content.trim()) {
    textSections.push(content.trim());
  }
  if (attachments.length > 0) {
    textSections.push([
      'Attachments:',
      ...attachments.map((attachment) => {
        const lines = [
          `- ${attachment.name} (${attachment.mimeType}, ${attachment.size} bytes, ${attachment.category})`,
        ];
        if (attachment.textContent?.trim()) {
          lines.push(`  Text excerpt: ${attachment.textContent.trim().slice(0, 4000)}`);
        }
        return lines.join('\n');
      }),
    ].join('\n'));
  }
  const parts: Array<Record<string, unknown>> = [];
  const text = textSections.join('\n\n').trim() || 'The user sent attachments without additional text. Please acknowledge them and respond helpfully.';
  parts.push({ type: 'input_text', text });
  attachments
    .filter((attachment) => attachment.category === 'image' && attachment.dataUrl)
    .forEach((attachment) => {
      parts.push({
        type: 'input_image',
        image_url: attachment.dataUrl,
        detail: 'auto',
      });
    });
  return parts;
}

function buildOpenAiInputFromTranscript(params: {
  transcriptPayload: any;
  content: string;
  attachments: AskAttachmentPayload[];
  projectName?: string | null;
  rootPath?: unknown;
  workspaceSummary?: unknown;
}) {
  const history = Array.isArray(params.transcriptPayload?.messages) ? params.transcriptPayload.messages : [];
  const input: Array<Record<string, unknown>> = [
    {
      type: 'message',
      role: 'developer',
      content: [
        {
          type: 'input_text',
          text: buildWorkspaceContextText({
            projectName: params.projectName,
            rootPath: params.rootPath,
            workspaceSummary: params.workspaceSummary,
          }),
        },
      ],
    },
  ];

  history.forEach((message: any) => {
    const role = message?.role === 'assistant' || message?.role === 'system' ? message.role : 'user';
    const text = parseDecoratedTranscriptContent(String(message?.content || '')).content.trim();
    if (!text) return;
    input.push({
      type: 'message',
      role,
      content: [{ type: 'input_text', text }],
    });
  });

  input.push({
    type: 'message',
    role: 'user',
    content: buildUserInputParts(params.content, params.attachments),
  });
  return input;
}

function resolveHydroAskTarget(source?: { projectName?: unknown; rootPath?: unknown }): HydroAskTarget {
  const constructId = getHydroConstructId();
  const projectName = resolveAskProjectName(source);
  if (constructId === 'hydro-001' && projectName) {
    const projectSlug = slugifyHydroProjectName(projectName);
    const filename = `${projectSlug}_hydro_chat.md`;
    return {
      constructId,
      threadId: `${constructId}_${projectSlug}_hydro_chat`,
      filename,
      storagePath: `instances/${constructId}/code/${filename}`,
      title: `${projectName} Hydro`,
      projectName,
      projectSlug,
    };
  }

  return {
    constructId,
    threadId: `${constructId}_chat_with_${constructId}`,
    filename: `chat_with_${constructId}.md`,
    storagePath: `instances/${constructId}/chatty/chat_with_${constructId}.md`,
    title: 'Ask Hydro',
    projectName,
    projectSlug: null,
  };
}

function resolveCanonicalTranscriptPath(userId: string, target: HydroAskTarget) {
  return `/vvault_files/users/shard_0000/${userId}/${target.storagePath}`;
}

async function fetchHydroTranscriptPayload(params: {
  baseUrl: string;
  headers: Record<string, string>;
  target: HydroAskTarget;
  rootPath?: unknown;
}) {
  const requestUrl = new URL(`${params.baseUrl}/api/chatty/transcript/${params.target.constructId}`);
  if (params.target.projectName) {
    requestUrl.searchParams.set('projectName', params.target.projectName);
  }
  if (typeof params.rootPath === 'string' && params.rootPath.trim()) {
    requestUrl.searchParams.set('rootPath', params.rootPath.trim());
  }
  const upstream = await fetch(requestUrl.toString(), {
    method: 'GET',
    headers: params.headers,
  });
  if (upstream.status === 404) {
    return { messages: [], content: '', storageMode: 'canonical' };
  }
  if (!upstream.ok) {
    const details = await upstream.text().catch(() => 'Failed to fetch Hydro transcript');
    throw Object.assign(new Error(details || 'Failed to fetch Hydro transcript'), { status: upstream.status });
  }
  return upstream.json().catch(() => ({}));
}

async function appendHydroTranscriptMessage(params: {
  baseUrl: string;
  headers: Record<string, string>;
  target: HydroAskTarget;
  role: 'user' | 'assistant' | 'system';
  content: string;
  rootPath?: unknown;
  name?: string;
  metadata?: Record<string, unknown>;
  attachments?: AskAttachmentPayload[];
}) {
  const upstream = await fetch(`${params.baseUrl}/api/chatty/transcript/${params.target.constructId}/message`, {
    method: 'POST',
    headers: params.headers,
    body: JSON.stringify({
      role: params.role,
      content: params.content,
      name: params.name,
      timestamp: new Date().toISOString(),
      projectName: params.target.projectName,
      rootPath: typeof params.rootPath === 'string' ? params.rootPath : undefined,
      transcriptPath: params.target.storagePath,
      title: params.target.title,
      metadata: params.metadata,
      attachments: params.attachments,
    }),
  });
  if (!upstream.ok && upstream.status !== 202) {
    const details = await upstream.text().catch(() => 'Failed to append Hydro transcript message');
    throw Object.assign(new Error(details || 'Failed to append Hydro transcript message'), { status: upstream.status });
  }
  return upstream.json().catch(() => ({}));
}

async function callOpenAiHydroResponse(params: {
  instructions: string;
  input: Array<Record<string, unknown>>;
}) {
  const apiKey = (process.env.OPENAI_API_KEY || '').trim();
  if (!apiKey) {
    throw Object.assign(new Error('OPENAI_API_KEY is not configured for Ask Hydro.'), { status: 503 });
  }
  const runtime = getHydroRuntimeSelection();
  const response = await fetch('https://api.openai.com/v1/responses', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify({
      model: runtime.model,
      instructions: params.instructions,
      input: params.input,
      max_output_tokens: 900,
    }),
  });
  const payload: any = await response.json().catch(() => ({}));
  if (!response.ok) {
    const message =
      typeof payload?.error?.message === 'string' && payload.error.message.trim()
        ? payload.error.message.trim()
        : response.statusText || `OpenAI request failed (${response.status})`;
    throw Object.assign(new Error(message), { status: response.status });
  }
  const text = extractResponseText(payload);
  if (!text) {
    throw Object.assign(new Error('OpenAI returned an empty response.'), { status: 502 });
  }
  return { payload, text };
}

function getVvaultRelayConfig() {
  const baseUrl = (process.env.VVAULT_API_BASE_URL || '').trim().replace(/\/+$/, '');
  const serviceToken = (process.env.VVAULT_SERVICE_TOKEN || '').trim();
  return {
    baseUrl,
    serviceToken,
  };
}

function legacyCodeRoutesEnabled() {
  return process.env.AUTH_ENABLE_LEGACY_CODE_ROUTES === '1';
}

function getHydroAskStatusPayload(userId: string, target: HydroAskTarget) {
  const { baseUrl } = getVvaultRelayConfig();
  const openAiConfigured = Boolean((process.env.OPENAI_API_KEY || '').trim());
  const relayConfigured = Boolean(baseUrl);
  const configured = relayConfigured && openAiConfigured;
  return {
    configured,
    relayConfigured,
    openAiConfigured,
    canonicalTranscriptPath: resolveCanonicalTranscriptPath(userId, target),
    projectName: target.projectName,
    threadId: target.threadId,
    setupMessage: configured
      ? 'Ask Hydro is ready.'
      : !relayConfigured
        ? 'Ask Hydro needs the VVAULT relay configured before canonical project chat can load.'
        : 'Ask Hydro needs OPENAI_API_KEY configured before project chat can respond.',
  };
}

function createVvaultHeaders(userEmail: string | null, serviceToken: string) {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  if (serviceToken) headers['X-Chatty-Key'] = serviceToken;
  if (userEmail) headers['X-Chatty-User'] = userEmail;
  return headers;
}

function parseTranscriptMessages(content: string) {
  const lines = String(content || '').split('\n');
  const messages: Array<{ id: string; role: 'user' | 'assistant' | 'system'; content: string; createdAt: number }> = [];
  let currentRole: 'user' | 'assistant' | 'system' | null = null;
  let currentContent: string[] = [];
  let currentTimestamp = Date.now();

  const commitCurrent = () => {
    if (!currentRole) return;
    const body = currentContent.join('\n').trim();
    if (!body) return;
    messages.push({
      id: `msg-${messages.length + 1}`,
      role: currentRole,
      content: body,
      createdAt: currentTimestamp,
    });
  };

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#') || trimmed === '---') continue;
    const simpleMatch = trimmed.match(/^(You|User|Assistant|Hydro|Zen|Lin|Nova)\s+said:\s*(.*)$/i);
    if (simpleMatch) {
      commitCurrent();
      currentRole = /you|user/i.test(simpleMatch[1]) ? 'user' : 'assistant';
      currentContent = [simpleMatch[2] || ''];
      currentTimestamp = Date.now() + messages.length;
      continue;
    }
    const markdownMatch = trimmed.match(/^\*\*(User|Assistant|Hydro|Zen|Lin|Nova)\*\*:\s*(.*)$/i);
    if (markdownMatch) {
      commitCurrent();
      currentRole = /user/i.test(markdownMatch[1]) ? 'user' : 'assistant';
      currentContent = [markdownMatch[2] || ''];
      currentTimestamp = Date.now() + messages.length;
      continue;
    }
    const transcriptHeadingMatch = trimmed.match(/^###\s+(You|Hydro|Worklog|Assistant|User)\s*$/i);
    if (transcriptHeadingMatch) {
      commitCurrent();
      currentRole = /user|you/i.test(transcriptHeadingMatch[1]) ? 'user' : /worklog/i.test(transcriptHeadingMatch[1]) ? 'system' : 'assistant';
      currentContent = [];
      currentTimestamp = Date.now() + messages.length;
      continue;
    }
    if (/^##\s+/.test(trimmed) || HYDRO_TASK_COMMENT_RE.test(trimmed) || HYDRO_MESSAGE_COMMENT_RE.test(trimmed)) continue;
    if (currentRole) {
      currentContent.push(line);
    }
  }

  commitCurrent();
  return messages;
}

function mapTranscriptPayloadToAskMessages(payload: any, target: HydroAskTarget) {
  const runtime = getHydroRuntimeSelection();
  const runtimeModelLabel = getHydroModelLabel();
  return Array.isArray(payload?.messages)
    ? payload.messages.map((message: any, index: number) => {
        const metadata = parseAskMetadata(message?.metadata);
        const storedTask = resolveStoredTaskMetadata(message);
        const attachments = Array.isArray(message?.attachments)
          ? message.attachments.map((attachment: Record<string, unknown>, attachmentIndex: number) => sanitizeAskAttachment(attachment, attachmentIndex))
          : Array.isArray(metadata.attachments)
            ? (metadata.attachments as Record<string, unknown>[]).map((attachment, attachmentIndex: number) => sanitizeAskAttachment(attachment, attachmentIndex))
            : undefined;
        return {
          id: String(message?.id || `msg-${index + 1}`),
          threadId: target.threadId,
          role: message?.role === 'assistant' || message?.role === 'system' ? message.role : 'user',
          content: storedTask.displayContent || '',
          createdAt: Date.parse(message?.timestamp || '') || Date.now() + index,
          status: 'completed' as const,
          ...(attachments?.length ? { attachments } : {}),
          ...(storedTask.taskId ? { taskId: storedTask.taskId } : {}),
          ...(storedTask.taskTitle ? { taskTitle: storedTask.taskTitle } : {}),
          ...(storedTask.taskKind ? { taskKind: storedTask.taskKind } : {}),
          ...(typeof storedTask.checkpointSaved === 'boolean'
            ? { checkpointSaved: storedTask.checkpointSaved }
            : message?.role === 'assistant'
              ? { checkpointSaved: true }
              : {}),
          ...(typeof storedTask.workDurationMs === 'number' ? { workDurationMs: storedTask.workDurationMs } : {}),
          ...(typeof metadata.agentId === 'string' ? { agentId: metadata.agentId } : {}),
          ...(typeof metadata.agentLabel === 'string'
            ? { agentLabel: metadata.agentLabel }
            : message?.role === 'assistant'
              ? { agentLabel: 'Hydro' }
              : {}),
          ...(typeof metadata.askMode === 'string' ? { askMode: metadata.askMode } : {}),
          ...(typeof metadata.modeLabel === 'string'
            ? { modeLabel: metadata.modeLabel }
            : typeof metadata.askMode === 'string'
              ? { modeLabel: getHydroCanonicalModeLabel(metadata.askMode) }
              : {}),
          ...(typeof metadata.provider === 'string'
            ? { provider: metadata.provider }
            : message?.role === 'assistant'
              ? { provider: runtime.provider }
              : {}),
          ...(typeof metadata.model === 'string'
            ? { model: metadata.model }
            : message?.role === 'assistant'
              ? { model: runtime.model }
              : {}),
          ...(typeof metadata.modelKey === 'string'
            ? { modelKey: metadata.modelKey }
            : message?.role === 'assistant'
              ? { modelKey: runtime.model }
              : {}),
          ...(typeof metadata.modelLabel === 'string'
            ? { modelLabel: metadata.modelLabel }
            : message?.role === 'assistant'
              ? { modelLabel: runtimeModelLabel }
              : {}),
        };
      })
    : parseTranscriptMessages(String(payload?.content || '')).map((message) => ({
        ...message,
        threadId: target.threadId,
        status: 'completed' as const,
      }));
}

function mapTranscriptPayloadToAskThread(payload: any, target: HydroAskTarget) {
  const messages = mapTranscriptPayloadToAskMessages(payload, target);
  return {
    id: target.threadId,
    constructId: target.constructId,
    title: target.title,
    updatedAt: messages[messages.length - 1]?.createdAt || Date.now(),
    messages,
    storageMode: 'canonical',
    runtime: getHydroRuntimeSelection(),
  };
}

type CreateAuthAppOptions = {
  magicEmailDelivery?: MagicEmailDelivery;
  storage?: StorageAdapter;
  refreshTokenStore?: RefreshTokenStore;
  ephemeralStore?: EphemeralAuthStore;
  configStore?: AppConfigStore;
  providers?: Record<string, OAuthProviderClient>;
  turnstileVerifier?: TurnstileVerifier;
  sessionSecret?: string;
  cookieName?: string;
  resolveLifeProfile?: (input: ResolveLifeProfileInput) => Promise<LifeProfileResult>;
  resolveVvaultOwnerId?: (email: string, providerIdentity?: VerifiedProviderIdentity) => Promise<string | null>;
  /** Override for tests; default checks Supabase `users` by email. */
  isEmailInLifeRegistry?: (email: string) => Promise<boolean>;
  githubFetchImpl?: typeof fetch;
  githubRepoSessions?: GitHubRepoSessionStore;
};

export function createDefaultStorage() {
  if (process.env.AUTH_STORAGE_ADAPTER === 'memory') return new MemoryStorageAdapter();
  const canonicalDatabaseUrl = String(
    process.env.DATABASE_URL || process.env.VVAULT_BODY_DATABASE_URL || '',
  ).trim();
  if (canonicalDatabaseUrl && !process.env.DATABASE_URL) {
    process.env.DATABASE_URL = canonicalDatabaseUrl;
  }
  if (process.env.AUTH_STORAGE_ADAPTER === 'postgres' || (!process.env.AUTH_STORAGE_ADAPTER && canonicalDatabaseUrl)) {
    return new PostgresStorageAdapter(getAuthPrismaClient());
  }
  return new SqliteStorageAdapter(getDbPath());
}

export function createDefaultRefreshTokenStore() {
  const canonicalDatabaseUrl = String(
    process.env.DATABASE_URL || process.env.VVAULT_BODY_DATABASE_URL || '',
  ).trim();
  if (canonicalDatabaseUrl && !process.env.DATABASE_URL) {
    process.env.DATABASE_URL = canonicalDatabaseUrl;
  }
  return process.env.AUTH_STORAGE_ADAPTER === 'postgres' || (!process.env.AUTH_STORAGE_ADAPTER && canonicalDatabaseUrl)
    ? new PostgresRefreshTokenStore(getAuthPrismaClient())
    : new MemoryRefreshTokenStore();
}

async function resolveCanonicalVvaultOwnerId(email: string, providerIdentity?: VerifiedProviderIdentity): Promise<string | null> {
  try {
    const client = getCanonicalOwnerPrismaClient();
    if (!client) return null;
    return await resolveCanonicalOwner(email, (sql, ...parameters) => client.$queryRawUnsafe(sql, ...parameters), providerIdentity);
  } catch { return null; }
}

function resolveProviderClients(config: AuthAppConfig, overrides?: Record<string, OAuthProviderClient>) {
  if (overrides) return overrides;
  return {
    google: createGoogleProviderClient(config),
    github: createGitHubProviderClient(config),
  };
}

function buildProviderStatuses(
  config: AuthAppConfig,
  providers: Record<string, OAuthProviderClient>,
): AuthProviderConfig[] {
  return config.providers.map((provider) => {
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
}

export async function createAuthApp(options: CreateAuthAppOptions = {}) {
  const startupStartedAt = performance.now();
  const logStartupStage = (stage: string) => {
    console.log(`[startup] ${stage}_ms=${(performance.now() - startupStartedAt).toFixed(2)}`);
  };
  const storage = options.storage || createDefaultStorage();
  const magicEmailDelivery = options.magicEmailDelivery || createPostalMagicDelivery();
  const refreshTokenStore = options.refreshTokenStore || createDefaultRefreshTokenStore();
  const ephemeralStore = options.ephemeralStore || createDefaultEphemeralAuthStore();
  const configStore = options.configStore || new FileAppConfigStore();
  const turnstileVerifier = options.turnstileVerifier || verifyTurnstileToken;
  const sessionSecret = options.sessionSecret || getSessionSecret();
  const tokenConfig = resolveJwtTokenConfig(sessionSecret);
  const providerTokenSecret = process.env.AUTH_PROVIDER_TOKEN_SECRET || options.sessionSecret || getProviderTokenSecret();
  const cookieName = options.cookieName || getCookieName();
  const refreshCookieName = getRefreshCookieName();
  const resolveProfile = options.resolveLifeProfile ?? defaultResolveLifeProfile;
  const resolveVvaultOwnerId = options.resolveVvaultOwnerId ?? resolveCanonicalVvaultOwnerId;
  const checkLifeRegistry = options.isEmailInLifeRegistry ?? defaultIsEmailInLifeRegistry;
  const githubFetchImpl = options.githubFetchImpl ?? fetch.bind(globalThis);
  const githubRepoSessions = options.githubRepoSessions ?? new GitHubRepoSessionStore();
  logStartupStage('crypto_session_initialized');

  await storage.initialize();
  await refreshTokenStore.initialize();
  await ephemeralStore.initialize();
  logStartupStage('database_initialized');

  function reqWithOriginHint(req: any, origin?: string) {
    if (!origin) return req;
    return {
      ...req,
      query: {
        ...(req?.query || {}),
        origin,
      },
    };
  }

  async function getConfigForRequest(req: any, originHint?: string) {
    return configStore.getConfig(reqWithOriginHint(req, originHint));
  }

  async function buildSessionForUser(user: StoredUser, providerIdentity?: VerifiedProviderIdentity): Promise<SessionUser> {
    const resolved = await resolveProfile({
      email: user.email,
      displayName: user.displayName,
      cachedLifeUserId: user.lifeUserId,
      cachedSupabaseUserId: user.supabaseUserId,
    });
    const vvaultOwnerId = await resolveVvaultOwnerId(user.email, providerIdentity);
    await storage.updateUserLifeAnchors(user.id, resolved.lifeUserId, resolved.supabaseUserId);
    const uid = resolved.supabaseUserId || resolved.lifeUserId;
    const ageAssurance = ['adult', 'minor', 'unknown'].includes(String(user.ageAssurance || ''))
      ? user.ageAssurance
      : undefined;
    const canonicalOwnerEvidenceSource = vvaultOwnerId ? 'ovvaults_user' as const : null;
    const canonicalOwnerId = vvaultOwnerId;
    const canonicalOwnerReady = Boolean(canonicalOwnerEvidenceSource);
    return {
      ...(providerIdentity ? { providerIdentity } : {}),
      id: resolved.lifeUserId,
      sub: resolved.lifeUserId,
      uid,
      lifeUserId: resolved.lifeUserId,
      ...(canonicalOwnerId ? { vvaultUserId: canonicalOwnerId } : {}),
      ...(resolved.supabaseUserId ? { supabaseUserId: resolved.supabaseUserId } : {}),
      email: user.email,
      name: user.displayName,
      picture: user.avatarUrl || undefined,
      auth_provider: user.authProvider,
      ...(canonicalOwnerReady ? {
        actorAttestation: {
          version: 'life-auth-actor-attestation/v1',
          subject: resolved.lifeUserId,
          vvaultOwnerId: canonicalOwnerId!,
          issuer: 'quantum-auth',
          ...(ageAssurance ? { ageAssurance } : {}),
        },
      } : {}),
      accountContextReadiness: canonicalOwnerEvidenceSource ? {
        version: 'life-auth-account-context-readiness/v1',
        ready: true,
        subject: resolved.lifeUserId,
        reason: 'canonical_owner_verified',
        vvaultOwnerId: canonicalOwnerId!,
        evidenceSource: canonicalOwnerEvidenceSource,
      } : {
        version: 'life-auth-account-context-readiness/v1',
        ready: false,
        subject: resolved.lifeUserId,
        reason: 'canonical_owner_unverified',
      },
    };
  }

  async function issueTokenPairForUser(
    req: any,
    config: AuthAppConfig,
    user: StoredUser,
    sessionUser: SessionUser,
    clientId?: string,
  ) {
    const sessionId = crypto.randomUUID();
    const refreshTokenId = crypto.randomUUID();
    const metadata = requestMetadataHashes(req, tokenConfig);
    const refreshToken = await createRefreshToken(user.id, sessionId, tokenConfig, clientId, sessionUser.providerIdentity);
    const refreshTokenHash = hashRefreshToken(refreshToken.token, tokenConfig);
    await refreshTokenStore.createSession({
      sessionId,
      userId: user.id,
      appId: config.app.id,
      refreshTokenId,
      refreshTokenJti: refreshToken.jti,
      refreshTokenHash,
      refreshExpiresAt: refreshToken.expiresAt,
      requestId: req._rid || null,
      ...metadata,
    });
    // Browser app identity and registered OAuth client identity are resolved
    // server-side. Never accept a relying party from request input.
    const relyingPartyId = clientId === 'chatty-cli'
      ? 'chatty-cli'
      : config.app.id === 'chatty'
        ? 'chatty'
        : config.app.id === 'vvault'
          ? 'vvault'
          : undefined;
    const accessToken = await createAccessToken(sessionUser, sessionId, tokenConfig, relyingPartyId);
    return {
      accessToken: accessToken.token,
      accessJti: accessToken.jti,
      accessExp: accessToken.exp,
      refreshToken: refreshToken.token,
      sessionId,
      refreshTokenHash,
    };
  }

  async function cacheSessionRevoked(sessionId: string) {
    try {
      await ephemeralStore.setRevokedSession(sessionId, tokenConfig.refreshTtlSeconds);
    } catch (error) {
      console.warn('⚠️ [Auth] session revocation cache unavailable', {
        failureClass: 'session_revocation_cache_unavailable',
        errorClass: error instanceof Error ? error.name || 'Error' : typeof error,
        errorMessage: error instanceof Error ? error.message : String(error),
      });
    }
  }

  async function revokeSessionFromRequest(req: any, reason: string) {
    const cookies = parseCookieHeader(req.headers.cookie);
    const accessToken = cookies[cookieName];
    const refreshToken = cookies[refreshCookieName];
    let sessionId: string | null = null;
    if (accessToken) {
      const verifiedAccess = await verifyAccessToken(accessToken, tokenConfig);
      if (verifiedAccess) {
        sessionId = verifiedAccess.sessionId;
        const accessTtl = Math.max(1, verifiedAccess.exp - Math.floor(Date.now() / 1000));
        await ephemeralStore.setRevokedAccess(verifiedAccess.jti, accessTtl).catch((error) => {
          console.warn('⚠️ [Auth] access revocation cache unavailable', {
            failureClass: 'access_revocation_cache_unavailable',
            errorClass: error instanceof Error ? error.name || 'Error' : typeof error,
            errorMessage: error instanceof Error ? error.message : String(error),
          });
        });
      }
    }
    if (!sessionId && refreshToken) {
      const verifiedRefresh = await verifyRefreshToken(refreshToken, tokenConfig);
      sessionId = verifiedRefresh?.sessionId || null;
    }
    if (!sessionId) return;
    await refreshTokenStore.revokeSession(sessionId, reason, req._rid || null);
    await cacheSessionRevoked(sessionId);
  }

  async function refreshSessionForRequest(session: SessionUser) {
    const storedUser = await storage.findUserByEmail(session.email);
    if (!storedUser) return { session, refreshed: false };

    const nextSession = {
      ...await buildSessionForUser(storedUser, session.providerIdentity),
      // Preserve the relying party already verified from the access token.
      // Profile refresh cannot derive it from account or owner records.
      ...(session.relyingPartyId ? { relyingPartyId: session.relyingPartyId } : {}),
    };
    const refreshed = nextSession.id !== session.id
      || nextSession.sub !== session.sub
      || nextSession.uid !== session.uid
      || nextSession.vvaultUserId !== session.vvaultUserId
      || nextSession.name !== session.name
      || nextSession.picture !== session.picture
      || nextSession.auth_provider !== session.auth_provider
      || JSON.stringify(nextSession.actorAttestation) !== JSON.stringify(session.actorAttestation)
      || JSON.stringify(nextSession.accountContextReadiness) !== JSON.stringify(session.accountContextReadiness);
    return { session: nextSession, refreshed };
  }

  const app = express();
  app.disable('x-powered-by');
  app.set('trust proxy', 1);
  app.use(express.json({ limit: '12mb' }));
  app.use(express.urlencoded({ extended: false }));
  app.use((req, _res, next) => {
    req._rid = crypto.randomBytes(8).toString('hex');
    next();
  });
  app.use(async (req, res, next) => {
    if (req.path === '/health' || req.path === '/ready') {
      return next();
    }
    try {
      const config = await getConfigForRequest(req);
      applyCorsHeaders(req, res, config);
      if (req.method === 'OPTIONS') {
        return res.sendStatus(204);
      }
      return next();
    } catch (error) {
      if (error instanceof AuthConfigSelectionError) {
        return res.status(error.status).json({
          ok: false,
          error: error.code,
          message: error.message,
        });
      }
      return next(error);
    }
  });

  app.get('/health', (_req, res) => {
    res.json({ ok: true, service: 'auth' });
  });
  app.get('/ready', (_req, res) => {
    res.json({ ok: true, ready: true, service: 'auth' });
  });
  app.get('/favicon.ico', (_req, res) => res.status(204).send());
  logStartupStage('middleware_initialized');

  const oauthError = (res: any, status: number, error: string, description?: string) =>
    res.status(status).json({ error, ...(description ? { error_description: description } : {}) });
  const authorizationRequestKey = (id: string) => `auth:authorization-request:${id}`;
  const authorizationCodeKey = (code: string) => `auth:authorization-code:${code}`;
  const federationAssertionKey = (id: string) => `auth:federation-assertion:${id}`;
  const federationNonceKey = (productId: string, nonce: string) => `auth:federation-nonce:${productId}:${nonce}`;

  async function redirectWithAuthorizationCode(res: any, record: AuthorizationRequestRecord, userId: string, providerIdentity?: VerifiedProviderIdentity) {
    const code = crypto.randomBytes(32).toString('base64url');
    await ephemeralStore.setJson(authorizationCodeKey(code), {
      ...record,
      userId,
      ...(providerIdentity ? { providerIdentity } : {}),
      createdAt: Date.now(),
    } satisfies AuthorizationCodeRecord, AUTHORIZATION_CODE_TTL_SECONDS);
    return res.redirect(appendAuthorizationResult(record.redirectUri, { code, state: record.state }));
  }

  async function completeAuthorization(req: any, res: any, requestId: string, browserBinding?: string) {
    const record = await ephemeralStore.takeJson<NativeAuthorizationRequestRecord>(authorizationRequestKey(requestId));
    if (!record || Date.now() - record.createdAt > AUTHORIZATION_REQUEST_TTL_SECONDS * 1000) {
      return oauthError(res, 400, 'invalid_request', 'Authorization request is invalid or expired');
    }
    const config = await configStore.getConfig({ query: { app: record.appId }, headers: {} });
    const client = findPublicClient(config, record.clientId);
    if (!client || !validateRedirectUri(client, record.redirectUri)) {
      return oauthError(res, 400, 'invalid_request', 'Client registration changed');
    }
    const authSession = (record.forceReauthentication || record.identityAuthority==='vvault')
      ? {status:401,error:'Fresh authentication required'}
      : await readAuthSession(req, cookieName, tokenConfig, refreshTokenStore, ephemeralStore);
    if ('error' in authSession) {
      await ephemeralStore.setJson(authorizationRequestKey(requestId), record, AUTHORIZATION_REQUEST_TTL_SECONDS);
      if (browserBinding && record.federationBrowserBindingHash) {
        res.append(
          'Set-Cookie',
          createFederationBrowserBindingCookie(req, requestId, browserBinding),
        );
      }
      const loginUrl = record.identityAuthority==='vvault'
        ? new URL('/api/auth/chatty/authorize',process.env.AUTH_ENROLLMENT_AUTHORITY_ORIGIN)
        : record.nativeProvider
          ? new URL(`/api/auth/${encodeURIComponent(record.nativeProvider)}`, resolveHostedOrigin(req))
          : new URL(client.authorizationUiUrl);
      loginUrl.searchParams.set('authorization_request', requestId);
      loginUrl.searchParams.set('authorization_return', `${resolveAuthorizationOrigin()}/oauth/authorize/complete`);
      return res.redirect(loginUrl.toString());
    }
    const user = await storage.findUserByEmail(authSession.session.email);
    if (!user) return oauthError(res, 401, 'access_denied', 'Authenticated user no longer exists');
    return redirectWithAuthorizationCode(res, record, user.id, authSession.session.providerIdentity);
  }

  app.get('/oauth/authorize', async (req, res) => {
    const config = await getConfigForRequest(req);
    const responseType = String(req.query.response_type || '');
    const clientId = String(req.query.client_id || '');
    const redirectUri = String(req.query.redirect_uri || '');
    const state = String(req.query.state || '');
    const challenge = String(req.query.code_challenge || '');
    const challengeMethod = String(req.query.code_challenge_method || '');
    const requestedScope = String(req.query.scope || 'openid profile email').trim();
    const client = findPublicClient(config, clientId);
    if (!client) return oauthError(res, 400, 'unauthorized_client');
    const validatedRedirect = validateRedirectUri(client, redirectUri);
    if (!validatedRedirect) return oauthError(res, 400, 'invalid_request', 'redirect_uri is not registered');
    if (responseType !== 'code' || challengeMethod !== 'S256' || !isValidS256Challenge(challenge) || !isValidOpaqueState(state)) {
      return oauthError(res, 400, 'invalid_request', 'response_type, state, and S256 PKCE are required');
    }
    const allowedScopes = new Set(client.scopes || ['openid', 'profile', 'email']);
    if (requestedScope.split(/\s+/).some((scope) => !allowedScopes.has(scope))) {
      return oauthError(res, 400, 'invalid_scope');
    }
    if(req.query.identity_authority==='vvault'){
      try {const authority=new URL(process.env.AUTH_ENROLLMENT_AUTHORITY_ORIGIN || '');if(config.app.id!=='chatty'||clientId!=='chatty-web-link'||authority.username||authority.password||authority.origin!==String(process.env.AUTH_ENROLLMENT_AUTHORITY_ORIGIN).replace(/\/$/,'')||(authority.protocol!=='https:'&&!(authority.protocol==='http:'&&['localhost','127.0.0.1'].includes(authority.hostname))))return oauthError(res,400,'invalid_identity_authority');}catch{return oauthError(res,503,'identity_authority_unavailable');}
    }
    const requestedProvider = String(req.query.provider || '').trim().toLowerCase();
    if (requestedProvider) {
      const configuredProvider = config.providers.find((provider) => provider.provider === requestedProvider);
      const providerClient = resolveProviderClients(config, options.providers)[requestedProvider];
      if (!configuredProvider || !configuredProvider.enabled || !providerClient?.isConfigured()) {
        return oauthError(res, 503, 'provider_not_configured');
      }
    }
    const acceptedRequiredConsentDocs = req.query.accept_required_consent === 'true'
      ? requiredConsentDocs(config).map<ConsentAcceptance>((doc) => ({
          key: doc.key,
          version: doc.version,
          label: doc.label,
          url: doc.url,
          acceptedAt: new Date().toISOString(),
        }))
      : undefined;
    const requestId = crypto.randomBytes(32).toString('base64url');
    const browserBinding = crypto.randomBytes(32).toString('base64url');
    await ephemeralStore.setJson(authorizationRequestKey(requestId), {
      appId: config.app.id,
      clientId,
      redirectUri: validatedRedirect,
      state,
      codeChallenge: challenge,
      scope: requestedScope,
      createdAt: Date.now(),
      federationBrowserBindingHash: hashFederationBrowserBinding(requestId, browserBinding),
      ...(requestedProvider ? { nativeProvider: requestedProvider } : {}),
      ...(acceptedRequiredConsentDocs ? { acceptedRequiredConsentDocs } : {}),
      ...(req.query.prompt === 'login' ? {forceReauthentication:true} : {}),
      ...(req.query.identity_authority==='vvault' && config.app.id==='chatty' && clientId==='chatty-web-link' ? {identityAuthority:'vvault' as const} : {}),
    } satisfies NativeAuthorizationRequestRecord, AUTHORIZATION_REQUEST_TTL_SECONDS);
    return completeAuthorization(req, res, requestId, browserBinding);
  });

  app.get('/oauth/authorize/complete', async (req, res) =>
    completeAuthorization(req, res, String(req.query.authorization_request || '')));

  app.get('/signin', async (req, res) => {
    const config = await getConfigForRequest(req);
    const requestId = String(req.query.authorization_request || '');
    const authorizationReturn = `${resolveAuthorizationOrigin()}/oauth/authorize/complete`;
    if (!/^[A-Za-z0-9_-]{24,128}$/.test(requestId)
      || (req.query.authorization_return !== undefined && String(req.query.authorization_return) !== authorizationReturn)) {
      return oauthError(res, 400, 'invalid_authorization_request');
    }
    const pending = await ephemeralStore.getJson<AuthorizationRequestRecord>(authorizationRequestKey(requestId));
    if (!pending || pending.appId !== config.app.id || Date.now() - pending.createdAt > AUTHORIZATION_REQUEST_TTL_SECONDS * 1000) {
      return oauthError(res, 400, 'invalid_authorization_request');
    }
    const client = findPublicClient(config, pending.clientId);
    if (!client || !validateRedirectUri(client, pending.redirectUri)) {
      return oauthError(res, 400, 'invalid_authorization_request');
    }
    const providers = resolveProviderClients(config, options.providers);
    const providerStatuses = buildProviderStatuses(config, providers);
    const consentRequired = String(req.query.reason || '') === 'missing_consent';
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
    return res.type('html').send(renderHostedAuthorizationPage({
      config,
      providers: providerStatuses,
      authorizationRequest: requestId,
      authorizationReturn,
      consentRequired,
    }));
  });

  app.post('/oauth/federation/assertions', async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    if (req.body?.authority_proof !== undefined) {
      try {
        const proof=verifyVvaultSessionProof(req.body.authority_proof,{publicKeyPem:process.env.AUTH_ENROLLMENT_AUTHORITY_PUBLIC_KEY_PEM || '',issuer:process.env.AUTH_ENROLLMENT_AUTHORITY_ISSUER || 'vvault',audience:process.env.AUTH_JWT_ISSUER || 'quantum-auth'});
        const pending=await ephemeralStore.getJson<AuthorizationRequestRecord>(authorizationRequestKey(proof.authorization_request));
        if(!pending || pending.identityAuthority!=='vvault' || pending.appId!=='chatty' || pending.clientId!==proof.client_id)return oauthError(res,400,'invalid_authorization_request');
        const config=await configStore.getConfig({query:{app:'chatty'},headers:{}});
        const client=findPublicClient(config,pending.clientId);
        if(!client || !validateRedirectUri(client,pending.redirectUri))return oauthError(res,400,'invalid_authorization_request');
        if(!await verifyChattyConsentManifest(proof.chattyConsents,client.authorizationUiUrl))return oauthError(res,409,'product_consent_required');
        const docs=requiredConsentDocs(config);
        if(docs.length!==3 || !docs.every(doc=>proof.chattyConsents.some((r:any)=>r.key===doc.key && r.version===(process.env[`LEGAL_VERSION_CHATTY_${doc.key.split(':')[1]?.toUpperCase()}`] || doc.version))))return oauthError(res,409,'product_consent_required');
        const owner=await resolveVvaultOwnerId(proof.email,proof.provider_identity);
        if(owner!==proof.ownerId)return oauthError(res,409,'canonical_owner_mismatch');
        const authorityOrigin=new URL(process.env.AUTH_ENROLLMENT_AUTHORITY_ORIGIN || '');
        if(authorityOrigin.origin!==String(process.env.AUTH_ENROLLMENT_AUTHORITY_ORIGIN).replace(/\/$/,''))return oauthError(res,503,'federation_unavailable');
        if(!await ephemeralStore.setIfNotExists(federationNonceKey('vvault',proof.nonce),'1',60))return oauthError(res,409,'assertion_replayed');
        if(proof.expiresAt<=Math.floor(Date.now()/1000))return oauthError(res,401,'invalid_authority_assertion');
        const assertionId=crypto.randomBytes(32).toString('base64url');
        await ephemeralStore.setJson(federationAssertionKey(assertionId),{
          product_id:'chatty',authorization_request:proof.authorization_request,subject:proof.provider_identity.subject,email:proof.email,name:proof.name,
          provider_identity:proof.provider_identity,issued_at:proof.issuedAt,expires_at:proof.expiresAt,nonce:proof.nonce,createdAt:Date.now(),
          authorityOrigin:authorityOrigin.origin,canonicalOwnerId:proof.ownerId,chattyConsents:proof.chattyConsents,
        } satisfies ProductSessionAssertionRecord,Math.max(1,proof.expiresAt-Math.floor(Date.now()/1000)));
        return res.status(201).json({assertion_id:assertionId,completion_endpoint:'/oauth/federation/complete',expires_in:Math.max(1,proof.expiresAt-Math.floor(Date.now()/1000))});
      }catch{return oauthError(res,401,'invalid_authority_assertion');}
    }
    const input = req.body as ProductSessionAssertionInput;
    // Native email identity is attested only by the pinned VVAULT signer.
    if (input?.provider_identity?.provider === 'email') return oauthError(res, 401, 'invalid_assertion');
    const config = await getConfigForRequest(req);
    const federation = config.sessionFederation;
    if (!federation?.enabled || config.app.id !== input?.product_id) {
      return oauthError(res, 403, 'invalid_product');
    }
    const secret = String(process.env[federation.assertionSecretEnv] || '');
    if (!isValidProductSessionFederationSecret(secret)) {
      return oauthError(res, 503, 'federation_unavailable');
    }
    if (!validateProductSessionAssertion(input) || !verifyProductSessionAssertionSignature(input, String(req.get('x-auth-assertion-signature') || ''), secret)) {
      return oauthError(res, 401, 'invalid_assertion');
    }
    const pending = await ephemeralStore.getJson<AuthorizationRequestRecord>(authorizationRequestKey(input.authorization_request));
    if (!pending || pending.identityAuthority === 'vvault' || pending.appId !== input.product_id) {
      return oauthError(res, 400, 'invalid_authorization_request');
    }
    const nonceAccepted = await ephemeralStore.setIfNotExists(
      federationNonceKey(input.product_id, input.nonce),
      '1',
      FEDERATION_ASSERTION_TTL_SECONDS,
    );
    if (!nonceAccepted) return oauthError(res, 409, 'assertion_replayed');
    const assertionId = crypto.randomBytes(32).toString('base64url');
    await ephemeralStore.setJson(federationAssertionKey(assertionId), {
      ...input,
      createdAt: Date.now(),
    } satisfies ProductSessionAssertionRecord, Math.max(1, input.expires_at - Math.floor(Date.now() / 1000)));
    return res.status(201).json({
      assertion_id: assertionId,
      completion_endpoint: '/oauth/federation/complete',
      expires_in: Math.max(1, input.expires_at - Math.floor(Date.now() / 1000)),
    });
  });

  app.post('/oauth/federation/complete', async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    const rejectAssertion=(reason:string)=>{console.warn('[auth] federation completion rejected',{reason});return oauthError(res,400,'invalid_assertion',reason);};
    const assertionId = String(req.body?.assertion_id || '');
    const assertion = assertionId
      ? await ephemeralStore.getJson<ProductSessionAssertionRecord>(federationAssertionKey(assertionId))
      : null;
    if (!assertionId) return rejectAssertion('ASSERTION_REFERENCE_MISSING');
    if (!assertion) return rejectAssertion('ASSERTION_REFERENCE_UNKNOWN_EXPIRED_OR_CONSUMED');
    if (assertion.expires_at <= Math.floor(Date.now() / 1000)) return rejectAssertion('ASSERTION_EXPIRED');
    const pending = await ephemeralStore.getJson<AuthorizationRequestRecord>(authorizationRequestKey(assertion.authorization_request));
    if (!pending || pending.appId !== assertion.product_id) {
      return oauthError(res, 400, 'invalid_authorization_request');
    }
    const config = await configStore.getConfig({ query: { app: assertion.product_id }, headers: {} });
    const client = findPublicClient(config, pending.clientId);
    if (!client || !validateRedirectUri(client, pending.redirectUri)) {
      return oauthError(res, 400, 'invalid_authorization_request');
    }
    if (!federationCompletionOriginMatches(req, assertion.authorityOrigin || client.authorizationUiUrl)) {
      return oauthError(res, 403, 'invalid_federation_origin');
    }
    if (!verifyFederationBrowserBinding(
      req,
      assertion.authorization_request,
      pending.federationBrowserBindingHash,
    )) {
      return oauthError(res, 400, 'invalid_browser_binding');
    }
    const consumedAssertion = await ephemeralStore.takeJson<ProductSessionAssertionRecord>(
      federationAssertionKey(assertionId),
    );
    if (!consumedAssertion) return rejectAssertion('ASSERTION_ALREADY_CONSUMED');
    if (consumedAssertion.expires_at <= Math.floor(Date.now() / 1000)) return rejectAssertion('ASSERTION_EXPIRED_AT_CONSUMPTION');
    if (
      consumedAssertion.authorization_request !== assertion.authorization_request
      || consumedAssertion.product_id !== assertion.product_id
    ) {
      return rejectAssertion('ASSERTION_TRANSACTION_CONFLICT');
    }
    const consumedPending = await ephemeralStore.takeJson<AuthorizationRequestRecord>(
      authorizationRequestKey(consumedAssertion.authorization_request),
    );
    if (!consumedPending || consumedPending.appId !== consumedAssertion.product_id) {
      return oauthError(res, 400, 'invalid_authorization_request');
    }
    if (!verifyFederationBrowserBinding(
      req,
      consumedAssertion.authorization_request,
      consumedPending.federationBrowserBindingHash,
    )) {
      return oauthError(res, 400, 'invalid_browser_binding');
    }
    if(consumedAssertion.canonicalOwnerId){
      const owner=await resolveVvaultOwnerId(consumedAssertion.email,consumedAssertion.provider_identity);
      if(owner!==consumedAssertion.canonicalOwnerId)return oauthError(res,409,'canonical_owner_mismatch');
      if(!await verifyChattyConsentManifest(consumedAssertion.chattyConsents || [],client.authorizationUiUrl))return oauthError(res,409,'product_consent_required');
      if(consumedAssertion.expires_at<=Math.floor(Date.now()/1000))return oauthError(res,401,'invalid_authority_assertion');
      const docs=requiredConsentDocs(config);
      if(docs.length!==3 || !docs.every(doc=>consumedAssertion.chattyConsents?.some(r=>r.key===doc.key && r.version===(process.env[`LEGAL_VERSION_CHATTY_${doc.key.split(':')[1]?.toUpperCase()}`] || doc.version))))return oauthError(res,409,'product_consent_required');
    }
    const user = await storage.upsertOAuthUser({
      provider: `federation:${consumedAssertion.product_id}`,
      providerUserId: consumedAssertion.subject,
      email: consumedAssertion.email.trim().toLowerCase(),
      displayName: consumedAssertion.name.trim(),
      avatarUrl: consumedAssertion.picture || null,
      profile: { issuer: consumedAssertion.product_id, subject: consumedAssertion.subject },
    });
    if(consumedAssertion.canonicalOwnerId){
      const docs=requiredConsentDocs(config);
      await storage.replaceConsentAcceptances(user.id,config.app.id,docs.map(doc=>{const receipt=consumedAssertion.chattyConsents!.find(r=>r.key===doc.key)!;return {key:doc.key,version:receipt.version,label:doc.label,url:doc.url,acceptedAt:receipt.acceptedAt};}));
    }
    const sessionUser = await buildSessionForUser(user, consumedAssertion.provider_identity);
    const tokens = await issueTokenPairForUser(req, config, user, sessionUser);
    res.setHeader('Set-Cookie', [
      createFederationBrowserBindingCookie(
        req,
        consumedAssertion.authorization_request,
        '',
        0,
      ),
      ...createHostedTokenCookies(req, cookieName, refreshCookieName, tokens, tokenConfig),
    ]);
    await storage.updateUserLogin(user.id);
    return redirectWithAuthorizationCode(res, consumedPending, user.id, sessionUser.providerIdentity);
  });

  app.post('/oauth/token', async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Pragma', 'no-cache');
    const grantType = String(req.body?.grant_type || '');
    if (grantType === 'authorization_code') {
      const code = String(req.body?.code || '');
      const record = code ? await ephemeralStore.takeJson<AuthorizationCodeRecord>(authorizationCodeKey(code)) : null;
      if (!record || Date.now() - record.createdAt > AUTHORIZATION_CODE_TTL_SECONDS * 1000) {
        return oauthError(res, 400, 'invalid_grant');
      }
      if (record.clientId !== String(req.body?.client_id || '') || record.redirectUri !== String(req.body?.redirect_uri || '') || !verifyS256(String(req.body?.code_verifier || ''), record.codeChallenge)) {
        return oauthError(res, 400, 'invalid_grant');
      }
      const config = await configStore.getConfig({ query: { app: record.appId }, headers: {} });
      const user = await storage.findUserById(record.userId);
      if (!user) return oauthError(res, 400, 'invalid_grant');
      const sessionUser = await buildSessionForUser(user, record.providerIdentity);
      const tokens = await issueTokenPairForUser(req, config, user, sessionUser, record.clientId);
      return res.json({
        access_token: tokens.accessToken,
        refresh_token: tokens.refreshToken,
        token_type: 'Bearer',
        expires_in: tokenConfig.accessTtlSeconds,
        scope: record.scope,
      });
    }
    if (grantType === 'refresh_token') {
      try {
        const raw = String(req.body?.refresh_token || '');
        const verified = await verifyRefreshToken(raw, tokenConfig);
        if (!verified) return oauthError(res, 400, 'invalid_grant');
        if (!verified.clientId || verified.clientId !== String(req.body?.client_id || '')) return oauthError(res, 400, 'invalid_grant');
        const user = await storage.findUserById(verified.userId);
        if (!user) return oauthError(res, 400, 'invalid_grant');
        const newRefresh = await createRefreshToken(user.id, verified.sessionId, tokenConfig, verified.clientId, verified.providerIdentity);
        const rotation = await refreshTokenStore.rotateRefreshToken({
          sessionId: verified.sessionId,
          userId: user.id,
          presentedTokenJti: verified.jti,
          presentedTokenHash: hashRefreshToken(raw, tokenConfig),
          newRefreshTokenId: crypto.randomUUID(),
          newRefreshTokenJti: newRefresh.jti,
          newRefreshTokenHash: hashRefreshToken(newRefresh.token, tokenConfig),
          newRefreshExpiresAt: newRefresh.expiresAt,
          requestId: req._rid || null,
          ...requestMetadataHashes(req, tokenConfig),
        });
        if (!rotation.ok) {
          if (rotation.sessionId) await cacheSessionRevoked(rotation.sessionId);
          return oauthError(res, 400, 'invalid_grant');
        }
        const access = await createAccessToken(
          await buildSessionForUser(user, verified.providerIdentity), verified.sessionId, tokenConfig,
          verified.clientId === 'chatty-cli' ? 'chatty-cli' : undefined,
        );
        return res.json({ access_token: access.token, refresh_token: newRefresh.token, token_type: 'Bearer', expires_in: tokenConfig.accessTtlSeconds });
      } catch (error) {
        console.warn('[Auth] native refresh temporarily unavailable', {
          requestPath: '/oauth/token',
          failureClass: 'refresh_exception',
          errorClass: error instanceof Error ? error.name || 'Error' : typeof error,
          errorCode:
            error && typeof error === 'object' && 'code' in error
              ? String((error as { code?: unknown }).code || 'unknown')
              : 'unknown',
          databaseError:
            error && typeof error === 'object' && 'meta' in error
              ? String(((error as { meta?: { message?: unknown } }).meta?.message) || 'unknown')
              : 'unknown',
        });
        return oauthError(
          res,
          503,
          'temporarily_unavailable',
          'Refresh session is temporarily unavailable',
        );
      }
    }
    return oauthError(res, 400, 'unsupported_grant_type');
  });

  app.post('/oauth/revoke', async (req, res) => {
    const token = String(req.body?.token || '');
    const access = await verifyAccessToken(token, tokenConfig);
    const refresh = access ? null : await verifyRefreshToken(token, tokenConfig);
    const sessionId = access?.sessionId || refresh?.sessionId;
    if (access) await ephemeralStore.setRevokedAccess(access.jti, Math.max(1, access.exp - Math.floor(Date.now() / 1000)));
    if (sessionId) {
      await refreshTokenStore.revokeSession(sessionId, 'client_revocation', req._rid || null);
      await cacheSessionRevoked(sessionId);
    }
    return res.status(200).send('');
  });

  app.get('/oauth/userinfo', async (req, res) => {
    const header = String(req.get('authorization') || '');
    const token = header.startsWith('Bearer ') ? header.slice(7).trim() : '';
    const verified = token ? await verifyAccessToken(token, tokenConfig) : null;
    if (!verified || await ephemeralStore.isAccessRevoked(verified.jti) || await ephemeralStore.isSessionRevoked(verified.sessionId) || await refreshTokenStore.getSessionStatus(verified.sessionId) !== 'active') {
      res.setHeader('WWW-Authenticate', 'Bearer error="invalid_token"');
      return oauthError(res, 401, 'invalid_token');
    }
    return res.json({
      sub: verified.session.sub,
      uid: verified.session.uid,
      email: verified.session.email,
      name: verified.session.name,
      picture: verified.session.picture,
      account_context_readiness: verified.session.accountContextReadiness,
    });
  });

  app.get('/', async (req, res) => {
    const config = await getConfigForRequest(req);
    const selectedOrigin = resolveConsumerOrigin(req, config);

    res.status(410).json({
      ok: false,
      error: 'auth_frontend_removed',
      message:
        'AUTH HAS NO FRONTEND. This service does not serve login, signup, consent, or account screens. Build and route those screens in the consuming app.',
      app: config.app,
      consumerOrigin: selectedOrigin,
      useTheseApiSurfaces: [
        '/api/auth/config',
        '/api/auth/login',
        '/api/auth/register',
        '/api/auth/:provider',
        '/api/auth/:provider/callback',
        '/api/me',
        '/api/auth/vvault-account-assertion',
        '/api/auth/logout',
      ],
    });
  });

  app.get('/api/me', async (req, res) => {
    const authSession = await readAuthSession(req, cookieName, tokenConfig, refreshTokenStore, ephemeralStore);
    if ('error' in authSession) {
      return res.status(authSession.status).json({ ok: false, error: authSession.error });
    }

    if (!sessionNeedsRefresh(authSession.session)) {
      logAuthApiMeIdentityDiagnostics(req, authSession.session, {
        refreshRan: false,
        refreshChanged: false,
      });
      return res.json({ ok: true, user: authSession.session });
    }

    const refreshStartedAt = Date.now();
    try {
      const refreshed = await refreshSessionForRequest(authSession.session);
      if (refreshed.refreshed) {
        const accessToken = await createAccessToken(
          refreshed.session, authSession.sessionId, tokenConfig, authSession.session.relyingPartyId,
        );
        res.setHeader(
          'Set-Cookie',
          createHostedSessionCookie(
            req,
            cookieName,
            accessToken.token,
            tokenConfig,
          ),
        );
      }
      logAuthApiMeIdentityDiagnostics(req, refreshed.session, {
        refreshRan: true,
        refreshChanged: refreshed.refreshed,
      });
      return res.json({ ok: true, user: refreshed.session });
    } catch (error) {
      logAuthApiMeIdentityDiagnostics(req, authSession.session, {
        refreshRan: true,
        refreshChanged: false,
        refreshFailed: true,
      });
      console.warn('⚠️ [Auth] /api/me refresh fallback', {
        requestPath: '/api/me',
        email: authSession.session.email || null,
        sessionUidState: describeSessionUidState(authSession.session),
        elapsedMs: Date.now() - refreshStartedAt,
        failureClass: 'refresh_exception',
        errorClass: error instanceof Error ? error.name || 'Error' : typeof error,
        errorMessage: error instanceof Error ? error.message : String(error),
      });
      return res.json({ ok: true, user: authSession.session });
    }
  });

  app.post('/api/auth/vvault-account-assertion', async (req, res) => {
    const authSession = await readAuthSession(req, cookieName, tokenConfig, refreshTokenStore, ephemeralStore);
    if ('error' in authSession) {
      return res.status(authSession.status).json({ ok: false, error: authSession.error });
    }
    if (!authSession.session.accountContextReadiness?.ready) {
      return res.status(409).json({
        ok: false,
        error: 'Canonical VVAULT owner binding is required',
        errorCode: 'CANONICAL_OWNER_UNVERIFIED',
        readiness: authSession.session.accountContextReadiness,
      });
    }
    const assertionConfig = resolveAccountContextAssertionConfig();
    if (!assertionConfig) {
      return res.status(503).json({
        ok: false,
        error: 'VVAULT account-context assertion signing key is not configured',
        errorCode: 'VVAULT_ACCOUNT_ASSERTION_SIGNING_KEY_MISSING',
        readiness: authSession.session.accountContextReadiness,
      });
    }
    try {
      const issued = await createAccountContextAssertion(
        authSession.session,
        authSession.sessionId,
        assertionConfig,
      );
      return res.json({
        ok: true,
        assertion: issued.token,
        accountContext: accountContextProfileForSession(authSession.session),
        readiness: authSession.session.accountContextReadiness,
        expiresAt: issued.assertion.expiresAt,
      });
    } catch {
      return res.status(409).json({
        ok: false,
        error: 'Canonical VVAULT owner binding is required',
        errorCode: 'CANONICAL_OWNER_UNVERIFIED',
        readiness: authSession.session.accountContextReadiness,
      });
    }
  });

  mountEnrollmentHost(app, req => readAuthSession(req, cookieName, tokenConfig, refreshTokenStore, ephemeralStore), createEnrollmentConsent(storage, configStore));

  app.post('/api/auth/vvault-access-assertion', async (req, res) => {
    if (req.get('X-Chatty-Auth-Bridge') !== 'vvault-access-assertion/v2') {
      return res.status(403).json({
        ok: false,
        error: 'Trusted Chatty assertion request header is required',
        errorCode: 'ACCESS_ASSERTION_REQUEST_REJECTED',
      });
    }
    const authSession = await readAuthSession(req, cookieName, tokenConfig, refreshTokenStore, ephemeralStore);
    if ('error' in authSession) {
      return res.status(authSession.status).json({
        ok: false,
        error: authSession.error,
        errorCode: 'AUTH_SESSION_REQUIRED',
      });
    }
    const assertionConfig = resolveVvaultAccessAssertionConfig();
    if (!assertionConfig) {
      return res.status(503).json({
        ok: false,
        error: 'VVAULT access-assertion signing key is not configured',
        errorCode: 'ACCESS_ASSERTION_UNAVAILABLE',
      });
    }
    try {
      const relyingPartyId = authSession.session.relyingPartyId === 'chatty-cli' ? 'chatty-cli' : 'chatty';
      const issued = await createVvaultAccessAssertion(
        authSession.session,
        authSession.sessionId,
        assertionConfig,
        relyingPartyId,
      );
      return res.json({
        ok: true,
        assertion: issued.token,
        expiresAt: issued.assertion.expiresAt,
        keyId: issued.assertion.keyId,
        scopes: issued.assertion.scopes,
        relyingPartyId: issued.assertion.relyingPartyId,
      });
    } catch {
      return res.status(409).json({
        ok: false,
        error: 'Canonical VVAULT owner binding is required',
        errorCode: 'CANONICAL_OWNER_UNVERIFIED',
      });
    }
  });

  app.post('/api/auth/postgrest-token', async (req, res) => {
    const postgrestJwtSecret = getPostgrestJwtSecret();
    if (!postgrestJwtSecret) {
      return res.status(503).json({
        ok: false,
        error: 'PostgREST JWT secret is not configured',
        errorCode: 'POSTGREST_JWT_SECRET_MISSING',
      });
    }
    if (postgrestJwtSecret === sessionSecret) {
      return res.status(503).json({
        ok: false,
        error: 'PostgREST JWT secret must not reuse the auth session secret',
        errorCode: 'POSTGREST_JWT_SECRET_REUSES_SESSION_SECRET',
      });
    }

    const authSession = await readAuthSession(req, cookieName, tokenConfig, refreshTokenStore, ephemeralStore);
    if ('error' in authSession) {
      return res.status(authSession.status).json({ ok: false, error: authSession.error });
    }

    const supabaseUserId = authSession.session.uid?.trim();
    if (!isSupabaseUuid(supabaseUserId)) {
      return res.status(409).json({
        ok: false,
        error: 'Supabase UUID is required before issuing a PostgREST token',
        errorCode: 'SUPABASE_UID_REQUIRED',
      });
    }

    const ttlSeconds = getPostgrestJwtTtlSeconds();
    const issued = await createPostgrestJwt({
      sub: supabaseUserId,
      email: authSession.session.email,
      role: 'authenticated',
      secret: postgrestJwtSecret,
      ttlSeconds,
    });

    return res.json({
      ok: true,
      token: issued.token,
      exp: issued.claims.exp,
      expiresIn: ttlSeconds,
      tokenType: 'Bearer',
    });
  });

  const sendCodeAskMovedResponse = (res: any) => {
    return res.status(501).json({
      ok: false,
      code: 'CODE_ASK_MOVED_TO_CODE_RUNTIME',
      movedTo: 'code-runtime',
      message: 'Code Ask runtime endpoints moved out of auth and must be served by the Code runtime.',
    });
  };

  if (legacyCodeRoutesEnabled()) {
    app.get('/api/code/ask/status', (_req, res) => {
      return sendCodeAskMovedResponse(res);
    });

    app.post('/api/code/projects/scratch', async (req, res) => {
      const authUser = await readAuthenticatedUser(req, storage, cookieName, tokenConfig, refreshTokenStore, ephemeralStore);
      if ('error' in authUser) {
        return res.status(authUser.status).json({ ok: false, error: authUser.error });
      }

      const name = String(req.body?.name || '').trim();
      if (!name) {
        return res.status(400).json({ ok: false, error: 'Project name is required.' });
      }
      const initialPrompt = String(req.body?.initialPrompt || '').trim() || null;
      const projectSlug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') || 'project';
      const rootPath = typeof req.body?.rootPath === 'string' && req.body.rootPath.trim()
        ? req.body.rootPath.trim()
        : `/workspaces/${projectSlug}`;

      return res.status(201).json({
        ok: true,
        project: {
          rootPath,
          name,
          source: 'generated',
          starterIntent: initialPrompt,
          hydroInterestTags: [],
          hydroInterestSummary: initialPrompt,
          hydroInterestUpdatedAt: initialPrompt ? Date.now() : null,
          createdAt: Date.now(),
          lastOpenedAt: Date.now(),
        },
      });
    });

    app.get('/api/code/ask/thread', (_req, res) => {
      return sendCodeAskMovedResponse(res);
    });

    app.get('/api/code/ask/messages', (_req, res) => {
      return sendCodeAskMovedResponse(res);
    });

    app.post('/api/code/ask/messages', (_req, res) => {
      return sendCodeAskMovedResponse(res);
    });
  }

  app.get('/api/github/status', async (req, res) => {
    const authContext = await readAuthenticatedUser(req, storage, cookieName, tokenConfig, refreshTokenStore, ephemeralStore);
    if ('error' in authContext) {
      return res.status(authContext.status).json({ ok: false, error: authContext.error });
    }
    const githubAccount = await storage.findProviderAccount(authContext.user.id, 'github');
    if (!githubAccount?.accessTokenEncrypted) {
      return res.json({ connected: false });
    }
    return res.json(githubConnectionPayload(githubAccount));
  });

  app.post('/api/github/connect', async (req, res) => {
    const authContext = await readAuthenticatedUser(req, storage, cookieName, tokenConfig, refreshTokenStore, ephemeralStore);
    if ('error' in authContext) {
      return res.status(authContext.status).json({ ok: false, error: authContext.error });
    }

    const existing = await storage.findProviderAccount(authContext.user.id, 'github');
    if (existing?.accessTokenEncrypted) {
      return res.json(githubConnectionPayload(existing));
    }

    const config = await getConfigForRequest(req);
    const githubProvider = config.providers.find((provider) => provider.provider === 'github');
    if (!githubProvider || !githubProvider.enabled) {
      return res.status(404).json({ ok: false, error: 'GitHub repo access is not available for this app.' });
    }

    const originSelection = resolveStrictOAuthStartOrigin(req, config);
    if ('error' in originSelection) {
      return res.status(403).json({ ok: false, error: originSelection.error });
    }

    const { clientId, clientSecret, callbackUrl: configuredCallbackUrl } = resolveGitHubOAuthCredentials(config);
    let callbackUrl = configuredCallbackUrl;
    try {
      callbackUrl = callbackUrl || resolveCallbackUrl(req, config, 'github', originSelection.origin);
    } catch (error) {
      return res.status((error as any).status || 503).json({
        ok: false,
        error: (error as any).code || 'OAUTH_CALLBACK_NOT_ALLOWED',
        message: error instanceof Error ? error.message : 'OAuth callback is not allowed',
      });
    }
    if (!clientId || !clientSecret || !callbackUrl) {
      return res.status(503).json({ ok: false, error: 'GitHub repo access is not configured yet.' });
    }

    const origin = originSelection.origin || config.allowedOrigins[0] || new URL(callbackUrl).origin;
    const state = await issueOAuthState(ephemeralStore, 'github', origin, callbackUrl, { mode: 'repo_connect' });

    return res.json({
      url: buildGitHubAuthorizationUrl({
        clientId,
        callbackUrl,
        state,
        scope: 'repo read:org',
      }),
    });
  });

  app.post('/api/github/disconnect', async (req, res) => {
    const authContext = await readAuthenticatedUser(req, storage, cookieName, tokenConfig, refreshTokenStore, ephemeralStore);
    if ('error' in authContext) {
      return res.status(authContext.status).json({ ok: false, error: authContext.error });
    }
    await storage.clearProviderAccountConnection(authContext.user.id, 'github');
    githubRepoSessions.delete(authContext.user.id);
    return res.json({ ok: true });
  });

  app.get('/api/github/owners', async (req, res) => {
    const authContext = await readAuthenticatedUser(req, storage, cookieName, tokenConfig, refreshTokenStore, ephemeralStore);
    if ('error' in authContext) {
      return res.status(authContext.status).json({ ok: false, error: authContext.error });
    }
    const githubAccount = await storage.findProviderAccount(authContext.user.id, 'github');
    if (!githubAccount?.accessTokenEncrypted) {
      return res.status(401).json({ ok: false, error: 'GitHub is not connected. Connect GitHub to continue.' });
    }

    try {
      const cachedOwners = githubRepoSessions.getCachedOwners(authContext.user.id);
      if (cachedOwners) return res.json(cachedOwners);
      const owners = await listGitHubOwners(
        decryptProviderToken(githubAccount.accessTokenEncrypted, providerTokenSecret),
        githubFetchImpl,
      );
      githubRepoSessions.setCachedOwners(authContext.user.id, owners);
      return res.json(owners);
    } catch (error) {
      const status = (error as Error & { status?: number }).status;
      if (status === 401 || status === 403) {
        await storage.clearProviderAccountConnection(authContext.user.id, 'github');
        githubRepoSessions.delete(authContext.user.id);
        return res.status(401).json({ ok: false, error: 'GitHub connection expired. Reconnect GitHub to continue.' });
      }
      return res.status(502).json({ ok: false, error: error instanceof Error ? error.message : 'Failed to load GitHub owners' });
    }
  });

  app.get('/api/github/repos', async (req, res) => {
    const authContext = await readAuthenticatedUser(req, storage, cookieName, tokenConfig, refreshTokenStore, ephemeralStore);
    if ('error' in authContext) {
      return res.status(authContext.status).json({ ok: false, error: authContext.error });
    }
    const githubAccount = await storage.findProviderAccount(authContext.user.id, 'github');
    if (!githubAccount?.accessTokenEncrypted) {
      return res.status(401).json({ ok: false, error: 'GitHub is not connected. Connect GitHub to continue.' });
    }

    const providerProfile = parseProviderProfile(githubAccount.profileJson);
    const viewerLogin = typeof providerProfile.login === 'string' ? providerProfile.login : '';
    const owner = String(req.query.owner || '').trim() || viewerLogin;
    const query = String(req.query.query || '').trim().toLowerCase();
    const page = Math.max(1, Number.parseInt(String(req.query.page || '1'), 10) || 1);
    const perPage = Math.min(100, Math.max(20, Number.parseInt(String(req.query.perPage || '50'), 10) || 50));
    const cacheKey = `${owner.toLowerCase()}::${page}::${perPage}`;

    try {
      const cached = githubRepoSessions.getCachedRepos(authContext.user.id, cacheKey);
      const result = cached ?? await listGitHubRepos({
        accessToken: decryptProviderToken(githubAccount.accessTokenEncrypted, providerTokenSecret),
        viewerLogin,
        owner,
        page,
        perPage,
        fetchImpl: githubFetchImpl,
      });

      if (!cached) {
        githubRepoSessions.setCachedRepos(authContext.user.id, cacheKey, result);
      }

      return res.json({
        repos: query
          ? result.repos.filter((repo) => (
            repo.name.toLowerCase().includes(query) || repo.fullName.toLowerCase().includes(query)
          ))
          : result.repos,
        nextPage: result.nextPage,
      });
    } catch (error) {
      const status = (error as Error & { status?: number }).status;
      if (status === 401 || status === 403) {
        await storage.clearProviderAccountConnection(authContext.user.id, 'github');
        githubRepoSessions.delete(authContext.user.id);
        return res.status(401).json({ ok: false, error: 'GitHub connection expired. Reconnect GitHub to continue.' });
      }
      return res.status(502).json({ ok: false, error: error instanceof Error ? error.message : 'Failed to load GitHub repositories' });
    }
  });

  app.get('/api/auth/config', async (_req, res) => {
    const config = await getConfigForRequest(_req);
    const providers = resolveProviderClients(config, options.providers);
    const providerStatuses = buildProviderStatuses(config, providers);

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
    const config = await getConfigForRequest(req);
    const providers = resolveProviderClients(config, options.providers);
    const providerId = String(req.params.provider || '').toLowerCase();
    const configuredProvider = config.providers.find((provider) => provider.provider === providerId);
    if (!configuredProvider) {
      if (['google', 'github', 'microsoft', 'apple'].includes(providerId)) {
        return res.json({ ok: true, provider: providerId, enabled: false, available: false, reason: 'Provider is not configured' });
      }
      return res.status(404).json({ ok: false, error: 'Unknown auth provider' });
    }

    const client = providers[providerId];
    const available = configuredProvider.enabled && Boolean(client?.isConfigured());
    const credentialEnv = resolveProviderCredentialEnv(providerId, config);
    return res.json({
      ok: true,
      provider: providerId,
      label: configuredProvider.label,
      enabled: configuredProvider.enabled,
      available,
      credentialEnv,
      reason: available ? undefined : client ? 'Provider is not configured' : 'Provider is not implemented',
    });
  });

  app.post('/api/auth/magic/deliver', async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    const secret = process.env.AUTH_MAGIC_DELIVERY_SECRET || '';
    const supplied = String(req.headers.authorization || '').replace(/^Bearer /, '');
    if (secret.length < 32) return res.status(503).json({ ok: false, code: 'MAGIC_EMAIL_NOT_CONFIGURED' });
    if (Buffer.byteLength(supplied) !== Buffer.byteLength(secret) || !crypto.timingSafeEqual(Buffer.from(supplied), Buffer.from(secret))) {
      return res.status(401).json({ ok: false, code: 'UNAUTHORIZED' });
    }
    const config = await getConfigForRequest(req);
    const email = String(req.body?.email || '').trim().toLowerCase();
    let url: URL;
    try { url = new URL(String(req.body?.url || '')); } catch { return res.status(400).json({ ok: false, code: 'INVALID_MAGIC_REQUEST' }); }
    if (config.app.id !== 'vvault' || !config.allowedOrigins.includes(url.origin) || url.pathname !== '/' || url.search || url.username || url.password || !/^#magic_link=[A-Za-z0-9_-]+$/.test(url.hash) || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ ok: false, code: 'INVALID_MAGIC_REQUEST' });
    }
    if (!magicEmailDelivery.isConfigured()) return res.status(503).json({ ok: false, code: 'MAGIC_EMAIL_NOT_CONFIGURED' });
    try {
      await magicEmailDelivery.send({ email, url: url.toString(), appName: config.app.name });
      return res.status(202).json({ ok: true, state: 'EMAIL_REQUEST_ACCEPTED' });
    } catch { return res.status(503).json({ ok: false, code: 'MAGIC_EMAIL_DELIVERY_FAILED' }); }
  });

  app.post('/api/auth/magic/request', async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    const config = await getConfigForRequest(req);
    const origin = String(req.body?.origin || req.headers.origin || '');
    const email = String(req.body?.email || '').trim().toLowerCase();
    const intent = req.body?.intent;
    if (!config.allowedOrigins.includes(origin) || (req.headers.origin && req.headers.origin !== origin)) {
      return res.status(403).json({ ok: false, code: 'ORIGIN_NOT_ALLOWED', error: 'Return to the product and try again.' });
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !['login', 'signup'].includes(intent)) {
      return res.status(400).json({ ok: false, code: 'INVALID_MAGIC_REQUEST', error: 'Enter a valid email and login or signup intent.' });
    }
    // Product signup owns consent and enrollment; AUTH must not start it by email.
    const existingUser = intent === 'login' ? await storage.findUserByEmail(email) : null;
    if (intent === 'signup' || !existingUser || !await hasRequiredConsentForApp(storage, config, existingUser.id)) {
      return res.status(403).json({ ok: false, code: 'ENROLLMENT_REQUIRED', requiresProductSignup: true, intent, error: `Complete ${config.app.name} signup before signing in.` });
    }
    if (!magicEmailDelivery.isConfigured()) {
      return res.status(503).json({ ok: false, code: 'MAGIC_EMAIL_NOT_CONFIGURED', error: 'Magic email is not configured. Use another sign-in method.' });
    }
    const throttleKey = `auth:magic:rate:${crypto.createHash('sha256').update(`${config.app.id}:${email}`).digest('hex')}`;
    if (!await ephemeralStore.setIfNotExists(throttleKey, '1', 60)) {
      return res.status(429).json({ ok: false, code: 'MAGIC_EMAIL_RATE_LIMITED', error: 'Wait a minute before requesting another email.' });
    }
    try {
      await sendMagicChallenge(ephemeralStore, magicEmailDelivery, { email, appId: config.app.id, origin, intent }, config.app.name);
      return res.status(202).json({ ok: true, state: 'EMAIL_REQUEST_ACCEPTED' });
    } catch {
      return res.status(503).json({ ok: false, code: 'MAGIC_EMAIL_DELIVERY_FAILED', error: 'Email delivery could not be confirmed. Try again later or use another sign-in method.' });
    }
  });

  app.post('/api/auth/magic/consume', async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    const config = await getConfigForRequest(req);
    const origin = String(req.body?.origin || req.headers.origin || '');
    if (!config.allowedOrigins.includes(origin) || (req.headers.origin && req.headers.origin !== origin)) {
      return res.status(403).json({ ok: false, code: 'ORIGIN_NOT_ALLOWED', error: 'Return to the product and try again.' });
    }
    const record = await consumeMagicChallenge(ephemeralStore, String(req.body?.token || ''), config.app.id, origin);
    if (!record) return res.status(400).json({ ok: false, code: 'MAGIC_LINK_INVALID', error: 'This link expired or was already used. Request another email.' });
    const user = await storage.findUserByEmail(record.email);
    if (!user || !await hasRequiredConsentForApp(storage, config, user.id)) {
      return res.status(403).json({ ok: false, code: 'ENROLLMENT_REQUIRED', requiresProductSignup: true, intent: record.intent, error: `Complete ${config.app.name} signup before signing in.` });
    }
    const sessionUser = await buildSessionForUser(user);
    const tokens = await issueTokenPairForUser(req, config, user, sessionUser);
    await storage.updateUserLogin(user.id);
    res.setHeader('Set-Cookie', createHostedTokenCookies(req, cookieName, refreshCookieName, tokens, tokenConfig));
    return res.json({ ok: true, user: sessionUser, intent: record.intent });
  });

  app.post('/api/auth/login', async (req, res) => {
    const config = await getConfigForRequest(req);
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
    const tokens = await issueTokenPairForUser(req, config, user, sessionUser);
    res.setHeader(
      'Set-Cookie',
      createHostedTokenCookies(req, cookieName, refreshCookieName, tokens, tokenConfig),
    );
    return res.json({ ok: true, user: sessionUser });
  });

  app.post('/api/auth/register', async (req, res) => {
    const config = await getConfigForRequest(req);
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
    const tokens = await issueTokenPairForUser(req, config, user, sessionUser);
    res.setHeader(
      'Set-Cookie',
      createHostedTokenCookies(req, cookieName, refreshCookieName, tokens, tokenConfig),
    );
    return res.status(201).json({ ok: true, user: sessionUser });
  });

  app.post('/api/auth/refresh', async (req, res) => {
    const cookies = parseCookieHeader(req.headers.cookie);
    const rawRefreshToken = cookies[refreshCookieName];
    if (!rawRefreshToken) {
      res.setHeader('Set-Cookie', createHostedClearCookies(req, [cookieName, refreshCookieName]));
      return res.status(401).json({ ok: false, error: 'No refresh session' });
    }

    const verifiedRefresh = await verifyRefreshToken(rawRefreshToken, tokenConfig);
    if (!verifiedRefresh) {
      res.setHeader('Set-Cookie', createHostedClearCookies(req, [cookieName, refreshCookieName]));
      return res.status(401).json({ ok: false, error: 'Refresh session expired' });
    }

    const presentedTokenHash = hashRefreshToken(rawRefreshToken, tokenConfig);
    const lockKey = `auth:refresh:lock:${presentedTokenHash}`;
    const lockValue = crypto.randomUUID();
    let lockAcquired = false;
    let lockUnavailable = false;
    try {
      try {
        lockAcquired = await ephemeralStore.setIfNotExists(lockKey, lockValue, 5);
      } catch (error) {
        lockUnavailable = true;
        console.warn('⚠️ [Auth] refresh lock unavailable; falling back to session store', {
          requestPath: '/api/auth/refresh',
          failureClass: 'refresh_lock_unavailable',
          errorClass: error instanceof Error ? error.name || 'Error' : typeof error,
          errorMessage: error instanceof Error ? error.message : String(error),
        });
      }
      if (!lockAcquired && !lockUnavailable) {
        return res.status(409).json({
          ok: false,
          error: 'Refresh already in progress',
          errorCode: 'REFRESH_IN_PROGRESS',
        });
      }
      const user = await storage.findUserById(verifiedRefresh.userId);
      if (!user) {
        await refreshTokenStore.revokeSession(verifiedRefresh.sessionId, 'refresh_user_missing', req._rid || null);
        await cacheSessionRevoked(verifiedRefresh.sessionId);
        res.setHeader('Set-Cookie', createHostedClearCookies(req, [cookieName, refreshCookieName]));
        return res.status(401).json({ ok: false, error: 'Refresh session expired' });
      }

      const sessionUser = await buildSessionForUser(user, verifiedRefresh.providerIdentity);
      const newRefreshTokenId = crypto.randomUUID();
      const newRefreshToken = await createRefreshToken(user.id, verifiedRefresh.sessionId, tokenConfig, verifiedRefresh.clientId, verifiedRefresh.providerIdentity);
      const newRefreshTokenHash = hashRefreshToken(newRefreshToken.token, tokenConfig);
      const metadata = requestMetadataHashes(req, tokenConfig);
      const rotation = await refreshTokenStore.rotateRefreshToken({
        sessionId: verifiedRefresh.sessionId,
        userId: user.id,
        presentedTokenJti: verifiedRefresh.jti,
        presentedTokenHash,
        newRefreshTokenId,
        newRefreshTokenJti: newRefreshToken.jti,
        newRefreshTokenHash,
        newRefreshExpiresAt: newRefreshToken.expiresAt,
        requestId: req._rid || null,
        ...metadata,
      });

      if (!rotation.ok) {
        if (rotation.sessionId) {
          await cacheSessionRevoked(rotation.sessionId);
        }
        res.setHeader('Set-Cookie', createHostedClearCookies(req, [cookieName, refreshCookieName]));
        return res.status(rotation.status).json({
          ok: false,
          error: rotation.replay ? 'Refresh token replay detected' : 'Refresh session expired',
          errorCode: rotation.replay ? 'REFRESH_TOKEN_REPLAY' : 'REFRESH_TOKEN_INVALID',
        });
      }

      const accessToken = await createAccessToken(
        sessionUser, verifiedRefresh.sessionId, tokenConfig,
        verifiedRefresh.clientId === 'chatty-cli' ? 'chatty-cli' : undefined,
      );
      res.setHeader(
        'Set-Cookie',
        createHostedTokenCookies(
          req,
          cookieName,
          refreshCookieName,
          { accessToken: accessToken.token, refreshToken: newRefreshToken.token },
          tokenConfig,
        ),
      );
      return res.json({ ok: true, user: sessionUser });
    } catch (error) {
      console.warn('⚠️ [Auth] refresh failed closed', {
        requestPath: '/api/auth/refresh',
        failureClass: 'refresh_exception',
        errorClass: error instanceof Error ? error.name || 'Error' : typeof error,
        errorMessage: error instanceof Error ? error.message : String(error),
      });
      return res.status(503).json({ ok: false, error: 'Refresh session is temporarily unavailable' });
    } finally {
      if (lockAcquired) {
        await ephemeralStore.deleteIfValue(lockKey, lockValue).catch(() => {});
      }
    }
  });

  app.post('/api/auth/consent', async (req, res) => {
    const config = await getConfigForRequest(req);
    const authContext = await readAuthenticatedUser(req, storage, cookieName, tokenConfig, refreshTokenStore, ephemeralStore);
    if ('error' in authContext) {
      return res.status(authContext.status).json({ ok: false, error: authContext.error });
    }
    const consent = (req.body?.consent && typeof req.body.consent === 'object') ? req.body.consent as Record<string, boolean> : {};
    const missingConsent = missingRequiredConsent(config, consent);
    if (missingConsent) {
      return res.status(400).json({ ok: false, error: `Please accept ${missingConsent.label}` });
    }

    await storage.replaceConsentAcceptances(
      authContext.user.id,
      config.app.id,
      buildAcceptedConsentDocs(config, consent),
    );
    await storage.updateUserLogin(authContext.user.id);
    return res.json({ ok: true, user: authContext.session });
  });

  const logoutHandler = async (req: any, res: any) => {
    await revokeSessionFromRequest(req, 'logout');
    res.setHeader('Set-Cookie', createHostedClearCookies(req, [cookieName, refreshCookieName]));
    return res.json({ ok: true });
  };
  const hostedLogoutHandler = async (req: any, res: any) => {
    const config = await getConfigForRequest(req);
    const origin = resolveConsumerOrigin(req, config);
    const postLogoutPath = config.redirects?.postLogoutPath || '/';
    await revokeSessionFromRequest(req, 'logout');
    res.setHeader('Set-Cookie', createHostedClearCookies(req, [cookieName, refreshCookieName]));
    return res.redirect(`${origin}${postLogoutPath}`);
  };
  app.post('/api/logout', logoutHandler);
  // Aliases for clients that expect `/api/auth/*` (matches sign-out fallbacks in Code host).
  app.post('/api/auth/logout', logoutHandler);
  app.get('/api/auth/logout', hostedLogoutHandler);

  app.get('/api/auth/set-session', async (req, res) => {
    const code = String(req.query.code || '');
    const entry = code ? await ephemeralStore.getJson<ExchangeCodeRecord>(exchangeCodeKey(code)) : null;
    const config = await getConfigForRequest(req, entry?.origin);
    if (!code || !entry) {
      return res.redirect(`${config.allowedOrigins[0] || getPublicOriginFallback()}${config.redirects.postLoginPath}?error=invalid_or_expired_code`);
    }
    await ephemeralStore.delete(exchangeCodeKey(code));
    if (Date.now() - entry.createdAt > EXCHANGE_CODE_TTL_MS) {
      return res.redirect(`${entry.origin}${config.redirects.postLoginPath}?error=expired_code`);
    }
    res.setHeader(
      'Set-Cookie',
      createHostedTokenCookies(
        req,
        cookieName,
        refreshCookieName,
        { accessToken: entry.accessToken, refreshToken: entry.refreshToken },
        tokenConfig,
      ),
    );
    return res.redirect(`${entry.origin}${config.redirects.postLoginPath}`);
  });

  app.get('/api/auth/:provider', async (req, res) => {
    const config = await getConfigForRequest(req);
    const providers = resolveProviderClients(config, options.providers);
    const providerId = String(req.params.provider || '').toLowerCase();
    const configuredProvider = config.providers.find((provider) => provider.provider === providerId);
    const client = providers[providerId];
    if (!configuredProvider || !configuredProvider.enabled || !client) {
      if (['google', 'github', 'microsoft', 'apple'].includes(providerId)) {
        return res.status(503).json({ ok: false, provider: providerId, code: 'PROVIDER_NOT_CONFIGURED', error: `${providerId} sign-in is not configured yet. Use another sign-in method.` });
      }
      return res.status(404).json({ ok: false, error: 'Unknown auth provider' });
    }
    if (!client.isConfigured()) {
      return res.status(503).json({ ok: false, error: `${providerId} sign-in is not configured yet.` });
    }

    const originSelection = resolveStrictOAuthStartOrigin(req, config);
    if ('error' in originSelection) {
      return res.status(403).json({ ok: false, error: originSelection.error });
    }
    let callbackUrl = '';
    try {
      callbackUrl = resolveCallbackUrl(req, config, providerId, originSelection.origin);
    } catch (error) {
      return res.status((error as any).status || 503).json({
        ok: false,
        error: (error as any).code || 'OAUTH_CALLBACK_NOT_ALLOWED',
        message: error instanceof Error ? error.message : 'OAuth callback is not allowed',
      });
    }
    const origin = originSelection.origin || config.allowedOrigins[0] || new URL(callbackUrl).origin;
    const authorizationRequestId = String(req.query.authorization_request || '');
    if (authorizationRequestId) {
      const pending = await ephemeralStore.getJson<NativeAuthorizationRequestRecord>(authorizationRequestKey(authorizationRequestId));
      const expectedReturn = `${resolveAuthorizationOrigin()}/oauth/authorize/complete`;
      if (!pending || pending.appId !== config.app.id || String(req.query.authorization_return || '') !== expectedReturn) {
        return res.status(400).json({ ok: false, error: 'INVALID_AUTHORIZATION_REQUEST' });
      }
    }
    const state = await issueOAuthState(ephemeralStore, providerId, origin, callbackUrl, {
      mode: 'identity_login',
      authorizationRequestId: authorizationRequestId || undefined,
    });
    return res.redirect(client.buildAuthorizationUrl({ origin, callbackUrl, state }));
  });

  app.get('/api/auth/:provider/callback', async (req, res) => {
    const providerId = String(req.params.provider || '').toLowerCase();
    const oauthError = String(req.query.error || '');
    const code = String(req.query.code || '');
    const state = String(req.query.state || '');
    const stateRecord = await consumeOAuthState(ephemeralStore, providerId, state);
    let config: AuthAppConfig;
    try {
      config = await getConfigForRequest(req, stateRecord?.origin);
    } catch (error) {
      if (error instanceof AuthConfigSelectionError) {
        return res.status(error.status).json({
          ok: false,
          error: error.code,
          message: error.message,
        });
      }
      throw error;
    }
    const providers = resolveProviderClients(config, options.providers);
    const fallbackOrigin = stateRecord?.origin || resolveRequestOrigin(req, config);
    if (oauthError) {
      return res.redirect(`${fallbackOrigin}${config.redirects.postLoginPath}?error=${encodeURIComponent(oauthError)}`);
    }
    if (!stateRecord) {
      return res.redirect(`${fallbackOrigin}${config.redirects.postLoginPath}?error=invalid_state`);
    }
    if (stateRecord.mode === 'repo_connect') {
      if (providerId !== 'github') {
        return res.redirect(`${stateRecord.origin}${config.redirects.postLoginPath}?error=unsupported_provider`);
      }
      if (!code) {
        return res.redirect(`${stateRecord.origin}${config.redirects.postLoginPath}?error=missing_code`);
      }
      const authContext = await readAuthenticatedUser(req, storage, cookieName, tokenConfig, refreshTokenStore, ephemeralStore);
      if ('error' in authContext) {
        return res.redirect(`${stateRecord.origin}${config.redirects.postLoginPath}?error=missing_session`);
      }

      const { clientId, clientSecret, callbackUrl: configuredCallbackUrl } = resolveGitHubOAuthCredentials(config);
      const callbackUrl = configuredCallbackUrl || stateRecord.callbackUrl;
      if (!clientId || !clientSecret || !callbackUrl) {
        return res.redirect(`${stateRecord.origin}${config.redirects.postLoginPath}?error=github_not_configured`);
      }

      try {
        const exchange = await exchangeGitHubCodeForAccessToken({
          fetchImpl: githubFetchImpl,
          clientId,
          clientSecret,
          code,
          callbackUrl,
        });
        const viewer = await fetchGitHubViewer(exchange.accessToken, githubFetchImpl);
        await storage.upsertProviderAccountConnection({
          userId: authContext.user.id,
          provider: 'github',
          providerUserId: viewer.providerId,
          displayName: viewer.name || viewer.login,
          avatarUrl: viewer.avatarUrl || null,
          email: null,
          profile: {
            id: viewer.providerId,
            login: viewer.login,
            name: viewer.name,
            avatar_url: viewer.avatarUrl,
          },
          accessTokenEncrypted: encryptProviderToken(exchange.accessToken, providerTokenSecret),
          accessTokenScope: exchange.scope,
        });
        githubRepoSessions.delete(authContext.user.id);
        return res.redirect(`${stateRecord.origin}${config.redirects.postLoginPath}`);
      } catch (error) {
        const message = error instanceof Error ? error.message : 'github_connect_failed';
        return res.redirect(`${stateRecord.origin}${config.redirects.postLoginPath}?error=${encodeURIComponent(message)}`);
      }
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
      let hasRequiredConsent = await hasRequiredConsentForApp(storage, config, user.id);
      if (!hasRequiredConsent && stateRecord.authorizationRequestId) {
        const pending = await ephemeralStore.getJson<NativeAuthorizationRequestRecord>(authorizationRequestKey(stateRecord.authorizationRequestId));
        const acceptedDocs = pending?.acceptedRequiredConsentDocs;
        const currentRequired = requiredConsentDocs(config);
        const acceptedCurrentRequired = Boolean(acceptedDocs)
          && acceptedDocs!.length === currentRequired.length
          && currentRequired.every((doc) => acceptedDocs!.some((accepted) => accepted.key === doc.key && accepted.version === doc.version));
        if (acceptedCurrentRequired) {
          await storage.replaceConsentAcceptances(user.id, config.app.id, acceptedDocs!);
          hasRequiredConsent = true;
        }
      }
      // The subject comes only from the current successful provider exchange.
      const providerIdentity: VerifiedProviderIdentity | undefined = providerId === 'google' || providerId === 'github'
        ? { provider: providerId, subject: profile.providerUserId, issuer: providerId === 'google' ? 'https://accounts.google.com' : 'https://github.com', ...(providerId === 'google' && profile.raw?.email_verified === true ? {verifiedEmail:profile.email} : {}) }
        : undefined;
      const sessionUser = await buildSessionForUser(user, providerIdentity);
      const tokens = await issueTokenPairForUser(req, config, user, sessionUser);
      if (!hasRequiredConsent) {
        res.setHeader('Set-Cookie', createHostedTokenCookies(req, cookieName, refreshCookieName, tokens, tokenConfig));
        res.setHeader('Cache-Control', 'no-store');
        if (stateRecord.authorizationRequestId) {
          const consentPage = new URL('/signin', resolveHostedOrigin(req));
          consentPage.searchParams.set('authorization_request', stateRecord.authorizationRequestId);
          consentPage.searchParams.set('authorization_return', `${resolveAuthorizationOrigin()}/oauth/authorize/complete`);
          consentPage.searchParams.set('reason', 'missing_consent');
          return res.redirect(consentPage.toString());
        }
        return res.status(403).json({
          ok: false,
          state: 'ENROLLMENT_REQUIRED',
          reason: 'missing_consent',
          requiresProductSignup: true,
          appId: config.app.id,
          message: `Complete ${config.app.name} consent before continuing.`,
          consent: { method: 'POST', url: `/api/auth/consent?app=${encodeURIComponent(config.app.id)}`, docs: config.docs },
          continuation: stateRecord.authorizationRequestId
            ? `/oauth/authorize/complete?authorization_request=${encodeURIComponent(stateRecord.authorizationRequestId)}`
            : `${stateRecord.origin}${config.redirects.postLoginPath}`,
        });
      }
      await storage.updateUserLogin(user.id);
      if (stateRecord.authorizationRequestId) {
        res.setHeader('Set-Cookie', createHostedTokenCookies(req, cookieName, refreshCookieName, tokens, tokenConfig));
        const continuation = new URL('/oauth/authorize/complete', resolveHostedOrigin(req));
        continuation.searchParams.set('authorization_request', stateRecord.authorizationRequestId);
        return res.redirect(continuation.toString());
      }
      const callbackOrigin = new URL(stateRecord.callbackUrl).origin;
      if (callbackOrigin !== stateRecord.origin && !getCookieDomain(req)) {
        const exchangeCode = crypto.randomUUID();
        await ephemeralStore.setJson(exchangeCodeKey(exchangeCode), {
          accessToken: tokens.accessToken,
          refreshToken: tokens.refreshToken,
          origin: stateRecord.origin,
          createdAt: Date.now(),
        } satisfies ExchangeCodeRecord, Math.floor(EXCHANGE_CODE_TTL_MS / 1000));
        return res.redirect(`${stateRecord.origin}/api/auth/set-session?code=${encodeURIComponent(exchangeCode)}`);
      }
      res.setHeader('Set-Cookie', createHostedTokenCookies(req, cookieName, refreshCookieName, tokens, tokenConfig));
      return res.redirect(`${stateRecord.origin}${config.redirects.postLoginPath}`);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'oauth_failed';
      return res.redirect(`${stateRecord.origin}${config.redirects.postLoginPath}?error=${encodeURIComponent(message)}`);
    }
  });

  logStartupStage('route_registration');
  return app;
}
