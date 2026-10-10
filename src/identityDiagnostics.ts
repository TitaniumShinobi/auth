import crypto from 'node:crypto';

import { parseCookieHeader } from './auth/session.js';
import type { SessionUser } from './types.js';

const DIAGNOSTICS_FLAG = 'VVAULT_IDENTITY_DIAGNOSTICS';
const DIAGNOSTICS_SALT_ENV = 'VVAULT_IDENTITY_DIAGNOSTICS_SALT';
const SESSION_KEY_LENGTH = 12;
const SUPABASE_UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

let warnedMissingSalt = false;

function normalizeString(value: unknown) {
  return typeof value === 'string' ? value.trim() : '';
}

function getDiagnosticsSalt() {
  return normalizeString(process.env[DIAGNOSTICS_SALT_ENV]);
}

function hashCookieValue(rawValue: string | undefined, salt: string) {
  const normalized = normalizeString(rawValue);
  if (!normalized || !salt) return null;
  return crypto
    .createHash('sha256')
    .update(`${normalized}${salt}`)
    .digest('hex')
    .slice(0, SESSION_KEY_LENGTH);
}

function warnMissingSaltOnce() {
  if (warnedMissingSalt) return;
  warnedMissingSalt = true;
  console.warn('⚠️ [VvaultIdentityDiagnostics]', {
    warning: 'missing_diagnostics_salt',
    env: DIAGNOSTICS_SALT_ENV,
  });
}

function isSupabaseUuid(value: string | null) {
  return Boolean(value && SUPABASE_UUID_RE.test(value));
}

function getRequestPath(req: any) {
  const originalUrl = normalizeString(req?.originalUrl);
  if (originalUrl) return originalUrl;
  const url = normalizeString(req?.url);
  return url || null;
}

export function isVvaultIdentityDiagnosticsEnabled() {
  return normalizeString(process.env[DIAGNOSTICS_FLAG]).toLowerCase() === 'true';
}

export function buildSessionKeys(rawCookieHeader: string | undefined) {
  if (!isVvaultIdentityDiagnosticsEnabled()) {
    return {
      authSessionKey: null,
      chattySessionKey: null,
    };
  }

  const salt = getDiagnosticsSalt();
  if (!salt) {
    warnMissingSaltOnce();
    return {
      authSessionKey: null,
      chattySessionKey: null,
    };
  }

  const cookies = parseCookieHeader(rawCookieHeader);
  const authCookieName = normalizeString(process.env.AUTH_COOKIE_NAME) || 'auth_sid';
  const chattyCookieName = normalizeString(process.env.COOKIE_NAME) || 'sid';

  return {
    authSessionKey: hashCookieValue(cookies[authCookieName], salt),
    chattySessionKey: hashCookieValue(cookies[chattyCookieName], salt),
  };
}

export function buildIdentityShape(session: Pick<SessionUser, 'id' | 'sub' | 'uid'> | null | undefined) {
  const computedUid = normalizeString(session?.uid) || normalizeString(session?.id) || normalizeString(session?.sub) || null;
  const lifeUserId = normalizeString(session?.id) || normalizeString(session?.sub);

  return {
    uid: computedUid,
    uidState: !computedUid
      ? 'missing'
      : isSupabaseUuid(computedUid)
        ? 'supabase_uuid'
        : computedUid === normalizeString(session?.id) || computedUid === normalizeString(session?.sub)
          ? 'life_fallback'
          : 'non_uuid',
    life_user_id_present: Boolean(lifeUserId),
    supabase_user_id_present: isSupabaseUuid(computedUid),
  };
}

export function logAuthApiMeIdentityDiagnostics(
  req: any,
  session: Pick<SessionUser, 'id' | 'sub' | 'uid'> | null | undefined,
  options: {
    refreshRan: boolean;
    refreshChanged: boolean;
    refreshFailed?: boolean;
  },
) {
  if (!isVvaultIdentityDiagnosticsEnabled()) return null;

  const sessionKeys = buildSessionKeys(req?.headers?.cookie);
  const entry = {
    label: 'auth_api_me',
    rid: req?._rid || null,
    requestPath: getRequestPath(req),
    authSessionKey: sessionKeys.authSessionKey,
    chattySessionKey: sessionKeys.chattySessionKey,
    ...buildIdentityShape(session),
    refreshRan: options.refreshRan,
    refreshChanged: options.refreshChanged,
    refreshFailed: options.refreshFailed === true,
  };
  console.info('ℹ️ [VvaultIdentityDiagnostics]', entry);
  return entry;
}
