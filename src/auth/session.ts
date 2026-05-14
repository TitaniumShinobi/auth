import crypto from 'node:crypto';

import type { SessionPayload, SessionUser } from '../types.js';

function base64UrlEncode(value: Buffer | string) {
  return Buffer.from(value).toString('base64url');
}

function base64UrlDecode(value: string) {
  return Buffer.from(value, 'base64url').toString('utf8');
}

export function createSessionToken(user: SessionUser, secret: string, maxAgeSeconds: number): string {
  const now = Math.floor(Date.now() / 1000);
  const payload: SessionPayload = {
    ...user,
    iat: now,
    exp: now + maxAgeSeconds,
  };
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  const signature = crypto.createHmac('sha256', secret).update(encodedPayload).digest('base64url');
  return `${encodedPayload}.${signature}`;
}

export function verifySessionToken(token: string, secret: string): SessionPayload | null {
  const [encodedPayload, providedSignature] = token.split('.');
  if (!encodedPayload || !providedSignature) return null;
  const expectedSignature = crypto.createHmac('sha256', secret).update(encodedPayload).digest('base64url');
  if (providedSignature.length !== expectedSignature.length) {
    return null;
  }
  if (!crypto.timingSafeEqual(Buffer.from(providedSignature), Buffer.from(expectedSignature))) {
    return null;
  }
  try {
    const payload = JSON.parse(base64UrlDecode(encodedPayload)) as SessionPayload;
    if (!payload.exp || payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch {
    return null;
  }
}

export function parseCookieHeader(headerValue: string | undefined): Record<string, string> {
  if (!headerValue) return {};
  return headerValue.split(';').reduce<Record<string, string>>((accumulator, part) => {
    const [rawKey, ...valueParts] = part.trim().split('=');
    if (!rawKey) return accumulator;
    accumulator[rawKey] = decodeURIComponent(valueParts.join('=') || '');
    return accumulator;
  }, {});
}

type SessionCookieOptions =
  | boolean
  | {
      secure?: boolean;
      domain?: string | null;
    };

function normalizeSessionCookieOptions(options: SessionCookieOptions) {
  if (typeof options === 'boolean') {
    return {
      secure: options,
      domain: null,
    };
  }

  return {
    secure: options?.secure === true,
    domain: typeof options?.domain === 'string' && options.domain.trim() ? options.domain.trim() : null,
  };
}

export function createSetCookieHeader(
  name: string,
  value: string,
  maxAgeSeconds: number,
  options: SessionCookieOptions,
) {
  const cookieOptions = normalizeSessionCookieOptions(options);
  const parts = [
    `${name}=${encodeURIComponent(value)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    `Max-Age=${maxAgeSeconds}`,
  ];
  if (cookieOptions.domain) parts.push(`Domain=${cookieOptions.domain}`);
  if (cookieOptions.secure) parts.push('Secure');
  return parts.join('; ');
}

export function createClearCookieHeader(
  name: string,
  options: SessionCookieOptions,
) {
  const cookieOptions = normalizeSessionCookieOptions(options);
  const parts = [
    `${name}=`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    'Max-Age=0',
  ];
  if (cookieOptions.domain) parts.push(`Domain=${cookieOptions.domain}`);
  if (cookieOptions.secure) parts.push('Secure');
  return parts.join('; ');
}
