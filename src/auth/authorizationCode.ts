import crypto from 'node:crypto';

import type { AuthAppConfig, AuthPublicClient } from '../types.js';
import type { VerifiedProviderIdentity } from './canonicalOwner.js';

export const AUTHORIZATION_REQUEST_TTL_SECONDS = 10 * 60;
export const AUTHORIZATION_CODE_TTL_SECONDS = 2 * 60;

export type AuthorizationRequestRecord = {
  appId: string;
  clientId: string;
  redirectUri: string;
  state: string;
  codeChallenge: string;
  scope: string;
  createdAt: number;
  federationBrowserBindingHash?: string;
  forceReauthentication?: boolean;
  identityAuthority?: 'vvault';
};

export type AuthorizationCodeRecord = AuthorizationRequestRecord & {
  userId: string;
  providerIdentity?: VerifiedProviderIdentity;
  createdAt: number;
};

export function findPublicClient(config: AuthAppConfig, clientId: string) {
  return (config.publicClients || []).find((client) => client.clientId === clientId) || null;
}

export function validateRedirectUri(client: AuthPublicClient, raw: string) {
  if (client.redirectUris?.includes(raw)) return raw;
  let url: URL;
  try { url = new URL(raw); } catch { return null; }
  const policy = client.loopback;
  if (!policy || url.protocol !== 'http:' || url.username || url.password || url.search || url.hash) return null;
  const host = url.hostname.replace(/^\[(.*)\]$/, '$1').toLowerCase();
  if (!policy.hosts.includes(host) || url.pathname !== policy.path) return null;
  if (policy.allowDynamicPorts && !url.port) return null;
  return url.toString();
}

export function isValidOpaqueState(value: string) {
  return value.length >= 32 && value.length <= 512 && /^[A-Za-z0-9._~-]+$/.test(value);
}

export function isValidS256Challenge(value: string) {
  return value.length === 43 && /^[A-Za-z0-9_-]+$/.test(value);
}

export function verifyS256(verifier: string, challenge: string) {
  if (verifier.length < 43 || verifier.length > 128 || !/^[A-Za-z0-9._~-]+$/.test(verifier)) return false;
  const actual = crypto.createHash('sha256').update(verifier).digest('base64url');
  const left = Buffer.from(actual);
  const right = Buffer.from(challenge);
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

export function appendAuthorizationResult(redirectUri: string, values: Record<string, string>) {
  const url = new URL(redirectUri);
  for (const [key, value] of Object.entries(values)) url.searchParams.set(key, value);
  return url.toString();
}
