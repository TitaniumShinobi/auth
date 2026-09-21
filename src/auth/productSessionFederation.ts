import crypto from 'node:crypto';
import { normalizeVerifiedProviderIdentity, type VerifiedProviderIdentity } from './canonicalOwner.js';

export const FEDERATION_ASSERTION_TTL_SECONDS = 60;
export const FEDERATION_CLOCK_SKEW_SECONDS = 30;

const REJECTED_FEDERATION_SECRETS = new Set([
  'change-me-to-a-distinct-random-secret',
]);

export type ProductSessionAssertionInput = {
  product_id: string;
  authorization_request: string;
  subject: string;
  email: string;
  name: string;
  picture?: string;
  provider_identity?: VerifiedProviderIdentity;
  issued_at: number;
  expires_at: number;
  nonce: string;
};

export type ProductSessionAssertionRecord = ProductSessionAssertionInput & {
  createdAt: number;
  authorityOrigin?: string;
  canonicalOwnerId?: string;
  chattyConsents?: {key:string;version:string;sha256:string;acceptedAt:string}[];
};

export function canonicalizeProductSessionAssertion(input: ProductSessionAssertionInput) {
  const providerIdentity = normalizeVerifiedProviderIdentity(input.provider_identity);
  if (input.provider_identity !== undefined && !providerIdentity) throw new Error('INVALID_PROVIDER_IDENTITY');
  return JSON.stringify({
    product_id: input.product_id,
    authorization_request: input.authorization_request,
    subject: input.subject,
    email: input.email,
    name: input.name,
    picture: input.picture || '',
    issued_at: input.issued_at,
    expires_at: input.expires_at,
    nonce: input.nonce,
    ...(providerIdentity ? { provider_identity: providerIdentity } : {}),
  });
}

export function signProductSessionAssertion(input: ProductSessionAssertionInput, secret: string) {
  const version = input.provider_identity === undefined ? 'v1' : 'v2';
  return `${version}=${crypto.createHmac('sha256', secret).update(canonicalizeProductSessionAssertion(input)).digest('base64url')}`;
}

export function isValidProductSessionFederationSecret(secret: string) {
  const normalized = typeof secret === 'string' ? secret.trim() : '';
  return Buffer.byteLength(normalized, 'utf8') >= 32
    && !REJECTED_FEDERATION_SECRETS.has(normalized.toLowerCase());
}

export function verifyProductSessionAssertionSignature(input: ProductSessionAssertionInput, signature: string, secret: string) {
  const version = input.provider_identity === undefined ? 'v1' : 'v2';
  if (typeof signature !== 'string' || !signature.startsWith(`${version}=`) || !secret) return false;
  if (input.provider_identity !== undefined && !normalizeVerifiedProviderIdentity(input.provider_identity)) return false;
  const expected = signProductSessionAssertion(input, secret);
  const left = Buffer.from(signature);
  const right = Buffer.from(expected);
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

export function validateProductSessionAssertion(input: ProductSessionAssertionInput, nowSeconds = Math.floor(Date.now() / 1000)) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return false;
  if (input.provider_identity !== undefined && !normalizeVerifiedProviderIdentity(input.provider_identity)) return false;
  if (!input.product_id || !input.authorization_request || !input.subject || !input.email || !input.name || !input.nonce) return false;
  if (!/^[A-Za-z0-9_-]{24,128}$/.test(input.authorization_request)) return false;
  if (!/^[A-Za-z0-9._~-]{16,128}$/.test(input.nonce)) return false;
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(input.email)) return false;
  if (!Number.isInteger(input.issued_at) || !Number.isInteger(input.expires_at)) return false;
  if (input.issued_at > nowSeconds + FEDERATION_CLOCK_SKEW_SECONDS) return false;
  if (input.issued_at < nowSeconds - FEDERATION_ASSERTION_TTL_SECONDS - FEDERATION_CLOCK_SKEW_SECONDS) return false;
  if (input.expires_at <= nowSeconds || input.expires_at > input.issued_at + FEDERATION_ASSERTION_TTL_SECONDS) return false;
  return true;
}
