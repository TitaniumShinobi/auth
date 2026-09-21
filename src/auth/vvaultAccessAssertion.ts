import crypto from 'node:crypto';
import { SignJWT, errors as JoseErrors, jwtVerify } from 'jose';

import type {
  SessionUser,
  VvaultAccessAssertionV2,
  VvaultAccessScope,
} from '../types.js';

export const VVAULT_ACCESS_ASSERTION_TTL_SECONDS = 60;
export const VVAULT_ACCESS_SCOPES: readonly VvaultAccessScope[] = Object.freeze([
  'constructs:read',
  'identity:read',
  'knowledge:read',
  'memory:read',
  'transcripts:read',
  'transcripts:append',
  'work:read',
]);

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export type VvaultAccessAssertionConfig = {
  privateKeyPem: string;
  publicKeyPem: string;
  issuer: string;
  audience: 'vvault';
  keyId: string;
  ttlSeconds: number;
};

export type IssuedVvaultAccessAssertion = {
  token: string;
  assertion: VvaultAccessAssertionV2;
};

export type VvaultRelyingPartyId = 'chatty' | 'chatty-cli';

function normalizedPem(value: string | undefined) {
  return String(value || '').trim().replace(/\\n/g, '\n');
}

function keyMaterial(privateKeyPem: string, publicKeyPem?: string) {
  const privateKey = crypto.createPrivateKey(normalizedPem(privateKeyPem));
  if (privateKey.asymmetricKeyType !== 'ed25519') throw new Error('vvault_access_key_invalid');
  const publicKey = publicKeyPem
    ? crypto.createPublicKey(normalizedPem(publicKeyPem))
    : crypto.createPublicKey(normalizedPem(privateKeyPem));
  if (publicKey.asymmetricKeyType !== 'ed25519') throw new Error('vvault_access_key_invalid');
  const canonicalPublicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  return {
    privateKey,
    publicKey,
    publicKeyPem: canonicalPublicKeyPem,
    keyId: crypto.createHash('sha256').update(canonicalPublicKeyPem).digest('hex'),
  };
}

function positiveInt(value: string | undefined, fallback: number) {
  const parsed = Number.parseInt(value || '', 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

export function resolveVvaultAccessAssertionConfig(): VvaultAccessAssertionConfig | null {
  const privateKeyPem = normalizedPem(
    process.env.AUTH_VVAULT_ACCESS_ASSERTION_PRIVATE_KEY_PEM
      || process.env.AUTH_VVAULT_ACCOUNT_ASSERTION_PRIVATE_KEY_PEM,
  );
  if (!privateKeyPem) return null;
  try {
    const material = keyMaterial(
      privateKeyPem,
      normalizedPem(
        process.env.AUTH_VVAULT_ACCESS_ASSERTION_PUBLIC_KEY_PEM
          || process.env.AUTH_VVAULT_ACCOUNT_ASSERTION_PUBLIC_KEY_PEM,
      ),
    );
    const configuredKeyId = String(
      process.env.AUTH_VVAULT_ACCESS_ASSERTION_KEY_ID
        || process.env.AUTH_VVAULT_ACCOUNT_ASSERTION_KEY_ID
        || '',
    ).trim();
    if (configuredKeyId && configuredKeyId !== material.keyId) return null;
    return {
      privateKeyPem,
      publicKeyPem: material.publicKeyPem,
      issuer: String(process.env.AUTH_JWT_ISSUER || 'quantum-auth').trim() || 'quantum-auth',
      audience: 'vvault',
      keyId: material.keyId,
      ttlSeconds: Math.min(
        60,
        positiveInt(
          process.env.AUTH_VVAULT_ACCESS_ASSERTION_TTL_SECONDS,
          VVAULT_ACCESS_ASSERTION_TTL_SECONDS,
        ),
      ),
    };
  } catch {
    return null;
  }
}

export function canIssueVvaultAccessAssertion(session: SessionUser) {
  const readiness = session.accountContextReadiness;
  const attestation = session.actorAttestation;
  return Boolean(
    readiness?.version === 'life-auth-account-context-readiness/v1'
    && readiness.ready
    && readiness.reason === 'canonical_owner_verified'
    && readiness.subject === session.sub
    && typeof session.vvaultUserId === 'string'
    && UUID_RE.test(session.vvaultUserId)
    && readiness.vvaultOwnerId === session.vvaultUserId
    && attestation?.version === 'life-auth-actor-attestation/v1'
    && attestation.subject === session.sub
    && attestation.vvaultOwnerId === session.vvaultUserId
  );
}

export async function createVvaultAccessAssertion(
  session: SessionUser,
  sessionId: string,
  config: VvaultAccessAssertionConfig,
  relyingPartyId: VvaultRelyingPartyId,
  nowSeconds = Math.floor(Date.now() / 1000),
): Promise<IssuedVvaultAccessAssertion> {
  if (!canIssueVvaultAccessAssertion(session)) throw new Error('canonical_owner_unverified');
  const assertionId = crypto.randomUUID();
  const expiresAt = nowSeconds + Math.min(60, config.ttlSeconds);
  if (relyingPartyId !== 'chatty' && relyingPartyId !== 'chatty-cli') throw new Error('relying_party_invalid');
  const assertion: VvaultAccessAssertionV2 = {
    version: 'life-auth-vvault-access-assertion/v2',
    subject: session.sub,
    vvaultOwnerId: session.vvaultUserId!,
    issuer: config.issuer,
    audience: config.audience,
    sessionId,
    assertionId,
    keyId: config.keyId,
    issuedAt: nowSeconds,
    expiresAt,
    scopes: [...VVAULT_ACCESS_SCOPES],
    relyingPartyId,
  };
  const token = await new SignJWT({
    version: assertion.version,
    vvault_owner_id: assertion.vvaultOwnerId,
    sid: assertion.sessionId,
    scopes: assertion.scopes,
    relying_party_id: assertion.relyingPartyId,
  })
    .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT', kid: config.keyId })
    .setIssuer(config.issuer)
    .setAudience(config.audience)
    .setSubject(session.sub)
    .setJti(assertionId)
    .setIssuedAt(nowSeconds)
    .setExpirationTime(expiresAt)
    .sign(keyMaterial(config.privateKeyPem, config.publicKeyPem).privateKey);
  return { token, assertion };
}

export async function verifyVvaultAccessAssertion(
  token: string,
  config: VvaultAccessAssertionConfig,
): Promise<VvaultAccessAssertionV2 | null> {
  try {
    const { payload, protectedHeader } = await jwtVerify(
      token,
      // jose's browser-oriented TypeScript declarations omit Node's KeyObject,
      // although Ed25519 KeyObjects are a supported Node runtime key input.
      keyMaterial(config.privateKeyPem, config.publicKeyPem).publicKey as unknown as CryptoKey,
      { issuer: config.issuer, audience: config.audience, algorithms: ['EdDSA'] },
    );
    const raw = payload as Record<string, unknown>;
    if (
      protectedHeader.kid !== config.keyId
      || raw.version !== 'life-auth-vvault-access-assertion/v2'
      || typeof payload.sub !== 'string'
      || !payload.sub.trim()
      || typeof payload.jti !== 'string'
      || !payload.jti.trim()
      || typeof payload.iat !== 'number'
      || typeof payload.exp !== 'number'
      || typeof raw.sid !== 'string'
      || !raw.sid.trim()
      || typeof raw.vvault_owner_id !== 'string'
      || !UUID_RE.test(raw.vvault_owner_id.trim())
      || !Array.isArray(raw.scopes)
      || raw.scopes.length === 0
      || raw.scopes.some((scope) => !VVAULT_ACCESS_SCOPES.includes(scope as VvaultAccessScope))
      || (raw.relying_party_id !== 'chatty' && raw.relying_party_id !== 'chatty-cli')
    ) return null;
    return {
      version: 'life-auth-vvault-access-assertion/v2',
      subject: payload.sub,
      vvaultOwnerId: raw.vvault_owner_id.trim(),
      issuer: config.issuer,
      audience: config.audience,
      sessionId: raw.sid.trim(),
      assertionId: payload.jti,
      keyId: config.keyId,
      issuedAt: payload.iat,
      expiresAt: payload.exp,
      scopes: raw.scopes as VvaultAccessScope[],
      relyingPartyId: raw.relying_party_id,
    };
  } catch (error) {
    if (error instanceof JoseErrors.JWTExpired) return null;
    return null;
  }
}
