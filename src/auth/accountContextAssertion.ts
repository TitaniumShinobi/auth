import crypto from 'node:crypto';
import { SignJWT, errors as JoseErrors, jwtVerify } from 'jose';

import type {
  AccountContextAssertionV1,
  AccountContextProfileV1,
  SessionUser,
} from '../types.js';

export const ACCOUNT_CONTEXT_ASSERTION_TTL_SECONDS = 60;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export type AccountContextAssertionConfig = {
  privateKeyPem: string;
  publicKeyPem: string;
  issuer: string;
  audience: 'vvault';
  keyId: string;
  ttlSeconds: number;
};

export type IssuedAccountContextAssertion = {
  token: string;
  assertion: AccountContextAssertionV1;
};

function normalizedPem(value: string | undefined) {
  return String(value || '').trim().replace(/\\n/g, '\n');
}

function accountContextKeyMaterial(privateKeyPem: string, publicKeyPem?: string) {
  const privateKey = crypto.createPrivateKey(normalizedPem(privateKeyPem));
  if (privateKey.asymmetricKeyType !== 'ed25519') throw new Error('account_context_key_invalid');
  const publicKey = publicKeyPem
    ? crypto.createPublicKey(normalizedPem(publicKeyPem))
    : crypto.createPublicKey(normalizedPem(privateKeyPem));
  if (publicKey.asymmetricKeyType !== 'ed25519') throw new Error('account_context_key_invalid');
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

export function resolveAccountContextAssertionConfig(): AccountContextAssertionConfig | null {
  const privateKeyPem = normalizedPem(process.env.AUTH_VVAULT_ACCOUNT_ASSERTION_PRIVATE_KEY_PEM);
  if (!privateKeyPem) return null;
  try {
    const material = accountContextKeyMaterial(
      privateKeyPem,
      normalizedPem(process.env.AUTH_VVAULT_ACCOUNT_ASSERTION_PUBLIC_KEY_PEM),
    );
    const configuredKeyId = String(process.env.AUTH_VVAULT_ACCOUNT_ASSERTION_KEY_ID || '').trim();
    if (configuredKeyId && configuredKeyId !== material.keyId) return null;
    return {
      privateKeyPem,
      publicKeyPem: material.publicKeyPem,
    issuer: String(process.env.AUTH_JWT_ISSUER || 'quantum-auth').trim() || 'quantum-auth',
    audience: 'vvault',
      keyId: material.keyId,
    ttlSeconds: positiveInt(
      process.env.AUTH_VVAULT_ACCOUNT_ASSERTION_TTL_SECONDS,
      ACCOUNT_CONTEXT_ASSERTION_TTL_SECONDS,
    ),
    };
  } catch {
    return null;
  }
}

export function accountContextProfileForSession(session: SessionUser): AccountContextProfileV1 | null {
  const displayName = typeof session.name === 'string' ? session.name.trim() : '';
  if (!displayName) return null;
  const ageAssurance = session.actorAttestation?.ageAssurance;
  return {
    displayName,
    ...(ageAssurance === 'adult' || ageAssurance === 'minor' ? { ageAssurance } : {}),
  };
}

export function canIssueAccountContextAssertion(session: SessionUser) {
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
    && accountContextProfileForSession(session),
  );
}

export async function createAccountContextAssertion(
  session: SessionUser,
  sessionId: string,
  config: AccountContextAssertionConfig,
  nowSeconds = Math.floor(Date.now() / 1000),
): Promise<IssuedAccountContextAssertion> {
  if (!canIssueAccountContextAssertion(session)) {
    throw new Error('canonical_owner_unverified');
  }
  const accountContext = accountContextProfileForSession(session);
  if (!accountContext) throw new Error('account_context_invalid');

  const assertionId = crypto.randomUUID();
  const expiresAt = nowSeconds + config.ttlSeconds;
  const assertion: AccountContextAssertionV1 = {
    version: 'life-auth-account-context-assertion/v1',
    subject: session.sub,
    vvaultOwnerId: session.accountContextReadiness!.vvaultOwnerId!,
    issuer: config.issuer,
    audience: config.audience,
    sessionId,
    assertionId,
    keyId: config.keyId,
    issuedAt: nowSeconds,
    expiresAt,
    accountContext,
  };
  const token = await new SignJWT({
    version: assertion.version,
    vvault_owner_id: assertion.vvaultOwnerId,
    sid: assertion.sessionId,
    key_id: assertion.keyId,
    account_context: assertion.accountContext,
  })
    .setProtectedHeader({ alg: 'EdDSA', typ: 'JWT', kid: config.keyId })
    .setIssuer(config.issuer)
    .setAudience(config.audience)
    .setSubject(session.sub)
    .setJti(assertionId)
    .setIssuedAt(nowSeconds)
    .setExpirationTime(expiresAt)
    .sign(accountContextKeyMaterial(config.privateKeyPem, config.publicKeyPem).privateKey);
  return { token, assertion };
}

export async function verifyAccountContextAssertion(
  token: string,
  config: AccountContextAssertionConfig,
): Promise<AccountContextAssertionV1 | null> {
  try {
    const { payload, protectedHeader } = await jwtVerify(
      token,
      // jose's browser-oriented TypeScript declarations omit Node's KeyObject,
      // although Ed25519 KeyObjects are a supported Node runtime key input.
      accountContextKeyMaterial(config.privateKeyPem, config.publicKeyPem).publicKey as unknown as CryptoKey,
      {
      issuer: config.issuer,
      audience: config.audience,
        algorithms: ['EdDSA'],
      },
    );
    const raw = payload as Record<string, unknown>;
    const context = raw.account_context;
    if (
      protectedHeader.kid !== config.keyId
      || raw.version !== 'life-auth-account-context-assertion/v1'
      || typeof payload.sub !== 'string'
      || !payload.sub.trim()
      || typeof payload.jti !== 'string'
      || !payload.jti.trim()
      || typeof payload.iat !== 'number'
      || typeof payload.exp !== 'number'
      || typeof raw.sid !== 'string'
      || !raw.sid.trim()
      || raw.key_id !== config.keyId
      || typeof raw.vvault_owner_id !== 'string'
      || !UUID_RE.test(raw.vvault_owner_id.trim())
      || !context
      || typeof context !== 'object'
    ) return null;
    const profile = context as Record<string, unknown>;
    const displayName = typeof profile.displayName === 'string' ? profile.displayName.trim() : '';
    if (!displayName) return null;
    const age = profile.ageAssurance;
    if (age !== undefined && age !== 'adult' && age !== 'minor') return null;
    if (Object.keys(profile).some((key) => key !== 'displayName' && key !== 'ageAssurance')) return null;
    return {
      version: 'life-auth-account-context-assertion/v1',
      subject: payload.sub,
      vvaultOwnerId: raw.vvault_owner_id.trim(),
      issuer: config.issuer,
      audience: config.audience,
      sessionId: raw.sid.trim(),
      assertionId: payload.jti,
      keyId: config.keyId,
      issuedAt: payload.iat,
      expiresAt: payload.exp,
      accountContext: {
        displayName,
        ...(age === 'adult' || age === 'minor' ? { ageAssurance: age } : {}),
      },
    };
  } catch (error) {
    if (error instanceof JoseErrors.JWTExpired) return null;
    return null;
  }
}
