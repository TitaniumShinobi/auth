import crypto from 'node:crypto';
import { SignJWT, jwtVerify, errors as JoseErrors } from 'jose';
import { normalizeVerifiedProviderIdentity } from './canonicalOwner.js';
export const ACCESS_TOKEN_TTL_SECONDS = 15 * 60;
export const REFRESH_TOKEN_TTL_SECONDS = 60 * 60 * 24 * 30;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
function secretBytes(secret) {
    return new TextEncoder().encode(secret);
}
function secondsNow() {
    return Math.floor(Date.now() / 1000);
}
function positiveInt(value, fallback) {
    const parsed = Number.parseInt(value || '', 10);
    return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}
function requireStringClaim(payload, key) {
    const value = payload[key];
    return typeof value === 'string' && value.trim() ? value.trim() : '';
}
function actorAttestationClaim(value, subject, vvaultOwnerId) {
    if (!value || typeof value !== 'object')
        return undefined;
    const raw = value;
    if (raw.version !== 'life-auth-actor-attestation/v1'
        || raw.issuer !== 'quantum-auth'
        || raw.subject !== subject
        || raw.vvaultOwnerId !== vvaultOwnerId)
        return undefined;
    const age = raw.ageAssurance;
    const ageAssurance = age === 'adult' || age === 'minor' || age === 'unknown' ? age : undefined;
    return {
        version: 'life-auth-actor-attestation/v1',
        subject,
        vvaultOwnerId,
        issuer: 'quantum-auth',
        ...(ageAssurance ? { ageAssurance } : {}),
    };
}
function accountContextReadinessClaim(value, subject, vvaultOwnerId) {
    if (!value || typeof value !== 'object')
        return undefined;
    const raw = value;
    if (raw.version !== 'life-auth-account-context-readiness/v1'
        || raw.subject !== subject
        || typeof raw.ready !== 'boolean')
        return undefined;
    if (raw.ready === false && raw.reason === 'canonical_owner_unverified') {
        return {
            version: 'life-auth-account-context-readiness/v1',
            ready: false,
            subject,
            reason: 'canonical_owner_unverified',
        };
    }
    const evidenceSources = new Set([
        'ovvaults_user',
        'cache',
        'supabase_found',
        'supabase_upserted',
        'local_registry',
    ]);
    if (raw.ready !== true
        || raw.reason !== 'canonical_owner_verified'
        || !UUID_RE.test(vvaultOwnerId)
        || raw.vvaultOwnerId !== vvaultOwnerId
        || typeof raw.evidenceSource !== 'string'
        || !evidenceSources.has(raw.evidenceSource))
        return undefined;
    return {
        version: 'life-auth-account-context-readiness/v1',
        ready: true,
        subject,
        reason: 'canonical_owner_verified',
        vvaultOwnerId,
        evidenceSource: raw.evidenceSource,
    };
}
export function resolveJwtTokenConfig(sessionSecret) {
    const accessSecret = process.env.AUTH_ACCESS_TOKEN_SECRET || sessionSecret;
    const refreshSecret = process.env.AUTH_REFRESH_TOKEN_SECRET || `${sessionSecret}:refresh`;
    const refreshTokenHashSecret = process.env.AUTH_REFRESH_TOKEN_HASH_SECRET || `${sessionSecret}:refresh-token-hash`;
    return {
        accessSecret,
        refreshSecret,
        refreshTokenHashSecret,
        issuer: process.env.AUTH_JWT_ISSUER || 'quantum-auth',
        audience: process.env.AUTH_JWT_AUDIENCE || 'auth-browser-session',
        accessTtlSeconds: positiveInt(process.env.AUTH_ACCESS_TOKEN_TTL_SECONDS, ACCESS_TOKEN_TTL_SECONDS),
        refreshTtlSeconds: positiveInt(process.env.AUTH_REFRESH_TOKEN_TTL_SECONDS, REFRESH_TOKEN_TTL_SECONDS),
    };
}
export async function createAccessToken(user, sessionId, config, relyingPartyId) {
    const providerIdentity = normalizeVerifiedProviderIdentity(user.providerIdentity);
    if (user.providerIdentity !== undefined && !providerIdentity)
        throw new Error('INVALID_PROVIDER_IDENTITY');
    const now = secondsNow();
    const exp = now + config.accessTtlSeconds;
    const jti = crypto.randomUUID();
    const token = await new SignJWT({
        token_use: 'access',
        sid: sessionId,
        id: user.id,
        uid: user.uid,
        ...(user.lifeUserId ? { life_user_id: user.lifeUserId } : {}),
        ...(user.vvaultUserId ? { vvault_user_id: user.vvaultUserId } : {}),
        ...(user.supabaseUserId ? { supabase_user_id: user.supabaseUserId } : {}),
        email: user.email,
        name: user.name,
        auth_provider: user.auth_provider,
        ...(providerIdentity ? { provider_identity: providerIdentity } : {}),
        ...(relyingPartyId ? { relying_party_id: relyingPartyId } : {}),
        ...(user.picture ? { picture: user.picture } : {}),
        ...(user.actorAttestation ? { actor_attestation: user.actorAttestation } : {}),
        ...(user.accountContextReadiness ? { account_context_readiness: user.accountContextReadiness } : {}),
    })
        .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
        .setIssuer(config.issuer)
        .setAudience(config.audience)
        .setSubject(user.sub || user.id)
        .setJti(jti)
        .setIssuedAt(now)
        .setExpirationTime(exp)
        .sign(secretBytes(config.accessSecret));
    return { token, jti, exp };
}
export async function verifyAccessToken(token, config) {
    try {
        const { payload } = await jwtVerify(token, secretBytes(config.accessSecret), {
            issuer: config.issuer,
            audience: config.audience,
            algorithms: ['HS256'],
        });
        const raw = payload;
        if (raw.token_use !== 'access')
            return null;
        const providerIdentity = normalizeVerifiedProviderIdentity(raw.provider_identity);
        if (raw.provider_identity !== undefined && !providerIdentity)
            return null;
        const sessionId = requireStringClaim(raw, 'sid');
        const sub = typeof payload.sub === 'string' ? payload.sub.trim() : '';
        const id = requireStringClaim(raw, 'id') || sub;
        const uid = requireStringClaim(raw, 'uid') || id;
        const email = requireStringClaim(raw, 'email');
        const name = requireStringClaim(raw, 'name');
        const authProvider = requireStringClaim(raw, 'auth_provider') || 'credentials';
        const jti = typeof payload.jti === 'string' ? payload.jti.trim() : '';
        if (!sessionId || !id || !sub || !uid || !email || !name || !jti || typeof payload.exp !== 'number') {
            return null;
        }
        const vvaultUserId = requireStringClaim(raw, 'vvault_user_id') || id;
        const actorAttestation = actorAttestationClaim(raw.actor_attestation, sub, vvaultUserId);
        const accountContextReadiness = accountContextReadinessClaim(raw.account_context_readiness, sub, vvaultUserId);
        return {
            sessionId,
            jti,
            exp: payload.exp,
            session: {
                id,
                sub,
                uid,
                lifeUserId: requireStringClaim(raw, 'life_user_id') || id,
                vvaultUserId,
                supabaseUserId: requireStringClaim(raw, 'supabase_user_id') || undefined,
                email,
                name,
                picture: requireStringClaim(raw, 'picture') || undefined,
                auth_provider: authProvider,
                ...(providerIdentity ? { providerIdentity } : {}),
                ...(raw.relying_party_id === 'chatty' || raw.relying_party_id === 'chatty-cli' || raw.relying_party_id === 'vvault'
                    ? { relyingPartyId: raw.relying_party_id }
                    : {}),
                ...(actorAttestation ? { actorAttestation } : {}),
                ...(accountContextReadiness ? { accountContextReadiness } : {}),
            },
        };
    }
    catch (error) {
        if (error instanceof JoseErrors.JWTExpired)
            return null;
        return null;
    }
}
export async function createRefreshToken(userId, sessionId, config, clientId, proof) {
    const providerIdentity = normalizeVerifiedProviderIdentity(proof);
    if (proof !== undefined && !providerIdentity)
        throw new Error('INVALID_PROVIDER_IDENTITY');
    const now = secondsNow();
    const exp = now + config.refreshTtlSeconds;
    const jti = crypto.randomUUID();
    const token = await new SignJWT({
        token_use: 'refresh',
        ...(providerIdentity ? { provider_identity: providerIdentity } : {}),
        sid: sessionId,
        ...(clientId ? { client_id: clientId } : {}),
    })
        .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
        .setIssuer(config.issuer)
        .setAudience(config.audience)
        .setSubject(userId)
        .setJti(jti)
        .setIssuedAt(now)
        .setExpirationTime(exp)
        .sign(secretBytes(config.refreshSecret));
    return {
        token,
        jti,
        exp,
        expiresAt: new Date(exp * 1000),
    };
}
export async function verifyRefreshToken(token, config) {
    try {
        const { payload } = await jwtVerify(token, secretBytes(config.refreshSecret), {
            issuer: config.issuer,
            audience: config.audience,
            algorithms: ['HS256'],
        });
        const raw = payload;
        if (raw.token_use !== 'refresh')
            return null;
        const providerIdentity = normalizeVerifiedProviderIdentity(raw.provider_identity);
        if (raw.provider_identity !== undefined && !providerIdentity)
            return null;
        const sessionId = requireStringClaim(raw, 'sid');
        const userId = typeof payload.sub === 'string' ? payload.sub.trim() : '';
        const jti = typeof payload.jti === 'string' ? payload.jti.trim() : '';
        if (!sessionId || !userId || !jti || typeof payload.exp !== 'number')
            return null;
        return {
            sessionId,
            userId,
            jti,
            exp: payload.exp,
            clientId: requireStringClaim(raw, 'client_id') || undefined,
            ...(providerIdentity ? { providerIdentity } : {}),
        };
    }
    catch (error) {
        if (error instanceof JoseErrors.JWTExpired)
            return null;
        return null;
    }
}
export function hashRefreshToken(rawRefreshToken, config) {
    return crypto
        .createHmac('sha256', config.refreshTokenHashSecret)
        .update(rawRefreshToken)
        .digest('hex');
}
export function hashRequestMetadata(value, secret) {
    const normalized = String(value || '').trim();
    if (!normalized)
        return null;
    return crypto.createHmac('sha256', secret).update(normalized).digest('hex');
}
