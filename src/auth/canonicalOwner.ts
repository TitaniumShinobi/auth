/** Identity proof comes from the existing authenticated session, never an owner override. */
export const OWNER_DATASOURCE_REFERENCE = 'env:AUTH_CANONICAL_OWNER_DATABASE_URL';
export type VerifiedProviderIdentity = { provider: 'google' | 'github' | 'email'; subject: string; issuer: string; verifiedEmail?: string };
export function normalizeVerifiedProviderIdentity(value: unknown): VerifiedProviderIdentity | null {
  if (!value || typeof value !== 'object') return null;
  const v = value as VerifiedProviderIdentity;
  const issuers: Record<string, string> = { google: 'https://accounts.google.com', github: 'https://github.com', email: 'https://vvault.thewreck.org' };
  if (!Object.hasOwn(issuers, v.provider) || v.issuer !== issuers[v.provider]
    || typeof v.subject !== 'string' || !v.subject.trim() || v.subject.length > 256
    || v.subject !== v.subject.trim()) return null;
  if (v.verifiedEmail !== undefined && (!['google','email'].includes(v.provider) || typeof v.verifiedEmail !== 'string' || v.verifiedEmail.length > 320 || !/^[^\s@]+@[^\s@]+$/.test(v.verifiedEmail))) return null;
  if (v.provider === 'email' && (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v.subject) || !v.verifiedEmail)) return null;
  return { provider: v.provider, subject: v.subject, issuer: v.issuer, ...(v.verifiedEmail ? {verifiedEmail:v.verifiedEmail} : {}) };
}
export function canonicalOwnerDatasource(env: Record<string, string | undefined>) {
  const reference = env.AUTH_CANONICAL_OWNER_DATASOURCE_REF;
  if (reference !== undefined) {
    if (reference !== OWNER_DATASOURCE_REFERENCE) return null;
    const url = String(env.AUTH_CANONICAL_OWNER_DATABASE_URL || '').trim();
    return url ? { url, dedicated: true } : null;
  }
  // Preserve existing deployments; the repair never writes these legacy variables.
  const url = String(env.DATABASE_URL || env.VVAULT_BODY_DATABASE_URL || '').trim();
  return url ? { url, dedicated: false } : null;
}
export async function resolveCanonicalOwner(
  email: string,
  query: (sql: string, ...parameters: string[]) => Promise<unknown>,
  providerIdentity?: VerifiedProviderIdentity,
): Promise<string | null> {
  const normalized = typeof email === 'string' ? email.trim().toLowerCase() : '';
  if (!normalized || !normalized.includes('@')) return null;
  try {
    const proof = providerIdentity === undefined ? undefined : normalizeVerifiedProviderIdentity(providerIdentity);
    if (providerIdentity !== undefined && !proof) return null;
    const rows = proof?.provider === 'email'
      ? await query("select users.id::text as id from ovvaults.external_identities identities join ovvaults.users users on users.id=identities.user_id join ovvaults.managed_emails emails on emails.user_id=identities.user_id join ovvaults.external_identities contact_source on contact_source.id=emails.identity_id and contact_source.user_id=identities.user_id where identities.id=$1::uuid and identities.provider='email' and identities.revoked_at is null and identities.verified_at is not null and emails.revoked_at is null and emails.verified_at is not null and emails.normalized_email=$2 and identities.provider_subject=$2 and contact_source.revoked_at is null and contact_source.verified_at is not null and users.account_state='ACTIVE' limit 2", proof.subject, proof.verifiedEmail!)
      : proof
      ? await query('select users.id::text as id from ovvaults.external_identities identities join ovvaults.users users on users.id=identities.user_id where identities.provider=$1 and identities.provider_subject=$2 and identities.revoked_at is null limit 2', proof.provider, proof.subject)
      : await query('select id::text as id from ovvaults.users where lower(email) = lower($1) order by created_at asc limit 2', normalized);
    if (!Array.isArray(rows) || rows.length !== 1) return null;
    const id = rows[0]?.id;
    return typeof id === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id) ? id : null;
  } catch { return null; } // Never log DB errors, URLs, email, or query payloads.
}
