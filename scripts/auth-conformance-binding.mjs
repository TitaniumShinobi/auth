import { createHash } from 'node:crypto';
export const CONFORMANCE_CONTRACT = 'auth-authority-conformance/1';
const canonical = value => Array.isArray(value) ? value.map(canonical) : value && typeof value === 'object'
  ? Object.fromEntries(Object.keys(value).sort().map(k => [k, canonical(value[k])])) : value;
export const digest = value => createHash('sha256').update(JSON.stringify(canonical(value))).digest('hex');
export function seal(record) { return { ...record, digest: digest(record) }; }
export function validBinding(record, adapter, now = Date.now()) {
  if (!record.binding) return !record.digest; // Existing operator-trusted legacy records remain supported.
  const { digest: claimed, ...payload } = record;
  const b = record.binding;
  return claimed === digest(payload) && b.contractVersion === CONFORMANCE_CONTRACT &&
    typeof b.configurationDigest === 'string' && /^[a-f0-9]{64}$/.test(b.configurationDigest) &&
    typeof b.runtimeDigest === 'string' && /^[a-f0-9]{64}$/.test(b.runtimeDigest) &&
    Number.isFinite(Date.parse(b.generatedAt)) && Date.parse(b.generatedAt) <= now &&
    Date.parse(b.expiresAt) > now && Date.parse(b.expiresAt) - Date.parse(b.generatedAt) <= 86400000 &&
    (!adapter.identityAuthority?.configurationDigest || adapter.identityAuthority.configurationDigest === b.configurationDigest) &&
    (!adapter.identityAuthority?.runtimeDigest || adapter.identityAuthority.runtimeDigest === b.runtimeDigest) &&
    (!adapter.identityAuthority?.contractVersion || adapter.identityAuthority.contractVersion === b.contractVersion);
}
