import { createHash } from 'node:crypto';
export const CONFORMANCE_CONTRACT = 'auth-authority-conformance/1';
const canonical = value => Array.isArray(value) ? value.map(canonical) : value && typeof value === 'object'
  ? Object.fromEntries(Object.keys(value).sort().map(k => [k, canonical(value[k])])) : value;
export const digest = value => createHash('sha256').update(JSON.stringify(canonical(value))).digest('hex');
export function seal(record) { return { ...record, digest: digest(record) }; }
export function validBinding(record, adapter, now = Date.now()) {
  if (!record.binding) return !record.digest;
  const { digest: claimed, ...payload } = record;
  const binding = record.binding;
  return claimed === digest(payload) && binding.contractVersion === CONFORMANCE_CONTRACT
    && typeof binding.configurationDigest === 'string' && /^[a-f0-9]{64}$/.test(binding.configurationDigest)
    && typeof binding.runtimeDigest === 'string' && /^[a-f0-9]{64}$/.test(binding.runtimeDigest)
    && Number.isFinite(Date.parse(binding.generatedAt)) && Date.parse(binding.generatedAt) <= now
    && Date.parse(binding.expiresAt) > now && Date.parse(binding.expiresAt) - Date.parse(binding.generatedAt) <= 86400000
    && (!adapter.identityAuthority?.configurationDigest || adapter.identityAuthority.configurationDigest === binding.configurationDigest)
    && (!adapter.identityAuthority?.runtimeDigest || adapter.identityAuthority.runtimeDigest === binding.runtimeDigest)
    && (!adapter.identityAuthority?.contractVersion || adapter.identityAuthority.contractVersion === binding.contractVersion);
}
