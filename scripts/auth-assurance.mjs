import { digest } from './auth-conformance-binding.mjs';

/** Pins come from reviewed operator/CI policy, never from the evidence being checked. */
export function runtimeAcceptance(report, proof, trustedDigest, now = Date.now()) {
  if (!proof || !trustedDigest) return 'INDETERMINATE';
  if (digest(proof) !== trustedDigest || proof.schema !== 'life.auth.runtime-acceptance/1' ||
      proof.productId !== report.productId || proof.revision !== report.revision ||
      typeof proof.runId !== 'string' || !proof.runId.trim() ||
      !Number.isFinite(Date.parse(proof.issuedAt)) || Date.parse(proof.issuedAt) > now ||
      !(Date.parse(proof.expiresAt) > now) || Date.parse(proof.expiresAt) - Date.parse(proof.issuedAt) > 86400000 ||
      !Array.isArray(proof.checks)) return 'FAIL';
  const required = report.profile_required_checks.filter(c => c.applicability === 'TRUE' && c.verification_owner !== 'EXTERNAL_AUTHORITY');
  if (!required.length) return 'INDETERMINATE';
  for (const check of required) {
    const rows = proof.checks.filter(row => row.capabilityId === check.capabilityId && row.checkId === check.checkId);
    if (rows.length !== 1 || !Array.isArray(rows[0].references) || !rows[0].references.length || !rows[0].references.every(x => typeof x === 'string' && x.trim())) return 'INDETERMINATE';
    if (rows[0].result === 'FAIL') return 'FAIL';
    if (rows[0].result !== 'PASS') return 'INDETERMINATE';
  }
  return 'PASS';
}
