import { validBinding } from './auth-conformance-binding.mjs';
/** Ownership is an AUTH contract, never a product-supplied per-check override. */
const external = {
  'assertion.resource_grant': ['registered_client_session_bound', 'narrow_capabilities_enforced', 'admission_separate_from_owner', 'artifact_expiry_bounded', 'durable_grant_revocation'],
  'assertion.resource_status': ['authenticated_workload_required', 'online_status_per_request', 'status_failure_fails_closed', 'current_owner_policy_enforced', 'read_replay_policy_explicit'],
  'enrollment.product': ['authority_completion_verified'],
  'assertion.issuance': ['authenticated_session_required', 'subject_owner_binding_authorized', 'relying_party_scope_authorized'],
  'assertion.validation': ['signature_issuer_audience_verified', 'signed_subject_owner_binding_verified', 'relying_party_scope_verified', 'expiry_verified', 'replay_policy_enforced', 'wrong_owner_rejected', 'wrong_relying_party_rejected', 'excess_scope_rejected', 'invalid_assertion_fails_closed'],
  'signin': ['invalid_credentials_rejected'],
  'signin.returning': ['returning_identity_reused', 'enrollment_status_respected'],
  'session.establishment': ['verified_identity_required', 'session_expiry_enforced'],
  'session.restart': ['revocation_preserved_after_restart'],
  'session.validation': ['invalid_session_rejected', 'expired_session_rejected', 'revoked_session_rejected'],
  'session.refresh': ['refresh_proof_verified', 'token_rotated', 'replay_rejected'],
  'session.logout': ['server_session_invalidated'],
  'session.revocation': ['revocation_persisted', 'revoked_access_rejected', 'revoked_refresh_rejected'],
  'session.expiry': ['expiry_enforced'],
  'relying_party.authorization': ['client_validated', 'redirect_validated', 'subject_assertion_verified', 'replay_rejected'],
  'relying_party.pkce': ['verifier_checked_when_applicable'],
  'relying_party.callback': ['redirect_allowlisted'],
  'security.identity': ['unverified_identity_not_authenticated', 'duplicate_creation_prevented'],
  'security.protocol': ['replay_protection_enforced', 'redirect_validation_enforced', 'nonce_verified_when_required'],
};
const shared = {
  'security.crypto': ['tokens_cryptographically_random', 'sensitive_tokens_protected_at_rest', 'secrets_not_logged', 'tokens_not_logged'],
};
const contract = { 'relying_party.authority': ['identity_authority_boundary_declared'], 'assertion.integration': ['authority_boundary_declared', 'replay_policy_declared'] };
export function verificationOwner(capabilityId, checkId) {
  if (external[capabilityId]?.includes(checkId)) return 'EXTERNAL_AUTHORITY';
  if (shared[capabilityId]?.includes(checkId)) return 'SHARED';
  if (contract[capabilityId]?.includes(checkId)) return 'CONTRACT';
  return 'PRODUCT';
}

/** Trusted evidence is provided separately by the invoking operator, not the adapter.
 * Bind every attestation to the exact product revision, authority deployment and check.
 * Health is not conformance. Evidence contains references only, never tokens.
 */
export function evaluateOwnedCheck(capabilityId, id, entry, adapter, trustedEvidence = []) {
  const boundAdapter = ['assertion.validation', 'assertion.resource_status'].includes(capabilityId) ? { ...adapter, identityAuthority: adapter.resourceAuthority }
    : capabilityId === 'enrollment.product' && id === 'authority_completion_verified'
      ? { ...adapter, identityAuthority: adapter.enrollmentAuthority } : adapter;
  const owner = verificationOwner(capabilityId, id);
  const local = typeof entry?.checks?.[id] === 'boolean' && Array.isArray(entry.evidence) && entry.evidence.some(v => typeof v === 'string' && v.trim())
    ? (entry.checks[id] ? 'PASS' : 'FAIL') : 'INDETERMINATE';
  const records = trustedEvidence.filter(e => e && validBinding(e, boundAdapter) && e.productId === adapter.productId && e.revision === adapter.revision &&
    e.authority === boundAdapter.identityAuthority?.id && e.authorityRevision === boundAdapter.identityAuthority?.revision &&
    typeof e.authority === 'string' && e.authority.length && typeof e.authorityRevision === 'string' && e.authorityRevision.length &&
    e.capabilityId === capabilityId && e.checkId === id && e.verification_owner === 'EXTERNAL_AUTHORITY' &&
    e.kind === 'CONFORMANCE' && Array.isArray(e.references) && e.references.length && e.references.every(r => typeof r === 'string' && r.trim()) &&
    ['PASS', 'FAIL'].includes(e.result));
  const authority = records.some(e => e.result === 'FAIL') ? 'FAIL' : records.some(e => e.result === 'PASS') ? 'PASS' : 'INDETERMINATE';
  const result = owner === 'EXTERNAL_AUTHORITY' ? authority : owner === 'SHARED'
    ? (local === 'FAIL' || authority === 'FAIL' ? 'FAIL' : local === 'PASS' && authority === 'PASS' ? 'PASS' : 'INDETERMINATE') : local;
  return { id, result, verification_owner: owner,
    evidence_method: owner === 'CONTRACT' ? 'STATIC_CONTRACT' : owner === 'PRODUCT' ? 'PRODUCT_RUNTIME_OR_SAFE_NEGATIVE_TEST' : 'AUTHORITY_CONFORMANCE',
    product_result: owner === 'EXTERNAL_AUTHORITY' ? 'NOT_REQUIRED' : local,
    authority_result: ['EXTERNAL_AUTHORITY', 'SHARED'].includes(owner) ? authority : 'NOT_REQUIRED',
    authority_evidence: records.flatMap(e => e.references) };
}
