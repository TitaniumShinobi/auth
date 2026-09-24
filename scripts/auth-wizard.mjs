import { applyVerificationProfile } from './auth-verification-profiles.mjs';
import { CAPABILITIES, CATALOG_VERSION, COMPATIBLE_BASELINE_VERSIONS } from './auth-capability-catalog.mjs';
import { evaluateOwnedCheck } from './auth-evidence-ownership.mjs';
import { verifyLifecycle } from './auth-lifecycle.mjs';

const own = (value, key) => Object.prototype.hasOwnProperty.call(value || {}, key);
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const nonempty = value => typeof value === 'string' && value.trim().length > 0;
const evidencePresent = entry => Array.isArray(entry?.evidence) && entry.evidence.length > 0 && entry.evidence.every(nonempty);
const operators = ['OBSERVE', 'ASSESS', 'DECIDE', 'VERIFY'];

function evaluateCapability(contract, entry, adapter, trustedAuthorityEvidence) {
    let applicability = ['TRUE', 'FALSE', 'INDETERMINATE'].includes(entry?.applicability) ? entry.applicability : 'INDETERMINATE';
    if (applicability === 'FALSE' && !nonempty(entry.reason)) applicability = 'INDETERMINATE';
    let implementation = ['ESTABLISHED', 'NOT_ESTABLISHED', 'INDETERMINATE'].includes(entry?.implementation) ? entry.implementation : 'INDETERMINATE';
    if (implementation === 'ESTABLISHED' && !evidencePresent(entry)) implementation = 'INDETERMINATE';
    const checks = contract.checks.map(id => adapter?.authenticationRole === 'RELYING_PARTY'
      ? evaluateOwnedCheck(contract.id, id, entry, adapter, trustedAuthorityEvidence) : ({ id, result: own(entry?.checks, id) && typeof entry.checks[id] === 'boolean'
      ? (entry.checks[id] ? 'PASS' : 'FAIL') : 'INDETERMINATE' }));
    const failures = checks.filter(check => check.result === 'FAIL').map(check => check.id);
    const missing = checks.filter(check => check.result === 'INDETERMINATE').map(check => check.id);
    let verification = applicability === 'FALSE' ? 'NOT_APPLICABLE' : applicability === 'INDETERMINATE' ? 'INDETERMINATE'
      : implementation === 'NOT_ESTABLISHED' || failures.length ? 'FAIL'
      : implementation !== 'ESTABLISHED' || missing.length ? 'INDETERMINATE' : 'PASS';
    let lifecycle;
    if (entry?.trace !== undefined && applicability === 'TRUE') {
      lifecycle = verifyLifecycle(entry.trace);
      if (lifecycle.verification === 'FAIL') verification = 'FAIL';
      else if (lifecycle.verification !== 'PASS' && verification === 'PASS') verification = 'INDETERMINATE';
    }
    return { id: contract.id, family: contract.family, applicability, implementation, verification, checks,
      ...(nonempty(entry?.reason) ? { reason: entry.reason } : {}),
      evidence: evidencePresent(entry) ? [...entry.evidence] : [], ...(lifecycle ? { lifecycle } : {}) };
}

/** Evaluate product-owned observations, never infer applicability from product names. */
export function evaluateAdapter(adapter, { baseline, operator = 'VERIFY', trustedAuthorityEvidence = [], verificationProfile = 'FULL_AUTHORITY_CONFORMANCE' } = {}) {
  if (!operators.includes(operator)) throw new Error('Use executeRepair for explicitly authorized ACT');
  if (!object(adapter) || adapter.schemaVersion !== 1 || !nonempty(adapter.productId) || !nonempty(adapter.revision) || !object(adapter.capabilities)) {
    throw new Error('Adapter requires schemaVersion:1, productId, revision and capabilities object');
  }
  if (!Array.isArray(trustedAuthorityEvidence)) throw new Error('trustedAuthorityEvidence must be an operator-supplied array');
  if (adapter.authenticationRole !== undefined && !['RELYING_PARTY', 'IDENTITY_AUTHORITY'].includes(adapter.authenticationRole)) throw new Error('Invalid authenticationRole');
  const known = new Set(CAPABILITIES.map(capability => capability.id));
  const unknown = Object.keys(adapter.capabilities).filter(id => !known.has(id)).sort();
  const unknownDeclarations = [...unknown];
  const capabilities = CAPABILITIES.map(contract => evaluateCapability(contract, adapter.capabilities[contract.id], adapter, trustedAuthorityEvidence));
  const counterparts = adapter.counterparts === undefined ? [] : adapter.counterparts;
  const emails = adapter.emails === undefined ? [] : adapter.emails;
  if (!Array.isArray(counterparts) || !Array.isArray(emails)) throw new Error('counterparts and emails must be arrays');
  const ids = new Set();
  for (const counterpart of counterparts) {
    if (!object(counterpart) || !nonempty(counterpart.productId) || counterpart.productId === adapter.productId || ids.has(counterpart.productId)) throw new Error('Counterparts require unique other product IDs');
    ids.add(counterpart.productId);
    capabilities.push(evaluateCapability({ id: `counterpart:${counterpart.productId}`, family: 'cross_product',
      checks: ['optional_offer', 'explicit_acceptance', 'decline_preserves_primary_access', 'existing_account_reused'] }, counterpart));
  }
  const kinds = new Set(['verification', 'verification_resend', 'magic_link', 'password_recovery', 'account_security_change', 'new_device_notice', 'welcome']);
  ids.clear();
  for (const email of emails) {
    if (!object(email) || !nonempty(email.id) || ids.has(email.id)) throw new Error('Emails require unique IDs');
    ids.add(email.id);
    const result = evaluateCapability({ id: `email-message:${email.id}`, family: email.kind === 'welcome' ? 'enrollment' : 'auth_email', checks:
      email.kind === 'welcome'
        ? ['trigger_after_success', 'recipient_defined', 'delivery_adapter', 'template_exists', 'delivery_result', 'duplicate_policy_defined']
        : ['trigger_defined', 'recipient_defined', 'delivery_adapter', 'template_exists', 'delivery_result', 'duplicate_policy_defined', 'token_url_secrecy', 'expiry_policy_defined'] }, email);
    if (!kinds.has(email.kind)) { result.verification = 'FAIL'; result.error = 'OUTSIDE_AUTH_EMAIL_AUTHORITY'; }
    capabilities.push(result);
  }
  if (capabilities.some(item => item.id === 'cross_product.offer' && item.applicability === 'TRUE') && !counterparts.length) unknown.push('counterparts:missing');
  if (capabilities.some(item => item.family === 'auth_email' && item.applicability === 'TRUE') && !emails.length) unknown.push('emails:missing');
  if (capabilities.some(item => item.id === 'welcome.email' && item.applicability === 'TRUE') &&
      !emails.some(email => email.kind === 'welcome' && email.applicability === 'TRUE')) unknown.push('welcome-emails:missing');

  const regressions = [];
  if (baseline !== undefined) {
    if (!object(baseline) || baseline.schemaVersion !== 1 || !COMPATIBLE_BASELINE_VERSIONS.includes(baseline.catalogVersion) || baseline.productId !== adapter.productId || !Array.isArray(baseline.capabilities)) {
      throw new Error('Baseline must be a wizard report for the same product and catalog');
    }
    if (baseline.authenticationRole === 'RELYING_PARTY' && adapter.authenticationRole !== 'RELYING_PARTY') throw new Error('Relying-party baseline requires explicit relying-party ownership');
    const current = new Map(capabilities.map(capability => [capability.id, capability]));
    for (const previous of baseline.capabilities) {
      if (previous.applicability === 'TRUE' && previous.verification === 'PASS' && current.get(previous.id)?.verification !== 'PASS') {
        regressions.push({ id: previous.id, before: 'PASS', after: current.get(previous.id)?.verification || 'MISSING' });
      }
    }
  }
  const verification = regressions.length || capabilities.some(entry => entry.verification === 'FAIL') ? 'FAIL'
    : unknown.length || capabilities.some(entry => entry.verification === 'INDETERMINATE') ? 'INDETERMINATE' : 'PASS';
  return applyVerificationProfile({ schemaVersion: 1, catalogVersion: CATALOG_VERSION, productId: adapter.productId, revision: adapter.revision,
    operator, verification, authenticationRole: adapter.authenticationRole || 'UNSPECIFIED', capabilities, unknownCapabilities: unknown, unknownDeclarations, regressions,
    decisions: capabilities.filter(entry => !['PASS', 'NOT_APPLICABLE'].includes(entry.verification)).map(entry => ({ id: entry.id,
      action: entry.applicability === 'INDETERMINATE' ? 'ESTABLISH_APPLICABILITY'
        : entry.implementation !== 'ESTABLISHED' ? 'ESTABLISH_IMPLEMENTATION' : 'VERIFY_OR_REPAIR' })) }, verificationProfile, baseline);
}

/** Product integrations supply bounded handlers; AUTH never executes manifest commands. */
export async function executeRepair(adapter, { capabilityId, authorization, handlers, observe, baseline, trustedAuthorityEvidence = [], verificationProfile = 'FULL_AUTHORITY_CONFORMANCE' } = {}) {
  if (!authorization || authorization.authorized !== true || authorization.productId !== adapter?.productId ||
      authorization.revision !== adapter?.revision || authorization.capabilityId !== capabilityId) {
    throw new Error('ACT requires explicit product/revision/capability-scoped authorization');
  }
  const before = evaluateAdapter(adapter, { baseline, trustedAuthorityEvidence, verificationProfile });
  const capability = before.capabilities.find(entry => entry.id === capabilityId);
  if (!capability || capability.applicability !== 'TRUE') throw new Error('ACT requires established applicability');
  const handler = handlers instanceof Map ? handlers.get(capabilityId) : undefined;
  if (typeof handler !== 'function' || typeof observe !== 'function') throw new Error('No supported repair handler and observer');
  let failure;
  try { await handler(Object.freeze({ productId: adapter.productId, revision: adapter.revision, capabilityId })); }
  catch (error) { failure = typeof error?.code === 'string' && /^[A-Z][A-Z0-9_]{1,79}$/.test(error.code) ? error.code : 'REPAIR_FAILED'; }
  const observed = await observe();
  if (observed.productId !== adapter.productId) throw new Error('Repair observer changed product identity');
  let report = evaluateAdapter(observed, { baseline: before, operator: 'VERIFY', trustedAuthorityEvidence, verificationProfile });
  if (baseline) {
    const historical = evaluateAdapter(observed, { baseline, operator: 'VERIFY', trustedAuthorityEvidence, verificationProfile });
    if (historical.regressions.length) report = { ...report, verification: 'FAIL', regressions: [...report.regressions, ...historical.regressions] };
  }
  return { ...report, operator: 'ACT', verificationRequired: true, verifiedAfterAct: true,
    ...(failure ? { verification: 'FAIL', full_verification: 'FAIL', profile_verification: 'FAIL', error: failure } : {}) };
}
