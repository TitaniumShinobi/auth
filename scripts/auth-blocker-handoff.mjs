import { CAPABILITIES, CATALOG_VERSION } from './auth-capability-catalog.mjs';

const contracts = new Map(CAPABILITIES.map(entry => [entry.id, entry]));
const nonempty = value => typeof value === 'string' && value.trim().length > 0;
const command = value => Array.isArray(value) && value.length > 0 && value.every(nonempty) ? [...value] : null;
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const supportedDynamic = id => /^(counterpart:|email-message:).+/.test(id);
const evidence = value => Array.isArray(value) ? value.filter(nonempty) : [];

function handlerAvailable(context, id) {
  const registered = context.registeredCapabilities ?? context.actCapabilities;
  if (registered instanceof Map) return typeof registered.get(id) === 'function';
  if (Array.isArray(registered)) return registered.includes(id);
  return false;
}

/** Transfer blockers as data. Commands are argument arrays and are never executed here. */
export function createBlockerHandoffs(report, context = {}) {
  const validReport = object(report) && Array.isArray(report.capabilities);
  const rows = validReport ? report.capabilities : [];
  const blockers = new Map();
  for (const row of rows) {
    if (nonempty(row?.id) && !['PASS', 'NOT_APPLICABLE'].includes(row.verification)) blockers.set(row.id, { row });
  }
  for (const id of Array.isArray(report?.unknownCapabilities) ? report.unknownCapabilities : []) {
    if (nonempty(id)) blockers.set(id, { ...blockers.get(id), unknown: true });
  }
  for (const regression of Array.isArray(report?.regressions) ? report.regressions : []) {
    if (nonempty(regression?.id)) blockers.set(regression.id, {
      ...blockers.get(regression.id), row: rows.find(row => row.id === regression.id), regression,
    });
  }
  if (!blockers.size && validReport && report.verification === 'PASS' && !report.error) return [];
  if (!blockers.size && report?.operator === 'ACT' && nonempty(context.capabilityId || report.capabilityId)) {
    const id = context.capabilityId || report.capabilityId;
    blockers.set(id, { row: { id, applicability: 'INDETERMINATE', verification: report.verification || 'INDETERMINATE', reason: report.error || report.message } });
  }
  if (!blockers.size) blockers.set('', { ambiguous: true });

  return [...blockers].sort(([left], [right]) => left.localeCompare(right)).map(([id, blocker]) => {
    const row = blocker.row || {};
    const contract = contracts.get(id);
    const known = Boolean(contract || (supportedDynamic(id) && row.id === id) || ['counterparts:missing', 'emails:missing', 'welcome-emails:missing'].includes(id));
    const contractUnavailable = context.reusableContracts?.[id] === false;
    const authGap = !blocker.ambiguous && (!known || contractUnavailable);
    const act = handlerAvailable(context, id);
    const authorized = context.authorization === true;
    const applicability = row.applicability || 'INDETERMINATE';
    const external = context.externalBlockers?.[id];
    const missingAuthority = row.applicability === 'TRUE' && row.checks?.some(check => check.authority_result === 'INDETERMINATE' || check.authority_result === 'FAIL');
    const establishedExternal = object(external) && external.established === true && nonempty(external.reason);
    let nextOwner = 'INDETERMINATE';
    let reasonCode = nonempty(report?.error) ? report.error : 'BLOCKER_NOT_ESTABLISHED';
    const actError = report?.operator === 'ACT' && ['AUTHORIZATION_REQUIRED', 'NO_SUPPORTED_REPAIR'].includes(report.error) ? report.error : null;
    if (actError === 'AUTHORIZATION_REQUIRED') {
      nextOwner = 'OPERATOR APPROVAL'; reasonCode = actError;
    } else if (actError === 'NO_SUPPORTED_REPAIR') {
      nextOwner = authGap ? 'AUTH DEVELOPMENT' : 'PRODUCT INTEGRATION'; reasonCode = actError;
    } else if (authGap) {
      nextOwner = 'AUTH DEVELOPMENT'; reasonCode = known ? 'AUTH_CONTRACT_UNSUPPORTED' : 'UNKNOWN_CAPABILITY';
    } else if (missingAuthority) {
      nextOwner = 'EXTERNAL AUTHORITY'; reasonCode = 'AUTHORITY_EVIDENCE_INCOMPLETE';
    } else if (establishedExternal) {
      nextOwner = 'EXTERNAL AUTHORITY'; reasonCode = 'EXTERNAL_BLOCKER_ESTABLISHED';
    } else if (act && applicability === 'TRUE' && context.authorization === false) {
      nextOwner = 'OPERATOR APPROVAL'; reasonCode = 'ACT_AUTHORIZATION_REQUIRED';
    } else if (!blocker.ambiguous && known) {
      nextOwner = 'PRODUCT INTEGRATION';
      reasonCode = blocker.regression ? 'CAPABILITY_REGRESSION' : blocker.unknown ? 'DECLARATION_MISSING'
        : applicability === 'INDETERMINATE' ? 'APPLICABILITY_NOT_ESTABLISHED'
        : row.implementation === 'NOT_ESTABLISHED' ? 'IMPLEMENTATION_NOT_ESTABLISHED'
        : row.verification === 'FAIL' ? 'VERIFICATION_FAILED' : 'EVIDENCE_INCOMPLETE';
    }
    const declarationChecks = { 'counterparts:missing': ['declare_applicable_counterpart_contracts'], 'emails:missing': ['declare_applicable_auth_email_contracts'], 'welcome-emails:missing': ['declare_applicable_welcome_email_contract'] };
    const expected = declarationChecks[id] || contract?.checks || (Array.isArray(row.checks) ? row.checks.map(check => check.id).filter(nonempty) : []);
    const observedChecks = Array.isArray(row.checks) ? row.checks.filter(check => nonempty(check?.id)).map(check => ({ ...check, id: check.id, result: check.result || 'INDETERMINATE' })) : [];
    const reason = nonempty(row.reason) ? row.reason : reasonCode;
    const observed = new Map(observedChecks.map(check => [check.id, check.result]));
    const unmet = expected.filter(check => observed.get(check) !== 'PASS');
    return {
      wizard: 'AUTH', version: '1', catalogVersion: report?.catalogVersion || CATALOG_VERSION,
      target: { productId: report?.productId || null, ...(nonempty(report?.revision) ? { revision: report.revision } : {}), ...(nonempty(context.repository) ? { repository: context.repository } : {}) },
      requestedOutcome: nonempty(context.requestedOutcome) ? context.requestedOutcome : 'Establish the applicable AUTH capability and verify its required evidence.',
      capabilityId: id || null,
      verification_profile: report?.verification_profile || 'FULL_AUTHORITY_CONFORMANCE',
      profile_scope: report?.profile_required_checks ? (report.profile_required_checks.some(check => check.capabilityId === id && !['PASS','NOT_APPLICABLE'].includes(check.verification)) ? 'REQUIRED_CURRENT_PROFILE' : 'OUTSIDE_CURRENT_PROFILE') : 'REQUIRED_CURRENT_PROFILE',
      mdboLineage: { status: 'NOT_ESTABLISHED', reason: 'This report does not establish MDBO evaluator lineage; no L1 is assigned.' },
      operator: report?.operator || 'INDETERMINATE', applicability,
      implementation: row.implementation || 'INDETERMINATE', verification: row.verification || 'INDETERMINATE',
      reasonCode,
      observedEvidence: { references: evidence(row.evidence), checks: observedChecks,
        ...(blocker.regression ? { regression: { before: blocker.regression.before, after: blocker.regression.after } } : {}),
        ...(establishedExternal ? { externalBlocker: { reason: external.reason, ...(nonempty(external.owner) ? { owner: external.owner } : {}) } } : {}) },
      expectedEvidence: expected.map(check => ({ id: check, result: 'PASS', source: row.checks?.find(item => item.id === check)?.verification_owner || 'PRODUCT' })),
      capabilityGap: authGap ? 'AUTH_REUSABLE_CONTRACT_REQUIRED' : `${reason}${unmet.length ? `; failed or missing evidence: ${unmet.join(', ')}` : ''}`,
      actAvailability: act ? 'AVAILABLE' : 'UNAVAILABLE', authorizationRequired: (act || report?.operator === 'ACT') && !authorized,
      authorizationState: context.authorization === true ? 'GRANTED' : context.authorization === false ? 'NOT_GRANTED' : 'NOT_ESTABLISHED',
      verificationRequired: true,
      nextOwner,
      reproductionCommand: command(context.reproductionCommand), verificationCommand: command(context.verificationCommand),
      resumeCondition: actError === 'NO_SUPPORTED_REPAIR' ? 'Register a supported bounded repair adapter for the established contract (or establish the missing reusable AUTH contract), obtain scoped authorization, and rerun verification.'
        : authGap && nextOwner !== 'OPERATOR APPROVAL' ? 'A reusable AUTH contract covers this capability and the wizard can evaluate it.'
        : nextOwner === 'OPERATOR APPROVAL' ? 'Explicit capability-scoped ACT authorization is supplied; a supported bounded repair handler is still required before ACT, followed by fresh verification.'
        : 'The declared blocker is resolved and a fresh report verifies the capability without regression.',
      instruction: authGap || actError === 'NO_SUPPORTED_REPAIR' ? 'STOP' : 'Resolve the blocker with the named owner; rerun verification before resuming.',
    };
  });
}
