import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const requirements = {
  NATIVE_SIGNIN: {
    configured_runtime: ['canonical_enrollment_completion_schema_compatible'],
    live_acceptance: ['native_credentials_accepted', 'canonical_admitted_session_established'],
  },
  ASSERTION_INTEGRATION: {
    configured_runtime: ['issuer_signer_available', 'resource_trust_configured'],
    live_acceptance: ['current_session_assertion_issued', 'resource_accepts_current_session_assertion'],
  },
  PROVIDER_SIGNIN: {
    configured_runtime: ['selected_provider_configured'],
    live_acceptance: ['provider_authorization_completed', 'canonical_session_established'],
  },
};
const aggregate = checks => checks.some(c => c.result === 'FAIL') ? 'FAIL'
  : checks.some(c => c.result !== 'PASS') ? 'INDETERMINATE' : 'PASS';

// A source-test report is deliberately not an input to runtime aggregation.
// Observations are scoped to one environment and one selected flow.
export function evaluateRuntimeAcceptance(input, { now = Date.now(), maxAgeMs = 24 * 60 * 60 * 1000 } = {}) {
  const contract = requirements[input.contract];
  if (!contract || !input.environment || !input.target) throw new Error('INVALID_ACCEPTANCE_SCOPE');
  const gates = {};
  for (const [gate, ids] of Object.entries(contract)) {
    const checks = ids.map(id => {
      const matches = (input[gate] || []).filter(c => c.id === id);
      const supplied = matches[0];
      const observed = Date.parse(supplied?.observedAt);
      const evidenced = matches.length === 1 && supplied?.environment === input.environment
        && Array.isArray(supplied?.evidence) && supplied.evidence.length > 0
        && supplied.evidence.every(value => typeof value === 'string' && value.trim().length > 0)
        && supplied?.freshness === 'CURRENT_OBSERVATION' && Number.isFinite(observed)
        && observed <= now && now - observed <= maxAgeMs
        && supplied?.expected && supplied?.owner;
      return { id, ...(supplied || {}), result: evidenced && ['PASS', 'FAIL'].includes(supplied.result) ? supplied.result : 'INDETERMINATE' };
    });
    gates[gate] = { result: aggregate(checks), checks };
  }
  return { schemaVersion: 1, target: input.target, environment: input.environment, contract: input.contract,
    source_conformance: input.source_conformance || { result: 'INDETERMINATE', reason: 'Not assessed in this runtime observation' },
    ...gates, acceptance: aggregate(Object.values(gates)),
    cause: input.cause || { result: 'INDETERMINATE' },
    evaluatedAt: new Date(now).toISOString(), maxEvidenceAgeMs: maxAgeMs,
    limitation: 'Runtime observations do not establish other environments or unobserved signin methods. Source conformance cannot satisfy runtime gates.' };
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const report = evaluateRuntimeAcceptance(JSON.parse(readFileSync(process.argv[2], 'utf8')));
  console.log(JSON.stringify(report, null, 2));
  if (report.acceptance !== 'PASS') process.exitCode = 2;
}
