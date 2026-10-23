import { createHash, randomUUID } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';
import { createExistingRepair } from './auth-existing-repair.mjs';
import { evaluateAdapter } from './auth-wizard.mjs';
import { executeRepair } from './auth-wizard.mjs';
import { LANES, runVerificationLane, validateLaneSpec } from './auth-verification-lane.mjs';
import { assessNativeTarget, recoverNativeTransactions } from './auth-native-wizard.mjs';
import { digest } from './auth-conformance-binding.mjs';

const hash = value => createHash('sha256').update(value).digest('hex');
const nonempty = value => typeof value === 'string' && value.trim().length > 0;

/** Run the existing read-only AUTH gates when a request supplies no reviewed repair. */
export async function diagnosePlainLanguageObjective({ root, objective }) {
  if (!nonempty(objective)) throw new Error('OBJECTIVE_REQUIRED');
  root = await fs.realpath(path.resolve(root));
  const nativeAssessment = await assessNativeTarget(root);
  let head = null;
  try { head = execFileSync('git', ['rev-parse', '--verify', 'HEAD'], { cwd: root, encoding: 'utf8', timeout: 5000, stdio: ['ignore', 'pipe', 'ignore'] }).trim(); }
  catch { /* A non-Git product has no source revision proof. */ }
  // A Git HEAD is a locator, not proof of the current working tree or runtime.
  const adapter = { schemaVersion: 1, productId: path.basename(root), revision: head || 'UNBOUND', capabilities: {} };
  const operators = ['OBSERVE', 'ASSESS', 'DECIDE', 'VERIFY'];
  const wizard = operators.map(operator => {
    const report = evaluateAdapter(adapter, { operator });
    return { operator, verification: report.verification, profileVerification: report.profile_verification,
      indeterminateCapabilities: report.capabilities.filter(item => item.verification === 'INDETERMINATE').length };
  });
  return {
    schema: 'life.auth.completion-result/1', result: 'NOT_VERIFIED',
    objectiveBinding: { objective, objectiveSha256: hash(objective), repository: root,
      productId: adapter.productId, headRevision: head, workingTreeRevisionVerified: false, preserved: true },
    inputConstruction: { mode: 'AUTOMATIC_READ_ONLY', result: 'PARTIAL', adapter: 'UNKNOWN_EVIDENCE',
      nativeAssessment: 'EXECUTED', reviewedRepairSpec: 'UNAVAILABLE',
      reason: 'The request and static assessment do not establish a capability-scoped repair, postimage, or live verification commands.' },
    nativeAssessment,
    mdbo: { contract: 'AI Wizard Execution Contract', gate: 'NOT_EXECUTED_NO_SUPPORTED_REPAIR', lineage: 'NOT_CLAIMED',
      operatorSequence: operators, act: 'NOT_EXECUTED_NO_SUPPORTED_REPAIR', durableCompletion: false },
    wizard,
    repair: { result: 'NOT_ATTEMPTED', changedFiles: [] },
    rptvl: { result: 'NOT_VERIFIED', lanes: LANES.map(id => ({ id, required: true, result: 'NOT_VERIFIED' })) },
    productE2E: { result: 'NOT_VERIFIED', evidenceScope: null },
    blocker: 'NO_SUPPORTED_OBJECTIVE_BOUND_REPAIR',
  };
}
function laneAssessment(rptvl) {
  const rows = new Map(Array.isArray(rptvl?.lanes) ? rptvl.lanes.map(row => [row.id, row]) : []);
  const complete = LANES.every(id => rows.has(id));
  const required = complete && LANES.every(id => rows.get(id).required === true);
  const passing = required && LANES.every(id => rows.get(id).result === 'PASS');
  const acceptance = rows.get('acceptance');
  return {
    ids: [...LANES], complete, required, passing,
    acceptance: acceptance?.result || 'NOT_VERIFIED',
  };
}

function objectiveCapabilityAssessment(wizardReport, verificationSpec) {
  const requiredChecks = [...new Set(verificationSpec.lanes.filter(lane => lane.required).flatMap(lane => lane.checks))];
  const required = new Map(wizardReport.profile_required_checks.map(row => [`${row.capabilityId}/${row.checkId}`, row]));
  const checks = requiredChecks.map(id => {
    const row = required.get(id);
    return { id, result: row?.verification || 'INDETERMINATE',
      applicability: row?.applicability || 'INDETERMINATE',
      implementation: row?.implementation || 'INDETERMINATE' };
  });
  const knownFailures = wizardReport.capabilities.filter(row => row.verification === 'FAIL').map(row => row.id);
  const unknownDeclarations = wizardReport.unknownDeclarations || [];
  const regressions = wizardReport.regressions || [];
  return {
    result: checks.some(check => check.result === 'FAIL') || knownFailures.length || regressions.length ? 'FAIL'
      : unknownDeclarations.length ? 'INDETERMINATE'
      : checks.length && checks.every(check => check.result === 'PASS') ? 'PASS' : 'INDETERMINATE',
    checks, knownFailures, unknownDeclarations, regressions,
    fullAuthorityProfile: wizardReport.profile_verification,
    indeterminateCapabilities: wizardReport.capabilities.filter(row => row.verification === 'INDETERMINATE').map(row => row.id),
  };
}

/** Verify an already implemented objective without manufacturing an ACT. */
export async function verifyExistingAuthObjective({ root, objective, adapter, verificationSpec }) {
  if (!nonempty(objective)) throw new Error('OBJECTIVE_REQUIRED');
  if (!adapter || !verificationSpec) throw new Error('VERIFICATION_INPUT_REQUIRED');
  if (verificationSpec.requestedOutcome !== objective) throw new Error('OBJECTIVE_BINDING_MISMATCH');
  if (verificationSpec.productId !== adapter.productId || verificationSpec.revision !== adapter.revision) {
    throw new Error('OBJECTIVE_PRODUCT_BINDING_MISMATCH');
  }
  root = await fs.realpath(path.resolve(root));
  validateLaneSpec(verificationSpec, { productId: adapter.productId, revision: adapter.revision });
  const operators = ['OBSERVE', 'ASSESS', 'DECIDE', 'VERIFY'];
  const wizardReports = operators.map(operator => evaluateAdapter(adapter, { operator }));
  const wizard = wizardReports.map(report => ({ operator: report.operator,
    verification: report.verification, profileVerification: report.profile_verification }));
  const objectiveCapabilityConformance = objectiveCapabilityAssessment(wizardReports.at(-1), verificationSpec);
  const rptvl = await runVerificationLane({ root, spec: verificationSpec,
    binding: { productId: adapter.productId, revision: adapter.revision },
    changedPaths: [], executionId: randomUUID() });
  const lanes = laneAssessment(rptvl);
  const objectivePreserved = rptvl.outcomeDigest === digest(objective);
  const revisionBound = rptvl.productId === adapter.productId && rptvl.revision === adapter.revision &&
    nonempty(rptvl.candidateDigest) && nonempty(rptvl.executionId);
  const normalBuild = rptvl.normalBuild?.result || 'NOT_VERIFIED';
  const liveAcceptance = objectivePreserved && revisionBound && rptvl.result === 'VERIFIED' && lanes.passing &&
    normalBuild === 'PASS' && rptvl.evidenceScope === 'live';
  const verified = liveAcceptance && objectiveCapabilityConformance.result === 'PASS';
  const blocker = verified ? null
    : !objectivePreserved ? 'OBJECTIVE_PRESERVATION_NOT_VERIFIED'
    : !revisionBound ? 'REVISION_BOUND_EVIDENCE_REQUIRED'
    : !lanes.complete ? 'SEVEN_LANE_RESULT_REQUIRED'
    : lanes.acceptance !== 'PASS' ? 'LIVE_PRODUCT_ACCEPTANCE_FAILED'
    : !lanes.passing ? 'RPTVL_LANE_FAILURE'
    : normalBuild !== 'PASS' ? 'NORMAL_PRODUCT_GATE_NOT_VERIFIED'
    : rptvl.evidenceScope !== 'live' ? 'LIVE_PRODUCT_E2E_REQUIRED'
    : 'AUTH_CAPABILITY_CONFORMANCE_NOT_VERIFIED';
  return {
    schema: 'life.auth.completion-result/1', result: verified ? 'VERIFIED' : 'NOT_VERIFIED',
    objectiveBinding: { objective, objectiveSha256: hash(objective), repository: root,
      productId: adapter.productId, inputRevision: adapter.revision, preserved: objectivePreserved },
    mdbo: { contract: 'AI Wizard Execution Contract', gate: 'READ_ONLY_VERIFY_EXECUTED',
      lineage: 'NOT_CLAIMED', operatorSequence: operators, act: 'NOT_APPLICABLE_NO_SOURCE_REPAIR' },
    wizard, objectiveCapabilityConformance, repair: { result: 'NO_SOURCE_REPAIR', changedFiles: [] }, rptvl,
    sevenLaneAssessment: lanes,
    productE2E: { result: liveAcceptance ? 'PASS' : 'NOT_VERIFIED',
      evidenceScope: rptvl.evidenceScope, normalBuild, acceptanceLane: lanes.acceptance },
    blocker,
  };
}
/**
 * One bounded execution of the canonical MDBO completion obligation for an
 * existing AUTH repair. This coordinates existing AUTH machinery; it is not a
 * second repair engine and does not claim shared MDBO capability lineage.
 */
export async function completeAuthObjective({ root, objective, adapter, repairSpec, authorized = false }) {
  if (!nonempty(objective)) throw new Error('OBJECTIVE_REQUIRED');
  if (!root || !adapter || !repairSpec) throw new Error('COMPLETION_INPUT_REQUIRED');
  if (repairSpec?.verificationSpec?.requestedOutcome !== objective) throw new Error('OBJECTIVE_BINDING_MISMATCH');
  if (repairSpec.productId !== adapter.productId || repairSpec.revision !== adapter.revision) throw new Error('OBJECTIVE_PRODUCT_BINDING_MISMATCH');

  root = await fs.realpath(path.resolve(root));
  const objectiveBinding = {
    objective,
    objectiveSha256: hash(objective),
    productId: adapter.productId,
    inputRevision: adapter.revision,
    repository: root,
  };
  let recovery;
  try {
    recovery = await recoverNativeTransactions(root);
  } catch (error) {
    return {
      schema: 'life.auth.completion-result/1', result: 'NOT_VERIFIED',
      objectiveBinding, mdbo: { contract: 'AI Wizard Execution Contract', gate: 'EXECUTED', lineage: 'NOT_CLAIMED' },
      recovery: { state: 'BLOCKED', reason: error.message },
      rptvl: { result: 'NOT_VERIFIED' }, productE2E: { result: 'NOT_VERIFIED' },
      blocker: 'RECOVERY_BLOCKED',
    };
  }
  if (!authorized) {
    return {
      schema: 'life.auth.completion-result/1', result: 'NOT_VERIFIED', objectiveBinding,
      mdbo: { contract: 'AI Wizard Execution Contract', gate: 'EXECUTED', lineage: 'NOT_CLAIMED' },
      recovery, rptvl: { result: 'NOT_VERIFIED' }, productE2E: { result: 'NOT_VERIFIED' },
      blocker: 'EXPLICIT_AUTHORIZATION_REQUIRED',
    };
  }

  const kit = await createExistingRepair({ root, spec: repairSpec, adapter });
  let wizard;
  try {
    wizard = await executeRepair(adapter, {
      capabilityId: repairSpec.capabilityId,
      authorization: { authorized: true, productId: adapter.productId, revision: adapter.revision, capabilityId: repairSpec.capabilityId },
      handlers: kit.handlers,
      observe: kit.observe,
    });
  } catch (error) {
    wizard = { verification: 'FAIL', durableCompletion: false, error: error.message };
  }

  const repair = kit.getResult();
  const rptvl = wizard.rptvl || repair.rptvl || { result: 'NOT_VERIFIED', reason: 'RPTVL_RESULT_REQUIRED' };
  const lanes = laneAssessment(rptvl);
  const objectivePreserved = rptvl.outcomeDigest === digest(objective);
  const revisionBound = rptvl.productId === adapter.productId && rptvl.revision === adapter.revision &&
    nonempty(rptvl.candidateDigest) && nonempty(rptvl.executionId);
  const normalBuild = rptvl.normalBuild?.result || 'NOT_VERIFIED';
  const harnessConformance = wizard.durableCompletion === true && rptvl.result === 'VERIFIED' && lanes.passing &&
    objectivePreserved && revisionBound && normalBuild === 'PASS';
  const liveAcceptance = harnessConformance && rptvl.evidenceScope === 'live' && lanes.acceptance === 'PASS';
  const blocker = liveAcceptance ? null
    : !objectivePreserved ? 'OBJECTIVE_PRESERVATION_NOT_VERIFIED'
    : !revisionBound ? 'REVISION_BOUND_EVIDENCE_REQUIRED'
    : !lanes.complete ? 'SEVEN_LANE_RESULT_REQUIRED'
    : !lanes.passing ? 'RPTVL_LANE_FAILURE'
    : normalBuild !== 'PASS' ? 'NORMAL_PRODUCT_GATE_NOT_VERIFIED'
    : wizard.durableCompletion !== true ? (wizard.error || 'MDBO_COMPLETION_GATE_REJECTED')
    : rptvl.evidenceScope !== 'live' ? 'LIVE_PRODUCT_E2E_REQUIRED'
    : lanes.acceptance !== 'PASS' ? 'PRODUCT_ACCEPTANCE_LANE_REQUIRED'
    : 'PRODUCT_E2E_NOT_VERIFIED';

  return {
    schema: 'life.auth.completion-result/1',
    result: liveAcceptance ? 'VERIFIED' : 'NOT_VERIFIED',
    objectiveBinding: { ...objectiveBinding, preserved: objectivePreserved },
    mdbo: {
      contract: 'AI Wizard Execution Contract', gate: 'EXECUTED', lineage: 'NOT_CLAIMED',
      operatorSequence: ['OBSERVE', 'ASSESS', 'DECIDE', 'ACT', 'VERIFY'],
      durableCompletion: wizard.durableCompletion === true,
    },
    recovery,
    repair,
    rptvl,
    sevenLaneAssessment: lanes,
    productE2E: { result: liveAcceptance ? 'PASS' : 'NOT_VERIFIED', evidenceScope: rptvl.evidenceScope || null, normalBuild, acceptanceLane: lanes.acceptance },
    harnessConformance: harnessConformance ? 'PASS' : 'FAIL',
    blocker,
  };
}
