#!/usr/bin/env node
/** Read-only CleanHouse observation. Python auth remains the sole active authority. */
import { lstat, readFile, realpath } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { CAPABILITIES } from '../../scripts/auth-capability-catalog.mjs';
import { evaluateAdapter } from '../../scripts/auth-wizard.mjs';
import { createBlockerHandoffs } from '../../scripts/auth-blocker-handoff.mjs';

const active = new Set([
  'signin', 'signin.returning', 'signup', 'signup.admission', 'providers.password', 'providers.google',
  'providers.additional', 'providers.callback', 'session.establishment', 'session.persistence',
  'session.restart', 'session.expiry', 'session.validation', 'session.logout', 'consent.policy',
  'consent.reverification', 'ux.entry', 'ux.terminal', 'ux.continuation', 'security.failure',
  'security.identity', 'security.rate_limits', 'security.crypto', 'security.protocol',
]);
const requiredFiles = [
  'backend/api/auth.py', 'backend/auth_runtime_config.py', 'config/auth-runtime.json',
  'frontend/login.html', 'frontend/signup.html', 'frontend/js/auth.js',
  'tests/test_auth_api_validation.py', 'tests/test_auth_runtime_config.py',
];

async function regular(root, relative) {
  const target = path.join(root, relative);
  try {
    const entry = await lstat(target);
    return entry.isFile() && !entry.isSymbolicLink();
  } catch (error) { if (error?.code === 'ENOENT') return false; throw error; }
}

export async function observeCleanHouse(root) {
  root = await realpath(root);
  const presence = Object.fromEntries(await Promise.all(requiredFiles.map(async file => [file, await regular(root, file)])));
  let commit = 'UNAVAILABLE';
  try { commit = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim(); } catch {}
  const capabilities = Object.fromEntries(CAPABILITIES.map(capability => {
    if (!active.has(capability.id)) return [capability.id, {
      applicability: 'FALSE', implementation: 'NOT_ESTABLISHED',
      reason: 'Not offered by the observed CleanHouse Python authority scope.',
    }];
    return [capability.id, {
      applicability: 'TRUE', implementation: 'INDETERMINATE',
      evidence: requiredFiles.filter(file => presence[file]).map(file => `source:${file}`),
      checks: Object.fromEntries(capability.checks.map(check => [check, null])),
      reason: 'Fresh fixture or live evidence is required; source presence alone is not PASS.',
    }];
  }));
  return {
    root, presence,
    adapter: { schemaVersion: 1, productId: 'cleanhouse', revision: commit, authenticationRole: 'IDENTITY_AUTHORITY', capabilities },
  };
}

export async function assessCleanHouse(root) {
  const observed = await observeCleanHouse(root);
  const report = evaluateAdapter(observed.adapter, { operator: 'ASSESS' });
  const externalBlockers = {
    'providers.google': { established: true, owner: 'repository owner/provider administrator', reason: 'Live provider registration, credentials, and interactive consent are not available to automation.' },
    'providers.additional': { established: true, owner: 'repository owner/provider administrator', reason: 'Each additional provider requires owner registration, credentials, and consent.' },
  };
  const handoffs = createBlockerHandoffs(report, {
    repository: observed.root,
    requestedOutcome: 'Observe the existing Python authority without activating a second authority.',
    externalBlockers,
    reproductionCommand: ['node', 'integrations/cleanhouse/readiness.mjs', '--root', observed.root],
    verificationCommand: ['python3', '-m', 'unittest', 'tests.test_auth_api_validation', 'tests.test_auth_runtime_config'],
  });
  return {
    schemaVersion: 1,
    productId: 'cleanhouse',
    activeAuthority: { implementation: 'python', status: 'SOLE_ACTIVE_AUTHORITY' },
    nodeRuntime: { status: 'INACTIVE_CANDIDATE', activationAuthorized: false },
    sourceRevision: observed.adapter.revision,
    observedFiles: observed.presence,
    verification: report.verification,
    handoffs,
    classifications: Object.fromEntries(handoffs.map(handoff => [handoff.capabilityId || 'unscoped', handoff.executionClassification])),
    prohibitedAutomatedActions: ['provider_registration', 'credential_entry', 'live_identity_migration', 'authority_cutover'],
  };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const index = process.argv.indexOf('--root');
  if (index < 0 || !process.argv[index + 1]) throw new Error('Usage: readiness.mjs --root <cleanhouse>');
  process.stdout.write(`${JSON.stringify(await assessCleanHouse(process.argv[index + 1]), null, 2)}\n`);
}
