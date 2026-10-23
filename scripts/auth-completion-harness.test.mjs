import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { CAPABILITIES } from './auth-capability-catalog.mjs';
import { LANES } from './auth-verification-lane.mjs';
import { productTestSource } from './auth-product-test.mjs';
import { completeAuthObjective, diagnosePlainLanguageObjective, verifyExistingAuthObjective } from './auth-completion-harness.mjs';

const hash = value => createHash('sha256').update(value).digest('hex');

test('plain-language completion constructs read-only inputs and preserves an unsupported objective', async t => {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'auth-plain-completion-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  await fs.writeFile(path.join(root, 'source'), 'unchanged');
  const objective = 'Complete oauth thumbnail runtime for cleanhouse/ using auth/.';
  const result = await diagnosePlainLanguageObjective({ root, objective });
  assert.equal(result.objectiveBinding.objective, objective);
  assert.equal(result.result, 'NOT_VERIFIED');
  assert.equal(result.inputConstruction.mode, 'AUTOMATIC_READ_ONLY');
  assert.equal(result.mdbo.act, 'NOT_EXECUTED_NO_SUPPORTED_REPAIR');
  assert.deepEqual(result.wizard.map(row => row.operator), ['OBSERVE', 'ASSESS', 'DECIDE', 'VERIFY']);
  assert.deepEqual(result.rptvl.lanes.map(row => row.id), LANES);
  assert.equal(result.productE2E.result, 'NOT_VERIFIED');
  assert.equal(await fs.readFile(path.join(root, 'source'), 'utf8'), 'unchanged');
});
async function fixture(t, { objective = 'Repair disposable sign in', evidenceScope = 'isolated', fail = false } = {}) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'auth-completion-'));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  const adapter = { schemaVersion: 1, productId: 'completion-fixture', revision: 'fixture-r1', authenticationRole: 'IDENTITY_AUTHORITY', capabilities: Object.fromEntries(CAPABILITIES.map(row => [row.id, { applicability: 'FALSE', reason: 'fixture scope' }])) };
  const checks = CAPABILITIES.find(row => row.id === 'signin').checks;
  adapter.capabilities.signin = { applicability: 'TRUE', implementation: 'ESTABLISHED', checks: Object.fromEntries(checks.map(check => [check, false])), evidence: ['fixture'] };
  const behavior = `if(require('fs').readFileSync('source','utf8')!=='correct')process.exit(1)`;
  await fs.writeFile(path.join(root, 'source'), 'broken');
  await fs.writeFile(path.join(root, 'behavior.cjs'), behavior);
  await fs.mkdir(path.join(root, 'test'));
  const runner = productTestSource({ argv: ['$NODE', 'behavior.cjs'], timeoutMs: 2000 });
  await fs.writeFile(path.join(root, 'test/auth-behavior.mjs'), runner);
  const command = { argv: [process.execPath, ...(fail ? ['-e', 'process.exit(1)'] : ['test/auth-behavior.mjs'])], timeoutMs: 2000, maxOutputBytes: 4096 };
  const repairSpec = { schemaVersion: 1, productId: adapter.productId, revision: adapter.revision, capabilityId: 'signin', file: 'source', beforeSha256: hash('broken'), afterSha256: hash('correct'), replacement: 'correct', checks, evidenceFiles: [{ path: 'behavior.cjs', sha256: hash(behavior) }], command: { executable: process.execPath, args: ['behavior.cjs'], timeoutMs: 2000, maxOutputBytes: 4096 } };
  repairSpec.verificationSpec = { schema: 'life.auth.verification-lane/1', productId: adapter.productId, revision: adapter.revision, requestedOutcome: objective, evidenceScope, authorizedPaths: ['source'], inputs: [...repairSpec.evidenceFiles, { path: 'test/auth-behavior.mjs', sha256: hash(runner) }], normalBuildGate: 'test/auth-behavior.mjs', normalBuild: command, lanes: LANES.map(id => ({ id, required: true, checks: checks.map(check => `signin/${check}`), command })) };
  return { root, objective, adapter, repairSpec };
}

test('one execution preserves objective, runs MDBO gate and all RPTVL lanes', async t => {
  const input = await fixture(t);
  const result = await completeAuthObjective({ ...input, authorized: true });
  assert.equal(result.result, 'NOT_VERIFIED');
  assert.equal(result.harnessConformance, 'PASS');
  assert.equal(result.blocker, 'LIVE_PRODUCT_E2E_REQUIRED');
  assert.equal(result.objectiveBinding.objective, input.objective);
  assert.equal(result.objectiveBinding.preserved, true);
  assert.equal(result.mdbo.gate, 'EXECUTED');
  assert.equal(result.recovery.state, 'CLEAN');
  assert.deepEqual(result.rptvl.lanes.map(row => row.id), LANES);
  assert.equal(result.rptvl.result, 'VERIFIED');
  assert.equal(result.productE2E.result, 'NOT_VERIFIED');
});

test('read-only completion runs reviewed lanes without an ACT or source change', async t => {
  const input = await fixture(t);
  await fs.writeFile(path.join(input.root, 'source'), 'correct');
  const result = await verifyExistingAuthObjective({ root: input.root, objective: input.objective,
    adapter: input.adapter, verificationSpec: input.repairSpec.verificationSpec });
  assert.equal(result.result, 'NOT_VERIFIED');
  assert.equal(result.blocker, 'LIVE_PRODUCT_E2E_REQUIRED');
  assert.equal(result.mdbo.act, 'NOT_APPLICABLE_NO_SOURCE_REPAIR');
  assert.deepEqual(result.repair.changedFiles, []);
  assert.deepEqual(result.rptvl.lanes.map(row => row.id), LANES);
  assert.equal(result.rptvl.result, 'VERIFIED');
  assert.equal(await fs.readFile(path.join(input.root, 'source'), 'utf8'), 'correct');
});

test('read-only completion uses proven objective checks while retaining full catalog uncertainty', async t => {
  const input = await fixture(t, { evidenceScope: 'live' });
  await fs.writeFile(path.join(input.root, 'source'), 'correct');
  input.adapter.capabilities = {
    signin: { applicability: 'TRUE', implementation: 'ESTABLISHED',
      evidence: ['behavior.cjs', 'test/auth-behavior.mjs'],
      checks: Object.fromEntries(CAPABILITIES.find(row => row.id === 'signin').checks.map(id => [id, true])) },
  };
  const result = await verifyExistingAuthObjective({ root: input.root, objective: input.objective,
    adapter: input.adapter, verificationSpec: input.repairSpec.verificationSpec });
  assert.equal(result.result, 'VERIFIED');
  assert.equal(result.objectiveCapabilityConformance.result, 'PASS');
  assert.equal(result.objectiveCapabilityConformance.fullAuthorityProfile, 'INDETERMINATE');
  assert.ok(result.objectiveCapabilityConformance.indeterminateCapabilities.includes('providers.github'));
  assert.equal(result.productE2E.result, 'PASS');
});

test('read-only completion rejects a missing or failed required capability check despite passing lanes', async t => {
  const input = await fixture(t, { evidenceScope: 'live' });
  await fs.writeFile(path.join(input.root, 'source'), 'correct');
  const requiredCheck = CAPABILITIES.find(row => row.id === 'signin').checks[0];
  for (const value of [undefined, false]) {
    const checks = Object.fromEntries(CAPABILITIES.find(row => row.id === 'signin').checks.map(id => [id, true]));
    if (value === undefined) delete checks[requiredCheck];
    else checks[requiredCheck] = value;
    input.adapter.capabilities.signin.checks = checks;
    const result = await verifyExistingAuthObjective({ root: input.root, objective: input.objective,
      adapter: input.adapter, verificationSpec: input.repairSpec.verificationSpec });
    assert.equal(result.rptvl.result, 'VERIFIED');
    assert.equal(result.productE2E.result, 'PASS');
    assert.equal(result.result, 'NOT_VERIFIED');
    assert.equal(result.blocker, 'AUTH_CAPABILITY_CONFORMANCE_NOT_VERIFIED');
    assert.equal(result.objectiveCapabilityConformance.result, value === false ? 'FAIL' : 'INDETERMINATE');
  }
});

test('read-only completion retains known failures and unknown declarations outside the mapped checks', async t => {
  const input = await fixture(t, { evidenceScope: 'live' });
  await fs.writeFile(path.join(input.root, 'source'), 'correct');
  input.adapter.capabilities.signin.checks = Object.fromEntries(
    CAPABILITIES.find(row => row.id === 'signin').checks.map(id => [id, true]));
  input.adapter.capabilities['providers.github'] = { applicability: 'TRUE', implementation: 'NOT_ESTABLISHED' };
  const failed = await verifyExistingAuthObjective({ root: input.root, objective: input.objective,
    adapter: input.adapter, verificationSpec: input.repairSpec.verificationSpec });
  assert.equal(failed.result, 'NOT_VERIFIED');
  assert.equal(failed.objectiveCapabilityConformance.result, 'FAIL');
  assert.deepEqual(failed.objectiveCapabilityConformance.knownFailures, ['providers.github']);
  delete input.adapter.capabilities['providers.github'];
  input.adapter.capabilities['typo.capability'] = { applicability: 'FALSE', reason: 'fixture' };
  const unknown = await verifyExistingAuthObjective({ root: input.root, objective: input.objective,
    adapter: input.adapter, verificationSpec: input.repairSpec.verificationSpec });
  assert.equal(unknown.result, 'NOT_VERIFIED');
  assert.equal(unknown.objectiveCapabilityConformance.result, 'INDETERMINATE');
  assert.deepEqual(unknown.objectiveCapabilityConformance.unknownDeclarations, ['typo.capability']);
});

test('live product evidence is the only successful completion', async t => {
  const input = await fixture(t, { evidenceScope: 'live' });
  const result = await completeAuthObjective({ ...input, authorized: true });
  assert.equal(result.result, 'VERIFIED');
  assert.equal(result.productE2E.result, 'PASS');
  assert.equal(result.blocker, null);
});

test('objective mismatch fails before mutation', async t => {
  const input = await fixture(t);
  await assert.rejects(completeAuthObjective({ ...input, objective: 'Different request', authorized: true }), /OBJECTIVE_BINDING_MISMATCH/);
  assert.equal(await fs.readFile(path.join(input.root, 'source'), 'utf8'), 'broken');
});

test('failed lane rejects completion and rolls back owned repair', async t => {
  const input = await fixture(t, { fail: true, evidenceScope: 'live' });
  const result = await completeAuthObjective({ ...input, authorized: true });
  assert.equal(result.result, 'NOT_VERIFIED');
  assert.equal(result.harnessConformance, 'FAIL');
  assert.equal(result.blocker, 'RPTVL_LANE_FAILURE');
  assert.equal(result.repair.rolledBack, true);
  assert.equal(await fs.readFile(path.join(input.root, 'source'), 'utf8'), 'broken');
});

test('authorization omission is a precise blocker and does not mutate', async t => {
  const input = await fixture(t);
  const result = await completeAuthObjective({ ...input, authorized: false });
  assert.equal(result.result, 'NOT_VERIFIED');
  assert.equal(result.blocker, 'EXPLICIT_AUTHORIZATION_REQUIRED');
  assert.equal(await fs.readFile(path.join(input.root, 'source'), 'utf8'), 'broken');
});
