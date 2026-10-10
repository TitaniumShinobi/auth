import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtemp, access, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { CAPABILITIES } from './auth-capability-catalog.mjs';

const cli = fileURLToPath(new URL('./auth-cli.mjs', import.meta.url));
function run(args) {
  return spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8', timeout: 5000 });
}

test('setup refuses writes without explicit authorization', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'auth-cli-'));
  try {
    const result = run(['setup', '--repo', directory, '--app', 'code']);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /explicit --authorize/);
    await assert.rejects(access(path.join(directory, '.auth-kit')));
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('setup dry-run remains read-only without authorization', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'auth-cli-'));
  try {
    const result = run(['setup', '--repo', directory, '--app', 'code', '--dry-run']);
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /no files were written/);
    await assert.rejects(access(path.join(directory, '.auth-kit')));
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('wizard ACT requires authorization and never runs arbitrary repairs', () => {
  for (const authorized of [false, true]) {
    const result = run(['wizard', '--adapter', '/does-not-exist.json', '--operator', 'ACT',
      ...(authorized ? ['--authorize'] : [])]);
    assert.equal(result.status, 2);
    const report = JSON.parse(result.stdout);
    assert.equal(report.error, authorized ? 'NO_SUPPORTED_REPAIR' : 'AUTHORIZATION_REQUIRED');
    assert.deepEqual(report.changedFiles, []);
    assert.equal(report.blockerHandoffs.length, 1);
    assert.equal(report.blockerHandoffs[0].capabilityId, null);
    assert.equal(report.blockerHandoffs[0].reasonCode, report.error);
    assert.equal(report.blockerHandoffs[0].verificationCommand.includes('--authorize'), false);
  }
});

test('ACT handoff preserves a declared capability without supporting mutations', () => {
  const result = run(['wizard', '--adapter', '/does-not-exist.json', '--operator', 'ACT',
    '--capability', 'signin', '--authorize']);
  assert.equal(result.status, 2);
  const report = JSON.parse(result.stdout);
  assert.equal(report.capabilityId, 'signin');
  assert.equal(report.blockerHandoffs[0].capabilityId, 'signin');
  assert.deepEqual(report.changedFiles, []);
  const unknown = run(['wizard', '--adapter', '/does-not-exist.json', '--operator', 'ACT',
    '--capability', 'invented-capability']);
  assert.equal(unknown.status, 1);
  assert.match(unknown.stderr, /Unknown capability/);
});

test('wizard rejects unknown operators before reading adapters', () => {
  const result = run(['wizard', '--adapter', '/does-not-exist.json', '--operator', 'DELETE']);
  assert.equal(result.status, 1);
  assert.match(result.stderr, /Unsupported wizard operator/);
});

test('wizard defaults to fail-closed VERIFY and OBSERVE accepts arbitrary products', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'auth-wizard-cli-'));
  try {
    const adapter = path.join(directory, 'adapter.json');
    await writeFile(adapter, JSON.stringify({ schemaVersion: 1, productId: 'arbitrary-product', revision: 'r1', capabilities: {} }));
    const verification = run(['wizard', '--adapter', adapter]);
    assert.equal(verification.status, 2, verification.stderr);
    assert.equal(JSON.parse(verification.stdout).verification, 'INDETERMINATE');
    const outcome = 'Restore login; keep $(literal) input unchanged';
    const observation = run(['wizard', '--adapter', adapter, '--operator', 'OBSERVE', '--repo', directory, '--outcome', outcome]);
    assert.equal(observation.status, 0, observation.stderr);
    const observedReport = JSON.parse(observation.stdout);
    assert.equal(observedReport.verification, 'INDETERMINATE');
    assert.ok(observedReport.blockerHandoffs.length > 0);
    const handoff = observedReport.blockerHandoffs[0];
    assert.equal(handoff.target.repository, directory);
    assert.equal(handoff.requestedOutcome, outcome);
    assert.deepEqual(handoff.reproductionCommand.slice(0, 3), [process.execPath, cli, 'wizard']);
    assert.equal(handoff.reproductionCommand[handoff.reproductionCommand.indexOf('--operator') + 1], 'OBSERVE');
    assert.equal(handoff.verificationCommand[handoff.verificationCommand.indexOf('--operator') + 1], 'VERIFY');
    assert.ok(handoff.reproductionCommand.includes(outcome));
    const baseline = path.join(directory, 'baseline.json');
    await writeFile(baseline, observation.stdout);
    const decision = run(['wizard', '--adapter', adapter, '--baseline', baseline, '--operator', 'DECIDE']);
    assert.equal(decision.status, 2, decision.stderr);
    assert.equal(JSON.parse(decision.stdout).verification, 'INDETERMINATE');
    assert.ok(JSON.parse(decision.stdout).blockerHandoffs[0].verificationCommand.includes(baseline));
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('PASS does not invent a blocker handoff', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'auth-wizard-pass-'));
  try {
    const adapter = path.join(directory, 'adapter.json');
    await writeFile(adapter, JSON.stringify({ schemaVersion: 1, productId: 'not-an-allowlisted-product', revision: 'r1',
      capabilities: Object.fromEntries(CAPABILITIES.map(({ id }) => [id, {
        applicability: 'FALSE', reason: 'Not offered by this product', implementation: 'NOT_ESTABLISHED',
      }])),
    }));
    const result = run(['wizard', '--adapter', adapter]);
    assert.equal(result.status, 0, result.stderr);
    const report = JSON.parse(result.stdout);
    assert.equal(report.verification, 'PASS');
    assert.deepEqual(report.blockerHandoffs, []);
  } finally { await rm(directory, { recursive: true, force: true }); }
});
