import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, access, mkdir, readFile, readdir, rename, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { CAPABILITIES } from './auth-capability-catalog.mjs';
import { installInitialSetupTransaction } from './auth-setup-transaction.mjs';

const cli = fileURLToPath(new URL('./auth-cli.mjs', import.meta.url));
const sourceRoot = path.resolve(path.dirname(cli), '..');
function run(args, env = {}) {
  return spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8', timeout: 5000, env: { ...process.env, ...env } });
}

async function assertNoSetupResidue(directory) {
  const names = await readdir(directory);
  assert.deepEqual(names.filter((name) => name.startsWith('.auth-setup-staging-') || name.startsWith('.auth-setup-journal-') || name.startsWith('.auth-setup-quarantine-')), []);
}

async function directSetupOptions(testHooks) {
  const config = JSON.parse(await readFile(path.join(sourceRoot, 'config', 'code.json'), 'utf8'));
  return {
    authorized: true, sourceRoot, productId: 'code', config,
    inputs: {
      artifact: ['.auth-runtime/auth-system/src/index.ts'],
      configuration: ['.auth-runtime/auth-system/AUTH-RUNTIME-MANIFEST.json', '.auth-runtime/auth-system/config/example-app.json'],
    },
    authConfig: '{}\n', systemInstructions: '# Installed AUTH system\n', report: '# Setup report\n',
    testMode: true, testHooks,
  };
}

async function seedProductFiles(directory) {
  await mkdir(path.join(directory, '.auth-runtime'), { recursive: true });
  await mkdir(path.join(directory, '.github', 'workflows'), { recursive: true });
  await writeFile(path.join(directory, '.auth-runtime', 'owned.txt'), 'runtime parent owner bytes\n');
  await writeFile(path.join(directory, '.github', 'workflows', 'owned.yml'), 'name: pre-existing\n');
  await writeFile(path.join(directory, 'owned.txt'), 'product bytes\n');
  return Promise.all([
    readFile(path.join(directory, '.auth-runtime', 'owned.txt')),
    readFile(path.join(directory, '.github', 'workflows', 'owned.yml')),
    readFile(path.join(directory, 'owned.txt')),
  ]);
}

async function assertProductFilesUnchanged(directory, before) {
  assert.deepEqual(await readFile(path.join(directory, '.auth-runtime', 'owned.txt')), before[0]);
  assert.deepEqual(await readFile(path.join(directory, '.github', 'workflows', 'owned.yml')), before[1]);
  assert.deepEqual(await readFile(path.join(directory, 'owned.txt')), before[2]);
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
    await assertNoSetupResidue(directory);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('setup installs a complete product-local authentication runtime', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'auth-cli-runtime-'));
  try {
    const result = run(['setup', '--repo', directory, '--app', 'code', '--authorize']);
    assert.equal(result.status, 0, result.stderr);
    const runtimeRoot = path.join(directory, '.auth-runtime', 'auth-system');
    const manifest = JSON.parse(await readFile(path.join(runtimeRoot, 'AUTH-RUNTIME-MANIFEST.json'), 'utf8'));
    assert.equal(manifest.productId, 'code');
    assert.equal(manifest.sourceIndependent, true);
    assert.equal(manifest.contractVersion, 2);
    assert.equal(manifest.source.mode, 'git-commit');
    assert.equal(manifest.source.developmentMode, false);
    assert.equal(manifest.source.revision, spawnSync('git', ['rev-parse', 'HEAD'], { cwd: sourceRoot, encoding: 'utf8' }).stdout.trim());
    const committedIndex = spawnSync('git', ['show', `${manifest.source.revision}:src/index.ts`], { cwd: sourceRoot }).stdout;
    assert.equal(manifest.files['src/index.ts'].sha256, createHash('sha256').update(committedIndex).digest('hex'));
    assert.match(manifest.source.contentDigest, /^[0-9a-f]{64}$/);
    assert.equal(manifest.dependencyLockfileDigest, manifest.files['package-lock.json'].sha256);
    assert.match(manifest.installationId, /^[0-9a-f]{64}$/);
    assert.ok(manifest.files['src/app.ts']);
    assert.ok(manifest.files['src/auth/session.ts']);
    assert.ok(manifest.files['src/persistence/sqliteStorage.ts']);
    assert.ok(manifest.files['prisma/schema.prisma']);
    assert.equal(JSON.parse(await readFile(path.join(runtimeRoot, 'config/example-app.json'))).app.id, 'code');
    assert.equal(JSON.parse(await readFile(path.join(runtimeRoot, 'package.json'))).scripts.start, 'node dist/index.js');
    assert.ok(JSON.parse(await readFile(path.join(runtimeRoot, 'package-lock.json'))).lockfileVersion >= 2);
    assert.match(await readFile(path.join(directory, '.auth-kit', 'SYSTEM.md'), 'utf8'), /complete installed authentication system/);
    const observerInput = JSON.parse(await readFile(path.join(directory, '.auth-kit', 'observer-input.json'), 'utf8'));
    assert.equal(observerInput.adapter.productId, 'code');
    assert.equal(Object.keys(observerInput.adapter.capabilities).length, CAPABILITIES.length);
    const observer = run(['observer', 'scaffold', '--repo', directory, '--app', 'code', '--authorize']);
    assert.equal(observer.status, 0, observer.stderr);
    assert.equal(JSON.parse(observer.stdout).state, 'ALREADY_SCAFFOLDED_UNESTABLISHED');
    await assert.rejects(access(path.join(directory, '.auth-kit', 'ADAPTER.md')));
    const validation = run(['validate', '--repo', directory, '--app', 'code']);
    assert.match(validation.stdout, /PASS complete product-local auth runtime integrity/);
    await assertNoSetupResidue(directory);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('setup refuses to overwrite an existing product-local authentication runtime', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'auth-cli-runtime-collision-'));
  try {
    const runtime = path.join(directory, '.auth-runtime', 'auth-system');
    await mkdir(runtime, { recursive: true });
    await writeFile(path.join(runtime, 'owned.txt'), 'pre-existing runtime\n');
    const before = await readFile(path.join(runtime, 'owned.txt'));
    const result = run(['setup', '--repo', directory, '--app', 'code', '--authorize']);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /AUTH_SETUP_DESTINATION_EXISTS:.auth-runtime\/auth-system/);
    assert.deepEqual(await readFile(path.join(runtime, 'owned.txt')), before);
    await assertNoSetupResidue(directory);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('setup refuses to overwrite an existing lifecycle bundle', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'auth-cli-lifecycle-collision-'));
  try {
    await mkdir(path.join(directory, '.auth-kit'), { recursive: true });
    await writeFile(path.join(directory, '.auth-kit', 'contract.json'), 'pre-existing contract\n');
    const before = await readFile(path.join(directory, '.auth-kit', 'contract.json'));
    const result = run(['setup', '--repo', directory, '--app', 'code', '--authorize']);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /AUTH_SETUP_DESTINATION_EXISTS:.auth-kit/);
    assert.deepEqual(await readFile(path.join(directory, '.auth-kit', 'contract.json')), before);
    await assert.rejects(access(path.join(directory, '.auth-runtime', 'auth-system')));
    await assertNoSetupResidue(directory);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('setup refuses to overwrite an existing verification workflow', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'auth-cli-workflow-collision-'));
  try {
    const workflow = path.join(directory, '.github', 'workflows', 'auth-product-contract.yml');
    await mkdir(path.dirname(workflow), { recursive: true });
    await writeFile(workflow, 'name: product-owned workflow\n');
    const before = await readFile(workflow);
    const result = run(['setup', '--repo', directory, '--app', 'code', '--authorize']);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /AUTH_SETUP_DESTINATION_EXISTS:.github\/workflows\/auth-product-contract.yml/);
    assert.deepEqual(await readFile(workflow), before);
    await assert.rejects(access(path.join(directory, '.auth-runtime', 'auth-system')));
    await assertNoSetupResidue(directory);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

for (const failurePoint of [
  'before-runtime-publication',
  'after-runtime-publication',
  'during-lifecycle-bundle-publication',
  'auth-config-write',
  'system-write',
  'report-write',
  'workflow-publication',
  'final-completion',
]) {
  test(`transaction rolls back cleanly at ${failurePoint}`, async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), 'auth-cli-transaction-'));
    try {
      await mkdir(path.join(directory, '.auth-runtime'), { recursive: true });
      await mkdir(path.join(directory, '.github', 'workflows'), { recursive: true });
      await writeFile(path.join(directory, '.auth-runtime', 'owned.txt'), 'runtime parent owner bytes\n');
      await writeFile(path.join(directory, '.github', 'workflows', 'owned.yml'), 'name: pre-existing\n');
      await writeFile(path.join(directory, 'owned.txt'), 'product bytes\n');
      const before = await Promise.all([
        readFile(path.join(directory, '.auth-runtime', 'owned.txt')),
        readFile(path.join(directory, '.github', 'workflows', 'owned.yml')),
        readFile(path.join(directory, 'owned.txt')),
      ]);
      const result = run(['setup', '--repo', directory, '--app', 'code', '--authorize'], {
        AUTH_SETUP_TEST_MODE: '1',
        AUTH_SETUP_TEST_FAILURE_POINT: failurePoint,
      });
      assert.equal(result.status, 1, `${failurePoint}: ${result.stderr}`);
      assert.match(result.stderr, new RegExp(`INJECTED_SETUP_FAILURE:${failurePoint}`));
      await assert.rejects(access(path.join(directory, '.auth-runtime', 'auth-system')));
      await assert.rejects(access(path.join(directory, '.auth-kit')));
      await assert.rejects(access(path.join(directory, '.github', 'workflows', 'auth-product-contract.yml')));
      assert.deepEqual(await readFile(path.join(directory, '.auth-runtime', 'owned.txt')), before[0]);
      assert.deepEqual(await readFile(path.join(directory, '.github', 'workflows', 'owned.yml')), before[1]);
      assert.deepEqual(await readFile(path.join(directory, 'owned.txt')), before[2]);
      await assertNoSetupResidue(directory);
    } finally { await rm(directory, { recursive: true, force: true }); }
  });
}

test('replaced staging directory with copied marker is never recursively deleted', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'auth-staging-replacement-'));
  try {
    let replacement;
    const options = await directSetupOptions({
      beforeStagingCleanup: async ({ stageRoot, markerPath }) => {
        const marker = await readFile(markerPath);
        await rename(stageRoot, `${stageRoot}.original`);
        await mkdir(stageRoot);
        await writeFile(path.join(stageRoot, '.transaction-id'), marker);
        await writeFile(path.join(stageRoot, 'adversarial.txt'), 'replacement\n');
        replacement = stageRoot;
      },
    });
    await assert.rejects(installInitialSetupTransaction(directory, options), /AUTH_SETUP_TRANSACTION_ROLLBACK_FAILED/);
    assert.equal(await readFile(path.join(replacement, 'adversarial.txt'), 'utf8'), 'replacement\n');
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('staging marker mismatch prevents recursive deletion', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'auth-staging-marker-'));
  try {
    let stage;
    const options = await directSetupOptions({
      beforeStagingCleanup: async ({ stageRoot, markerPath }) => {
        stage = stageRoot;
        await writeFile(markerPath, 'not-the-transaction\n');
      },
    });
    await assert.rejects(installInitialSetupTransaction(directory, options), /AUTH_SETUP_TRANSACTION_ROLLBACK_FAILED/);
    assert.ok((await readdir(stage)).includes('.transaction-id'));
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('published tree replacement is quarantined, restored, and never deleted', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'auth-tree-replacement-'));
  try {
    const options = await directSetupOptions({
      afterPublication: async ({ publication, destination }) => {
        if (publication.path !== '.auth-runtime/auth-system') return;
        await rename(destination, `${destination}.original`);
        await mkdir(destination);
        await writeFile(path.join(destination, 'adversarial.txt'), 'replacement tree\n');
        throw new Error('ADVERSARIAL_TREE_REPLACEMENT');
      },
    });
    await assert.rejects(installInitialSetupTransaction(directory, options), /AUTH_SETUP_TRANSACTION_ROLLBACK_FAILED/);
    assert.equal(await readFile(path.join(directory, '.auth-runtime/auth-system/adversarial.txt'), 'utf8'), 'replacement tree\n');
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('published workflow replacement is quarantined, restored, and never deleted', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'auth-file-replacement-'));
  try {
    const options = await directSetupOptions({
      afterPublication: async ({ publication, destination }) => {
        if (publication.path !== '.github/workflows/auth-product-contract.yml') return;
        await rename(destination, `${destination}.original`);
        await writeFile(destination, 'name: adversarial replacement\n');
        throw new Error('ADVERSARIAL_FILE_REPLACEMENT');
      },
    });
    await assert.rejects(installInitialSetupTransaction(directory, options), /AUTH_SETUP_TRANSACTION_ROLLBACK_FAILED/);
    assert.equal(await readFile(path.join(directory, '.github/workflows/auth-product-contract.yml'), 'utf8'), 'name: adversarial replacement\n');
  } finally { await rm(directory, { recursive: true, force: true }); }
});

for (const abruptPoint of ['journal-temp-write-2', 'after-runtime-publication', 'after-lifecycle-publication', 'after-workflow-publication']) {
  test(`abandoned transaction at ${abruptPoint} is recovered by the next setup`, async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), 'auth-abrupt-recovery-'));
    try {
      const before = await seedProductFiles(directory);
      const interrupted = run(['setup', '--repo', directory, '--app', 'code', '--authorize'], {
        AUTH_SETUP_TEST_MODE: '1', AUTH_SETUP_TEST_ABRUPT_POINT: abruptPoint,
      });
      assert.equal(interrupted.status, 86, interrupted.stderr);
      const resumed = run(['setup', '--repo', directory, '--app', 'code', '--authorize']);
      assert.equal(resumed.status, 0, resumed.stderr);
      assert.ok(await readFile(path.join(directory, '.auth-kit', 'contract.json')));
      await assertProductFilesUnchanged(directory, before);
      await assertNoSetupResidue(directory);
    } finally { await rm(directory, { recursive: true, force: true }); }
  });
}

test('COMPLETE journal left by abrupt exit is finalized without rolling back installation', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'auth-complete-recovery-'));
  try {
    const before = await seedProductFiles(directory);
    const interrupted = run(['setup', '--repo', directory, '--app', 'code', '--authorize'], {
      AUTH_SETUP_TEST_MODE: '1', AUTH_SETUP_TEST_ABRUPT_POINT: 'after-complete-journal',
    });
    assert.equal(interrupted.status, 86, interrupted.stderr);
    const resumed = run(['setup', '--repo', directory, '--app', 'code', '--authorize']);
    assert.equal(resumed.status, 1);
    assert.match(resumed.stderr, /AUTH_SETUP_DESTINATION_EXISTS:.auth-runtime\/auth-system/);
    const validation = run(['validate', '--repo', directory, '--app', 'code']);
    assert.match(validation.stdout, /PASS complete product-local auth runtime integrity/);
    await assertProductFilesUnchanged(directory, before);
    await assertNoSetupResidue(directory);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

const fixedTransactionId = '11111111-1111-4111-8111-111111111111';
for (const invalidCase of ['malformed', 'symlinked', 'unsupported']) {
  test(`${invalidCase} abandoned journal fails closed`, async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), 'auth-invalid-journal-'));
    try {
      const journal = path.join(directory, `.auth-setup-journal-${fixedTransactionId}.json`);
      if (invalidCase === 'malformed') await writeFile(journal, '{');
      if (invalidCase === 'unsupported') await writeFile(journal, JSON.stringify({ contract: 'unsupported' }));
      if (invalidCase === 'symlinked') {
        await writeFile(path.join(directory, 'journal-target.json'), '{}');
        await symlink(path.join(directory, 'journal-target.json'), journal);
      }
      const result = run(['setup', '--repo', directory, '--app', 'code', '--authorize']);
      assert.equal(result.status, 1);
      assert.match(result.stderr, /AUTH_SETUP_JOURNAL_(MALFORMED|UNSUPPORTED|FILE_INVALID)/);
      assert.ok(await access(journal).then(() => true));
    } finally { await rm(directory, { recursive: true, force: true }); }
  });
}

test('multiple abandoned transaction journals fail closed', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'auth-multiple-journals-'));
  try {
    const before = await seedProductFiles(directory);
    for (const transactionId of ['00000000-0000-4000-8000-000000000001', '00000000-0000-4000-8000-000000000002']) {
      await writeFile(path.join(directory, `.auth-setup-journal-${transactionId}.json`), '{}\n');
    }
    const result = run(['setup', '--repo', directory, '--app', 'code', '--authorize']);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /AUTH_SETUP_MULTIPLE_ACTIVE_TRANSACTIONS/);
    await assertProductFilesUnchanged(directory, before);
    assert.equal((await readdir(directory)).filter((name) => name.startsWith('.auth-setup-journal-')).length, 2);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('foreign transaction-prefixed residue is preserved before recovery mutation', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'auth-foreign-residue-'));
  try {
    const interrupted = run(['setup', '--repo', directory, '--app', 'code', '--authorize'], {
      AUTH_SETUP_TEST_MODE: '1', AUTH_SETUP_TEST_ABRUPT_POINT: 'after-runtime-publication',
    });
    assert.equal(interrupted.status, 86, interrupted.stderr);
    const runtimeManifest = await readFile(path.join(directory, '.auth-runtime', 'auth-system', 'AUTH-RUNTIME-MANIFEST.json'));
    const foreign = path.join(directory, '.auth-setup-quarantine-foreign-evidence');
    await writeFile(foreign, 'preserve me\n');
    const result = run(['setup', '--repo', directory, '--app', 'code', '--authorize']);
    assert.equal(result.status, 1);
    assert.match(result.stderr, /AUTH_SETUP_AMBIGUOUS_RESIDUE/);
    assert.deepEqual(await readFile(foreign), Buffer.from('preserve me\n'));
    assert.deepEqual(await readFile(path.join(directory, '.auth-runtime', 'auth-system', 'AUTH-RUNTIME-MANIFEST.json')), runtimeManifest);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

for (const invalidCase of ['path-escaping', 'duplicate-publication']) {
  test(`${invalidCase} journal fails closed`, async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), 'auth-invalid-publication-'));
    try {
      const interrupted = run(['setup', '--repo', directory, '--app', 'code', '--authorize'], {
        AUTH_SETUP_TEST_MODE: '1', AUTH_SETUP_TEST_ABRUPT_POINT: 'after-runtime-publication',
      });
      assert.equal(interrupted.status, 86, interrupted.stderr);
      const journalName = (await readdir(directory)).find((name) => /^\.auth-setup-journal-.*\.json$/.test(name));
      const journalPath = path.join(directory, journalName);
      const journal = JSON.parse(await readFile(journalPath, 'utf8'));
      if (invalidCase === 'path-escaping') journal.publications[0].path = '../outside';
      else journal.publications.push({ ...journal.publications[0] });
      await writeFile(journalPath, JSON.stringify(journal));
      const result = run(['setup', '--repo', directory, '--app', 'code', '--authorize']);
      assert.equal(result.status, 1);
      assert.match(result.stderr, /AUTH_SETUP_JOURNAL_PUBLICATION_INVALID/);
      assert.ok(await access(journalPath).then(() => true));
    } finally { await rm(directory, { recursive: true, force: true }); }
  });
}

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

test('wizard ACT executes only a registered bounded handler and verifies fresh observations', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'auth-cli-act-'));
  try {
    const adapterPath = path.join(directory, 'adapter.json');
    const adapter = { schemaVersion: 1, productId: 'fixture', revision: 'r1', capabilities: Object.fromEntries(CAPABILITIES.map(({ id }) => [id, {
      applicability: 'FALSE', reason: 'Fixture excludes this capability', implementation: 'NOT_ESTABLISHED',
    }])) };
    const signin = CAPABILITIES.find(({ id }) => id === 'signin');
    adapter.capabilities.signin = { applicability: 'TRUE', implementation: 'ESTABLISHED', evidence: ['fixture:before'], checks: Object.fromEntries(signin.checks.map((id) => [id, id !== 'explicit_entry'])) };
    await writeFile(adapterPath, JSON.stringify(adapter));
    const modulePath = path.join(directory, 'registered-act.mjs');
    await writeFile(modulePath, `import {readFile,writeFile} from 'node:fs/promises';\nconst adapterPath=${JSON.stringify(adapterPath)};\nexport const handlers=new Map([['signin',async()=>{const a=JSON.parse(await readFile(adapterPath,'utf8'));a.capabilities.signin.checks.explicit_entry=true;a.capabilities.signin.evidence=['fixture:after'];await writeFile(adapterPath,JSON.stringify(a));}]]);\nexport const observe=async()=>JSON.parse(await readFile(adapterPath,'utf8'));\n`);
    const blocked = run(['wizard', '--adapter', adapterPath, '--operator', 'ACT', '--capability', 'signin', '--repo', directory, '--act-module', modulePath]);
    assert.equal(blocked.status, 2);
    assert.equal(JSON.parse(blocked.stdout).blockerHandoffs[0].executionClassification, 'EXTERNAL_ACTION_REQUIRED');
    const result = run(['wizard', '--adapter', adapterPath, '--operator', 'ACT', '--capability', 'signin', '--repo', directory, '--act-module', modulePath, '--authorize']);
    assert.equal(result.status, 0, result.stderr);
    const report = JSON.parse(result.stdout);
    assert.equal(report.verification, 'PASS');
    assert.equal(report.verifiedAfterAct, true);
    assert.deepEqual(report.blockerHandoffs, []);
  } finally { await rm(directory, { recursive: true, force: true }); }
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
