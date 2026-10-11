import test from 'node:test';
import assert from 'node:assert/strict';
import { access, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { applyNativePlan, discoverNativeTarget, planNativeTarget, recoverNativeTransactions, repairNativeTarget, verifyNativeReceipt } from './auth-native-wizard.mjs';

const sourceRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const cli = path.join(sourceRoot, 'scripts', 'auth-cli.mjs');
const absent = async file => assert.rejects(access(file));

test('CLI advertises native workflow and disables persistent-artifact commands', () => {
  const help = spawnSync(process.execPath, [cli, '--help'], { encoding: 'utf8' });
  assert.equal(help.status, 0); assert.match(help.stdout, /auth native/); assert.doesNotMatch(help.stdout, /auth setup --repo/);
  for (const command of ['setup', 'validate', 'runtime', 'product', 'observer']) {
    const result = spawnSync(process.execPath, [cli, command], { encoding: 'utf8' });
    assert.equal(result.status, 1); assert.match(result.stderr, /LEGACY_PERSISTENT_AUTH_COMMAND_REMOVED/);
  }
});

test('discovery is read-only and distinguishes greenfield from prohibited legacy footprint', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'auth-native-discover-'));
  try {
    const before = await readdir(root);
    assert.equal((await discoverNativeTarget(root)).classification, 'GREENFIELD');
    assert.deepEqual(await readdir(root), before);
    await import('node:fs/promises').then(({ mkdir }) => mkdir(path.join(root, '.auth-kit')));
    const report = await discoverNativeTarget(root);
    assert.equal(report.classification, 'NONCONFORMANT');
    assert.deepEqual(report.prohibitedPersistentArtifacts, ['.auth-kit']);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('plan and dry-run are read-only; apply creates product-native source with no AUTH footprint', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'auth-native-apply-'));
  const receipt = path.join(os.tmpdir(), `auth-native-receipt-${Date.now()}-${Math.random()}.json`);
  try {
    const plan = await planNativeTarget(root, { sourceRoot, productId: 'fixture-product', receiptPath: receipt });
    assert.equal(plan.classification, 'GREENFIELD');
    assert.ok(plan.operations.some(item => item.path === 'src/app.ts'));
    assert.ok(plan.operations.some(item => item.path === 'prisma/schema.prisma'));
    assert.ok(plan.operations.some(item => item.path === 'package-lock.json'));
    assert.deepEqual(await readdir(root), []);
    assert.equal((await applyNativePlan(plan, { sourceRoot, dryRun: true })).state, 'DRY_RUN');
    assert.deepEqual(await readdir(root), []);
    await assert.rejects(applyNativePlan(plan, { sourceRoot }), /AUTHORIZATION_REQUIRED/);
    const result = await applyNativePlan(plan, { sourceRoot, authorized: true });
    assert.equal(result.verification.verification, 'PASS');
    assert.equal((await verifyNativeReceipt(root, receipt)).verification, 'PASS');
    await absent(path.join(root, '.auth-runtime'));
    await absent(path.join(root, '.auth-kit'));
    assert.ok(JSON.parse(await readFile(path.join(root, 'auth-standards.json'), 'utf8')).capabilities.includes('mcp-resource-server'));
    assert.deepEqual((await readdir(root)).filter(name => name.startsWith('.auth-native-transaction-')), []);
  } finally { await rm(root, { recursive: true, force: true }); await rm(receipt, { force: true }); }
});

test('existing conflicting product files fail planning without mutation', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'auth-native-conflict-'));
  const receipt = path.join(os.tmpdir(), `auth-native-conflict-receipt-${Date.now()}.json`);
  try {
    await writeFile(path.join(root, 'package.json'), '{"name":"owned"}\n');
    const before = await readFile(path.join(root, 'package.json'));
    await assert.rejects(planNativeTarget(root, { sourceRoot, productId: 'fixture', receiptPath: receipt }), /EXISTING_PRODUCT_FILE_REVIEW_REQUIRED/);
    assert.deepEqual(await readFile(path.join(root, 'package.json')), before);
    await absent(receipt);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('VERIFY detects tamper and REPAIR restores authenticated bytes without changing versions', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'auth-native-verify-'));
  const receipt = path.join(os.tmpdir(), `auth-native-verify-receipt-${Date.now()}.json`);
  try {
    const plan = await planNativeTarget(root, { sourceRoot, productId: 'fixture', receiptPath: receipt });
    await applyNativePlan(plan, { sourceRoot, authorized: true });
    await writeFile(path.join(root, 'src', 'app.ts'), '// tampered\n');
    assert.equal((await verifyNativeReceipt(root, receipt)).verification, 'FAIL');
    const repaired = await repairNativeTarget(root, receipt, { sourceRoot, authorized: true });
    assert.equal(repaired.state, 'COMPLETE');
    assert.equal(repaired.versionChanged, false);
    assert.deepEqual(repaired.repaired, ['src/app.ts']);
    assert.equal((await verifyNativeReceipt(root, receipt)).verification, 'PASS');
  } finally { await rm(root, { recursive: true, force: true }); await rm(receipt, { force: true }); }
});

test('abrupt APPLY publication is recovered to the complete pre-run state', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'auth-native-crash-'));
  const receipt = path.join(os.tmpdir(), `auth-native-crash-receipt-${Date.now()}.json`);
  try {
    const program = `import {planNativeTarget,applyNativePlan} from ${JSON.stringify(new URL('./auth-native-wizard.mjs', import.meta.url).href)};const p=await planNativeTarget(${JSON.stringify(root)},{sourceRoot:${JSON.stringify(sourceRoot)},productId:'fixture',receiptPath:${JSON.stringify(receipt)}});await applyNativePlan(p,{sourceRoot:${JSON.stringify(sourceRoot)},authorized:true});`;
    const child = spawnSync(process.execPath, ['--input-type=module', '-e', program], { encoding: 'utf8', env: { ...process.env, AUTH_NATIVE_TEST_MODE: '1', AUTH_NATIVE_TEST_CRASH_AT: 'apply-published:prisma/schema.prisma' } });
    assert.equal(child.status, 86);
    assert.equal((await recoverNativeTransactions(root)).state, 'ROLLED_BACK');
    assert.deepEqual(await readdir(root), []);
    await absent(receipt);
  } finally { await rm(root, { recursive: true, force: true }); await rm(receipt, { force: true }); }
});

test('recovery preserves an adversarial replacement and fails closed', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'auth-native-adversary-'));
  const receipt = path.join(os.tmpdir(), `auth-native-adversary-receipt-${Date.now()}.json`);
  try {
    const program = `import {planNativeTarget,applyNativePlan} from ${JSON.stringify(new URL('./auth-native-wizard.mjs', import.meta.url).href)};const p=await planNativeTarget(${JSON.stringify(root)},{sourceRoot:${JSON.stringify(sourceRoot)},productId:'fixture',receiptPath:${JSON.stringify(receipt)}});await applyNativePlan(p,{sourceRoot:${JSON.stringify(sourceRoot)},authorized:true});`;
    const child = spawnSync(process.execPath, ['--input-type=module', '-e', program], { encoding: 'utf8', env: { ...process.env, AUTH_NATIVE_TEST_MODE: '1', AUTH_NATIVE_TEST_CRASH_AT: 'apply-published:prisma/schema.prisma' } });
    assert.equal(child.status, 86);
    const published = path.join(root, 'prisma', 'schema.prisma');
    await rm(published); await writeFile(published, '// foreign replacement\n');
    await assert.rejects(recoverNativeTransactions(root), /PUBLICATION_AMBIGUOUS/);
    assert.equal(await readFile(published, 'utf8'), '// foreign replacement\n');
  } finally { await rm(root, { recursive: true, force: true }); await rm(receipt, { force: true }); }
});

test('journal temp interruption recovers from the prior valid revision', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'auth-native-journal-crash-'));
  const receipt = path.join(os.tmpdir(), `auth-native-journal-crash-receipt-${Date.now()}.json`);
  try {
    const program = `import {planNativeTarget,applyNativePlan} from ${JSON.stringify(new URL('./auth-native-wizard.mjs', import.meta.url).href)};const p=await planNativeTarget(${JSON.stringify(root)},{sourceRoot:${JSON.stringify(sourceRoot)},productId:'fixture',receiptPath:${JSON.stringify(receipt)}});await applyNativePlan(p,{sourceRoot:${JSON.stringify(sourceRoot)},authorized:true});`;
    const child = spawnSync(process.execPath, ['--input-type=module', '-e', program], { encoding: 'utf8', env: { ...process.env, AUTH_NATIVE_TEST_MODE: '1', AUTH_NATIVE_TEST_CRASH_AT: 'journal-temp-written-2' } });
    assert.equal(child.status, 86);
    assert.equal((await recoverNativeTransactions(root)).state, 'ROLLED_BACK');
    assert.deepEqual(await readdir(root), []);
  } finally { await rm(root, { recursive: true, force: true }); await rm(receipt, { force: true }); }
});
