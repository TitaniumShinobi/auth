import test from 'node:test';
import assert from 'node:assert/strict';
import { access, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { applyNativePlan, assessNativeTarget, discoverNativeTarget, migrateNativeTarget, planNativeAlignment, planNativeTarget, recoverNativeTransactions, repairNativeTarget, verifyNativeReceipt } from './auth-native-wizard.mjs';

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
    assert.ok(plan.operations.some(item => item.path === 'src/index.ts'));
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

test('existing authentication is assessed and aligned without overwriting product source', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'auth-native-align-'));
  const receipt = path.join(os.tmpdir(), `auth-native-align-receipt-${Date.now()}.json`);
  try {
    const { mkdir } = await import('node:fs/promises'); await mkdir(path.join(root, 'src', 'auth'), { recursive: true });
    await writeFile(path.join(root, 'package.json'), JSON.stringify({ name: 'existing', type: 'module', dependencies: { express: '^5.1.0', '@prisma/client': '6.12.0' }, devDependencies: { typescript: '^6.0.3', prisma: '6.12.0' } }));
    await writeFile(path.join(root, 'tsconfig.json'), '{}\n');
    const existing = `// product owned\n// oauth authorization_code code_challenge code_verifier S256 state nonce passwordHash magic email HttpOnly refresh rotation replay revoke logout PrismaClient loopback oauth-protected-resource mcp\n`;
    await writeFile(path.join(root, 'src', 'auth', 'existing.ts'), existing);
    const assessment = await assessNativeTarget(root); assert.equal(assessment.classification, 'COMPATIBLE'); assert.equal(assessment.executionClassification, 'AGENT_INTEGRATION_REQUIRED');
    const before = await readFile(path.join(root, 'src', 'auth', 'existing.ts'));
    const plan = await planNativeAlignment(root, { authenticationRole: 'IDENTITY_AUTHORITY', authenticationEntrypoint: 'src/auth/existing.ts', sourceRoot, productId: 'existing', receiptPath: receipt });
    assert.equal(plan.mode, 'align-existing'); assert.deepEqual(plan.operations.map(item => item.path), ['auth-standards.json', 'test/auth-contract.test.mjs', 'test/auth-entrypoint.test.mjs', '.github/workflows/authentication-regression.yml']);
    await applyNativePlan(plan, { sourceRoot, authorized: true });
    assert.deepEqual(await readFile(path.join(root, 'src', 'auth', 'existing.ts')), before);
    assert.equal((await verifyNativeReceipt(root, receipt)).verification, 'PASS');
  } finally { await rm(root, { recursive: true, force: true }); await rm(receipt, { force: true }); }
});

test('Python Flask SQLite authentication is recognized without installing AUTH artifacts', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'auth-native-python-'));
  try {
    const { mkdir } = await import('node:fs/promises');
    await mkdir(path.join(root, 'backend', 'api'), { recursive: true });
    await mkdir(path.join(root, 'models'), { recursive: true });
    await writeFile(path.join(root, 'requirements.txt'), 'flask>=3\nbcrypt>=4\n');
    await writeFile(path.join(root, 'backend', 'api', 'auth.py'), '# oauth authorization_code code_challenge code_verifier S256 state nonce password_hash magic email HttpOnly refresh rotation replay revoke logout loopback\n');
    await writeFile(path.join(root, 'models', 'database.py'), 'import sqlite3\n# CREATE TABLE User\n');
    const discovery = await discoverNativeTarget(root);
    assert.deepEqual(discovery.stack, { language: 'python', runtime: 'python', framework: 'flask', persistence: 'sqlite', express: false, prisma: false });
    assert.equal(discovery.classification, 'COMPATIBLE');
    const assessment = await assessNativeTarget(root);
    assert.equal(assessment.executionClassification, 'AGENT_INTEGRATION_REQUIRED');
    assert.deepEqual(assessment.prohibitedPersistentArtifacts, []);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('VERIFY detects tamper and REPAIR restores authenticated bytes without changing versions', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'auth-native-verify-'));
  const receipt = path.join(os.tmpdir(), `auth-native-verify-receipt-${Date.now()}.json`);
  try {
    const plan = await planNativeTarget(root, { sourceRoot, productId: 'fixture', receiptPath: receipt });
    await applyNativePlan(plan, { sourceRoot, authorized: true });
    await writeFile(path.join(root, 'src', 'index.ts'), '// tampered\n');
    assert.equal((await verifyNativeReceipt(root, receipt)).verification, 'FAIL');
    const repaired = await repairNativeTarget(root, receipt, { sourceRoot, authorized: true });
    assert.equal(repaired.state, 'COMPLETE');
    assert.equal(repaired.versionChanged, false);
    assert.deepEqual(repaired.repaired, ['src/index.ts']);
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

test('abrupt REPAIR states recover to an unmixed old or repaired pair', async () => {
  for (const point of ['repair-quarantined:src/index.ts', 'repair-published:src/index.ts', 'repair-verified', 'repair-complete']) {
    const root = await mkdtemp(path.join(os.tmpdir(), 'auth-native-repair-crash-'));
    const receipt = path.join(os.tmpdir(), `auth-native-repair-crash-${Date.now()}-${Math.random()}.json`);
    try {
      const plan = await planNativeTarget(root, { sourceRoot, productId: 'fixture', receiptPath: receipt });
      await applyNativePlan(plan, { sourceRoot, authorized: true });
      await writeFile(path.join(root, 'src', 'index.ts'), '// pre-repair tamper\n');
      const program = `import {repairNativeTarget} from ${JSON.stringify(new URL('./auth-native-wizard.mjs', import.meta.url).href)};await repairNativeTarget(${JSON.stringify(root)},${JSON.stringify(receipt)},{sourceRoot:${JSON.stringify(sourceRoot)},authorized:true});`;
      const child = spawnSync(process.execPath, ['--input-type=module', '-e', program], { encoding: 'utf8', env: { ...process.env, AUTH_NATIVE_TEST_MODE: '1', AUTH_NATIVE_TEST_CRASH_AT: point } });
      assert.equal(child.status, 86, point);
      const recovery = await recoverNativeTransactions(root);
      if (point === 'repair-complete') {
        assert.equal(recovery.state, 'FINALIZED');
        assert.equal((await verifyNativeReceipt(root, receipt)).verification, 'PASS');
      } else {
        assert.equal(recovery.state, 'ROLLED_BACK');
        assert.equal(await readFile(path.join(root, 'src', 'index.ts'), 'utf8'), '// pre-repair tamper\n');
        assert.equal((await verifyNativeReceipt(root, receipt)).verification, 'FAIL');
        assert.equal((await repairNativeTarget(root, receipt, { sourceRoot, authorized: true })).verification.verification, 'PASS');
      }
      assert.deepEqual((await readdir(root)).filter(name => name.startsWith('.auth-native-transaction-')), []);
    } finally { await rm(root, { recursive: true, force: true }); await rm(receipt, { force: true }); }
  }
});

test('explicit migration records lineage and crash recovery never leaves a mixed runtime/receipt pair', async () => {
  const source = await mkdtemp(path.join(os.tmpdir(), 'auth-native-upgrade-source-'));
  try {
    assert.equal(spawnSync('git', ['clone', '--quiet', '--shared', sourceRoot, source]).status, 0);
    const base = spawnSync('git', ['rev-parse', 'HEAD'], { cwd: source, encoding: 'utf8' }).stdout.trim();
    const markerPath = path.join(source, 'profiles', 'typescript-node-express-prisma', 'src', 'index.ts');
    await writeFile(markerPath, `${await readFile(markerPath, 'utf8')}\n// immutable upgrade fixture\n`);
    assert.equal(spawnSync('git', ['-c', 'user.name=AUTH Test', '-c', 'user.email=auth-test@example.invalid', 'add', 'profiles/typescript-node-express-prisma/src/index.ts'], { cwd: source }).status, 0);
    assert.equal(spawnSync('git', ['-c', 'user.name=AUTH Test', '-c', 'user.email=auth-test@example.invalid', 'commit', '--quiet', '-m', 'upgrade fixture'], { cwd: source }).status, 0);
    const target = spawnSync('git', ['rev-parse', 'HEAD'], { cwd: source, encoding: 'utf8' }).stdout.trim();
    for (const point of [null, 'migrate-quarantined:src/index.ts', 'migrate-published:src/index.ts', 'migrate-verified', 'migrate-receipt-published', 'migrate-complete']) {
      const root = await mkdtemp(path.join(os.tmpdir(), 'auth-native-upgrade-'));
      const receipt = path.join(os.tmpdir(), `auth-native-upgrade-old-${Date.now()}-${Math.random()}.json`);
      const nextReceipt = path.join(os.tmpdir(), `auth-native-upgrade-new-${Date.now()}-${Math.random()}.json`);
      try {
        const plan = await planNativeTarget(root, { sourceRoot: source, sourceRevision: base, productId: 'fixture', receiptPath: receipt });
        await applyNativePlan(plan, { sourceRoot: source, authorized: true });
        if (!point) {
          const result = await migrateNativeTarget(root, receipt, { sourceRoot: source, targetRevision: target, newReceiptPath: nextReceipt, authorized: true });
          assert.equal(result.state, 'COMPLETE'); assert.equal(result.from, base); assert.equal(result.to, target);
          const next = JSON.parse(await readFile(nextReceipt, 'utf8')); assert.equal(next.priorReceiptDigest, JSON.parse(await readFile(receipt, 'utf8')).receiptDigest);
          assert.equal((await verifyNativeReceipt(root, nextReceipt)).verification, 'PASS');
        } else {
          const program = `import {migrateNativeTarget} from ${JSON.stringify(new URL('./auth-native-wizard.mjs', import.meta.url).href)};await migrateNativeTarget(${JSON.stringify(root)},${JSON.stringify(receipt)},{sourceRoot:${JSON.stringify(source)},targetRevision:${JSON.stringify(target)},newReceiptPath:${JSON.stringify(nextReceipt)},authorized:true});`;
          const child = spawnSync(process.execPath, ['--input-type=module', '-e', program], { encoding: 'utf8', env: { ...process.env, AUTH_NATIVE_TEST_MODE: '1', AUTH_NATIVE_TEST_CRASH_AT: point } });
          assert.equal(child.status, 86, point);
          const recovery = await recoverNativeTransactions(root);
          if (point === 'migrate-complete') { assert.equal(recovery.state, 'FINALIZED'); assert.equal((await verifyNativeReceipt(root, nextReceipt)).verification, 'PASS'); }
          else { assert.equal(recovery.state, 'ROLLED_BACK'); assert.equal((await verifyNativeReceipt(root, receipt)).verification, 'PASS'); await absent(nextReceipt); }
        }
        assert.deepEqual((await readdir(root)).filter(name => name.startsWith('.auth-native-transaction-')), []);
      } finally { await rm(root, { recursive: true, force: true }); await rm(receipt, { force: true }); await rm(nextReceipt, { force: true }); }
    }
  } finally { await rm(source, { recursive: true, force: true }); }
});

test('installed entrypoint protection survives unrelated development without AUTH and fails contract loss', async () => {
  const { mkdir, rename, symlink } = await import('node:fs/promises');
  const root = await mkdtemp(path.join(os.tmpdir(), 'auth-entrypoint-'));
  const receipt = `${root}-receipt.json`;
  try {
    await mkdir(path.join(root, 'src/auth'), { recursive: true });
    await writeFile(path.join(root, 'package.json'), JSON.stringify({ dependencies: { express: '5' } }));
    const entry = path.join(root, 'src/auth/existing.js');
    await writeFile(entry, '// oauth session refresh');
    const plan = await planNativeAlignment(root, { sourceRoot, productId: 'fixture', receiptPath: receipt, authenticationRole: 'RELYING_PARTY', authenticationEntrypoint: 'src/auth/existing.js' });
    await applyNativePlan(plan, { sourceRoot, authorized: true });
    const testPath = path.join(root, 'test/auth-entrypoint.test.mjs');
    const childEnv = { ...process.env }; delete childEnv.NODE_TEST_CONTEXT;
    const run = () => spawnSync(process.execPath, ['--test', testPath], { cwd: os.tmpdir(), env: childEnv, encoding: 'utf8' });
    assert.equal(run().status, 0);
    await writeFile(path.join(root, 'unrelated.txt'), 'new feature');
    await writeFile(entry, '// legitimate auth implementation development');
    assert.equal(run().status, 0);
    const contractPath = path.join(root, 'auth-standards.json');
    const bytes = await readFile(contractPath);
    for (const key of ['authenticationRole', 'authenticationRuntime', 'authenticationEntrypoint', 'productId']) {
      const changed = JSON.parse(bytes); changed[key] = 'changed';
      await writeFile(contractPath, JSON.stringify(changed));
      assert.notEqual(run().status, 0, key);
    }
    await writeFile(contractPath, bytes);
    await rename(entry, `${entry}.old`);
    assert.notEqual(run().status, 0);
    await symlink(`${entry}.old`, entry);
    assert.notEqual(run().status, 0);
    await rm(entry); await mkdir(entry);
    assert.notEqual(run().status, 0);
    await rm(entry, { recursive: true }); await rename(`${entry}.old`, entry);
    assert.equal(run().status, 0);
    assert.equal(await readFile(path.join(root, 'unrelated.txt'), 'utf8'), 'new feature');
    assert.doesNotMatch(await readFile(testPath, 'utf8'), /auth-native-wizard|sourceRoot|fetch\(/);
  } finally { await rm(root, { recursive: true, force: true }); await rm(receipt, { force: true }); }
});

test('setup creates automatic product CI and rebuilds before behavioral tests', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'auth-gate-'));
  const receipt = `${root}-receipt.json`;
  try {
    const plan = await planNativeTarget(root, { sourceRoot, receiptPath: receipt });
    await applyNativePlan(plan, { sourceRoot, authorized: true });
    const pkg = JSON.parse(await readFile(path.join(root, 'package.json'), 'utf8'));
    assert.equal(pkg.scripts.pretest, 'npm run prisma:generate && npm run build');
    assert.equal(pkg.scripts.test, 'node --test test/*.test.mjs');
    const workflow = await readFile(path.join(root, '.github/workflows/authentication-regression.yml'), 'utf8');
    assert.match(workflow, /on: \[push, pull_request, workflow_dispatch\]/);
    assert.match(workflow, /run: npm ci/); assert.match(workflow, /run: npm test/);
    assert.doesNotMatch(workflow, /continue-on-error|auth-verifier|AUTH_CHECKOUT|pull_request_target/);
    assert.match(workflow, /persist-credentials: false/);
    assert.equal((await verifyNativeReceipt(root, receipt)).verification, 'PASS');
  } finally { await rm(root, { recursive: true, force: true }); await rm(receipt, { force: true }); }
});
