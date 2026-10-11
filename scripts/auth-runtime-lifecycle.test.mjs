import test from 'node:test';
import assert from 'node:assert/strict';
import { access, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { installProductAuthRuntime } from './auth-runtime-installer.mjs';
import { acceptRuntimeOperational, establishRuntimeBaseline, repairRuntime, upgradeRuntime, verifyRuntimeLifecycle } from './auth-runtime-lifecycle.mjs';

const authRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const accept = async () => ({ verification: 'PASS', checks: ['locked-install', 'prisma-generate', 'build', 'startup', 'readiness', 'source-independent'] });
const git = (cwd, args) => { const result = spawnSync('git', args, { cwd, encoding: 'utf8' }); assert.equal(result.status, 0, result.stderr); return result.stdout.trim(); };

test('baseline, bounded repair, upgrade, rollback, and product-state preservation', { timeout: 120_000 }, async () => {
  const fixture = await mkdtemp(path.join(os.tmpdir(), 'auth-runtime-lifecycle-'));
  const source = path.join(fixture, 'source'), product = path.join(fixture, 'product');
  try {
    git(fixture, ['clone', '--quiet', '--no-local', authRoot, source]);
    await mkdir(path.join(product, '.auth-kit'), { recursive: true });
    await mkdir(path.join(product, '.auth-runtime', 'data'), { recursive: true });
    await writeFile(path.join(product, '.auth-runtime', 'data', 'sessions.db'), 'session-identity-data\n');
    await writeFile(path.join(product, 'product-owned.txt'), 'product-owned\n');
    const config = JSON.parse(await readFile(path.join(authRoot, 'config', 'code.json'), 'utf8'));
    await installProductAuthRuntime(product, { sourceRoot: source, productId: 'code', config, authorized: true });
    const established = await establishRuntimeBaseline(product, 'code', { authorized: true, acceptance: accept });
    assert.equal((await verifyRuntimeLifecycle(product, 'code', { acceptance: accept })).verification, 'PASS');

    const runtimeFile = path.join(product, '.auth-runtime', 'auth-system', 'src', 'index.ts');
    await writeFile(runtimeFile, 'tampered\n');
    assert.equal((await verifyRuntimeLifecycle(product, 'code')).verification, 'FAIL');
    const repaired = await repairRuntime(product, 'code', { authorized: true, sourceRoot: source, acceptance: acceptRuntimeOperational });
    assert.equal(repaired.installationId, established.installationId);
    assert.equal((await verifyRuntimeLifecycle(product, 'code')).verification, 'PASS');

    await writeFile(path.join(source, 'src', 'index.ts'), `${await readFile(path.join(source, 'src', 'index.ts'), 'utf8')}\n// compatible fixture release\n`);
    git(source, ['add', 'src/index.ts']);
    git(source, ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.test', 'commit', '-qm', 'compatible runtime']);
    const target = git(source, ['rev-parse', 'HEAD']);
    const upgraded = await upgradeRuntime(product, 'code', { authorized: true, sourceRoot: source, targetRevision: target, acceptance: acceptRuntimeOperational });
    assert.notEqual(upgraded.installationId, established.installationId);
    assert.equal(upgraded.previousInstallationId, established.installationId);
    assert.equal((await verifyRuntimeLifecycle(product, 'code')).verification, 'PASS');

    await writeFile(path.join(source, 'src', 'index.ts'), `${await readFile(path.join(source, 'src', 'index.ts'), 'utf8')}\n// rejected fixture release\n`);
    git(source, ['add', 'src/index.ts']);
    git(source, ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.test', 'commit', '-qm', 'rejected runtime']);
    const rejected = git(source, ['rev-parse', 'HEAD']);
    await assert.rejects(upgradeRuntime(product, 'code', { authorized: true, sourceRoot: source, targetRevision: rejected, acceptance: async () => ({ verification: 'FAIL', error: 'FIXTURE_REJECTED' }) }), /FIXTURE_REJECTED/);
    assert.equal((await verifyRuntimeLifecycle(product, 'code')).installationId, upgraded.installationId);

    await writeFile(path.join(source, 'src', 'index.ts'), `${await readFile(path.join(source, 'src', 'index.ts'), 'utf8')}\n// interrupted fixture release\n`);
    git(source, ['add', 'src/index.ts']);
    git(source, ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.test', 'commit', '-qm', 'interrupted runtime']);
    const interrupted = git(source, ['rev-parse', 'HEAD']);
    await assert.rejects(upgradeRuntime(product, 'code', {
      authorized: true, sourceRoot: source, targetRevision: interrupted, acceptance: accept,
      testHook: async (point) => { if (point === 'after-runtime-publication') throw new Error('INTERRUPTED_AFTER_PUBLICATION'); },
    }), /INTERRUPTED_AFTER_PUBLICATION/);
    assert.equal((await verifyRuntimeLifecycle(product, 'code')).installationId, upgraded.installationId);

    await writeFile(path.join(source, 'src', 'index.ts'), `${await readFile(path.join(source, 'src', 'index.ts'), 'utf8')}\n// finalized fixture release\n`);
    git(source, ['add', 'src/index.ts']);
    git(source, ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.test', 'commit', '-qm', 'finalized runtime']);
    const finalized = git(source, ['rev-parse', 'HEAD']);
    await assert.rejects(upgradeRuntime(product, 'code', {
      authorized: true, sourceRoot: source, targetRevision: finalized, acceptance: accept,
      testHook: async (point) => { if (point === 'after-baseline-advance') throw new Error('INTERRUPTED_AFTER_BASELINE'); },
    }), /INTERRUPTED_AFTER_BASELINE/);
    const finalizedVerification = await verifyRuntimeLifecycle(product, 'code');
    assert.equal(finalizedVerification.verification, 'PASS');
    assert.notEqual(finalizedVerification.installationId, upgraded.installationId);

    assert.equal(await readFile(path.join(product, '.auth-runtime', 'data', 'sessions.db'), 'utf8'), 'session-identity-data\n');
    assert.equal(await readFile(path.join(product, 'product-owned.txt'), 'utf8'), 'product-owned\n');
    await assert.rejects(access(path.join(product, '.auth-runtime-lifecycle-journal.json')));
    assert.deepEqual((await readdir(product)).filter((name) => name.startsWith('.auth-runtime-candidate-') || name.startsWith('.auth-runtime-previous-')), []);
  } finally { await rm(fixture, { recursive: true, force: true }); }
});
