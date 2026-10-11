import test from 'node:test';
import assert from 'node:assert/strict';
import { access, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { installProductAuthRuntime } from './auth-runtime-installer.mjs';
import { establishRuntimeBaseline } from './auth-runtime-lifecycle.mjs';

const authRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const worker = path.join(authRoot, 'scripts', 'auth-runtime-lifecycle-worker.mjs');
const cli = path.join(authRoot, 'scripts', 'auth-cli.mjs');
const points = ['PREPARED', 'OLD_QUARANTINED', 'NEW_PUBLISHED', 'BASELINE_ADVANCING', 'BASELINE_PUBLISHED', 'BASELINE_ADVANCED'];
const accept = async () => ({ verification: 'PASS', checks: ['crash-fixture'] });
const git = (cwd, args) => {
  const result = spawnSync('git', args, { cwd, encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
};
const readJson = async (file) => JSON.parse(await readFile(file, 'utf8'));

async function makeFixture(operation, point) {
  const fixture = await mkdtemp(path.join(os.tmpdir(), `auth-runtime-${operation.toLowerCase()}-${point.toLowerCase()}-`));
  const source = path.join(fixture, 'source');
  const product = path.join(fixture, 'product');
  git(fixture, ['clone', '--quiet', '--no-local', authRoot, source]);
  await mkdir(path.join(product, '.auth-kit'), { recursive: true });
  await mkdir(path.join(product, '.auth-runtime', 'data'), { recursive: true });
  await writeFile(path.join(product, '.auth-runtime', 'data', 'sessions.db'), 'session-identity-data\n');
  await writeFile(path.join(product, 'product-owned.txt'), 'product-owned\n');
  const config = await readJson(path.join(authRoot, 'config', 'code.json'));
  await installProductAuthRuntime(product, { sourceRoot: source, productId: 'code', config, authorized: true });
  const established = await establishRuntimeBaseline(product, 'code', { authorized: true, acceptance: accept });
  let target = '';
  if (operation === 'REPAIR') {
    await writeFile(path.join(product, '.auth-runtime', 'auth-system', 'src', 'index.ts'), 'tampered runtime\n');
  } else {
    const sourceFile = path.join(source, 'src', 'index.ts');
    await writeFile(sourceFile, `${await readFile(sourceFile, 'utf8')}\n// ${point} crash target\n`);
    git(source, ['add', 'src/index.ts']);
    git(source, ['-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.test', 'commit', '-qm', `${point} target`]);
    target = git(source, ['rev-parse', 'HEAD']);
  }
  return { fixture, source, product, established, target };
}

async function assertNoResidue(product) {
  await assert.rejects(access(path.join(product, '.auth-runtime-lifecycle-journal.json')));
  const rootNames = await readdir(product);
  assert.deepEqual(rootNames.filter((name) => name.startsWith('.auth-runtime-candidate-') || name.startsWith('.auth-runtime-previous-')), []);
  const kitNames = await readdir(path.join(product, '.auth-kit'));
  assert.deepEqual(kitNames.filter((name) => name.startsWith('runtime-baseline.next-') || name.startsWith('runtime-baseline.previous-')), []);
}

for (const operation of ['REPAIR', 'UPGRADE']) {
  for (const point of points) {
    test(`${operation} recovers a child-process exit at ${point} without mixed runtime/baseline state`, { timeout: 120_000 }, async () => {
      const { fixture, source, product, established, target } = await makeFixture(operation, point);
      try {
        const child = spawnSync(process.execPath, [worker, operation.toLowerCase(), product, 'code', source, target], {
          encoding: 'utf8',
          env: { ...process.env, AUTH_RUNTIME_TEST_MODE: '1', AUTH_RUNTIME_TEST_ABRUPT_POINT: point },
        });
        assert.equal(child.status, 87, child.stderr || child.stdout);

        const restartArgs = operation === 'REPAIR'
          ? [cli, 'runtime', 'repair', '--repo', product, '--app', 'code', '--authorize']
          : [cli, 'runtime', 'recover', '--repo', product, '--app', 'code'];
        const recovery = spawnSync(process.execPath, restartArgs, {
          encoding: 'utf8',
          env: { ...process.env, AUTH_RUNTIME_TEST_MODE: '1', AUTH_RUNTIME_TEST_ACCEPTANCE: '1' },
        });
        assert.equal(recovery.status, 0, recovery.stderr || recovery.stdout);
        if (operation === 'UPGRADE') assert.equal(JSON.parse(recovery.stdout).recovered, true);
        const verification = spawnSync(process.execPath, [cli, 'runtime', 'verify', '--repo', product, '--app', 'code'], { encoding: 'utf8' });
        assert.equal(verification.status, 0, verification.stderr || verification.stdout);
        assert.equal(JSON.parse(verification.stdout).verification, 'PASS');

        const runtimeManifest = await readJson(path.join(product, '.auth-runtime', 'auth-system', 'AUTH-RUNTIME-MANIFEST.json'));
        const baselineManifest = await readJson(path.join(product, '.auth-kit', 'runtime-baseline', 'AUTH-RUNTIME-MANIFEST.json'));
        const state = await readJson(path.join(product, '.auth-kit', 'runtime-baseline', 'state.json'));
        assert.equal(runtimeManifest.installationId, baselineManifest.installationId);
        assert.equal(runtimeManifest.installationId, state.installationId);

        const finishesNewPair = point === 'BASELINE_PUBLISHED' || point === 'BASELINE_ADVANCED';
        if (operation === 'UPGRADE' && finishesNewPair) {
          assert.notEqual(state.installationId, established.installationId);
          assert.equal(runtimeManifest.source.revision, target);
          assert.equal(state.lineage.at(-1)?.operation, 'UPGRADE');
        } else {
          assert.equal(state.installationId, established.installationId);
          if (operation === 'REPAIR') assert.equal(state.lineage.at(-1)?.operation, 'REPAIR');
          else assert.equal(state.lineage.length, 0);
        }

        assert.equal(await readFile(path.join(product, '.auth-runtime', 'data', 'sessions.db'), 'utf8'), 'session-identity-data\n');
        assert.equal(await readFile(path.join(product, 'product-owned.txt'), 'utf8'), 'product-owned\n');
        await assertNoResidue(product);
      } finally {
        await rm(fixture, { recursive: true, force: true });
      }
    });
  }
}
