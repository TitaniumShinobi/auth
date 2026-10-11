import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { spawn, spawnSync } from 'node:child_process';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { installProductAuthRuntime } from './auth-runtime-installer.mjs';

const sourceRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const cli = path.join(sourceRoot, 'scripts', 'auth-cli.mjs');
const node = path.join(sourceRoot, 'bin', 'node20');
const npm = path.join(sourceRoot, 'bin', 'npm20');

async function unusedPort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => server.listen(0, '127.0.0.1', resolve).once('error', reject));
  const address = server.address();
  await new Promise((resolve) => server.close(resolve));
  return address.port;
}

async function waitForReady(url, child) {
  const deadline = Date.now() + 20_000;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(`runtime exited before readiness: ${child.exitCode}`);
    try {
      const response = await fetch(url);
      if (response.status === 200 && (await response.json()).ready === true) return;
    } catch {}
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error('runtime readiness timeout');
}

test('committed lockfile installs without source-checkout resolution and drift is detected', { timeout: 180_000 }, async () => {
  const product = await mkdtemp(path.join(os.tmpdir(), 'auth-runtime-independent-'));
  try {
    const setup = spawnSync(node, [cli, 'setup', '--repo', product, '--app', 'code', '--authorize'], {
      cwd: os.tmpdir(), encoding: 'utf8', timeout: 30_000, env: { ...process.env, AGENTS_ALLOW_APPLY_EDITS: 'true' },
    });
    assert.equal(setup.status, 0, setup.stderr);
    const runtime = path.join(product, '.auth-runtime', 'auth-system');
    const lockBefore = await readFile(path.join(runtime, 'package-lock.json'));
    const install = spawnSync(npm, ['ci', '--no-audit', '--no-fund'], { cwd: runtime, encoding: 'utf8', timeout: 120_000 });
    assert.equal(install.status, 0, install.stderr);
    assert.deepEqual(await readFile(path.join(runtime, 'package-lock.json')), lockBefore);
    const generate = spawnSync(npm, ['run', 'prisma:generate'], { cwd: runtime, encoding: 'utf8', timeout: 60_000 });
    assert.equal(generate.status, 0, `${generate.stdout}\n${generate.stderr}`);
    const build = spawnSync(npm, ['run', 'build'], { cwd: runtime, encoding: 'utf8', timeout: 60_000 });
    assert.equal(build.status, 0, `${build.stdout}\n${build.stderr}`);
    const packageText = await readFile(path.join(runtime, 'package.json'), 'utf8');
    const lockText = await readFile(path.join(runtime, 'package-lock.json'), 'utf8');
    assert.equal(packageText.includes(sourceRoot), false);
    assert.equal(lockText.includes(sourceRoot), false);

    await writeFile(path.join(runtime, 'package-lock.json'), `${lockText}\n`);
    const validate = spawnSync(node, [cli, 'validate', '--repo', product, '--app', 'code'], { encoding: 'utf8', timeout: 30_000 });
    assert.equal(validate.status, 2);
    assert.match(validate.stdout, /AUTH_RUNTIME_FILE_DRIFT:package-lock.json/);
  } finally {
    await rm(product, { recursive: true, force: true });
  }
});

test('built runtime starts after its immutable source checkout is made unavailable', { timeout: 180_000 }, async () => {
  const fixture = await mkdtemp(path.join(os.tmpdir(), 'auth-source-independence-'));
  const source = path.join(fixture, 'source');
  const unavailableSource = path.join(fixture, 'source.unavailable');
  const product = path.join(fixture, 'product');
  let child;
  try {
    const clone = spawnSync('git', ['clone', '--quiet', '--no-local', sourceRoot, source], { encoding: 'utf8', timeout: 30_000 });
    assert.equal(clone.status, 0, clone.stderr);
    await writeFile(path.join(fixture, 'clone-created'), 'yes\n');
    await mkdir(product);
    const config = JSON.parse(await readFile(path.join(sourceRoot, 'config', 'code.json'), 'utf8'));
    await installProductAuthRuntime(product, { sourceRoot: source, productId: 'code', config, authorized: true });
    const runtime = path.join(product, '.auth-runtime', 'auth-system');
    for (const args of [['ci', '--no-audit', '--no-fund'], ['run', 'prisma:generate'], ['run', 'build']]) {
      const result = spawnSync(npm, args, { cwd: runtime, encoding: 'utf8', timeout: 120_000 });
      assert.equal(result.status, 0, `${args.join(' ')}\n${result.stdout}\n${result.stderr}`);
    }
    await rename(source, unavailableSource);
    const port = await unusedPort();
    child = spawn(node, ['dist/index.js'], {
      cwd: runtime, stdio: ['ignore', 'pipe', 'pipe'],
      env: {
        PATH: process.env.PATH, AUTH_HOST: '127.0.0.1', AUTH_PORT: String(port), AUTH_STORAGE_ADAPTER: 'memory',
        AUTH_APP_CONFIG_PATH: 'config/example-app.json', AUTH_SESSION_SECRET: 'fixture-session-secret-32-characters',
        AUTH_ACCESS_TOKEN_SECRET: 'fixture-access-secret-32-characters', AUTH_REFRESH_TOKEN_SECRET: 'fixture-refresh-secret-32-characters',
        AUTH_REFRESH_TOKEN_HASH_SECRET: 'fixture-refresh-hash-secret-32-chars',
      },
    });
    await waitForReady(`http://127.0.0.1:${port}/ready`, child);
    assert.equal((await fetch(`http://127.0.0.1:${port}/health`)).status, 200);
    assert.notEqual((await fetch(`http://127.0.0.1:${port}/api/auth/config`)).status, 404);
    assert.notEqual((await fetch(`http://127.0.0.1:${port}/api/auth/google/callback`)).status, 404);
  } finally {
    if (child && child.exitCode === null) {
      child.kill('SIGTERM');
      await new Promise((resolve) => child.once('exit', resolve));
    }
    await rm(fixture, { recursive: true, force: true });
  }
});
