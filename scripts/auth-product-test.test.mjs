import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { productTestSource, validateProductTest } from './auth-product-test.mjs';

async function fixture(t, argv, timeoutMs = 5000, extra = {}) {
  const root = await mkdtemp(path.join(tmpdir(), 'product-behavior-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(path.join(root, 'test'));
  const source = productTestSource({ argv, timeoutMs, ...extra });
  await writeFile(path.join(root, 'test/auth-behavior.mjs'), source);
  const env = { ...process.env }; delete env.NODE_TEST_CONTEXT;
  return { root, source, run: (overrides = {}) => spawnSync(process.execPath, [path.join(root, 'test/auth-behavior.mjs')], { cwd: tmpdir(), encoding: 'utf8', env: { ...env, ...overrides } }) };
}
test('product-owned runner succeeds from any cwd without AUTH and tolerates unrelated files', async t => {
  const f = await fixture(t, ['$NODE', '-e', "require('node:assert').ok(require('node:fs').existsSync('test/auth-behavior.mjs'))"]);
  assert.equal(f.run().status, 0);
  await writeFile(path.join(f.root, 'unrelated.txt'), 'unrelated');
  assert.equal(f.run().status, 0);
  assert.doesNotMatch(f.source, /from ['"].*auth|fetch\(/);
});
test('actual behavioral failure propagates exit status', async t => {
  const f = await fixture(t, ['$NODE', '-e', 'process.exit(7)']);
  assert.equal(f.run().status, 7);
});
test('timeout fails explicitly', async t => {
  const f = await fixture(t, ['$NODE', '-e', 'setInterval(()=>{},1000)'], 100);
  const result = f.run(); assert.equal(result.status, 2); assert.match(result.stderr, /PRODUCT_TEST_TIMEOUT/);
});
test('arguments are literal and not shell-interpolated', async t => {
  const f = await fixture(t, ['$NODE', '-e', "require('node:assert').equal(process.argv[1], '$HOME; echo unexpected')", '$HOME; echo unexpected']);
  assert.equal(f.run().status, 0);
});
test('explicit executable environment requires configuration and does not print secrets', async t => {
  const f = await fixture(t, ['python3', '-e', 'process.exit(0)'], 5000, { executableEnvironment: 'PRODUCT_TEST_EXECUTABLE' });
  assert.equal(f.run({ PRODUCT_TEST_EXECUTABLE: '' }).status, 2);
  assert.equal(f.run({ PRODUCT_TEST_EXECUTABLE: process.execPath }).status, 0);
  const result = f.run({ PRODUCT_TEST_EXECUTABLE: '/missing/secret-value' });
  assert.equal(result.status, 2); assert.doesNotMatch(result.stderr, /secret-value/);
});
test('malformed specs and unbounded execution rejected', () => {
  for (const spec of [{ argv: [], timeoutMs: 100 }, { argv: ['node'], timeoutMs: 0 }, { argv: ['node'], timeoutMs: 600001 }, { argv: ['node'], timeoutMs: 100, env: { PASSWORD: 'secret' } }]) assert.throws(() => validateProductTest(spec));
});
