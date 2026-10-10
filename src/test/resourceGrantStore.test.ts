import test from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, mkdtempSync, readFileSync, realpathSync, rmSync, statSync, symlinkSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { execFileSync } from 'node:child_process';
import { SqliteResourceGrantStore, type ResourceGrantRecord } from '../auth/resourceGrantStore.js';

const fixture: ResourceGrantRecord = {
  id: 'grant-a', jti: 'artifact-a', tokenDigest: 'a'.repeat(64), issuer: 'https://auth.example.test', subject: 'subject-a',
  sessionId: 'session-a', sourceAccessJti: 'access-a', clientId: 'fixture-native', applicationId: 'fixture-app',
  audience: 'https://resource.example.test', ownerId: 'fixture-owner', capabilities: ['fixture:read'],
  issuedAt: 100, expiresAt: 160, admissionVersion: 'fixture-admission-v1',
};
function setup(t: any) {
  const root = mkdtempSync(join(realpathSync(tmpdir()), 'auth-resource-grants-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  return { root, path: join(root, 'grants.sqlite') };
}

test('grant and revocation persist across restart with protected permissions', async t => {
  const { path, root } = setup(t);
  const first = new SqliteResourceGrantStore(path);
  await first.initialize(); await first.put(fixture);
  const restarted = new SqliteResourceGrantStore(path);
  await restarted.initialize();
  assert.deepEqual(await restarted.get(fixture.id), { ...fixture, revoked: false });
  await restarted.revoke(fixture.id);
  const third = new SqliteResourceGrantStore(path); await third.initialize();
  assert.equal((await third.get(fixture.id))?.revoked, true);
  assert.equal(statSync(root).mode & 0o777, 0o700);
  assert.equal(statSync(path).mode & 0o777, 0o600);
});

test('insert-only grants and immutable session identity/client/application are transactional', async t => {
  const { path } = setup(t); const store = new SqliteResourceGrantStore(path); await store.initialize();
  await store.put(fixture);
  await assert.rejects(store.put(fixture));
  for (const [key, value] of [['subject', 'other-owner'], ['clientId', 'other-client'], ['applicationId', 'other-app']]) {
    await assert.rejects(store.put({ ...fixture, id: `conflict-${key}`, jti: `artifact-${key}`, [key]: value }));
    assert.equal(await store.get(`conflict-${key}`), null);
  }
  await store.put({ ...fixture, id: 'reissued', jti: 'reissued-artifact' });
  assert.equal((await store.get('reissued'))?.subject, fixture.subject);
  await store.put({ ...fixture, id: 'different-session', jti: 'different-artifact', sessionId: 'session-b', subject: 'subject-b' });
  await store.revoke(fixture.id);
  assert.equal((await store.get('different-session'))?.revoked, false);
});

test('dedicated stores are isolated and unexpected raw-token properties are discarded', async t => {
  const { root, path } = setup(t);
  const first = new SqliteResourceGrantStore(path); await first.initialize();
  await first.put({ ...fixture, rawToken: 'DO-NOT-PERSIST-SYNTHETIC-TOKEN' } as ResourceGrantRecord);
  const second = new SqliteResourceGrantStore(join(root, 'second.sqlite')); await second.initialize();
  assert.equal(await second.get(fixture.id), null);
  assert.equal(readFileSync(path).includes(Buffer.from('DO-NOT-PERSIST-SYNTHETIC-TOKEN')), false);
});

test('foreign database is rejected without altering its schema or application ID', async t => {
  const { path } = setup(t);
  execFileSync('sqlite3', [path, 'CREATE TABLE existing_accounts(id TEXT); PRAGMA application_id=123;']); chmodSync(path, 0o600);
  const before = readFileSync(path);
  await assert.rejects(new SqliteResourceGrantStore(path).initialize(), /FOREIGN_DATABASE/);
  assert.deepEqual(readFileSync(path), before);
});

test('unmarked nonempty databases, symlinks, insecure parents and relative paths are rejected', async t => {
  const { path, root } = setup(t);
  execFileSync('sqlite3', [path, 'CREATE TABLE accounts(id TEXT);']); chmodSync(path, 0o600);
  await assert.rejects(new SqliteResourceGrantStore(path).initialize(), /FOREIGN_DATABASE/);
  const link = join(root, 'link.sqlite'); symlinkSync(path, link);
  await assert.rejects(new SqliteResourceGrantStore(link).initialize(), /SYMLINK_REJECTED/);
  assert.throws(() => new SqliteResourceGrantStore('relative.sqlite'), /ABSOLUTE_PATH_REQUIRED/);
  chmodSync(root, 0o755);
  await assert.rejects(new SqliteResourceGrantStore(path).initialize(), /PROTECTION_REQUIRED/);
});

test('uninitialized stores and invalid artifact retention are rejected', async t => {
  const { path } = setup(t); const store = new SqliteResourceGrantStore(path);
  await assert.rejects(store.get('missing'), /NOT_INITIALIZED/); await store.initialize();
  await assert.rejects(store.put({ ...fixture, expiresAt: 161 }), /INVALID/);
  await assert.rejects(store.put({ ...fixture, tokenDigest: 'plaintext' }), /INVALID/);
});
