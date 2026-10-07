import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createAuthApp } from '../app.js';
import { MemoryStorageAdapter } from '../persistence/memoryStorage.js';
import { SqliteStorageAdapter } from '../persistence/sqliteStorage.js';
import { execSql, querySql } from '../persistence/sqliteCli.js';
import type { AuthAppConfig } from '../types.js';

process.env.DESKTOP_FIXTURE_GITHUB_CALLBACK_URL = 'https://desktop.example.test/api/auth/github/callback';
const config: AuthAppConfig = {
  oauth: { envPrefix: 'DESKTOP_FIXTURE' },
  app: { id: 'fixture', name: 'Fixture Desktop' }, allowedOrigins: ['https://desktop.example.test'],
  redirects: { postLoginPath: '/return', postLogoutPath: '/' }, credentials: { enabled: true },
  docs: [], turnstile: { enabled: false, required: false }, providers: [{ provider: 'github', label: 'GitHub', enabled: true }],
  publicClients: [{ clientId: 'fixture-native', authorizationUiUrl: 'https://desktop.example.test/signin',
    loopback: { hosts: ['127.0.0.1'], path: '/callback', allowDynamicPorts: true } }],
};
async function server(fn: (base: string) => Promise<void>) {
  const storage = new MemoryStorageAdapter();
  storage.upsertOAuthUser = async () => { throw new Error('sqlite3 SQL PRIVATE_FIXTURE_VALUE'); };
  const app = await createAuthApp({ storage, configStore: { getConfig: async () => config }, sessionSecret: 'synthetic-only',
    providers: { github: { provider: 'github', label: 'GitHub', isConfigured: () => true,
      buildAuthorizationUrl: ({ state }) => `https://github.example.test/auth?state=${state}`,
      exchangeCodeForProfile: async () => ({ providerUserId: 'fixture-id', email: 'fixture@example.test', displayName: 'Fixture', raw: {} }),
    } },
  });
  const srv = app.listen(0, '127.0.0.1');
  await new Promise<void>((resolve, reject) => { srv.once('listening', resolve); srv.once('error', reject); });
  const address = srv.address(); assert.ok(address && typeof address !== 'string');
  try { await fn(`http://127.0.0.1:${address.port}`); } finally { await new Promise<void>(resolve => srv.close(() => resolve())); }
}
const get = (url: string) => fetch(url, { redirect: 'manual' });

test('GitHub persistence error is sanitized and returns initiating native state; replay fails', async () => {
  await server(async base => {
    const verifier = 'v'.repeat(43), state = 's'.repeat(43);
    const query = new URLSearchParams({ app: 'fixture', client_id: 'fixture-native', response_type: 'code',
      redirect_uri: 'http://127.0.0.1:54321/callback', state, code_challenge_method: 'S256',
      code_challenge: createHash('sha256').update(verifier).digest('base64url') });
    const auth = await get(`${base}/oauth/authorize?${query}`); assert.equal(auth.status, 302);
    const login = new URL(auth.headers.get('location')!);
    const begin = await get(`${base}/api/auth/github?${new URLSearchParams({
      authorization_request: login.searchParams.get('authorization_request')!,
      authorization_return: login.searchParams.get('authorization_return')!,
    })}`);
    assert.equal(begin.status, 302);
    const providerState = new URL(begin.headers.get('location')!).searchParams.get('state');
    const callback = `${base}/api/auth/github/callback?code=fixture&state=${providerState}`;
    const result = await get(callback); assert.equal(result.status, 302);
    const location = new URL(result.headers.get('location')!);
    assert.equal(location.origin, 'http://127.0.0.1:54321');
    assert.equal(location.searchParams.get('state'), state);
    assert.equal(location.searchParams.get('error'), 'temporarily_unavailable');
    assert.equal(location.searchParams.has('code'), false);
    assert.equal(result.headers.get('set-cookie'), null);
    assert.ok(!location.href.includes('PRIVATE_FIXTURE_VALUE'));
    assert.equal((await get(callback)).status, 400);
  });
});

test('browser persistence failure is explicit; return route never claims success or echoes errors', async () => {
  await server(async base => {
    const begin = await get(`${base}/api/auth/github`);
    const state = new URL(begin.headers.get('location')!).searchParams.get('state');
    const response = await get(`${base}/api/auth/github/callback?state=${state}&code=fixture`);
    assert.equal(response.status, 503); assert.equal(response.headers.get('location'), null);
    const body = await response.text(); assert.ok(body.includes('RECOVERABLE_ERROR')); assert.ok(!body.includes('PRIVATE_FIXTURE_VALUE'));
    for (const path of ['/return', '/return?error=sqlite3_PRIVATE_FIXTURE_VALUE']) {
      const result = await get(base + path); assert.ok([400, 409].includes(result.status));
      const text = await result.text(); assert.ok(!text.includes('PRIVATE_FIXTURE_VALUE')); assert.ok(!text.includes('Cannot GET'));
      assert.equal(result.headers.get('cache-control'), 'no-store');
    }
  });
});

test('SQLite runs stdin SQL against an isolated database and suppresses SQL/error details', () => {
  const dir = mkdtempSync(join(tmpdir(), 'auth-desktop-sql-'));
  try {
    const db = join(dir, 'fixture.sqlite');
    execSql(db, 'CREATE TABLE fixture (value TEXT); INSERT INTO fixture VALUES (\'fixture\');');
    assert.deepEqual(querySql(db, 'SELECT value FROM fixture;'), [{ value: 'fixture' }]);
    assert.throws(() => execSql(db, 'SELECT PRIVATE_FIXTURE_VALUE FROM absent;'), error => {
      assert.equal((error as { code: string }).code, 'AUTH_PERSISTENCE_UNAVAILABLE');
      assert.ok(!String(error).includes('PRIVATE_FIXTURE_VALUE')); assert.ok(!String(error).includes(db)); return true;
    });
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('SQLite operational categories do not expose underlying diagnostics', async () => {
  const { classifySqliteFailure } = await import('../persistence/sqliteCli.js');
  for (const [error, reason] of [
    [{ code: 'ENOENT' }, 'SQLITE_EXECUTABLE_MISSING'],
    [{ code: 'EACCES' }, 'SQLITE_ACCESS_DENIED'],
    [{ stderr: 'database is locked PRIVATE' }, 'SQLITE_BUSY'],
    [{ stderr: 'attempt to write a readonly database PRIVATE' }, 'SQLITE_READ_ONLY'],
    [{ stderr: 'no such table: PRIVATE' }, 'SQLITE_SCHEMA_MISMATCH'],
    [{ stderr: 'unable to open database PRIVATE' }, 'SQLITE_OPEN_FAILED'],
    [{ code: 'ETIMEDOUT' }, 'SQLITE_OPERATION_TIMEOUT'],
  ] as const) assert.equal(classifySqliteFailure(error), reason);
});

async function sqliteNativeFlow(failAt?: 'profile' | 'anchors' | 'completion') {
  const dir = mkdtempSync(join(tmpdir(), 'auth-native-callback-'));
  const db = join(dir, 'auth.sqlite');
  const storage = new SqliteStorageAdapter(db);
  const app = await createAuthApp({ storage, configStore: { getConfig: async () => config },
    sessionSecret: 'sqlite-native-fixture', cookieName: 'auth_sid',
    resolveLifeProfile: async ({ email, displayName }) => ({lifeUserId: `life:${email}`, supabaseUserId: null, displayName, source: 'local_only'}),
    resolveVvaultOwnerId: async () => null,
    providers: { github: { provider: 'github', label: 'GitHub', isConfigured: () => true,
      buildAuthorizationUrl: ({ state }) => `https://github.example.test/auth?state=${state}`,
      exchangeCodeForProfile: async () => ({ providerUserId: 'native-fixture', email: 'native@example.test', displayName: "O'Fixture", raw: { bio: "quoted ' profile" } }),
    } },
  });
  const srv = app.listen(0, '127.0.0.1');
  await new Promise<void>((resolve, reject) => { srv.once('listening', resolve); srv.once('error', reject); });
  const address = srv.address(); assert.ok(address && typeof address !== 'string');
  const base = `http://127.0.0.1:${address.port}`;
  const verifier = 'v'.repeat(43), state = 's'.repeat(43), redirect = 'http://127.0.0.1:54321/callback';
  try {
    for (let attempt = 0; attempt < (failAt ? 1 : 2); attempt++) {
      const authorize = await get(`${base}/oauth/authorize?${new URLSearchParams({app:'fixture', client_id:'fixture-native', response_type:'code', redirect_uri:redirect, state, code_challenge_method:'S256', code_challenge:createHash('sha256').update(verifier).digest('base64url')})}`);
      const login = new URL(authorize.headers.get('location')!);
      const begin = await get(`${base}/api/auth/github?${new URLSearchParams({authorization_request:login.searchParams.get('authorization_request')!, authorization_return:login.searchParams.get('authorization_return')!})}`);
      const providerState = new URL(begin.headers.get('location')!).searchParams.get('state');
      // Real SQLite failures, exclusively in disposable databases, not thrown mocks.
      if (failAt === 'profile') execSql(db, 'DROP TABLE provider_accounts;');
      if (failAt === 'anchors') execSql(db, 'ALTER TABLE users DROP COLUMN life_user_id;');
      const callbackUrl = `${base}/api/auth/github/callback?state=${providerState}&code=fixture`;
      const callback = await get(callbackUrl);
      assert.equal(callback.status, 302);
      let location = new URL(callback.headers.get('location')!);
      if (failAt !== 'profile' && failAt !== 'anchors') {
        const cookie = (callback.headers as any).getSetCookie().map((v:string) => v.split(';')[0]).join('; ');
        if (failAt === 'completion') execSql(db, 'DROP TABLE users;');
        const completed = await fetch(`${base}${location.pathname}${location.search}`, {redirect:'manual', headers:{cookie}});
        assert.equal(completed.status, 302);
        location = new URL(completed.headers.get('location')!);
      }
      assert.equal(location.origin + location.pathname, redirect);
      assert.equal(location.searchParams.get('state'), state);
      if (failAt) {
        assert.equal(location.searchParams.get('error'), 'temporarily_unavailable');
        assert.equal(location.searchParams.has('code'), false);
        assert.ok(!location.href.includes('sqlite'));
      } else {
        const code = location.searchParams.get('code'); assert.ok(code);
        const body = {grant_type:'authorization_code', client_id:'fixture-native', redirect_uri:redirect, code_verifier:verifier, code};
        const exchange = () => fetch(`${base}/oauth/token`, {method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});
        const tokenResponse = await exchange(); assert.equal(tokenResponse.status,200);
        const tokens = await tokenResponse.json() as {access_token?:string;refresh_token?:string}; assert.ok(tokens.access_token); assert.ok(tokens.refresh_token);
        assert.equal((await exchange()).status,400);
        assert.deepEqual(querySql(db,'SELECT count(*) AS n FROM users;'),[{n:1}]);
        assert.deepEqual(querySql(db,'SELECT count(*) AS n FROM provider_accounts;'),[{n:1}]);
      }
      assert.equal((await get(callbackUrl)).status,400);
    }
  } finally { await new Promise<void>(resolve => srv.close(() => resolve())); rmSync(dir,{recursive:true,force:true}); }
}
test('real SQLite GitHub new/returning identity completes native code exchange without duplicates', () => sqliteNativeFlow());
for (const stage of ['profile','anchors','completion'] as const) {
  test(`real SQLite ${stage} failure returns native error and never a code`, () => sqliteNativeFlow(stage));
}
