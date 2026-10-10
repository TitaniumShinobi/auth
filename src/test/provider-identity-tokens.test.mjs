import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { SignJWT } from 'jose';
import ts from 'typescript';

const compile = path => ts.transpileModule(readFileSync(new URL(path, import.meta.url), 'utf8'), {
  compilerOptions: { module: ts.ModuleKind.ES2022, target: ts.ScriptTarget.ES2022 },
}).outputText;
const dataUrl = code => 'data:text/javascript;base64,' + Buffer.from(code).toString('base64');
const ownerUrl = dataUrl(compile('../auth/canonicalOwner.ts'));
const tokenCode = compile('../auth/jwtTokens.ts')
  .replace("from 'jose'", `from '${import.meta.resolve('jose')}'`)
  .replace("from './canonicalOwner.js'", `from '${ownerUrl}'`)
  .replace("from './nativeClientBinding.js'", `from '${dataUrl(compile('../auth/nativeClientBinding.ts'))}'`);
const { createAccessToken, verifyAccessToken, createRefreshToken, verifyRefreshToken } = await import(dataUrl(tokenCode));
const config = { accessSecret: 'synthetic-access-fixture-secret', refreshSecret: 'synthetic-refresh-fixture-secret', refreshTokenHashSecret: 'synthetic-hash-secret', issuer: 'fixture-auth', audience: 'fixture-client', accessTtlSeconds: 60, refreshTtlSeconds: 120 };
const identity = { provider: 'google', subject: 'synthetic-provider-subject', issuer: 'https://accounts.google.com' };
const user = { id: 'life-fixture', sub: 'life-fixture', uid: 'fixture-account', email: 'fixture@example.test', name: 'Fixture', auth_provider: 'google' };

test('signed access and refresh preserve provider proof separately from LIFE subject', async () => {
  const access = await createAccessToken({ ...user, providerIdentity: identity }, 'fixture-session', config);
  const verified = await verifyAccessToken(access.token, config);
  assert.deepEqual(verified.session.providerIdentity, identity);
  assert.equal(verified.session.sub, user.sub);
  const refresh = await createRefreshToken(user.id, 'fixture-session', config, 'fixture-client', identity);
  const verifiedRefresh = await verifyRefreshToken(refresh.token, config);
  assert.deepEqual(verifiedRefresh.providerIdentity, identity);
  assert.equal(verifiedRefresh.userId, user.id);
});

test('legacy access and refresh do not invent provider proof', async () => {
  assert.equal((await verifyAccessToken((await createAccessToken(user, 'fixture-session', config)).token, config)).session.providerIdentity, undefined);
  assert.equal((await verifyRefreshToken((await createRefreshToken(user.id, 'fixture-session', config)).token, config)).providerIdentity, undefined);
});

test('tampering with signed provider identity rejects access and refresh tokens', async () => {
  for (const [token, verify] of [
    [(await createAccessToken({ ...user, providerIdentity: identity }, 'fixture-session', config)).token, verifyAccessToken],
    [(await createRefreshToken(user.id, 'fixture-session', config, undefined, identity)).token, verifyRefreshToken],
  ]) {
    const parts = token.split('.');
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url'));
    payload.provider_identity.subject = 'different-subject';
    parts[1] = Buffer.from(JSON.stringify(payload)).toString('base64url');
    assert.equal(await verify(parts.join('.'), config), null);
  }
});

test('malformed proof is rejected at issuance and even in validly signed refresh claims', async () => {
  const malformed = { ...identity, issuer: 'https://untrusted.example.test' };
  await assert.rejects(createAccessToken({ ...user, providerIdentity: malformed }, 'fixture-session', config), /INVALID_PROVIDER_IDENTITY/);
  await assert.rejects(createRefreshToken(user.id, 'fixture-session', config, undefined, malformed), /INVALID_PROVIDER_IDENTITY/);
  const token = await new SignJWT({ token_use: 'refresh', sid: 'fixture-session', provider_identity: malformed })
    .setProtectedHeader({ alg: 'HS256' }).setIssuer(config.issuer).setAudience(config.audience)
    .setSubject(user.id).setJti('fixture-jti').setExpirationTime('1m').sign(new TextEncoder().encode(config.refreshSecret));
  assert.equal(await verifyRefreshToken(token, config), null);
});
