import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { SignJWT } from 'jose';
import ts from 'typescript';

const data = code => 'data:text/javascript;base64,' + Buffer.from(code).toString('base64');
const compile = path => ts.transpileModule(readFileSync(new URL(path, import.meta.url), 'utf8'), {
  compilerOptions: { module: ts.ModuleKind.ES2022, target: ts.ScriptTarget.ES2022 },
}).outputText;
const bindingUrl = data(compile('../auth/nativeClientBinding.ts'));
const { deriveNativeClientBinding, registeredNativeClientBinding } = await import(bindingUrl);
const { createAccessToken, verifyAccessToken, createRefreshToken, verifyRefreshToken } = await import(data(
  compile('../auth/jwtTokens.ts').replace("from 'jose'", `from '${import.meta.resolve('jose')}'`)
    .replace("from './canonicalOwner.js'", `from '${data(compile('../auth/canonicalOwner.ts'))}'`)
    .replace("from './nativeClientBinding.js'", `from '${bindingUrl}'`),
));
const config = { accessSecret: 'synthetic-access', refreshSecret: 'synthetic-refresh', refreshTokenHashSecret: 'synthetic-hash', issuer: 'fixture-auth', audience: 'fixture-native', accessTtlSeconds: 60, refreshTtlSeconds: 120 };
const app = { app: { id: 'grid' }, publicClients: [{ clientId: 'grid-windows' }] };
const binding = { clientId: 'grid-windows', applicationId: 'grid' };
const user = { id: 'internal', sub: 'life-subject', uid: 'local-anchor', email: 'synthetic@example.test', name: 'Fixture', auth_provider: 'google', nativeClient: binding };

test('only registered unambiguous clients derive the configured application; no Chatty fallback', () => {
  assert.deepEqual(deriveNativeClientBinding(app, 'grid-windows'), binding);
  assert.equal(deriveNativeClientBinding(app, 'other'), null);
  assert.equal(deriveNativeClientBinding({ ...app, publicClients: [...app.publicClients, ...app.publicClients] }, 'grid-windows'), null);
  assert.equal(registeredNativeClientBinding(app, { ...binding, applicationId: 'chatty' }), null);
  assert.equal(registeredNativeClientBinding({ ...app, publicClients: [] }, binding), null);
});

test('access and refresh preserve native client independently of LIFE subject and legacy RP', async () => {
  const access = await createAccessToken(user, 'session', config);
  const verified = await verifyAccessToken(access.token, config);
  assert.deepEqual(verified.session.nativeClient, binding);
  assert.equal(verified.session.sub, 'life-subject');
  assert.equal(verified.session.relyingPartyId, undefined);
  const refresh = await createRefreshToken(user.id, 'session', config, binding.clientId, undefined, binding);
  const current = await verifyRefreshToken(refresh.token, config);
  assert.deepEqual(current.nativeClient, binding);
  assert.equal(current.clientId, binding.clientId);
  const rotated = await createRefreshToken(current.userId, current.sessionId, config, current.clientId, undefined, current.nativeClient);
  assert.deepEqual((await verifyRefreshToken(rotated.token, config)).nativeClient, binding);
});

test('legacy access and client-only refresh do not acquire a resource-authorizing binding', async () => {
  assert.equal((await verifyAccessToken((await createAccessToken({ ...user, nativeClient: undefined }, 'session', config, 'chatty')).token, config)).session.nativeClient, undefined);
  assert.equal((await verifyRefreshToken((await createRefreshToken(user.id, 'session', config, binding.clientId)).token, config)).nativeClient, undefined);
});

test('malformed or mismatched bindings fail closed including validly signed refresh claims', async () => {
  await assert.rejects(createRefreshToken(user.id, 'session', config, 'other-client', undefined, binding), /INVALID_NATIVE_CLIENT_BINDING/);
  await assert.rejects(createAccessToken({ ...user, nativeClient: { ...binding, applicationId: ' grid' } }, 'session', config), /INVALID_NATIVE_CLIENT_BINDING/);
  const token = await new SignJWT({ token_use: 'refresh', sid: 'session', client_id: 'other-client', native_client: binding })
    .setProtectedHeader({ alg: 'HS256' }).setIssuer(config.issuer).setAudience(config.audience)
    .setSubject(user.id).setJti('fixture').setExpirationTime('1m').sign(new TextEncoder().encode(config.refreshSecret));
  assert.equal(await verifyRefreshToken(token, config), null);
});

test('tampering with native client claims fails signature validation', async () => {
  const issued = await createAccessToken(user, 'session', config);
  const parts = issued.token.split('.');
  const payload = JSON.parse(Buffer.from(parts[1], 'base64url'));
  payload.native_client.applicationId = 'other';
  parts[1] = Buffer.from(JSON.stringify(payload)).toString('base64url');
  assert.equal(await verifyAccessToken(parts.join('.'), config), null);
});
