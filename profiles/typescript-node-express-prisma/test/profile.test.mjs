import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { execFileSync, spawn } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';

const root = path.resolve(new URL('..', import.meta.url).pathname);
const temporary = await mkdtemp(path.join(os.tmpdir(), 'product-auth-profile-'));
const database = path.join(temporary, 'auth.db');
const freePort = () => new Promise((resolve, reject) => { const server = net.createServer(); server.on('error', reject); server.listen(0, '127.0.0.1', () => { const { port } = server.address(); server.close(() => resolve(port)); }); });
const port = await freePort(), issuer = `http://127.0.0.1:${port}`;
const env = { ...process.env, DATABASE_URL: `file:${database}`, AUTH_ISSUER: issuer, AUTH_SIGNING_SECRET: 'profile-test-only-32-byte-secret!', AUTH_CLIENTS_JSON: JSON.stringify({ fixture: { redirectUris: ['http://127.0.0.1:45678/callback'], scopes: ['openid', 'mcp.read'] } }), PORT: String(port) };
execFileSync(process.execPath, ['scripts/prepare-database.mjs'], { cwd: root, env });
execFileSync(process.execPath, ['node_modules/prisma/build/index.js', 'migrate', 'deploy'], { cwd: root, env, stdio: 'ignore' });
const child = spawn(process.execPath, ['dist/index.js'], { cwd: root, env, stdio: ['ignore', 'pipe', 'pipe'] });
let stderr = ''; child.stderr.on('data', chunk => { stderr += chunk; });
await new Promise((resolve, reject) => { const deadline = Date.now() + 5000; const poll = async () => { try { if ((await fetch(`${issuer}/ready`)).ok) return resolve(); } catch {} if (child.exitCode !== null) return reject(new Error(`runtime exited ${child.exitCode}: ${stderr}`)); if (Date.now() > deadline) return reject(new Error('runtime readiness timeout')); setTimeout(poll, 25); }; poll(); });

test.after(async () => { child.kill('SIGTERM'); await new Promise(resolve => child.once('exit', resolve)); await rm(temporary, { recursive: true, force: true }); });

test('credentials, secure session, OAuth PKCE, refresh replay, revocation and MCP challenge operate', async () => {
  const metadata = await fetch(`${issuer}/.well-known/oauth-authorization-server`).then(response => response.json()); assert.deepEqual(metadata.code_challenge_methods_supported, ['S256']);
  const protectedMetadata = await fetch(`${issuer}/.well-known/oauth-protected-resource`).then(response => response.json()); assert.equal(protectedMetadata.resource, issuer);
  const unauthenticatedMcp = await fetch(`${issuer}/mcp`, { method: 'POST' }); assert.equal(unauthenticatedMcp.status, 401); assert.match(unauthenticatedMcp.headers.get('www-authenticate') || '', /resource_metadata/);

  const registration = await fetch(`${issuer}/api/auth/register`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email: 'person@example.invalid', password: 'correct horse battery staple' }) });
  assert.equal(registration.status, 201); const setCookie = registration.headers.get('set-cookie') || ''; assert.match(setCookie, /HttpOnly/); assert.match(setCookie, /Secure/); assert.match(setCookie, /SameSite=Lax/); const sessionCookie = setCookie.split(';')[0];
  assert.equal((await fetch(`${issuer}/api/me`, { headers: { cookie: sessionCookie } })).status, 200);
  assert.equal((await fetch(`${issuer}/api/auth/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email: 'person@example.invalid', password: 'wrong password' }) })).status, 401);

  const verifier = randomBytes(32).toString('base64url'), challenge = createHash('sha256').update(verifier).digest('base64url');
  const authorize = new URL(`${issuer}/oauth/authorize`); authorize.search = new URLSearchParams({ response_type: 'code', client_id: 'fixture', redirect_uri: 'http://127.0.0.1:45678/callback', scope: 'openid mcp.read', state: 'opaque-state', nonce: 'opaque-nonce', code_challenge: challenge, code_challenge_method: 'S256' });
  const authorization = await fetch(authorize, { headers: { cookie: sessionCookie }, redirect: 'manual' }); assert.equal(authorization.status, 303); const callback = new URL(authorization.headers.get('location')); assert.equal(callback.searchParams.get('state'), 'opaque-state');
  const token = await fetch(`${issuer}/oauth/token`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ grant_type: 'authorization_code', code: callback.searchParams.get('code'), redirect_uri: 'http://127.0.0.1:45678/callback', client_id: 'fixture', code_verifier: verifier }) }); assert.equal(token.status, 200); const issued = await token.json(); assert.ok(issued.access_token); assert.ok(issued.refresh_token);
  const refreshBody = new URLSearchParams({ grant_type: 'refresh_token', refresh_token: issued.refresh_token, client_id: 'fixture', scope: 'openid mcp.read' }); const rotated = await fetch(`${issuer}/oauth/token`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: refreshBody }); assert.equal(rotated.status, 200);
  const replay = await fetch(`${issuer}/oauth/token`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: refreshBody }); assert.equal(replay.status, 400);
  const rotatedBody = await rotated.json(); const revokedFamily = await fetch(`${issuer}/oauth/token`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: rotatedBody.refresh_token, client_id: 'fixture' }) }); assert.equal(revokedFamily.status, 400);
  assert.equal((await fetch(`${issuer}/api/auth/logout`, { method: 'POST', headers: { cookie: sessionCookie } })).status, 204);
});
