import { createHash, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import express from 'express';
import { PrismaClient } from '@prisma/client';
import { SignJWT, jwtVerify } from 'jose';

const required = (name: string) => { const value = process.env[name]?.trim(); if (!value) throw new Error(`MISSING_${name}`); return value; };
const origin = new URL(required('AUTH_ISSUER')).origin;
const secret = new TextEncoder().encode(required('AUTH_SIGNING_SECRET'));
if (secret.length < 32) throw new Error('AUTH_SIGNING_SECRET_TOO_SHORT');
const port = Number(process.env.PORT || 1111);
const prisma = new PrismaClient();
const app = express();
app.disable('x-powered-by'); app.use(express.json({ limit: '32kb' })); app.use(express.urlencoded({ extended: false, limit: '32kb' }));
const digest = (value: string) => createHash('sha256').update(value).digest('hex');
const opaque = () => randomBytes(32).toString('base64url');
const cookieName = process.env.AUTH_COOKIE_NAME || '__Host-auth_session';
const cookie = (value: string, maxAge: number) => `${cookieName}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
const cookies = (header?: string) => Object.fromEntries((header || '').split(';').map(item => item.trim().split('=')).filter(pair => pair.length === 2));
const clients = () => JSON.parse(process.env.AUTH_CLIENTS_JSON || '{}') as Record<string, { redirectUris: string[]; scopes: string[] }>;
const providers = () => JSON.parse(process.env.AUTH_PROVIDERS_JSON || '{}') as Record<string, { authorizationEndpoint: string; tokenEndpoint: string; userinfoEndpoint: string; clientId: string; clientSecret: string; scopes: string[] }>;
const passwordHash = (password: string, salt = randomBytes(16).toString('hex')) => `${salt}:${scryptSync(password, salt, 32).toString('hex')}`;
const passwordValid = (password: string, stored: string) => { const [salt, expected] = stored.split(':'); if (!salt || !expected) return false; const actual = scryptSync(password, salt, 32); return actual.length === expected.length / 2 && timingSafeEqual(actual, Buffer.from(expected, 'hex')); };
const accessToken = (sub: string, audience: string, scope: string, sessionId: string) => new SignJWT({ scope, sid: sessionId }).setProtectedHeader({ alg: 'HS256' }).setIssuer(origin).setAudience(audience).setSubject(sub).setIssuedAt().setExpirationTime('10m').setJti(opaque()).sign(secret);
async function session(req: express.Request) {
  const id = cookies(req.headers.cookie)[cookieName]; if (!id) return null;
  return prisma.session.findFirst({ where: { id, revokedAt: null, expiresAt: { gt: new Date() } }, include: { user: true } });
}
async function createSession(userId: string) { return prisma.session.create({ data: { userId, expiresAt: new Date(Date.now() + 30 * 86400000) } }); }
const safeReturn = (value: unknown) => { try { const url = new URL(String(value || '/'), origin); return url.origin === origin ? url.href : origin; } catch { return origin; } };

app.get('/health', (_req, res) => res.json({ ok: true }));
app.get('/ready', async (_req, res) => { try { await prisma.$queryRaw`SELECT 1`; res.json({ ready: true }); } catch { res.status(503).json({ ready: false }); } });
app.get('/.well-known/oauth-authorization-server', (_req, res) => res.json({ issuer: origin, authorization_endpoint: `${origin}/oauth/authorize`, token_endpoint: `${origin}/oauth/token`, revocation_endpoint: `${origin}/oauth/revoke`, code_challenge_methods_supported: ['S256'], response_types_supported: ['code'], grant_types_supported: ['authorization_code', 'refresh_token'] }));
app.get('/.well-known/oauth-protected-resource', (_req, res) => res.json({ resource: origin, authorization_servers: [origin], bearer_methods_supported: ['header'], scopes_supported: [...new Set(Object.values(clients()).flatMap(client => client.scopes))] }));

app.post('/api/auth/register', async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase(), password = String(req.body.password || '');
  if (!/^\S+@\S+\.\S+$/.test(email) || password.length < 12) return res.status(400).json({ error: 'invalid_registration' });
  try { const user = await prisma.user.create({ data: { email, name: String(req.body.name || '').trim() || null, passwordHash: passwordHash(password) } }); const s = await createSession(user.id); res.setHeader('Set-Cookie', cookie(s.id, 2592000)).status(201).json({ id: user.id, email: user.email }); }
  catch { res.status(409).json({ error: 'identity_exists' }); }
});
app.post('/api/auth/login', async (req, res) => {
  const user = await prisma.user.findUnique({ where: { email: String(req.body.email || '').trim().toLowerCase() } });
  if (!user?.passwordHash || !passwordValid(String(req.body.password || ''), user.passwordHash)) return res.status(401).json({ error: 'invalid_credentials' });
  const s = await createSession(user.id); res.setHeader('Set-Cookie', cookie(s.id, 2592000)).json({ authenticated: true });
});
app.get('/api/me', async (req, res) => { const s = await session(req); if (!s) return res.status(401).json({ error: 'unauthenticated' }); res.json({ id: s.user.id, sub: s.user.id, email: s.user.email, name: s.user.name }); });
app.post('/api/auth/logout', async (req, res) => { const s = await session(req); if (s) await prisma.session.update({ where: { id: s.id }, data: { revokedAt: new Date() } }); res.setHeader('Set-Cookie', cookie('', 0)).status(204).end(); });

app.post('/api/auth/magic/request', async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase(); if (!/^\S+@\S+\.\S+$/.test(email)) return res.status(202).end();
  const token = opaque(); await prisma.magicChallenge.create({ data: { email, digest: digest(token), expiresAt: new Date(Date.now() + 15 * 60000) } });
  const delivery = required('AUTH_MAGIC_DELIVERY_URL'); const response = await fetch(delivery, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${required('AUTH_MAGIC_DELIVERY_TOKEN')}` }, body: JSON.stringify({ email, verificationUrl: `${origin}/api/auth/magic/verify?token=${encodeURIComponent(token)}` }) });
  if (!response.ok) return res.status(503).json({ error: 'delivery_unavailable' }); res.status(202).end();
});
app.get('/api/auth/magic/verify', async (req, res) => {
  const value = String(req.query.token || ''), challenge = await prisma.magicChallenge.findUnique({ where: { digest: digest(value) } });
  if (!challenge || challenge.usedAt || challenge.expiresAt <= new Date()) return res.status(400).json({ error: 'invalid_or_expired_magic_link' });
  const updated = await prisma.magicChallenge.updateMany({ where: { id: challenge.id, usedAt: null }, data: { usedAt: new Date() } }); if (updated.count !== 1) return res.status(409).json({ error: 'magic_link_replayed' });
  const user = await prisma.user.upsert({ where: { email: challenge.email }, update: {}, create: { email: challenge.email } }); const s = await createSession(user.id); res.setHeader('Set-Cookie', cookie(s.id, 2592000)).redirect(303, origin);
});

app.get('/oauth/authorize', async (req, res) => {
  const clientId = String(req.query.client_id || ''), redirectUri = String(req.query.redirect_uri || ''), state = String(req.query.state || ''), challenge = String(req.query.code_challenge || ''), method = String(req.query.code_challenge_method || ''), scope = String(req.query.scope || ''), nonce = String(req.query.nonce || '');
  const client = clients()[clientId], s = await session(req); if (!client || !client.redirectUris.includes(redirectUri) || method !== 'S256' || !challenge || !state) return res.status(400).json({ error: 'invalid_request' });
  if (!scope.split(' ').every(value => client.scopes.includes(value))) return res.status(400).json({ error: 'invalid_scope' });
  if (!s) return res.redirect(303, `${origin}/login?return_to=${encodeURIComponent(req.originalUrl)}`);
  const code = opaque(); await prisma.authorizationCode.create({ data: { digest: digest(code), userId: s.userId, clientId, redirectUri, codeChallenge: challenge, nonce: nonce || null, scope, expiresAt: new Date(Date.now() + 5 * 60000) } }); const callback = new URL(redirectUri); callback.searchParams.set('code', code); callback.searchParams.set('state', state); res.redirect(303, callback.href);
});
app.post('/oauth/token', async (req, res) => {
  const grant = String(req.body.grant_type || '');
  if (grant === 'authorization_code') {
    const code = await prisma.authorizationCode.findUnique({ where: { digest: digest(String(req.body.code || '')) }, include: { user: true } });
    const verifier = String(req.body.code_verifier || ''), expected = createHash('sha256').update(verifier).digest('base64url');
    if (!code || code.usedAt || code.expiresAt <= new Date() || code.clientId !== req.body.client_id || code.redirectUri !== req.body.redirect_uri || expected !== code.codeChallenge) return res.status(400).json({ error: 'invalid_grant' });
    if ((await prisma.authorizationCode.updateMany({ where: { id: code.id, usedAt: null }, data: { usedAt: new Date() } })).count !== 1) return res.status(400).json({ error: 'invalid_grant' });
    const s = await createSession(code.userId), refresh = opaque(); await prisma.refreshToken.create({ data: { sessionId: s.id, digest: digest(refresh), generation: 0, expiresAt: s.expiresAt } });
    return res.json({ access_token: await accessToken(code.userId, code.clientId, code.scope, s.id), token_type: 'Bearer', expires_in: 600, refresh_token: refresh, scope: code.scope });
  }
  if (grant === 'refresh_token') {
    const presented = digest(String(req.body.refresh_token || '')), token = await prisma.refreshToken.findUnique({ where: { digest: presented }, include: { session: true } });
    if (!token || token.revokedAt || token.expiresAt <= new Date() || token.session.revokedAt) return res.status(400).json({ error: 'invalid_grant' });
    if (token.usedAt) { await prisma.refreshToken.updateMany({ where: { sessionId: token.sessionId }, data: { revokedAt: new Date() } }); await prisma.session.update({ where: { id: token.sessionId }, data: { revokedAt: new Date() } }); return res.status(400).json({ error: 'invalid_grant' }); }
    const next = opaque(); const won = await prisma.refreshToken.updateMany({ where: { id: token.id, usedAt: null }, data: { usedAt: new Date() } }); if (won.count !== 1) return res.status(400).json({ error: 'invalid_grant' }); await prisma.refreshToken.create({ data: { sessionId: token.sessionId, digest: digest(next), generation: token.generation + 1, expiresAt: token.expiresAt } });
    return res.json({ access_token: await accessToken(token.session.userId, String(req.body.client_id || ''), String(req.body.scope || ''), token.sessionId), token_type: 'Bearer', expires_in: 600, refresh_token: next });
  }
  res.status(400).json({ error: 'unsupported_grant_type' });
});
app.post('/oauth/revoke', async (req, res) => { const token = await prisma.refreshToken.findUnique({ where: { digest: digest(String(req.body.token || '')) } }); if (token) { await prisma.refreshToken.updateMany({ where: { sessionId: token.sessionId }, data: { revokedAt: new Date() } }); await prisma.session.update({ where: { id: token.sessionId }, data: { revokedAt: new Date() } }); } res.status(200).end(); });

app.use('/mcp', async (req, res, next) => { const bearer = req.headers.authorization?.match(/^Bearer (.+)$/)?.[1]; if (!bearer) return res.status(401).setHeader('WWW-Authenticate', `Bearer resource_metadata="${origin}/.well-known/oauth-protected-resource"`).json({ error: 'invalid_token' }); try { const verified = await jwtVerify(bearer, secret, { issuer: origin, audience: origin }); res.locals.auth = { subject: verified.payload.sub, scope: String(verified.payload.scope || '').split(' ') }; next(); } catch { res.status(401).json({ error: 'invalid_token' }); } });
app.post('/mcp', (_req, res) => res.status(501).json({ error: 'product_mcp_transport_not_configured' }));

const server = app.listen(port, '127.0.0.1', () => console.log(`auth-ready:${port}`));
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => server.close(() => prisma.$disconnect().finally(() => process.exit(0))));
