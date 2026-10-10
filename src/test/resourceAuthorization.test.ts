import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, X509Certificate } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import https from 'node:https';
import express from 'express';
import { decodeJwt, SignJWT } from 'jose';
import { ResourceAuthorizationService, resourceDependency, RESOURCE_CONTRACT, RESOURCE_TOKEN_TYPE, type ResourceAdmission, type ResourcePolicy, type ResourceSession } from '../auth/resourceAuthorization.js';
import type { ResourceGrantRecord, ResourceGrantStore } from '../auth/resourceGrantStore.js';
import { mountResourceAuthorizationHost, resourceWorkloadAudience } from '../auth/resourceAuthorizationHost.js';

const keys = generateKeyPairSync('ed25519');
const pem = keys.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
const audience = 'https://resource.example.test';
const owner = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const session: ResourceSession = { subject: 'life:test-account', sessionId: 'test-session', accessJti: 'test-access', expiresAt: 2000, clientId: 'fixture-native', applicationId: 'fixture-app' };
function fixture() {
  let now = 1000;
  let active = true;
  let unavailable = false;
  let admissionProbe = () => {};
  const records = new Map<string, ResourceGrantRecord & { revoked: boolean }>();
  const store: ResourceGrantStore = {
    async initialize() {},
    async put(record) { records.set(record.id, { ...record, revoked: false }); },
    async get(id) { return records.get(id) || null; },
    async revoke(id) { const record = records.get(id); if (record) record.revoked = true; },
  };
  const policy: ResourcePolicy = { enabled: true, contract: RESOURCE_CONTRACT, wireContract: 'synthetic-fixture/v1', clientId: session.clientId, applicationId: session.applicationId, audience, capabilities: ['fixture.workspace:read', 'fixture.unrelated:read'] };
  let admission: ResourceAdmission = { admitted: true, subject: session.subject, sessionId: session.sessionId,
    clientId: session.clientId, applicationId: session.applicationId, audience, ownerId: owner,
    capabilities: ['fixture.workspace:read'], expiresAt: 1900, policyVersion: 'fixture-policy/1' };
  const service = new ResourceAuthorizationService({ issuer: 'fixture-auth', keyId: 'fixture-key', privateKeyPem: pem, store,
    now: () => now, resolvePolicy: async () => policy,
    sessionActive: async () => { if (unavailable) throw new Error('secret-store-error-not-for-output'); return active; },
    resolveAdmission: async () => { admissionProbe(); return admission; },
  });
  const request = { audience, capabilities: ['fixture.workspace:read'] };
  return { service, policy, records, request, setNow: (v: number) => now = v,
    setActive: (v: boolean) => active = v, setUnavailable: () => unavailable = true,
    setAdmission: (v: ResourceAdmission) => admission = v, admission: () => admission,
    onAdmission: (probe: () => void) => admissionProbe = probe };
}

test('only explicitly requested narrow capability is issued; AUTH subject, owner, native client and app remain distinct', async () => {
  const f = fixture();
  const issued = await f.service.issue(session, f.request);
  const claims = decodeJwt(issued.token);
  assert.equal(claims.sub, session.subject);
  assert.equal(claims.owner_id, owner);
  assert.equal(claims.client_id, session.clientId);
  assert.equal(claims.application_id, session.applicationId);
  assert.equal(claims.exp, 1060);
  assert.deepEqual(claims.capabilities, ['fixture.workspace:read']);
  assert.equal((await f.service.status(issued.token, audience)).active, true);
  assert.equal((await f.service.status(issued.token, audience)).active, true, 'read replay is explicitly reusable');
  assert.ok(!JSON.stringify([...f.records.values()]).includes(issued.token));
});

test('no owner or pending enrollment cannot issue, despite authenticated session', async () => {
  for (const disposition of ['ENROLLMENT_REQUIRED', 'ACCOUNT_LINK_REQUIRED', 'REAUTH_REQUIRED'] as const) {
    const f = fixture(); f.setAdmission({ admitted: false, disposition });
    await assert.rejects(f.service.issue(session, f.request), { message: disposition });
    assert.equal(f.records.size, 0);
  }
});

test('request owner/subject/RP/session selectors and scope escalation fail closed', async () => {
  const f = fixture();
  for (const selector of ['owner_id', 'subject', 'sid', 'client_id', 'application_id', 'issuer']) {
    await assert.rejects(f.service.issue(session, { ...f.request, [selector]: 'attacker' }), /UNTRUSTED_SELECTOR/);
  }
  await assert.rejects(f.service.issue(session, { ...f.request, capabilities: ['fixture.unrelated:read'] }), /INSUFFICIENT_CAPABILITY/);
  await assert.rejects(f.service.issue(session, { ...f.request, capabilities: [] }), /INVALID_CAPABILITIES/);
  await assert.rejects(f.service.issue(session, { ...f.request, audience: 'http://resource.example.test' }), /INVALID_RESOURCE/);
});

test('admission binding mismatches cannot establish authority', async () => {
  for (const field of ['subject', 'sessionId', 'clientId', 'applicationId', 'audience', 'ownerId']) {
    const f = fixture(); f.setAdmission({ ...f.admission(), [field]: 'wrong' } as ResourceAdmission);
    await assert.rejects(f.service.issue(session, f.request), /ADMISSION_BINDING_INVALID/);
  }
});

test('malformed external admission/policy evidence cannot pass through TypeScript assertions', async () => {
  for (const patch of [{ admitted: 'false' }, { capabilities: 'fixture.workspace:read' }, { admitted: false, disposition: 'untrusted-secret' }]) {
    const f = fixture(); f.setAdmission({ ...f.admission(), ...patch } as unknown as ResourceAdmission);
    await assert.rejects(f.service.issue(session, f.request), /ADMISSION_EVIDENCE_INVALID/);
  }
  const f = fixture(); (f.policy as any).enabled = 'false';
  await assert.rejects(f.service.issue(session, f.request), /RESOURCE_NOT_ADMITTED/);
  f.policy.enabled = true; (f.policy as any).capabilities = 'fixture.workspace:read';
  await assert.rejects(f.service.issue(session, f.request), /RESOURCE_POLICY_INVALID/);
});

test('artifact expires at earliest source/admission/60 seconds and expiry fails', async () => {
  const f = fixture(); f.setAdmission({ ...f.admission(), expiresAt: 1025 } as ResourceAdmission);
  const issued = await f.service.issue({ ...session, expiresAt: 1020 }, f.request);
  assert.equal(issued.expires_at, 1020);
  f.setNow(1020);
  await assert.rejects(f.service.status(issued.token, audience), /RESOURCE_ASSERTION_INVALID/);
});

test('each read checks live session status; acknowledged revocation and outages deny', async () => {
  const f = fixture(); const issued = await f.service.issue(session, f.request);
  f.setActive(false);
  await assert.rejects(f.service.status(issued.token, audience), /REAUTH_REQUIRED/);
  f.setActive(true); f.setUnavailable();
  await assert.rejects(f.service.status(issued.token, audience), /secret-store-error/);
});

test('artifact expiring during online checks cannot return active after the deadline', async () => {
  const f = fixture(); const issued = await f.service.issue(session, f.request);
  f.onAdmission(() => f.setNow(issued.expires_at));
  await assert.rejects(f.service.status(issued.token, audience), /RESOURCE_GRANT_INACTIVE/);
});

test('current disabled registration, reduced capability or changed wire contract invalidates issued grant', async () => {
  for (const change of [(p: ResourcePolicy) => p.enabled = false, (p: ResourcePolicy) => p.capabilities = [], (p: ResourcePolicy) => p.wireContract = 'changed/v2']) {
    const f = fixture(); const issued = await f.service.issue(session, f.request); change(f.policy);
    await assert.rejects(f.service.status(issued.token, audience));
  }
});

test('current owner/enrollment/policy changes invalidate already issued artifacts', async () => {
  for (const change of [{ ownerId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' }, { policyVersion: 'changed' }, { expiresAt: 1010 }]) {
    const f = fixture(); const issued = await f.service.issue(session, f.request);
    f.setAdmission({ ...f.admission(), ...change } as ResourceAdmission);
    await assert.rejects(f.service.status(issued.token, audience), /RESOURCE_GRANT_STALE/);
  }
  const f = fixture(); const issued = await f.service.issue(session, f.request);
  f.setAdmission({ admitted: false, disposition: 'ENROLLMENT_REQUIRED' });
  await assert.rejects(f.service.status(issued.token, audience), /ENROLLMENT_REQUIRED/);
});

test('tampered/unsigned, wrong audience and even re-signed changed owner/scope/artifact fail', async () => {
  const f = fixture(); const issued = await f.service.issue(session, f.request);
  await assert.rejects(f.service.status(issued.token + 'x', audience));
  await assert.rejects(f.service.status(issued.token, 'https://other.example.test'));
  for (const patch of [{ owner_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb' }, { capabilities: ['fixture.unrelated:read'] }, { jti: 'unknown' }]) {
    const changed = await new SignJWT({ ...decodeJwt(issued.token), ...patch })
      .setProtectedHeader({ alg: 'EdDSA', kid: 'fixture-key', typ: RESOURCE_TOKEN_TYPE }).sign(keys.privateKey);
    await assert.rejects(f.service.status(changed, audience), /RESOURCE_GRANT_INACTIVE/);
  }
});

test('grant revoke checks account/session/client ownership and remains revoked', async () => {
  const f = fixture(); const issued = await f.service.issue(session, f.request);
  for (const field of ['subject', 'sessionId', 'clientId', 'applicationId']) {
    await assert.rejects(f.service.revoke({ ...session, [field]: 'wrong' }, issued.grant_id), /RESOURCE_GRANT_NOT_FOUND/);
  }
  await f.service.revoke(session, issued.grant_id);
  await assert.rejects(f.service.status(issued.token, audience), /RESOURCE_GRANT_INACTIVE/);
});

test('absent persistent grant or absent session after restart never becomes successful restoration', async () => {
  const f = fixture(); const issued = await f.service.issue(session, f.request);
  f.records.clear(); await assert.rejects(f.service.status(issued.token, audience), /RESOURCE_GRANT_INACTIVE/);
});

test('ordinary client or spoofed TLS-shaped object cannot become resource workload', () => {
  const spoof = { encrypted: true, authorized: true, getPeerCertificate: () => ({ fingerprint256: 'aa'.repeat(32) }) };
  assert.equal(resourceWorkloadAudience(spoof, [{ audience, fingerprint256: 'aa'.repeat(32) }]), null);
});

test('unresponsive dependency has a bounded explicit failure instead of continuing authorization', async () => {
  await assert.rejects(resourceDependency(() => new Promise(() => {}), 10), { code: 'RESOURCE_DEPENDENCY_TIMEOUT', status: 503 });
});

test('actual mutually authenticated TLS status accepts pinned workload, refuses wrong pin, and sanitizes outages', async () => {
  const directory = mkdtempSync('/private/tmp/auth-resource-tls-');
  let server: https.Server | undefined;
  try {
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', `${directory}/key.pem`,
      '-out', `${directory}/cert.pem`, '-days', '1', '-subj', '/CN=controlled-fixture',
      '-addext', 'subjectAltName=IP:127.0.0.1'], { stdio: 'ignore', timeout: 10000 });
    const key = readFileSync(`${directory}/key.pem`);
    const cert = readFileSync(`${directory}/cert.pem`);
    const pin = new X509Certificate(cert).fingerprint256;
    const f = fixture();
    const issued = await f.service.issue(session, f.request);
    const workloads = [{ audience, fingerprint256: pin }];
    const app = express(); app.use(express.json());
    mountResourceAuthorizationHost(app, { service: f.service, workloads, readSession: async () => session });
    server = https.createServer({ key, cert, ca: cert, requestCert: true, rejectUnauthorized: true }, app);
    server.listen(0, '127.0.0.1');
    await new Promise<void>((resolve, reject) => { server!.once('listening', resolve); server!.once('error', reject); });
    const port = (server.address() as { port: number }).port;
    async function status(withCertificate = true) {
      return new Promise<{ status: number; body: any }>((resolve, reject) => {
        const req = https.request({ hostname: '127.0.0.1', port, path: '/api/auth/resource-status', method: 'POST',
          ...(withCertificate ? { cert, key } : {}), ca: cert, agent: false, headers: { 'content-type': 'application/json' } }, res => {
          let data = ''; res.on('data', part => data += part); res.on('end', () => resolve({ status: res.statusCode!, body: JSON.parse(data) }));
        });
        req.on('error', reject); req.end(JSON.stringify({ assertion: issued.token }));
      });
    }
    assert.equal((await status()).body.active, true);
    await assert.rejects(status(false));
    workloads.push({ audience: 'https://wrong-resource.example.test', fingerprint256: pin });
    assert.equal((await status()).status, 401, 'ambiguous certificate registration is rejected');
    workloads.pop();
    workloads[0]!.fingerprint256 = 'bb'.repeat(32);
    assert.equal((await status()).status, 401);
    workloads[0]!.fingerprint256 = pin;
    f.setUnavailable();
    const unavailable = await status();
    assert.equal(unavailable.status, 503);
    assert.equal(unavailable.body.active, false);
    assert.ok(!JSON.stringify(unavailable).includes('secret-store-error'));
    assert.ok(!JSON.stringify(unavailable).includes(issued.token));
  } finally {
    if (server?.listening) await new Promise<void>(resolve => server!.close(() => resolve()));
    rmSync(directory, { recursive: true, force: true });
  }
});
