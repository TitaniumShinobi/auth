import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createPublicKey, generateKeyPairSync, X509Certificate } from 'node:crypto';
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import https from 'node:https';
import express from 'express';
import { decodeJwt, decodeProtectedHeader } from 'jose';
import { loadResourceRuntime, createResourceStatusServer, readResourcePolicies } from '../auth/resourceRuntime.js';
import { ResourceAuthorizationService, type ResourceSession } from '../auth/resourceAuthorization.js';
import { mountResourceAuthorizationHost } from '../auth/resourceAuthorizationHost.js';

const audience = 'https://vvault.thewreck.org';
const session: ResourceSession = { subject: 'life:fixture-account', sessionId: 'fixture-session', accessJti: 'fixture-access',
  clientId: 'grid-windows', applicationId: 'grid', expiresAt: Math.floor(Date.now() / 1000) + 300 };
const request = { audience, capabilities: ['workspace:resolve'] };
const ownerId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
function fixture() {
  const path = mkdtempSync('/private/tmp/auth-resource-runtime-');
  const privateKeyPem = generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  const publicPem = createPublicKey(privateKeyPem).export({ type: 'spki', format: 'pem' }).toString();
  const keyId = createHash('sha256').update(publicPem).digest('hex');
  const policies = JSON.parse(readFileSync('config/resource-policies.json', 'utf8'));
  policies.policies[0].enabled = true;
  writeFileSync(`${path}/policies.json`, JSON.stringify(policies), { mode: 0o600 });
  writeFileSync(`${path}/signer.pem`, privateKeyPem, { mode: 0o600 });
  execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', `${path}/tls-key.pem`,
    '-out', `${path}/tls-cert.pem`, '-days', '1', '-subj', '/CN=controlled-fixture',
    '-addext', 'subjectAltName=IP:127.0.0.1'], { stdio: 'ignore', timeout: 10000 });
  const cert = readFileSync(`${path}/tls-cert.pem`);
  const env = {
    AUTH_RESOURCE_ENABLED: 'true', AUTH_RESOURCE_ISSUER: 'fixture-auth', AUTH_RESOURCE_POLICY_PATH: `${path}/policies.json`,
    AUTH_RESOURCE_SIGNING_KEY_PATH: `${path}/signer.pem`, AUTH_RESOURCE_KEY_ID: keyId,
    AUTH_RESOURCE_GRANT_STORE_PATH: `${path}/grants/state.sqlite`,
    AUTH_RESOURCE_MTLS_HOST: '127.0.0.1', AUTH_RESOURCE_MTLS_PORT: '44443',
    AUTH_RESOURCE_MTLS_SERVER_CERT_PATH: `${path}/tls-cert.pem`, AUTH_RESOURCE_MTLS_SERVER_KEY_PATH: `${path}/tls-key.pem`,
    AUTH_RESOURCE_MTLS_CLIENT_CA_PATH: `${path}/tls-cert.pem`,
    AUTH_RESOURCE_WORKLOADS_JSON: JSON.stringify([{ audience, fingerprint256: new X509Certificate(cert).fingerprint256.replace(/:/g, '') }]),
  };
  const admission = async () => ({ admitted: true as const, subject: session.subject, sessionId: session.sessionId,
    clientId: session.clientId, applicationId: session.applicationId, audience, ownerId,
    capabilities: request.capabilities, expiresAt: session.expiresAt, policyVersion: 'fixture-admission/v1' });
  return { path, env, publicPem, keyId, policies, admission, cleanup: () => rmSync(path, { recursive: true, force: true }) };
}

test('runtime is opt-in, configured GRID policy disabled, no missing setting causes a fallback', () => {
  assert.equal(loadResourceRuntime({}), undefined);
  assert.equal(loadResourceRuntime({ AUTH_RESOURCE_ENABLED: 'false' }), undefined);
  assert.throws(() => loadResourceRuntime({ AUTH_RESOURCE_ENABLED: 'yes' }), /RESOURCE_RUNTIME_CONFIGURATION_INVALID/);
  assert.throws(() => loadResourceRuntime({ AUTH_RESOURCE_ENABLED: 'true' }), /RESOURCE_RUNTIME_CONFIGURATION_INVALID/);
  const p = readResourcePolicies(`${process.cwd()}/config/resource-policies.json`)[0]!;
  assert.equal(p.enabled, false);
  assert.equal(p.wireContract, 'life.vvault.resource-workspace/v1');
  assert.deepEqual(p.capabilities, ['workspace:resolve']);
});

test('runtime derives the VVAULT-required kid, issues exact wire claims, and reloads policy on every check', async () => {
  const f = fixture();
  try {
    const runtime = loadResourceRuntime(f.env, f.admission)!;
    const service = new ResourceAuthorizationService({ ...runtime.authorization, sessionActive: async () => true });
    await service.initialize();
    const grant = await service.issue(session, request);
    const claims = decodeJwt(grant.token);
    assert.deepEqual(decodeProtectedHeader(grant.token), { alg: 'EdDSA', kid: f.keyId, typ: 'life-resource+jwt' });
    assert.equal(claims.wire_contract, 'life.vvault.resource-workspace/v1');
    assert.equal(claims.aud, audience);
    assert.equal(claims.client_id, 'grid-windows');
    assert.equal(claims.application_id, 'grid');
    assert.deepEqual(claims.capabilities, ['workspace:resolve']);
    assert.equal((await service.status(grant.token, audience)).active, true);
    f.policies.policies[0].enabled = false;
    writeFileSync(f.env.AUTH_RESOURCE_POLICY_PATH, JSON.stringify(f.policies));
    await assert.rejects(service.status(grant.token, audience), /RESOURCE_NOT_ADMITTED/);
    assert.throws(() => loadResourceRuntime({ ...f.env, AUTH_RESOURCE_KEY_ID: '0'.repeat(64) }), /RESOURCE_RUNTIME_CONFIGURATION_INVALID/);
    assert.throws(() => loadResourceRuntime({ ...f.env, AUTH_RESOURCE_MTLS_PORT: '0' }), /RESOURCE_RUNTIME_CONFIGURATION_INVALID/);
  } finally { f.cleanup(); }
});

test('missing owner-admission workload configuration cannot fabricate admission', async () => {
  const f = fixture();
  try {
    assert.throws(() => loadResourceRuntime(f.env), /RESOURCE_RUNTIME_CONFIGURATION_INVALID/);
  } finally { f.cleanup(); }
});

test('runtime connects the configured owner-admission adapter without an injected callback', async () => {
  const f = fixture(); let server: https.Server | undefined;
  try {
    const cert = readFileSync(f.env.AUTH_RESOURCE_MTLS_SERVER_CERT_PATH);
    const key = readFileSync(f.env.AUTH_RESOURCE_MTLS_SERVER_KEY_PATH);
    server = https.createServer({ cert, key, ca: cert, requestCert: true, rejectUnauthorized: true }, (req, res) => {
      let data = ''; req.on('data', part => data += part); req.on('end', () => {
        const { issuedAt, expiresAt, ...echo } = JSON.parse(data);
        res.end(JSON.stringify({ ...echo, admitted: true, ownerId, policyVersion: 'runtime-fixture/v1', expiresAt: Math.floor(Date.now()/1000)+30 }));
      });
    });
    server.listen(0, '127.0.0.1');
    await new Promise<void>((resolve,reject)=>{server!.once('listening',resolve);server!.once('error',reject);});
    const runtime = loadResourceRuntime({ ...f.env,
      AUTH_RESOURCE_OWNER_ADMISSION_URL: `https://127.0.0.1:${(server.address() as any).port}/api/v1/resource/owner-admission/resolve`,
      AUTH_RESOURCE_OWNER_ADMISSION_CERT_PATH: f.env.AUTH_RESOURCE_MTLS_SERVER_CERT_PATH,
      AUTH_RESOURCE_OWNER_ADMISSION_KEY_PATH: f.env.AUTH_RESOURCE_MTLS_SERVER_KEY_PATH,
      AUTH_RESOURCE_OWNER_ADMISSION_CA_PATH: f.env.AUTH_RESOURCE_MTLS_CLIENT_CA_PATH,
    })!;
    const service = new ResourceAuthorizationService({ ...runtime.authorization, sessionActive: async () => true });
    await service.initialize();
    assert.equal(decodeJwt((await service.issue(session, request)).token).owner_id, ownerId);
  } finally { if(server?.listening) await new Promise<void>(resolve=>server!.close(()=>resolve())); f.cleanup(); }
});

test('configured direct mTLS listener supports the exact VVAULT probe/status and denies other routes and revoked grants', async () => {
  const f = fixture(); let server: https.Server | undefined;
  try {
    const runtime = loadResourceRuntime(f.env, f.admission)!;
    let active = true;
    const service = new ResourceAuthorizationService({ ...runtime.authorization, sessionActive: async () => active });
    await service.initialize();
    const app = express(); app.use(express.json({ limit: '20kb' }));
    mountResourceAuthorizationHost(app, { service, workloads: runtime.authorization.workloads, readSession: async () => session });
    server = createResourceStatusServer(runtime, app);
    server.listen(0, '127.0.0.1');
    await new Promise<void>((resolve, reject) => { server!.once('listening', resolve); server!.once('error', reject); });
    const port = (server.address() as { port: number }).port;
    function call(assertion: string, path = '/api/auth/resource-status', certificate = true) {
      return new Promise<{ status: number; body: any }>((resolve, reject) => {
        const req = https.request({ host: '127.0.0.1', port, path, method: 'POST', agent: false,
          ca: runtime.tls.ca, ...(certificate ? { cert: runtime.tls.cert, key: runtime.tls.key } : {}),
          headers: { 'content-type': 'application/json' } }, res => {
          let body = ''; res.on('data', chunk => body += chunk); res.on('end', () => resolve({ status: res.statusCode!, body: JSON.parse(body) }));
        });
        req.on('error', reject); req.end(JSON.stringify({ assertion }));
      });
    }
    const probe = await call('readiness-probe-not-an-assertion');
    assert.equal(probe.status, 401); assert.equal(probe.body.errorCode, 'RESOURCE_ASSERTION_INVALID');
    const grant = await service.issue(session, request);
    const result = await call(grant.token);
    assert.equal(result.status, 200);
    const c = decodeJwt(grant.token);
    for (const [field, claim] of Object.entries({ issuer: 'iss', subject: 'sub', sid: 'sid', grant_id: 'grant_id', jti: 'jti', audience: 'aud',
      client_id: 'client_id', application_id: 'application_id', owner_id: 'owner_id', capabilities: 'capabilities', admission_version: 'admission_version', expires_at: 'exp', wire_contract: 'wire_contract', contract: 'contract' })) {
      assert.deepEqual(result.body[field], c[claim]);
    }
    assert.equal((await call(grant.token, '/api/auth/resource-authorization')).status, 404);
    await assert.rejects(call(grant.token, '/api/auth/resource-status', false));
    active = false;
    assert.equal((await call(grant.token)).status, 401);
  } finally {
    if (server?.listening) await new Promise<void>(resolve => server!.close(() => resolve()));
    f.cleanup();
  }
});

test('AUTH artifact and status are accepted by the actual supplied VVAULT source validator', {
  skip: !process.env.AUTH_VVAULT_SOURCE_TEST_ROOT || !process.env.AUTH_VVAULT_TEST_PYTHON,
}, async () => {
  const f = fixture();
  try {
    const runtime = loadResourceRuntime(f.env, f.admission)!;
    const service = new ResourceAuthorizationService({ ...runtime.authorization, sessionActive: async () => true });
    await service.initialize();
    const grant = await service.issue(session, request);
    const status = await service.status(grant.token, audience);
    const script = `import sys,json,importlib.util\np=json.load(sys.stdin)\nspec=importlib.util.spec_from_file_location('resource_contract',sys.argv[1])\nm=importlib.util.module_from_spec(spec)\nsys.modules[spec.name]=m\nspec.loader.exec_module(m)\nv=m.verify_resource_assertion(p['assertion'],public_keys={p['kid']:p['public']},issuer=p['issuer'])\nclass Response:\n status_code=200\n def json(self): return p['status']\nc=m.ResourceStatusClient('https://fixture.invalid/api/auth/resource-status','fixture-cert','fixture-key','fixture-ca',post=lambda *a,**k:Response())\nc.validate(p['assertion'],v)\nprint('WIRE_COMPATIBILITY_PASS')`;
    const result = execFileSync(process.env.AUTH_VVAULT_TEST_PYTHON!, ['-B', '-c', script, `${process.env.AUTH_VVAULT_SOURCE_TEST_ROOT}/vvault/server/resource_authorization.py`], {
      input: JSON.stringify({ assertion: grant.token, status, kid: f.keyId, public: f.publicPem, issuer: runtime.authorization.issuer }),
      encoding: 'utf8', timeout: 10000, stdio: ['pipe', 'pipe', 'pipe'],
    });
    assert.equal(result.trim(), 'WIRE_COMPATIBILITY_PASS');
  } finally { f.cleanup(); }
});
