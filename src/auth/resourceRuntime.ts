import { createHash, createPrivateKey, createPublicKey } from 'node:crypto';
import { lstatSync, readFileSync } from 'node:fs';
import { isAbsolute } from 'node:path';
import https from 'node:https';
import type { RequestListener } from 'node:http';
import { ResourceAuthorizationError, RESOURCE_CONTRACT, type ResourceAuthorizationOptions, type ResourcePolicy } from './resourceAuthorization.js';
import type { ResourceWorkload } from './resourceAuthorizationHost.js';
import { SqliteResourceGrantStore } from './resourceGrantStore.js';
import { createVvaultOwnerAdmission } from './vvaultOwnerAdmission.js';

type Environment = Record<string, string | undefined>;
export type ResourceRuntime = {
  authorization: Omit<ResourceAuthorizationOptions, 'sessionActive'> & { workloads: ResourceWorkload[] };
  tls: { host: string; port: number; cert: Buffer; key: Buffer; ca: Buffer };
};
function invalid(): never { throw new ResourceAuthorizationError('RESOURCE_RUNTIME_CONFIGURATION_INVALID', 503); }
function required(env: Environment, key: string): string {
  const value = env[key]?.trim();
  if (!value) return invalid();
  return value;
}
function protectedFile(path: string, secret = false): Buffer {
  try {
    if (!isAbsolute(path)) return invalid();
    const stat = lstatSync(path);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 1024 * 1024
      || (stat.mode & 0o022) !== 0 || (secret && (stat.mode & 0o077) !== 0)
      || (typeof process.getuid === 'function' && stat.uid !== process.getuid() && stat.uid !== 0)) return invalid();
    return readFileSync(path);
  } catch { return invalid(); }
}

/** Server-owned registry; reread on every authorization decision, never caller selectors. */
export function readResourcePolicies(path: string): ResourcePolicy[] {
  try {
    const value = JSON.parse(protectedFile(path).toString());
    if (!value || !Array.isArray(value.policies) || value.policies.length > 100) return invalid();
    const seen = new Set<string>();
    for (const policy of value.policies) {
      if (!policy || typeof policy.enabled !== 'boolean' || policy.contract !== RESOURCE_CONTRACT
        || !['wireContract', 'clientId', 'applicationId', 'audience'].every(key => typeof policy[key] === 'string' && policy[key].length > 0 && policy[key].length <= 512)
        || !Array.isArray(policy.capabilities) || !policy.capabilities.length || policy.capabilities.length > 32
        || policy.capabilities.some((v: unknown) => typeof v !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9:._/-]{0,127}$/.test(v))
        || new Set(policy.capabilities).size !== policy.capabilities.length) return invalid();
      const url = new URL(policy.audience);
      if (url.protocol !== 'https:' || url.origin !== policy.audience) return invalid();
      const id = JSON.stringify([policy.clientId, policy.applicationId, policy.audience]);
      if (seen.has(id)) return invalid();
      seen.add(id);
    }
    return value.policies;
  } catch { return invalid(); }
}

/** No credentials are discovered in another product or generated during startup. */
export function loadResourceRuntime(
  env: Environment = process.env,
  resolveAdmission?: ResourceAuthorizationOptions['resolveAdmission'],
): ResourceRuntime | undefined {
  if (env.AUTH_RESOURCE_ENABLED === undefined || env.AUTH_RESOURCE_ENABLED === 'false') return undefined;
  if (env.AUTH_RESOURCE_ENABLED !== 'true') return invalid();
  try {
    const issuer = required(env, 'AUTH_RESOURCE_ISSUER');
    const policyPath = required(env, 'AUTH_RESOURCE_POLICY_PATH');
    const policies = readResourcePolicies(policyPath);
    const privateKeyPem = protectedFile(required(env, 'AUTH_RESOURCE_SIGNING_KEY_PATH'), true).toString();
    const privateKey = createPrivateKey(privateKeyPem);
    if (privateKey.asymmetricKeyType !== 'ed25519') return invalid();
    // VVAULT requires kid = SHA-256 of the canonical SPKI public PEM.
    const publicPem = createPublicKey(privateKeyPem).export({ type: 'spki', format: 'pem' }).toString();
    const keyId = createHash('sha256').update(publicPem).digest('hex');
    if (keyId !== required(env, 'AUTH_RESOURCE_KEY_ID')) return invalid();
    const workloads = JSON.parse(required(env, 'AUTH_RESOURCE_WORKLOADS_JSON')) as ResourceWorkload[];
    if (!Array.isArray(workloads) || !workloads.length || workloads.length > 100) return invalid();
    const pins = new Set<string>();
    for (const workload of workloads) {
      if (!workload || typeof workload.fingerprint256 !== 'string' || !/^[a-fA-F0-9]{64}$/.test(workload.fingerprint256)
        || !policies.some(p => p.audience === workload.audience)) return invalid();
      const pin = workload.fingerprint256.toLowerCase();
      if (pins.has(pin)) return invalid();
      pins.add(pin);
    }
    const port = Number(required(env, 'AUTH_RESOURCE_MTLS_PORT'));
    if (!Number.isInteger(port) || port < 1 || port > 65535) return invalid();
    return {
      authorization: {
        issuer, keyId, privateKeyPem, workloads,
        store: new SqliteResourceGrantStore(required(env, 'AUTH_RESOURCE_GRANT_STORE_PATH')),
        resolvePolicy: async (session, audience) => readResourcePolicies(policyPath).find(p => p.clientId === session.clientId && p.applicationId === session.applicationId && p.audience === audience) || null,
        resolveAdmission: resolveAdmission || createVvaultOwnerAdmission({
          issuer, url: required(env, 'AUTH_RESOURCE_OWNER_ADMISSION_URL'),
          cert: protectedFile(required(env, 'AUTH_RESOURCE_OWNER_ADMISSION_CERT_PATH')),
          key: protectedFile(required(env, 'AUTH_RESOURCE_OWNER_ADMISSION_KEY_PATH'), true),
          ca: protectedFile(required(env, 'AUTH_RESOURCE_OWNER_ADMISSION_CA_PATH')),
        }),
      },
      tls: {
        host: required(env, 'AUTH_RESOURCE_MTLS_HOST'), port,
        cert: protectedFile(required(env, 'AUTH_RESOURCE_MTLS_SERVER_CERT_PATH')),
        key: protectedFile(required(env, 'AUTH_RESOURCE_MTLS_SERVER_KEY_PATH'), true),
        ca: protectedFile(required(env, 'AUTH_RESOURCE_MTLS_CLIENT_CA_PATH')),
      },
    };
  } catch { return invalid(); }
}

/** Dedicated status-only listener: no browser/API traffic and no proxy-header authentication. */
export function createResourceStatusServer(runtime: ResourceRuntime, handler: RequestListener): https.Server {
  const server = https.createServer({ ...runtime.tls, minVersion: 'TLSv1.2', requestCert: true, rejectUnauthorized: true }, (req, res) => {
    if (req.method !== 'POST' || req.url !== '/api/auth/resource-status') {
      res.writeHead(404, { 'content-type': 'application/json', 'cache-control': 'no-store' });
      res.end('{"active":false,"errorCode":"RESOURCE_STATUS_ONLY"}');
      return;
    }
    handler(req, res);
  });
  server.requestTimeout = 5000;
  server.headersTimeout = 5000;
  server.keepAliveTimeout = 1000;
  return server;
}
