import https from 'node:https';
import { randomUUID } from 'node:crypto';
import { ResourceAuthorizationError, type ResourceAdmission, type ResourceSession } from './resourceAuthorization.js';

export const OWNER_ADMISSION_CONTRACT = 'life.vvault.resource-owner-admission/v1';
export const OWNER_ADMISSION_PATH = '/api/v1/resource/owner-admission/resolve';
export interface OwnerAdmissionOptions {
  issuer: string; url: string; cert: Buffer; key: Buffer; ca: Buffer;
  now?: () => number;
}
const failure = (code: string, status = 503): never => { throw new ResourceAuthorizationError(code, status); };

/** Dedicated service transport: no user bearer, proxy agent, redirects or positive cache. */
export function createVvaultOwnerAdmission(options: OwnerAdmissionOptions) {
  const url = new URL(options.url);
  if (url.protocol !== 'https:' || url.pathname !== OWNER_ADMISSION_PATH || url.search || url.hash || url.username || url.password) {
    return failure('OWNER_ADMISSION_CONFIGURATION_INVALID');
  }
  const now = options.now || (() => Math.floor(Date.now() / 1000));
  return async (session: ResourceSession, audience: string): Promise<ResourceAdmission> => {
    if (audience !== 'https://vvault.thewreck.org' || session.clientId !== 'grid-windows' || session.applicationId !== 'grid') {
      return failure('OWNER_ADMISSION_APPLICATION_NOT_ADMITTED', 403);
    }
    const issuedAt = now();
    const request = { contract: OWNER_ADMISSION_CONTRACT, requestId: randomUUID(), issuer: options.issuer,
      subject: session.subject, sessionId: session.sessionId, clientId: session.clientId,
      applicationId: session.applicationId, audience, capabilities: ['workspace:resolve'],
      issuedAt, expiresAt: Math.min(issuedAt + 30, session.expiresAt) };
    if (request.expiresAt <= issuedAt) return failure('REAUTH_REQUIRED', 401);
    const reply = await new Promise<{ status: number; body: any }>((resolve, reject) => {
      const unavailable = () => new ResourceAuthorizationError('OWNER_ADMISSION_UNAVAILABLE', 503);
      const req = https.request(url, { method: 'POST', cert: options.cert, key: options.key, ca: options.ca,
        rejectUnauthorized: true, minVersion: 'TLSv1.2', agent: false,
        headers: { 'content-type': 'application/json', accept: 'application/json' } }, res => {
        const chunks: Buffer[] = []; let size = 0;
        res.on('data', chunk => {
          size += chunk.length;
          if (size > 16384) { req.destroy(unavailable()); return; }
          chunks.push(Buffer.from(chunk));
        });
        res.on('error', () => reject(unavailable()));
        res.on('end', () => {
          try { resolve({ status: res.statusCode || 503, body: JSON.parse(Buffer.concat(chunks).toString('utf8')) }); }
          catch { reject(new ResourceAuthorizationError('OWNER_ADMISSION_RESPONSE_INVALID', 503)); }
        });
      });
      // Wall-clock deadline covers DNS, TLS and slowly streamed response bodies.
      const timer = setTimeout(() => req.destroy(unavailable()), 1500);
      req.once('close', () => clearTimeout(timer));
      req.on('error', () => reject(unavailable()));
      req.end(JSON.stringify(request));
    });
    if (reply.status !== 200) {
      if (reply.status === 409) return failure('OWNER_ADMISSION_CONFLICT', 409);
      if (reply.status === 401 || reply.status === 403) return failure('OWNER_ADMISSION_WORKLOAD_UNAUTHORIZED', 503);
      return failure('OWNER_ADMISSION_UNAVAILABLE');
    }
    const body = reply.body;
    if (!body || typeof body !== 'object' || Array.isArray(body)) return failure('OWNER_ADMISSION_RESPONSE_INVALID');
    for (const field of ['contract', 'requestId', 'issuer', 'subject', 'sessionId', 'clientId', 'applicationId', 'audience', 'capabilities'] as const) {
      if (JSON.stringify(body[field]) !== JSON.stringify(request[field])) return failure('OWNER_ADMISSION_BINDING_MISMATCH');
    }
    if (!Number.isSafeInteger(body.expiresAt) || body.expiresAt <= now() || body.expiresAt > now() + 60
      || request.expiresAt <= now()) return failure('OWNER_ADMISSION_RESPONSE_EXPIRED');
    const base = ['contract', 'requestId', 'admitted', 'issuer', 'subject', 'sessionId', 'clientId', 'applicationId', 'audience', 'capabilities', 'expiresAt'];
    const expected = [...base, ...(body.admitted === true ? ['ownerId', 'policyVersion'] : ['disposition', 'reasonCode'])];
    if (Object.keys(body).length !== expected.length || Object.keys(body).some(key => !expected.includes(key))) return failure('OWNER_ADMISSION_RESPONSE_INVALID');
    if (body.admitted === false) {
      const dispositions: Record<string, string> = { NO_OWNER_BINDING: 'ACCOUNT_LINK_REQUIRED', OWNER_ENROLLMENT_PENDING: 'ENROLLMENT_REQUIRED', OWNER_BINDING_REVOKED: 'REAUTH_REQUIRED', OWNER_DISABLED: 'REAUTH_REQUIRED' };
      if (!Object.hasOwn(dispositions, body.reasonCode) || dispositions[body.reasonCode] !== body.disposition) return failure('OWNER_ADMISSION_RESPONSE_INVALID');
      return { admitted: false, disposition: body.disposition };
    }
    if (body.admitted !== true || typeof body.ownerId !== 'string'
      || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(body.ownerId)
      || typeof body.policyVersion !== 'string' || !body.policyVersion.trim() || body.policyVersion.length > 512) return failure('OWNER_ADMISSION_RESPONSE_INVALID');
    return { admitted: true, subject: session.subject, sessionId: session.sessionId, clientId: session.clientId,
      applicationId: session.applicationId, audience, ownerId: body.ownerId, capabilities: ['workspace:resolve'],
      expiresAt: body.expiresAt, policyVersion: body.policyVersion };
  };
}
