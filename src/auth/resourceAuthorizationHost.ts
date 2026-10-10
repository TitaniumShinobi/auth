import { TLSSocket } from 'node:tls';
import { ResourceAuthorizationError, resourceDependency, type ResourceAuthorizationService, type ResourceSession } from './resourceAuthorization.js';

export interface ResourceWorkload {
  audience: string;
  /** SHA-256 fingerprint of an operator-approved client certificate, not a request header. */
  fingerprint256: string;
}
const fingerprint = (value: string) => value.replace(/:/g, '').toLowerCase();

/** Direct mutual TLS only. Proxy certificate headers are deliberately unsupported. */
export function resourceWorkloadAudience(socket: unknown, workloads: readonly ResourceWorkload[]): string | null {
  if (!(socket instanceof TLSSocket) || !socket.encrypted || !socket.authorized) return null;
  const peer = socket.getPeerCertificate();
  if (!peer.fingerprint256 || !/^[0-9a-f:]+$/i.test(peer.fingerprint256)) return null;
  const actual = fingerprint(peer.fingerprint256);
  if (actual.length !== 64) return null;
  const matches = workloads.filter(workload => fingerprint(workload.fingerprint256) === actual);
  return matches.length === 1 ? matches[0]!.audience : null;
}

export function mountResourceAuthorizationHost(app: any, dependencies: {
  service?: ResourceAuthorizationService;
  workloads: readonly ResourceWorkload[];
  readSession(req: any): Promise<ResourceSession>;
}) {
  async function handle(req: any, res: any, operation: 'issue' | 'status' | 'revoke') {
    res.set('Cache-Control', 'no-store');
    res.set('Pragma', 'no-cache');
    try {
      if (!dependencies.service) throw new ResourceAuthorizationError('RESOURCE_AUTHORIZATION_NOT_CONFIGURED', 503);
      if (operation === 'status') {
        const audience = resourceWorkloadAudience(req.socket, dependencies.workloads);
        if (!audience) throw new ResourceAuthorizationError('RESOURCE_WORKLOAD_REQUIRED', 401);
        const body = req.body;
        if (!body || Object.keys(body).some(key => key !== 'assertion')
          || typeof body.assertion !== 'string' || body.assertion.length > 16384) {
          throw new ResourceAuthorizationError('INVALID_REQUEST', 400);
        }
        return res.json(await dependencies.service.status(body.assertion, audience));
      }
      if (req.headers.cookie || !/^Bearer\s+\S+$/i.test(req.get('authorization') || '')) {
        throw new ResourceAuthorizationError('AUTH_BEARER_REQUIRED', 401);
      }
      const session = await resourceDependency(() => dependencies.readSession(req));
      if (operation === 'issue') return res.json(await dependencies.service.issue(session, req.body));
      if (!req.body || Object.keys(req.body).some(key => key !== 'grant_id')
        || typeof req.body.grant_id !== 'string' || req.body.grant_id.length > 128) {
        throw new ResourceAuthorizationError('INVALID_REQUEST', 400);
      }
      return res.json(await dependencies.service.revoke(session, req.body.grant_id));
    } catch (error) {
      // Never serialize exception messages, request bodies or authorization artifacts.
      const known = error instanceof ResourceAuthorizationError;
      return res.status(known ? error.status : 503).json({
        active: false, errorCode: known ? error.code : 'RESOURCE_AUTHORIZATION_UNAVAILABLE',
      });
    }
  }
  app.post('/api/auth/resource-authorization', (req: any, res: any) => handle(req, res, 'issue'));
  app.post('/api/auth/resource-status', (req: any, res: any) => handle(req, res, 'status'));
  app.post('/api/auth/resource-revoke', (req: any, res: any) => handle(req, res, 'revoke'));
}
