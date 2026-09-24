import { createHash, createPrivateKey, createPublicKey, randomUUID } from 'node:crypto';
import { SignJWT, jwtVerify } from 'jose';
import type { ResourceGrantRecord, ResourceGrantStore } from './resourceGrantStore.js';

export const RESOURCE_CONTRACT = 'life.auth.resource-authorization/v1';
export const RESOURCE_TOKEN_TYPE = 'life-resource+jwt';
export const RESOURCE_MAX_SECONDS = 60;

/** Obtained only from a verified AUTH access token and current session stores. */
export interface ResourceSession {
  subject: string;
  sessionId: string;
  accessJti: string;
  expiresAt: number;
  clientId: string;
  applicationId: string;
}
/** Operator-owned registration, including the resource owner's approved wire vocabulary. */
export interface ResourcePolicy {
  enabled: boolean;
  contract: typeof RESOURCE_CONTRACT;
  wireContract: string;
  clientId: string;
  applicationId: string;
  audience: string;
  capabilities: readonly string[];
}
export type ResourceAdmission = {
  admitted: true;
  subject: string;
  sessionId: string;
  clientId: string;
  applicationId: string;
  audience: string;
  ownerId: string;
  capabilities: readonly string[];
  expiresAt: number;
  policyVersion: string;
} | {
  admitted: false;
  disposition: 'ENROLLMENT_REQUIRED' | 'ACCOUNT_LINK_REQUIRED' | 'REAUTH_REQUIRED';
};

export class ResourceAuthorizationError extends Error {
  constructor(public readonly code: string, public readonly status: number) { super(code); }
}
function deny(code: string, status = 401): never { throw new ResourceAuthorizationError(code, status); }
/** Late dependency results cannot resume issuance after the deadline. Adapters should also cancel their I/O. */
export async function resourceDependency<T>(operation: () => Promise<T>, milliseconds = 2000): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([operation(), new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => reject(new ResourceAuthorizationError('RESOURCE_DEPENDENCY_TIMEOUT', 503)), milliseconds);
    })]);
  } finally { if (timer) clearTimeout(timer); }
}
const text = (value: unknown): value is string => typeof value === 'string' && value.length > 0 && value.length <= 512;
const digest = (token: string) => createHash('sha256').update(token).digest('hex');
function capabilities(value: unknown): string[] {
  if (!Array.isArray(value) || !value.length || value.length > 32
    || value.some(item => !text(item) || !/^[A-Za-z0-9][A-Za-z0-9:._/-]{0,127}$/.test(item))
    || new Set(value).size !== value.length) deny('INVALID_CAPABILITIES', 400);
  return [...value].sort();
}
function origin(value: unknown): string {
  if (!text(value)) return deny('INVALID_RESOURCE', 400);
  try {
    const url = new URL(value);
    if (url.protocol !== 'https:' || url.origin !== value || url.username || url.password) return deny('INVALID_RESOURCE', 400);
    return value;
  } catch { return deny('INVALID_RESOURCE', 400); }
}

export interface ResourceAuthorizationOptions {
  issuer: string;
  keyId: string;
  privateKeyPem: string;
  store: ResourceGrantStore;
  /** Must read current server registration. There is no default resource policy. */
  resolvePolicy(session: ResourceSession, audience: string): Promise<ResourcePolicy | null>;
  /** Must verify current AUTH session, access revocation and native registration. Errors propagate. */
  sessionActive(session: ResourceSession): Promise<boolean>;
  /** Trusted VVAULT authority adapter. Owner lookup alone MUST NOT implement this callback. */
  resolveAdmission(session: ResourceSession, audience: string): Promise<ResourceAdmission>;
  now?: () => number;
  dependencyTimeoutMs?: number;
}

/** No native VVAULT cookie, owner selector, email mapping or enrollment mutation exists here. */
export class ResourceAuthorizationService {
  private readonly signingKey;
  private readonly verificationKey;
  private readonly now: () => number;
  private readonly dependencyTimeout: number;
  constructor(private readonly options: ResourceAuthorizationOptions) {
    if (!text(options.issuer) || !text(options.keyId)) throw new Error('RESOURCE_SIGNER_CONFIGURATION_REQUIRED');
    this.signingKey = createPrivateKey(options.privateKeyPem);
    if (this.signingKey.asymmetricKeyType !== 'ed25519') throw new Error('RESOURCE_SIGNER_MUST_BE_ED25519');
    this.verificationKey = createPublicKey(this.signingKey);
    this.now = options.now || (() => Math.floor(Date.now() / 1000));
    this.dependencyTimeout = options.dependencyTimeoutMs ?? 2000;
    if (!Number.isInteger(this.dependencyTimeout) || this.dependencyTimeout < 10 || this.dependencyTimeout > 5000) {
      throw new Error('RESOURCE_DEPENDENCY_TIMEOUT_INVALID');
    }
  }
  async initialize() { await this.options.store.initialize(); }

  private async current(session: ResourceSession, audience: string, requested: string[]) {
    const now = this.now();
    if (![session.subject, session.sessionId, session.accessJti, session.clientId, session.applicationId].every(text)
      || !Number.isSafeInteger(session.expiresAt) || session.expiresAt <= now) deny('REAUTH_REQUIRED');
    if (!await resourceDependency(() => this.options.sessionActive(session), this.dependencyTimeout)) deny('REAUTH_REQUIRED');
    const policy = await resourceDependency(() => this.options.resolvePolicy(session, audience), this.dependencyTimeout);
    if (!policy || policy.enabled !== true || policy.contract !== RESOURCE_CONTRACT || !text(policy.wireContract)
      || policy.clientId !== session.clientId || policy.applicationId !== session.applicationId || policy.audience !== audience) {
      deny('RESOURCE_NOT_ADMITTED', 403);
    }
    if (!Array.isArray(policy.capabilities)) deny('RESOURCE_POLICY_INVALID', 503);
    if (requested.some(scope => !policy.capabilities.includes(scope))) deny('INSUFFICIENT_CAPABILITY', 403);
    const admission = await resourceDependency(() => this.options.resolveAdmission(session, audience), this.dependencyTimeout);
    if (!admission || typeof admission !== 'object') deny('ADMISSION_EVIDENCE_INVALID', 503);
    if (admission.admitted !== true) {
      if (admission.admitted === false && ['ENROLLMENT_REQUIRED', 'ACCOUNT_LINK_REQUIRED', 'REAUTH_REQUIRED'].includes(admission.disposition)) {
        deny(admission.disposition, 409);
      }
      deny('ADMISSION_EVIDENCE_INVALID', 503);
    }
    if (admission.subject !== session.subject || admission.sessionId !== session.sessionId
      || admission.clientId !== session.clientId || admission.applicationId !== session.applicationId
      || admission.audience !== audience || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(admission.ownerId)
      || !text(admission.policyVersion) || !Number.isSafeInteger(admission.expiresAt) || admission.expiresAt <= now) {
      deny('ADMISSION_BINDING_INVALID', 403);
    }
    if (!Array.isArray(admission.capabilities)) deny('ADMISSION_EVIDENCE_INVALID', 503);
    if (requested.some(scope => !admission.capabilities.includes(scope))) deny('INSUFFICIENT_CAPABILITY', 403);
    return { admission, policy };
  }

  async issue(session: ResourceSession, request: unknown) {
    if (!request || typeof request !== 'object' || Array.isArray(request)) deny('INVALID_REQUEST', 400);
    const input = request as Record<string, unknown>;
    if (Object.keys(input).some(key => !['audience', 'capabilities'].includes(key))) deny('UNTRUSTED_SELECTOR', 400);
    const audience = origin(input.audience);
    const scopes = capabilities(input.capabilities);
    const { admission, policy } = await this.current(session, audience, scopes);
    const iat = this.now();
    const exp = Math.min(iat + RESOURCE_MAX_SECONDS, session.expiresAt, admission.expiresAt);
    if (exp <= iat) deny('REAUTH_REQUIRED');
    const id = randomUUID();
    const jti = randomUUID();
    const claims = {
      contract: RESOURCE_CONTRACT, wire_contract: policy.wireContract,
      client_id: session.clientId, application_id: session.applicationId,
      owner_id: admission.ownerId, sid: session.sessionId, grant_id: id,
      capabilities: scopes, admission_version: admission.policyVersion,
    };
    const token = await new SignJWT(claims).setProtectedHeader({ alg: 'EdDSA', kid: this.options.keyId, typ: RESOURCE_TOKEN_TYPE })
      .setIssuer(this.options.issuer).setAudience(audience).setSubject(session.subject)
      .setJti(jti).setIssuedAt(iat).setExpirationTime(exp).sign(this.signingKey);
    await this.options.store.put({
      id, jti, tokenDigest: digest(token), issuer: this.options.issuer, subject: session.subject,
      sessionId: session.sessionId, sourceAccessJti: session.accessJti, clientId: session.clientId,
      applicationId: session.applicationId, audience, ownerId: admission.ownerId, capabilities: scopes,
      issuedAt: iat, expiresAt: exp, admissionVersion: admission.policyVersion,
    });
    return { contract: RESOURCE_CONTRACT, token, token_type: 'Bearer', grant_id: id, expires_at: exp, capabilities: scopes };
  }

  /** Caller must first authenticate the resource workload, never the product client. */
  async status(token: string, workloadAudience: string) {
    const audience = origin(workloadAudience);
    let verified;
    try {
      verified = await jwtVerify(token, this.verificationKey, {
        algorithms: ['EdDSA'], issuer: this.options.issuer, audience,
        typ: RESOURCE_TOKEN_TYPE, currentDate: new Date(this.now() * 1000), clockTolerance: 0,
      });
    } catch { return deny('RESOURCE_ASSERTION_INVALID'); }
    const p = verified.payload;
    if (verified.protectedHeader.kid !== this.options.keyId || p.contract !== RESOURCE_CONTRACT
      || p.aud !== audience || !text(p.grant_id) || !Number.isSafeInteger(p.iat) || !Number.isSafeInteger(p.exp)
      || p.iat! > this.now() || p.exp! - p.iat! > RESOURCE_MAX_SECONDS) deny('RESOURCE_ASSERTION_INVALID');
    const stored = await this.options.store.get(p.grant_id as string);
    if (!stored || stored.revoked || stored.expiresAt <= this.now() || stored.tokenDigest !== digest(token)) deny('RESOURCE_GRANT_INACTIVE');
    if (p.iss !== stored.issuer || p.sub !== stored.subject || p.sid !== stored.sessionId || p.jti !== stored.jti
      || p.client_id !== stored.clientId || p.application_id !== stored.applicationId || p.owner_id !== stored.ownerId
      || p.aud !== stored.audience || p.iat !== stored.issuedAt || p.exp !== stored.expiresAt
      || p.admission_version !== stored.admissionVersion
      || JSON.stringify(p.capabilities) !== JSON.stringify(stored.capabilities)) deny('RESOURCE_GRANT_MISMATCH');
    const session = this.sessionFrom(stored);
    const { admission, policy } = await this.current(session, audience, stored.capabilities);
    if (admission.ownerId !== stored.ownerId || admission.policyVersion !== stored.admissionVersion
      || admission.expiresAt < stored.expiresAt || p.wire_contract !== policy.wireContract) deny('RESOURCE_GRANT_STALE');
    // Dependencies can consume the remaining lifetime. A previously valid JWT
    // must not become a positive status response after it expires in flight.
    if (stored.expiresAt <= this.now() || admission.expiresAt <= this.now()) deny('RESOURCE_GRANT_INACTIVE');
    return { active: true, contract: RESOURCE_CONTRACT, wire_contract: policy.wireContract,
      admission_version: stored.admissionVersion, issuer: stored.issuer, subject: stored.subject,
      sid: stored.sessionId, jti: stored.jti, grant_id: stored.id, audience: stored.audience,
      client_id: stored.clientId, application_id: stored.applicationId, owner_id: stored.ownerId,
      capabilities: stored.capabilities, expires_at: stored.expiresAt };
  }

  async revoke(session: ResourceSession, grantId: string) {
    if (!await resourceDependency(() => this.options.sessionActive(session), this.dependencyTimeout)) deny('REAUTH_REQUIRED');
    const record = await this.options.store.get(grantId);
    if (!record || record.subject !== session.subject || record.sessionId !== session.sessionId
      || record.clientId !== session.clientId || record.applicationId !== session.applicationId) deny('RESOURCE_GRANT_NOT_FOUND', 404);
    await this.options.store.revoke(grantId);
    return { revoked: true };
  }

  private sessionFrom(record: ResourceGrantRecord): ResourceSession {
    return { subject: record.subject, sessionId: record.sessionId, accessJti: record.sourceAccessJti,
      expiresAt: record.expiresAt, clientId: record.clientId, applicationId: record.applicationId };
  }
}
