import { randomBytes, createHash } from 'node:crypto';
import { AUTHORIZATION_REQUEST_TTL_SECONDS, validateRedirectUri, verifyS256 } from './authorizationCode.js';
import type { AuthPublicClient } from '../types.js';

export const DESKTOP_HANDOFF_CONTRACT = 'life.auth.desktop-handoff/v1';
export type DesktopClientRegistration = AuthPublicClient & { appId: string };
export type DesktopState = 'pending' | 'exchanging' | 'authenticated' | 'cancelled' | 'denied' | 'timed-out' | 'recoverable-error';
export type PendingDesktopRequest = {
  transaction: string; state: string; verifier: string; challenge: string;
  issuer: string; clientId: string; appId: string; redirectUri: string; expiresAt: number;
  generation: number; resumeReference: string; phase: 'pending' | 'exchanging';
};
export type DesktopResult = { state: DesktopState; reason?: string; focus?: 'foreground' | 'user-action-required' };
export interface DesktopHost<Session> {
  /** All methods run in the sole primary instance; IPC forwards callbacks to it. */
  generation(): number;
  /** OS-protected storage only. Never log these records. */
  loadPending(): PendingDesktopRequest | null;
  savePending(request: PendingDesktopRequest): void;
  /** Atomically advance generation and erase pending secrets; preserve workspace reference. */
  invalidate(): void;
  openSystemBrowser(url: string, signal: AbortSignal): Promise<void>;
  /** Pinned issuer/token endpoint, no redirects. Validate tokens, identity and admission;
   * enforce provider nonce where applicable. Never accept browser identity claims. */
  exchange(request: Readonly<PendingDesktopRequest>, code: string, signal: AbortSignal): Promise<{ session: Session; issuer: string; clientId: string }>;
  /** Atomic generation/transaction check + secure session persistence + pending erasure. */
  commitSession(request: Readonly<PendingDesktopRequest>, session: Session): boolean;
  /** Restore only this generation's authorized account/workspace; reject stale work. */
  restoreWorkspace(reference: string, generation: number, signal: AbortSignal): Promise<void>;
  activateExistingInstance(generation: number, signal: AbortSignal): Promise<'foreground' | 'user-action-required'>;
  /** Validate/refresh persisted session through existing lifecycle; no bypass of gates. */
  restoreSession(generation: number, signal: AbortSignal): Promise<boolean>;
  clearSession(): void;
}

export class DesktopHandoff<Session> {
  constructor(private host: DesktopHost<Session>, private issuer: string, private client: DesktopClientRegistration,
    private now = () => Date.now(), private operationTimeoutMs = 30_000) {
    if (!Number.isFinite(operationTimeoutMs) || operationTimeoutMs <= 0 || operationTimeoutMs > 30_000) throw new Error('INVALID_OPERATION_TIMEOUT');
    if (!client.appId?.trim() || !client.clientId?.trim()) throw new Error('INVALID_DESKTOP_REGISTRATION');
    const url = new URL(issuer);
    if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || url.pathname !== '/') {
      throw new Error('INVALID_DESKTOP_ISSUER');
    }
  }
  private async bounded<T>(operation: (signal: AbortSignal) => Promise<T>): Promise<T> {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    try {
      return await Promise.race([
        new Promise<T>((_, reject) => { timer = setTimeout(() => { controller.abort(); reject(new Error('HOST_TIMEOUT')); }, this.operationTimeoutMs); }),
        operation(controller.signal),
      ]);
    } finally { clearTimeout(timer!); controller.abort(); }
  }
  async begin(redirectUri: string, resumeReference: string): Promise<DesktopResult> {
    let redirect: URL;
    try { redirect = new URL(redirectUri); } catch { return { state: 'recoverable-error', reason: 'UNREGISTERED_CALLBACK' }; }
    if (redirect.username || redirect.password || redirect.search || redirect.hash || ['javascript:', 'data:', 'file:', 'vbscript:', 'about:'].includes(redirect.protocol) || !validateRedirectUri(this.client, redirectUri)) return { state: 'recoverable-error', reason: 'UNREGISTERED_CALLBACK' };
    const current = this.host.loadPending();
    if (current && current.expiresAt > this.now()) return { state: current.phase, reason: 'SIGNIN_ALREADY_PENDING' };
    this.host.invalidate();
    const verifier = randomBytes(32).toString('base64url');
    const request: PendingDesktopRequest = {
      transaction: randomBytes(32).toString('base64url'), state: randomBytes(32).toString('base64url'),
      verifier, challenge: createHash('sha256').update(verifier).digest('base64url'),
      issuer: this.issuer, clientId: this.client.clientId, appId: this.client.appId, redirectUri,
      expiresAt: this.now() + AUTHORIZATION_REQUEST_TTL_SECONDS * 1000,
      generation: this.host.generation(), resumeReference, phase: 'pending',
    };
    this.host.savePending(request);
    const url = new URL('/oauth/authorize', this.issuer);
    for (const [key, value] of Object.entries({ app: request.appId, response_type: 'code', client_id: request.clientId,
      redirect_uri: redirectUri, state: request.state, code_challenge: request.challenge,
      code_challenge_method: 'S256', scope: (this.client.scopes || ['openid', 'profile', 'email']).join(' ') })) url.searchParams.set(key, value);
    try { await this.bounded(signal => this.host.openSystemBrowser(url.toString(), signal)); }
    catch { if (this.isCurrent(request)) this.host.invalidate(); return { state: 'recoverable-error', reason: 'BROWSER_LAUNCH_FAILED' }; }
    return this.isCurrent(request) ? { state: 'pending' } : { state: 'cancelled' };
  }
  private isCurrent(request: PendingDesktopRequest) {
    return this.host.generation() === request.generation && this.host.loadPending()?.transaction === request.transaction;
  }
  cancel(): DesktopResult { this.host.invalidate(); return { state: 'cancelled' }; }
  signOut(): DesktopResult { this.host.invalidate(); this.host.clearSession(); return { state: 'cancelled', reason: 'SIGNED_OUT' }; }
  expire(): DesktopResult {
    const pending = this.host.loadPending();
    if (pending && pending.expiresAt <= this.now()) { this.host.invalidate(); return { state: 'timed-out' }; }
    return { state: pending?.phase || 'recoverable-error', ...(!pending ? { reason: 'NO_PENDING_REQUEST' } : {}) };
  }
  async callback(raw: string): Promise<DesktopResult> {
    const pending = this.host.loadPending();
    if (!pending || pending.phase !== 'pending' || !this.isCurrent(pending)) return { state: 'recoverable-error', reason: 'STALE_CALLBACK' };
    if (pending.expiresAt <= this.now()) return this.expire();
    let url: URL;
    try { url = new URL(raw); } catch { return { state: 'recoverable-error', reason: 'INVALID_CALLBACK' }; }
    const base = new URL(url); base.search = '';
    const params = url.searchParams;
    const unique = ['state', 'code', 'error', 'iss'].every(key => params.getAll(key).length <= 1);
    if (!unique || base.toString() !== pending.redirectUri || params.get('state') !== pending.state ||
      (params.has('iss') && params.get('iss') !== pending.issuer) ||
      pending.issuer !== this.issuer || pending.clientId !== this.client.clientId || pending.appId !== this.client.appId ||
      !validateRedirectUri(this.client, pending.redirectUri) || !verifyS256(pending.verifier, pending.challenge) ||
      (params.has('error') === params.has('code')) || (params.has('code') && !params.get('code'))) {
      return { state: 'recoverable-error', reason: 'CALLBACK_BINDING_REJECTED' };
    }
    if (params.has('error')) {
      this.host.invalidate();
      return this.showFailure(params.get('error') === 'access_denied'
        ? { state: 'denied', reason: 'AUTHORIZATION_DENIED' }
        : { state: 'recoverable-error', reason: 'AUTHORIZATION_FAILED' });
    }
    this.host.savePending({ ...pending, phase: 'exchanging' });
    try {
      const result = await this.bounded(signal => this.host.exchange(Object.freeze({ ...pending }), params.get('code')!, signal));
      if (!this.isCurrent(pending)) return { state: 'recoverable-error', reason: 'STALE_CALLBACK' };
      if (pending.expiresAt <= this.now()) return this.expire();
      if (result.issuer !== pending.issuer || result.clientId !== pending.clientId) throw new Error('BINDING');
      if (!this.host.commitSession(pending, result.session)) throw new Error('COMMIT');
      return await this.finish(pending.resumeReference, pending.generation);
    } catch {
      if (!this.isCurrent(pending) && this.host.generation() !== pending.generation) return { state: 'cancelled' };
      if (this.isCurrent(pending)) this.host.invalidate();
      return this.showFailure({ state: 'recoverable-error', reason: 'SESSION_COMPLETION_FAILED' });
    }
  }
  private async showFailure(result: DesktopResult): Promise<DesktopResult> {
    const generation = this.host.generation();
    try {
      const focus = await this.bounded(signal => this.host.activateExistingInstance(generation, signal));
      return this.host.generation() === generation ? { ...result, focus } : { state: 'cancelled' };
    } catch { return { ...result, focus: 'user-action-required' }; }
  }
  private async finish(reference: string, generation: number): Promise<DesktopResult> {
    if (this.host.generation() !== generation) return { state: 'cancelled' };
    await this.bounded(signal => this.host.restoreWorkspace(reference, generation, signal));
    if (this.host.generation() !== generation) return { state: 'cancelled' };
    const focus = await this.bounded(signal => this.host.activateExistingInstance(generation, signal));
    return this.host.generation() === generation ? { state: 'authenticated', focus } : { state: 'cancelled' };
  }
  async recover(redirectUri: string, resumeReference: string): Promise<DesktopResult> {
    this.host.invalidate(); // Never retry a code whose exchange may have completed before a crash.
    const generation = this.host.generation();
    try {
      const restored = await this.bounded(signal => this.host.restoreSession(generation, signal));
      if (this.host.generation() !== generation) return { state: 'cancelled' };
      if (restored) return await this.finish(resumeReference, generation);
    } catch { return { state: 'recoverable-error', reason: 'SESSION_RESTORE_FAILED' }; }
    return this.begin(redirectUri, resumeReference);
  }
}

/** Render at the consuming callback host after session completion, never on AUTH's root.
 * activationUri is trusted registration configuration, not callback/request input. */
export function desktopCompletionPage(appName: string, activationUri: string) {
  return renderDesktopPage(appName, activationUri, true);
}

/** Callback hosts use this for validated failure callbacks; never echo provider errors. */
export function desktopRecoveryPage(appName: string, activationUri: string) {
  return renderDesktopPage(appName, activationUri, false);
}

function renderDesktopPage(appName: string, activationUri: string, completed: boolean) {
  const uri = new URL(activationUri);
  if (!/^[a-z][a-z0-9+.-]*:$/.test(uri.protocol) || ['http:', 'https:', 'javascript:', 'data:', 'file:', 'vbscript:', 'about:'].includes(uri.protocol) ||
    uri.username || uri.password || uri.search || uri.hash || uri.hostname !== 'auth-complete' || uri.pathname !== '') {
    throw new Error('INVALID_ACTIVATION_URI');
  }
  const escape = (s: string) => s.replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
  const title = completed ? 'Sign-in complete' : 'Sign-in could not complete';
  const nonce = randomBytes(18).toString('base64');
  const target = JSON.stringify(uri.toString()).replace(/</g, '\\u003c');
  return {
    headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer',
      'Content-Security-Policy': `default-src 'none'; script-src 'nonce-${nonce}'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'` },
    body: `<!doctype html><html><head><title>${title}</title></head><body><p>${title}. Return to ${escape(appName)}.</p><a href="${escape(uri.toString())}">Open ${escape(appName)}</a><script nonce="${nonce}">window.location.replace(${target});</script></body></html>`,
  };
}
