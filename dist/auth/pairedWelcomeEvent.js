import crypto from 'node:crypto';
/** Signed only after successful authority completion redemption and admission persistence. */
export function pairedWelcomeEvent(admission, privateKeyPem, issuer, now = Math.floor(Date.now() / 1000)) {
    if (admission.admission !== 'AUTHORIZED' || admission.relyingParty !== 'chatty' || admission.expiresAt <= now || !admission.identity?.subject || !admission.ownerId || !admission.transaction || !admission.sessionBinding)
        throw new Error('PAIRED_COMPLETION_REQUIRED');
    const payload = { version: 'auth.paired-welcome.v1', kind: 'PAIR_COMPLETED', issuer, audience: 'vvault', issuedAt: now, expiresAt: Math.min(now + 60, admission.expiresAt), subject: admission.identity.subject, ownerId: admission.ownerId, identity: admission.identity, sessionBinding: admission.sessionBinding, transaction: admission.transaction, relyingParty: 'chatty' };
    const encoded = Buffer.from(JSON.stringify(payload)).toString('base64url');
    return encoded + '.' + crypto.sign(null, Buffer.from(encoded), crypto.createPrivateKey(privateKeyPem)).toString('base64url');
}
export async function submitPairedWelcome(event, origin, fetchImpl = fetch) {
    const base = new URL(origin);
    if (base.username || base.password || base.pathname !== '/' || base.search || base.hash || (base.protocol !== 'https:' && !(base.protocol === 'http:' && ['localhost', '127.0.0.1'].includes(base.hostname))))
        throw new Error('WELCOME_ORIGIN_REQUIRED');
    const response = await fetchImpl(new URL('/api/auth/enrollment/welcome-event', base), { method: 'POST', redirect: 'error', signal: AbortSignal.timeout(5000), headers: { 'content-type': 'application/json' }, body: JSON.stringify({ event }) });
    return response.status === 202 ? 'QUEUED' : 'NOT_QUEUED';
}
