import crypto from 'node:crypto';
export const AUTHORIZATION_REQUEST_TTL_SECONDS = 10 * 60;
export const AUTHORIZATION_CODE_TTL_SECONDS = 2 * 60;
export function findPublicClient(config, clientId) {
    return (config.publicClients || []).find((client) => client.clientId === clientId) || null;
}
export function validateRedirectUri(client, raw) {
    if (client.redirectUris?.includes(raw))
        return raw;
    let url;
    try {
        url = new URL(raw);
    }
    catch {
        return null;
    }
    const policy = client.loopback;
    if (!policy || url.protocol !== 'http:' || url.username || url.password || url.search || url.hash)
        return null;
    const host = url.hostname.replace(/^\[(.*)\]$/, '$1').toLowerCase();
    if (!policy.hosts.includes(host) || url.pathname !== policy.path)
        return null;
    if (policy.allowDynamicPorts && !url.port)
        return null;
    return url.toString();
}
export function isValidOpaqueState(value) {
    return value.length >= 32 && value.length <= 512 && /^[A-Za-z0-9._~-]+$/.test(value);
}
export function isValidS256Challenge(value) {
    return value.length === 43 && /^[A-Za-z0-9_-]+$/.test(value);
}
export function verifyS256(verifier, challenge) {
    if (verifier.length < 43 || verifier.length > 128 || !/^[A-Za-z0-9._~-]+$/.test(verifier))
        return false;
    const actual = crypto.createHash('sha256').update(verifier).digest('base64url');
    const left = Buffer.from(actual);
    const right = Buffer.from(challenge);
    return left.length === right.length && crypto.timingSafeEqual(left, right);
}
export function appendAuthorizationResult(redirectUri, values) {
    const url = new URL(redirectUri);
    for (const [key, value] of Object.entries(values))
        url.searchParams.set(key, value);
    return url.toString();
}
