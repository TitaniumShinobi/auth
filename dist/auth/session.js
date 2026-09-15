import crypto from 'node:crypto';
function base64UrlEncode(value) {
    return Buffer.from(value).toString('base64url');
}
function base64UrlDecode(value) {
    return Buffer.from(value, 'base64url').toString('utf8');
}
export function createSessionToken(user, secret, maxAgeSeconds) {
    const now = Math.floor(Date.now() / 1000);
    const payload = {
        ...user,
        iat: now,
        exp: now + maxAgeSeconds,
    };
    const encodedPayload = base64UrlEncode(JSON.stringify(payload));
    const signature = crypto.createHmac('sha256', secret).update(encodedPayload).digest('base64url');
    return `${encodedPayload}.${signature}`;
}
export function verifySessionToken(token, secret) {
    const [encodedPayload, providedSignature] = token.split('.');
    if (!encodedPayload || !providedSignature)
        return null;
    const expectedSignature = crypto.createHmac('sha256', secret).update(encodedPayload).digest('base64url');
    if (providedSignature.length !== expectedSignature.length) {
        return null;
    }
    if (!crypto.timingSafeEqual(Buffer.from(providedSignature), Buffer.from(expectedSignature))) {
        return null;
    }
    try {
        const payload = JSON.parse(base64UrlDecode(encodedPayload));
        if (!payload.exp || payload.exp < Math.floor(Date.now() / 1000))
            return null;
        return payload;
    }
    catch {
        return null;
    }
}
export function parseCookieHeader(headerValue) {
    if (!headerValue)
        return {};
    return headerValue.split(';').reduce((accumulator, part) => {
        const [rawKey, ...valueParts] = part.trim().split('=');
        if (!rawKey)
            return accumulator;
        accumulator[rawKey] = decodeURIComponent(valueParts.join('=') || '');
        return accumulator;
    }, {});
}
export function createSetCookieHeader(name, value, maxAgeSeconds, secure, domain) {
    const parts = [
        `${name}=${encodeURIComponent(value)}`,
        'Path=/',
        'HttpOnly',
        'SameSite=Lax',
        `Max-Age=${maxAgeSeconds}`,
    ];
    if (domain)
        parts.push(`Domain=${domain}`);
    if (secure)
        parts.push('Secure');
    return parts.join('; ');
}
export function createClearCookieHeader(name, secure, domain) {
    const parts = [
        `${name}=`,
        'Path=/',
        'HttpOnly',
        'SameSite=Lax',
        'Max-Age=0',
    ];
    if (domain)
        parts.push(`Domain=${domain}`);
    if (secure)
        parts.push('Secure');
    return parts.join('; ');
}
