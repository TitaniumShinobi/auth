const fail = () => { throw Object.assign(new Error('CANONICAL_CONSENT_POLICY_UNAVAILABLE'), { code: 'CANONICAL_CONSENT_POLICY_UNAVAILABLE' }); };
export async function canonicalConsentManifest(env = process.env, fetchImpl = fetch) {
    let origin;
    try {
        origin = new URL(env.AUTH_ENROLLMENT_AUTHORITY_ORIGIN || '');
    }
    catch {
        return fail();
    }
    if (origin.origin !== String(env.AUTH_ENROLLMENT_AUTHORITY_ORIGIN).replace(/\/$/, '') || origin.username || origin.password || (origin.protocol !== 'https:' && !(origin.protocol === 'http:' && ['localhost', '127.0.0.1'].includes(origin.hostname))))
        return fail();
    const response = await fetchImpl(new URL('/api/auth/enrollment/documents', origin), { redirect: 'error', signal: AbortSignal.timeout(5000), headers: { accept: 'application/json' } });
    if (!response.ok)
        return fail();
    const body = await response.json();
    if (body.authority !== 'vvault' || body.version !== 'vvault.enrollment.documents.v1')
        return fail();
    const docs = body.documents;
    if (!Array.isArray(docs) || !docs.length || docs.length !== 3)
        return fail();
    const keys = new Set();
    return docs.map((doc) => {
        if (!doc || typeof doc.key !== 'string' || !doc.key || doc.key.length > 100 || keys.has(doc.key) || !['vvault:terms', 'vvault:privacy', 'vvault:eeccd'].includes(doc.key) || typeof doc.version !== 'string' || !doc.version || doc.version.length > 100 || !/^[a-f0-9]{64}$/.test(doc.sha256) || typeof doc.url !== 'string' || typeof doc.label !== 'string')
            return fail();
        let url;
        try {
            url = new URL(doc.url, origin);
        }
        catch {
            return fail();
        }
        if (url.origin !== origin.origin || url.username || url.password || url.hash)
            return fail();
        keys.add(doc.key);
        return { key: doc.key, version: doc.version, sha256: doc.sha256, url: url.href, label: doc.label };
    });
}
export function acceptedCanonicalConsent(input, documents, now = Math.floor(Date.now() / 1000)) {
    const supplied = input?.canonicalConsent;
    if (supplied?.accepted !== true || !Array.isArray(supplied.documents) || supplied.documents.length !== documents.length)
        return null;
    const triples = (rows) => rows.map(d => JSON.stringify([d?.key, d?.version, d?.sha256])).sort();
    if (JSON.stringify(triples(supplied.documents)) !== JSON.stringify(triples(documents)))
        return null;
    return { authority: 'vvault', acceptedAt: now, documents: documents.map(({ key, version, sha256 }) => ({ key, version, sha256 })) };
}
