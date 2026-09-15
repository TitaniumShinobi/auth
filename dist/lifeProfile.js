/**
 * Aligns auth session identity with LIFE / Chatty expectations:
 * - id/sub: LIFE-format user id (name_timestamp)
 * - uid: Supabase public.users.id (UUID) when available
 *
 * Uses Supabase PostgREST with the service role key (no @supabase/js dependency).
 */
const SUPABASE_QUERY_TIMEOUT_MS = Number(process.env.SUPABASE_QUERY_TIMEOUT_MS || 2500);
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
function normalizeEmail(email) {
    return String(email || '').trim().toLowerCase();
}
function isSupabaseUuid(value) {
    return typeof value === 'string' && UUID_RE.test(value.trim());
}
function parseConfiguredEmailMap(envKey, validator) {
    const mapped = new Map();
    const configured = String(process.env[envKey] || '').trim();
    if (!configured)
        return mapped;
    for (const entry of configured.split(',')) {
        const [rawEmail, rawValue] = entry.split('=');
        const normalizedEmail = normalizeEmail(rawEmail);
        const normalizedValue = String(rawValue || '').trim();
        if (!normalizedEmail || !normalizedValue)
            continue;
        if (validator && !validator(normalizedValue))
            continue;
        mapped.set(normalizedEmail, normalizedValue);
    }
    return mapped;
}
function resolveLocalRegistryLifeUserId(email) {
    const configured = parseConfiguredEmailMap('AUTH_CANONICAL_EMAIL_LIFE_IDS');
    return configured.get(normalizeEmail(email)) || null;
}
function resolveLocalRegistrySupabaseUserId(email) {
    const configured = parseConfiguredEmailMap('AUTH_CANONICAL_EMAIL_SUPABASE_IDS', isSupabaseUuid);
    return configured.get(normalizeEmail(email)) || null;
}
function trimSupabaseUrl(url) {
    return url.replace(/\/+$/, '');
}
function getSupabaseRestConfig() {
    const url = trimSupabaseUrl((process.env.SUPABASE_URL || '').trim());
    const key = (process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_SERVICE_KEY || '').trim();
    return url && key ? { url, key } : null;
}
/** Same rules as chatty/server/lib/userRegistry.js `generateLIFEUserId`. */
export function generateLIFEUserId(name, email, timestamp = null) {
    const ts = timestamp ?? Date.now();
    let userName = 'user';
    if (name?.trim()) {
        userName = name
            .replace(/[^a-z0-9]/gi, '_')
            .toLowerCase()
            .replace(/_+/g, '_')
            .replace(/^_|_$/g, '');
    }
    else if (email) {
        const emailName = email.split('@')[0]?.replace(/[^a-z0-9]/gi, '_').toLowerCase() ?? '';
        if (emailName.length > 0)
            userName = emailName;
    }
    return `${userName}_${ts}`;
}
async function supabaseRequest(path, init = {}) {
    const cfg = getSupabaseRestConfig();
    if (!cfg)
        return null;
    const headers = {
        apikey: cfg.key,
        Authorization: `Bearer ${cfg.key}`,
        ...init.headers,
    };
    if (init.prefer)
        headers.Prefer = init.prefer;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(new Error('timeout')), SUPABASE_QUERY_TIMEOUT_MS);
    try {
        const res = await fetch(`${cfg.url}/rest/v1/${path}`, {
            ...init,
            headers,
            signal: init.signal || controller.signal,
        });
        const text = await res.text();
        let json;
        try {
            json = text ? JSON.parse(text) : null;
        }
        catch {
            json = null;
        }
        return { ok: res.ok, status: res.status, json, text, timedOut: false };
    }
    catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        if (message === 'timeout' || error instanceof DOMException) {
            return {
                ok: false,
                status: null,
                json: null,
                text: '',
                timedOut: true,
            };
        }
        throw error;
    }
    finally {
        clearTimeout(timeoutId);
    }
}
async function fetchUsersByEmail(email) {
    const encoded = encodeURIComponent(email.toLowerCase());
    const r = await supabaseRequest(`users?email=eq.${encoded}&select=id,email,name,display_name`, { method: 'GET' });
    if (!r?.ok || !Array.isArray(r.json))
        return [];
    return r.json;
}
/** True if `public.users` has a row for this email (LIFE / shared registry). No writes. */
export async function isEmailInLifeRegistry(email) {
    if (!getSupabaseRestConfig())
        return false;
    const rows = await fetchUsersByEmail(email);
    return rows.length > 0;
}
async function fetchLifeUserIdColumn(userId) {
    const r = await supabaseRequest(`users?id=eq.${encodeURIComponent(userId)}&select=life_user_id`, { method: 'GET' });
    if (!r?.ok || !Array.isArray(r.json) || !r.json[0])
        return null;
    const v = r.json[0].life_user_id;
    return typeof v === 'string' && v.trim() ? v.trim() : null;
}
async function patchLifeUserId(userId, lifeUserId) {
    await supabaseRequest(`users?id=eq.${encodeURIComponent(userId)}`, {
        method: 'PATCH',
        prefer: 'return=minimal',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ life_user_id: lifeUserId }),
    });
}
async function upsertSupabaseUser(email, displayName) {
    const nameSlug = (email.split('@')[0] || 'user')
        .replace(/[^a-z0-9]/gi, '_')
        .toLowerCase()
        .slice(0, 50);
    const name = `${nameSlug}_${Date.now()}`;
    const body = {
        email: email.toLowerCase(),
        name,
    };
    if (displayName.trim())
        body.display_name = displayName.trim();
    const r = await supabaseRequest('users', {
        method: 'POST',
        prefer: 'resolution=merge-duplicates,return=representation',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
    });
    if (r?.ok && Array.isArray(r.json) && r.json[0]?.id) {
        return String(r.json[0].id);
    }
    const retry = await fetchUsersByEmail(email);
    return retry[0]?.id ? String(retry[0].id) : null;
}
export async function resolveLifeProfile(input) {
    const email = normalizeEmail(input.email);
    const displayName = input.displayName?.trim() || email.split('@')[0] || 'User';
    const cachedLifeUserId = input.cachedLifeUserId?.trim() || null;
    const cachedSupabaseUserId = input.cachedSupabaseUserId?.trim() || null;
    if (cachedLifeUserId && cachedSupabaseUserId) {
        return {
            lifeUserId: cachedLifeUserId,
            supabaseUserId: cachedSupabaseUserId,
            source: 'cache',
        };
    }
    const localRegistryLifeUserId = resolveLocalRegistryLifeUserId(email);
    const localRegistrySupabaseUserId = resolveLocalRegistrySupabaseUserId(email);
    if (localRegistrySupabaseUserId) {
        return {
            lifeUserId: cachedLifeUserId || localRegistryLifeUserId || generateLIFEUserId(displayName, email),
            supabaseUserId: localRegistrySupabaseUserId,
            source: 'local_registry',
        };
    }
    const cfg = getSupabaseRestConfig();
    if (!cfg) {
        const lifeUserId = cachedLifeUserId
            || localRegistryLifeUserId
            || generateLIFEUserId(displayName, email);
        return {
            lifeUserId,
            supabaseUserId: cachedSupabaseUserId || null,
            source: 'local_only',
        };
    }
    let rows = await fetchUsersByEmail(email);
    let supabaseUserId = rows[0]?.id ? String(rows[0].id) : null;
    let source = supabaseUserId ? 'supabase_found' : 'supabase_upserted';
    if (!supabaseUserId) {
        supabaseUserId = await upsertSupabaseUser(email, displayName);
        if (!supabaseUserId) {
            const lifeUserId = cachedLifeUserId
                || localRegistryLifeUserId
                || generateLIFEUserId(displayName, email);
            return { lifeUserId, supabaseUserId: null, source: 'local_only' };
        }
        rows = await fetchUsersByEmail(email);
        source = 'supabase_upserted';
    }
    let lifeUserId = cachedLifeUserId || localRegistryLifeUserId || null;
    if (!lifeUserId) {
        lifeUserId = await fetchLifeUserIdColumn(supabaseUserId);
    }
    if (!lifeUserId) {
        lifeUserId = generateLIFEUserId(displayName, email);
        await patchLifeUserId(supabaseUserId, lifeUserId);
    }
    return {
        lifeUserId,
        supabaseUserId,
        source,
    };
}
