/**
 * Aligns auth session identity with LIFE / Chatty expectations:
 * - id/sub: LIFE-format user id (name_timestamp)
 * - uid: Supabase public.users.id (UUID) when available
 *
 * Uses Supabase PostgREST with the service role key (no @supabase/js dependency).
 */

export type LifeProfileResult = {
  lifeUserId: string;
  supabaseUserId: string | null;
  source: 'cache' | 'supabase_found' | 'supabase_upserted' | 'local_only';
};

function trimSupabaseUrl(url: string) {
  return url.replace(/\/+$/, '');
}

function getSupabaseRestConfig() {
  const url = trimSupabaseUrl((process.env.SUPABASE_URL || '').trim());
  const key = (process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_SERVICE_KEY || '').trim();
  return url && key ? { url, key } : null;
}

/** Same rules as chatty/server/lib/userRegistry.js `generateLIFEUserId`. */
export function generateLIFEUserId(name: string | null | undefined, email: string | null, timestamp: number | null = null) {
  const ts = timestamp ?? Date.now();
  let userName = 'user';

  if (name?.trim()) {
    userName = name
      .replace(/[^a-z0-9]/gi, '_')
      .toLowerCase()
      .replace(/_+/g, '_')
      .replace(/^_|_$/g, '');
  } else if (email) {
    const emailName = email.split('@')[0]?.replace(/[^a-z0-9]/gi, '_').toLowerCase() ?? '';
    if (emailName.length > 0) userName = emailName;
  }

  return `${userName}_${ts}`;
}

async function supabaseRequest(
  path: string,
  init: RequestInit & { prefer?: string } = {},
) {
  const cfg = getSupabaseRestConfig();
  if (!cfg) return null;

  const headers: Record<string, string> = {
    apikey: cfg.key,
    Authorization: `Bearer ${cfg.key}`,
    ...(init.headers as Record<string, string>),
  };
  if (init.prefer) headers.Prefer = init.prefer;

  const res = await fetch(`${cfg.url}/rest/v1/${path}`, { ...init, headers });
  const text = await res.text();
  let json: unknown;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = null;
  }
  return { ok: res.ok, status: res.status, json, text };
}

type SupabaseUserRow = {
  id?: string;
  email?: string;
  life_user_id?: string | null;
  name?: string | null;
  display_name?: string | null;
};

async function fetchUsersByEmail(email: string): Promise<SupabaseUserRow[]> {
  const encoded = encodeURIComponent(email.toLowerCase());
  const r = await supabaseRequest(`users?email=eq.${encoded}&select=id,email,name,display_name`, { method: 'GET' });
  if (!r?.ok || !Array.isArray(r.json)) return [];
  return r.json as SupabaseUserRow[];
}

/** True if `public.users` has a row for this email (LIFE / shared registry). No writes. */
export async function isEmailInLifeRegistry(email: string): Promise<boolean> {
  if (!getSupabaseRestConfig()) return false;
  const rows = await fetchUsersByEmail(email);
  return rows.length > 0;
}

async function fetchLifeUserIdColumn(userId: string): Promise<string | null> {
  const r = await supabaseRequest(
    `users?id=eq.${encodeURIComponent(userId)}&select=life_user_id`,
    { method: 'GET' },
  );
  if (!r?.ok || !Array.isArray(r.json) || !r.json[0]) return null;
  const v = (r.json[0] as SupabaseUserRow).life_user_id;
  return typeof v === 'string' && v.trim() ? v.trim() : null;
}

async function patchLifeUserId(userId: string, lifeUserId: string) {
  await supabaseRequest(`users?id=eq.${encodeURIComponent(userId)}`, {
    method: 'PATCH',
    prefer: 'return=minimal',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ life_user_id: lifeUserId }),
  });
}

async function upsertSupabaseUser(email: string, displayName: string): Promise<string | null> {
  const nameSlug = (email.split('@')[0] || 'user')
    .replace(/[^a-z0-9]/gi, '_')
    .toLowerCase()
    .slice(0, 50);
  const name = `${nameSlug}_${Date.now()}`;
  const body: Record<string, string> = {
    email: email.toLowerCase(),
    name,
  };
  if (displayName.trim()) body.display_name = displayName.trim();

  const r = await supabaseRequest('users', {
    method: 'POST',
    prefer: 'resolution=merge-duplicates,return=representation',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (r?.ok && Array.isArray(r.json) && r.json[0]?.id) {
    return String((r.json[0] as SupabaseUserRow).id);
  }
  const retry = await fetchUsersByEmail(email);
  return retry[0]?.id ? String(retry[0].id) : null;
}

export type ResolveLifeProfileInput = {
  email: string;
  displayName: string;
  cachedLifeUserId?: string | null;
  cachedSupabaseUserId?: string | null;
};

export async function resolveLifeProfile(input: ResolveLifeProfileInput): Promise<LifeProfileResult> {
  const email = input.email.toLowerCase();
  const displayName = input.displayName?.trim() || email.split('@')[0] || 'User';

  if (input.cachedLifeUserId?.trim() && input.cachedSupabaseUserId?.trim()) {
    return {
      lifeUserId: input.cachedLifeUserId.trim(),
      supabaseUserId: input.cachedSupabaseUserId.trim(),
      source: 'cache',
    };
  }

  const cfg = getSupabaseRestConfig();
  if (!cfg) {
    const lifeUserId = input.cachedLifeUserId?.trim()
      || generateLIFEUserId(displayName, email);
    return {
      lifeUserId,
      supabaseUserId: input.cachedSupabaseUserId?.trim() || null,
      source: 'local_only',
    };
  }

  let rows = await fetchUsersByEmail(email);
  let supabaseUserId: string | null = rows[0]?.id ? String(rows[0].id) : null;
  let source: LifeProfileResult['source'] = supabaseUserId ? 'supabase_found' : 'supabase_upserted';

  if (!supabaseUserId) {
    supabaseUserId = await upsertSupabaseUser(email, displayName);
    if (!supabaseUserId) {
      const lifeUserId = input.cachedLifeUserId?.trim()
        || generateLIFEUserId(displayName, email);
      return { lifeUserId, supabaseUserId: null, source: 'local_only' };
    }
    rows = await fetchUsersByEmail(email);
    source = 'supabase_upserted';
  }

  let lifeUserId: string | null = input.cachedLifeUserId?.trim() || null;
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
