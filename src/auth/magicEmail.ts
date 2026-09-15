import crypto from 'node:crypto';
import type { EphemeralAuthStore } from './ephemeralStore.js';

export interface MagicEmailDelivery {
  isConfigured(): boolean;
  send(input: { email: string; url: string; appName: string }): Promise<void>;
}

/** Postal acceptance means queued by Postal, never proof of inbox delivery. */
export function createPostalMagicDelivery(env = process.env, fetchImpl = fetch): MagicEmailDelivery {
  const base = env.AUTH_POSTAL_URL || '';
  const key = env.AUTH_POSTAL_API_KEY || '';
  const from = env.AUTH_MAGIC_EMAIL_FROM || '';
  let endpoint = '';
  try {
    const url = new URL(base);
    if (url.protocol === 'https:' && !url.username && !url.password) endpoint = new URL('/api/v1/send/message', url).toString();
  } catch { /* Unconfigured transport is an explicit unavailable state. */ }
  return {
    isConfigured: () => Boolean(endpoint && key.trim() && from.trim()),
    async send({ email, url, appName }) {
      if (!endpoint || !key.trim() || !from.trim()) throw new Error('MAGIC_EMAIL_NOT_CONFIGURED');
      const response = await fetchImpl(endpoint, {
        method: 'POST', redirect: 'error', signal: AbortSignal.timeout(10000),
        headers: { 'Content-Type': 'application/json', 'X-Server-API-Key': key },
        body: JSON.stringify({ to: [email], from, subject: `Sign in to ${appName}`, plain_body: `Continue to ${appName}:\n${url}\n\nThis link expires shortly and can be used once. If you did not request it, ignore this email.` }),
      });
      const result = await response.json() as { status?: string };
      if (!response.ok || result.status !== 'success') throw new Error('MAGIC_EMAIL_DELIVERY_FAILED');
    },
  };
}

export type MagicChallenge = { email: string; appId: string; origin: string; intent: 'login' | 'signup' };
const keyFor = (token: string) => `auth:magic:${crypto.createHash('sha256').update(token).digest('hex')}`;

export async function sendMagicChallenge(store: EphemeralAuthStore, delivery: MagicEmailDelivery, record: MagicChallenge, appName: string) {
  const token = crypto.randomBytes(32).toString('base64url');
  const key = keyFor(token);
  // Store only after delivery is accepted: failed delivery never leaves a usable challenge.
  const url = new URL('/', record.origin);
  url.hash = new URLSearchParams({ magic_token: token }).toString();
  await delivery.send({ email: record.email, url: url.toString(), appName });
  await store.setJson(key, record, 600);
}

export async function consumeMagicChallenge(store: EphemeralAuthStore, token: string, appId: string, origin: string) {
  if (!/^[A-Za-z0-9_-]{43}$/.test(token)) return null;
  const key = keyFor(token);
  const record = await store.getJson<MagicChallenge>(key);
  if (!record || record.appId !== appId || record.origin !== origin) return null;
  return store.takeJson<MagicChallenge>(key);
}
