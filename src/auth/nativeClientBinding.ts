import type { AuthAppConfig, NativeClientBinding } from '../types.js';

const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

/** Structural validation only. A signed claim is not current registration. */
export function normalizeNativeClientBinding(value: unknown): NativeClientBinding | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const raw = value as Record<string, unknown>;
  if (typeof raw.clientId !== 'string' || !IDENTIFIER.test(raw.clientId)
    || typeof raw.applicationId !== 'string' || !IDENTIFIER.test(raw.applicationId)) return null;
  return { clientId: raw.clientId, applicationId: raw.applicationId };
}

/** Call only with the server configuration selected for the OAuth transaction. */
export function deriveNativeClientBinding(config: AuthAppConfig, clientId: string): NativeClientBinding | null {
  const matches = (config.publicClients || []).filter(client => client.clientId === clientId);
  if (matches.length !== 1) return null;
  return normalizeNativeClientBinding({ clientId, applicationId: config.app.id });
}

export function registeredNativeClientBinding(config: AuthAppConfig, value: unknown): NativeClientBinding | null {
  const binding = normalizeNativeClientBinding(value);
  if (!binding) return null;
  const current = deriveNativeClientBinding(config, binding.clientId);
  return current?.applicationId === binding.applicationId ? current : null;
}
