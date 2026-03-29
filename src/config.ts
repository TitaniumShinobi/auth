import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import './env.js';
import type { AppConfigStore, AuthAppConfig } from './types.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DEFAULT_CONFIG_PATH = path.resolve(__dirname, '..', 'config', 'code.json');

function normalizeOrigin(origin: string): string {
  return origin.replace(/\/+$/, '');
}

export function resolveConfigPath() {
  return path.resolve(process.env.AUTH_APP_CONFIG_PATH || DEFAULT_CONFIG_PATH);
}

export function getPort() {
  return Number.parseInt(process.env.AUTH_PORT || '1111', 10);
}

export function getDbPath() {
  return path.resolve(process.env.AUTH_DB_PATH || path.resolve(__dirname, '..', 'data', 'auth.sqlite'));
}

export function getSessionSecret() {
  return process.env.AUTH_SESSION_SECRET || 'dev-auth-session-secret-change-me';
}

export function getProviderTokenSecret() {
  return process.env.AUTH_PROVIDER_TOKEN_SECRET || getSessionSecret();
}

export function getCookieName() {
  return process.env.AUTH_COOKIE_NAME || 'auth_sid';
}

export function getTurnstileSecret() {
  return process.env.TURNSTILE_SECRET_KEY || '';
}

export function getPublicOriginFallback(port = getPort()) {
  return process.env.AUTH_PUBLIC_ORIGIN || `http://localhost:${port}`;
}

export class FileAppConfigStore implements AppConfigStore {
  constructor(private readonly configPath = resolveConfigPath()) {}

  async getConfig(): Promise<AuthAppConfig> {
    const raw = await readFile(this.configPath, 'utf8');
    const parsed = JSON.parse(raw) as AuthAppConfig;
    return {
      ...parsed,
      oauth: {
        envPrefix: parsed.oauth?.envPrefix || parsed.app?.id?.toUpperCase?.() || undefined,
      },
      allowedOrigins: (parsed.allowedOrigins || []).map(normalizeOrigin),
      redirects: {
        postLoginPath: parsed.redirects?.postLoginPath || '/',
        postLogoutPath: parsed.redirects?.postLogoutPath || '/',
      },
      credentials: {
        enabled: parsed.credentials?.enabled !== false,
      },
      turnstile: {
        required: parsed.turnstile?.required === true,
        enabled: parsed.turnstile?.enabled === true,
        siteKey: parsed.turnstile?.siteKey || process.env.TURNSTILE_SITE_KEY || undefined,
      },
      docs: parsed.docs || [],
      providers: (parsed.providers || []).map((provider) => ({
        provider: provider.provider,
        label: provider.label || provider.provider,
        enabled: provider.enabled !== false,
      })),
    };
  }
}
