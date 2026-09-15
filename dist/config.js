import { copyFileSync, existsSync, mkdirSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import './env.js';
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DEFAULT_CONFIG_PATH = path.resolve(__dirname, '..', 'config', 'example-app.json');
function normalizeOrigin(origin) {
    return origin.replace(/\/+$/, '');
}
export class AuthConfigSelectionError extends Error {
    code = 'AUTH_CONFIG_NOT_FOUND';
    status = 403;
    constructor(message = 'No auth app config matches this request') {
        super(message);
        this.name = 'AuthConfigSelectionError';
    }
}
export function resolveConfigPath() {
    return path.resolve(process.env.AUTH_APP_CONFIG_PATH || DEFAULT_CONFIG_PATH);
}
export function resolveConfigPaths() {
    const configuredPaths = (process.env.AUTH_APP_CONFIG_PATHS || '').trim();
    if (!configuredPaths)
        return [resolveConfigPath()];
    return [...new Set(configuredPaths
            .split(path.delimiter)
            .map((entry) => entry.trim())
            .filter(Boolean)
            .map((entry) => path.resolve(entry)))];
}
export function getPort() {
    return Number.parseInt(process.env.AUTH_PORT || '1111', 10);
}
export function getDbPath() {
    const explicitDbPath = String(process.env.AUTH_DB_PATH || '').trim();
    if (explicitDbPath)
        return path.resolve(explicitDbPath);
    const legacyDbPath = path.resolve(__dirname, '..', 'data', 'auth.sqlite');
    const localDbDir = path.join(os.tmpdir(), 'chatty-auth');
    const localDbPath = path.join(localDbDir, 'auth.sqlite');
    if (!existsSync(localDbPath) && existsSync(legacyDbPath)) {
        mkdirSync(localDbDir, { recursive: true });
        copyFileSync(legacyDbPath, localDbPath);
        for (const suffix of ['-wal', '-shm']) {
            const legacySidecar = `${legacyDbPath}${suffix}`;
            if (existsSync(legacySidecar)) {
                copyFileSync(legacySidecar, `${localDbPath}${suffix}`);
            }
        }
    }
    return path.resolve(localDbPath);
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
export function getRefreshCookieName() {
    return process.env.AUTH_REFRESH_COOKIE_NAME || 'auth_rid';
}
export function getTurnstileSecret() {
    return process.env.TURNSTILE_SECRET_KEY || '';
}
export function getPublicOriginFallback(port = getPort()) {
    return process.env.AUTH_PUBLIC_ORIGIN || `http://localhost:${port}`;
}
function buildConfigFromParsed(parsed) {
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
        publicClients: (parsed.publicClients || []).map((client) => ({
            ...client,
            clientId: client.clientId.trim(),
            authorizationUiUrl: client.authorizationUiUrl.trim(),
            redirectUris: (client.redirectUris || []).map((uri) => uri.trim()),
            scopes: client.scopes || ['openid', 'profile', 'email'],
            loopback: client.loopback ? {
                hosts: client.loopback.hosts.map((host) => host.toLowerCase()),
                path: client.loopback.path,
                allowDynamicPorts: client.loopback.allowDynamicPorts === true,
            } : undefined,
        })),
        sessionFederation: parsed.sessionFederation ? {
            enabled: parsed.sessionFederation.enabled === true,
            assertionSecretEnv: parsed.sessionFederation.assertionSecretEnv.trim(),
        } : undefined,
    };
}
function getRequestHeader(req, name) {
    if (!req)
        return '';
    if (typeof req.get === 'function') {
        const value = req.get(name);
        if (typeof value === 'string')
            return value;
    }
    const headers = req.headers;
    if (!headers || typeof headers !== 'object')
        return '';
    const headerValue = headers[name.toLowerCase()];
    return typeof headerValue === 'string' ? headerValue : '';
}
function getRequestQueryValue(req, key) {
    const query = req?.query;
    if (!query || typeof query !== 'object')
        return '';
    const value = query[key];
    return typeof value === 'string' ? value.trim() : '';
}
function getRequestCandidateAppIds(req) {
    const candidates = [
        getRequestQueryValue(req, 'app'),
        getRequestQueryValue(req, 'appId'),
        getRequestQueryValue(req, 'consumer'),
        getRequestHeader(req, 'x-auth-app-id').trim(),
        typeof req?.body?.product_id === 'string' ? req.body.product_id.trim() : '',
    ]
        .map((value) => value.toLowerCase())
        .filter(Boolean);
    return [...new Set(candidates)];
}
function getRequestCandidateOrigins(req) {
    const candidates = [
        getRequestQueryValue(req, 'origin'),
        getRequestHeader(req, 'origin').trim(),
    ];
    const referer = getRequestHeader(req, 'referer').trim();
    if (referer) {
        try {
            candidates.push(new URL(referer).origin);
        }
        catch {
            // ignore invalid referer
        }
    }
    return [...new Set(candidates.map(normalizeOrigin).filter(Boolean))];
}
function selectRequestConfig(configs, req) {
    if (configs.length <= 1 || !req)
        return configs[0];
    const candidateAppIds = getRequestCandidateAppIds(req);
    for (const candidateAppId of candidateAppIds) {
        const matchedById = configs.find((config) => config.app.id.trim().toLowerCase() === candidateAppId);
        if (matchedById)
            return matchedById;
    }
    if (candidateAppIds.length > 0) {
        throw new AuthConfigSelectionError('No auth app config matches the requested app id');
    }
    const candidateOrigins = getRequestCandidateOrigins(req);
    for (const candidateOrigin of candidateOrigins) {
        const matchedByOrigin = configs.find((config) => config.allowedOrigins.includes(candidateOrigin));
        if (matchedByOrigin)
            return matchedByOrigin;
    }
    if (candidateOrigins.length > 0) {
        throw new AuthConfigSelectionError('No auth app config allows the requested origin');
    }
    return configs[0];
}
export class FileAppConfigStore {
    configPaths;
    configsPromise = null;
    constructor(configPaths = resolveConfigPaths()) {
        this.configPaths = configPaths;
    }
    loadConfigs() {
        if (!this.configsPromise) {
            this.configsPromise = Promise.all(this.configPaths.map(async (configPath) => {
                const raw = await readFile(configPath, 'utf8');
                const parsed = JSON.parse(raw);
                return buildConfigFromParsed(parsed);
            }));
        }
        return this.configsPromise;
    }
    async getConfig(req) {
        const configs = await this.loadConfigs();
        return selectRequestConfig(configs, req);
    }
}
