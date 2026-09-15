import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadSigningKeyFromKeychain } from './signingKeyEnv.js';
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const AUTH_ROOT = path.resolve(__dirname, '..');
const DEFAULT_CONFIG_PATH = path.join(AUTH_ROOT, 'config', 'example-app.json');
function resolveConfiguredPaths() {
    const configuredPaths = (process.env.AUTH_APP_CONFIG_PATHS || '').trim();
    if (configuredPaths) {
        return configuredPaths
            .split(path.delimiter)
            .map((entry) => entry.trim())
            .filter(Boolean);
    }
    return [process.env.AUTH_APP_CONFIG_PATH || DEFAULT_CONFIG_PATH];
}
function resolveActiveAppIds() {
    const seen = new Set();
    const appIds = [];
    for (const configPath of resolveConfiguredPaths()) {
        const appId = path.basename(configPath, path.extname(configPath)).trim().toLowerCase() || 'example-app';
        if (seen.has(appId))
            continue;
        seen.add(appId);
        appIds.push(appId);
    }
    return appIds;
}
function envCandidatesForActiveApp() {
    const candidates = [
        path.join(AUTH_ROOT, '.env.local'),
        path.join(AUTH_ROOT, '.env'),
    ];
    for (const activeAppId of resolveActiveAppIds()) {
        candidates.push(path.join(AUTH_ROOT, `.env.${activeAppId}`));
    }
    const extraEnvFiles = (process.env.AUTH_ENV_FILES || '')
        .split(path.delimiter)
        .map((entry) => entry.trim())
        .filter(Boolean)
        .map((entry) => path.resolve(entry));
    if (extraEnvFiles.length > 0) {
        candidates.push(...extraEnvFiles);
    }
    return [...new Set(candidates)];
}
function normalizeEnvValue(rawValue) {
    const trimmed = rawValue.trim();
    if (!trimmed)
        return '';
    const withoutComment = trimmed.replace(/\s+#.*$/, '');
    if ((withoutComment.startsWith('"') && withoutComment.endsWith('"'))
        || (withoutComment.startsWith("'") && withoutComment.endsWith("'"))) {
        return withoutComment.slice(1, -1);
    }
    return withoutComment;
}
function applyEnvFile(filePath) {
    if (!existsSync(filePath))
        return;
    const raw = readFileSync(filePath, 'utf8');
    for (const line of raw.split(/\r?\n/)) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#'))
            continue;
        const separatorIndex = trimmed.indexOf('=');
        if (separatorIndex <= 0)
            continue;
        const key = trimmed.slice(0, separatorIndex).trim();
        const value = normalizeEnvValue(trimmed.slice(separatorIndex + 1));
        if (!key || process.env[key] !== undefined)
            continue;
        process.env[key] = value;
    }
}
let loaded = false;
export function loadWorkspaceEnvFiles() {
    if (loaded)
        return;
    for (const candidate of envCandidatesForActiveApp()) {
        applyEnvFile(candidate);
    }
    loadSigningKeyFromKeychain();
    loaded = true;
}
loadWorkspaceEnvFiles();
