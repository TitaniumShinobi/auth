import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, '..', '..');
const DEFAULT_CONFIG_PATH = path.join(REPO_ROOT, 'auth', 'config', 'code.json');

function resolveActiveAppId() {
  const configPath = process.env.AUTH_APP_CONFIG_PATH || DEFAULT_CONFIG_PATH;
  return path.basename(configPath, path.extname(configPath)).trim().toLowerCase() || 'code';
}

function envCandidatesForActiveApp() {
  const activeAppId = resolveActiveAppId();
  const candidates = [
    path.join(REPO_ROOT, 'auth', '.env.local'),
    path.join(REPO_ROOT, 'auth', '.env'),
    path.join(REPO_ROOT, activeAppId, '.env'),
  ];

  if (activeAppId === 'chatty') {
    candidates.push(path.join(REPO_ROOT, 'chatty', 'server', '.env'));
  }

  candidates.push(path.join(REPO_ROOT, '.env'));
  return candidates;
}

function normalizeEnvValue(rawValue: string) {
  const trimmed = rawValue.trim();
  if (!trimmed) return '';
  const withoutComment = trimmed.replace(/\s+#.*$/, '');
  if (
    (withoutComment.startsWith('"') && withoutComment.endsWith('"'))
    || (withoutComment.startsWith("'") && withoutComment.endsWith("'"))
  ) {
    return withoutComment.slice(1, -1);
  }
  return withoutComment;
}

function applyEnvFile(filePath: string) {
  if (!existsSync(filePath)) return;
  const raw = readFileSync(filePath, 'utf8');
  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const separatorIndex = trimmed.indexOf('=');
    if (separatorIndex <= 0) continue;
    const key = trimmed.slice(0, separatorIndex).trim();
    const value = normalizeEnvValue(trimmed.slice(separatorIndex + 1));
    if (!key || process.env[key] !== undefined) continue;
    process.env[key] = value;
  }
}

let loaded = false;

export function loadWorkspaceEnvFiles() {
  if (loaded) return;
  for (const candidate of envCandidatesForActiveApp()) {
    applyEnvFile(candidate);
  }
  loaded = true;
}

loadWorkspaceEnvFiles();
