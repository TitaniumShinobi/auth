import crypto from 'node:crypto';
import path from 'node:path';
import express from 'express';

import {
  FileAppConfigStore,
  getCookieName,
  getDbPath,
  getProviderTokenSecret,
  getPublicOriginFallback,
  getSessionSecret,
} from './config.js';
import {
  createGoogleProviderClient,
  createGitHubProviderClient,
  OAuthStateStore,
  resolveProviderCredentials,
} from './auth/oauth.js';
import {
  buildGitHubAuthorizationUrl,
  exchangeGitHubCodeForAccessToken,
  fetchGitHubViewer,
  listGitHubOwners,
  listGitHubRepos,
  resolveGitHubOAuthCredentials,
} from './github/api.js';
import { decryptProviderToken, encryptProviderToken } from './auth/providerTokens.js';
import { GitHubRepoSessionStore } from './github/repoSession.js';
import { hashPassword, validatePasswordStrength, verifyPassword } from './auth/passwords.js';
import {
  createClearCookieHeader,
  createSessionToken,
  createSetCookieHeader,
  parseCookieHeader,
  verifySessionToken,
} from './auth/session.js';
import { verifyTurnstileToken } from './auth/turnstile.js';
import { MemoryStorageAdapter } from './persistence/memoryStorage.js';
import { SqliteStorageAdapter } from './persistence/sqliteStorage.js';
import {
  isEmailInLifeRegistry as defaultIsEmailInLifeRegistry,
  resolveLifeProfile as defaultResolveLifeProfile,
  type LifeProfileResult,
  type ResolveLifeProfileInput,
} from './lifeProfile.js';
import type {
  AppConfigStore,
  AuthAppConfig,
  AuthProviderConfig,
  ConsentAcceptance,
  OAuthProviderClient,
  SessionUser,
  StoredUser,
  StorageAdapter,
  TurnstileVerifier,
} from './types.js';

const SESSION_MAX_AGE_SECONDS = 60 * 60 * 24 * 30;
const EXCHANGE_CODE_TTL_MS = 2 * 60 * 1000;

type ExchangeCodeRecord = {
  token: string;
  origin: string;
  createdAt: number;
};

type AuthenticatedSession = {
  token: string;
  session: SessionUser;
};

type AuthenticatedUserContext = AuthenticatedSession & {
  user: StoredUser;
};

function trimTrailingSlash(value: string) {
  return value.replace(/\/+$/, '');
}

function resolveRequestOrigin(req: any, config: AuthAppConfig) {
  const queryOrigin =
    req?.query && typeof req.query.origin === 'string'
      ? trimTrailingSlash(req.query.origin)
      : '';
  if (queryOrigin && config.allowedOrigins.includes(queryOrigin)) {
    return queryOrigin;
  }

  const originHeader = typeof req.get === 'function' ? req.get('origin') : undefined;
  if (originHeader && config.allowedOrigins.includes(trimTrailingSlash(originHeader))) {
    return trimTrailingSlash(originHeader);
  }

  const refererHeader = typeof req.get === 'function' ? req.get('referer') : undefined;
  if (refererHeader) {
    try {
      const refererOrigin = new URL(refererHeader).origin;
      if (config.allowedOrigins.includes(trimTrailingSlash(refererOrigin))) {
        return trimTrailingSlash(refererOrigin);
      }
    } catch {
      // ignore invalid referer
    }
  }

  const protoHeader = typeof req.get === 'function' ? req.get('x-forwarded-proto') : undefined;
  const forwardedProto = protoHeader ? String(protoHeader).split(',')[0].trim() : '';
  const proto = forwardedProto || (req.secure ? 'https' : 'http');
  const host = typeof req.get === 'function' ? req.get('host') : undefined;
  const hostOrigin = host ? `${proto}://${host}` : getPublicOriginFallback();
  const normalizedHostOrigin = trimTrailingSlash(hostOrigin);
  if (config.allowedOrigins.includes(normalizedHostOrigin)) return normalizedHostOrigin;
  return config.allowedOrigins[0] || normalizedHostOrigin;
}

function getClientIp(req: any) {
  const forwarded = typeof req.get === 'function' ? req.get('x-forwarded-for') : '';
  return forwarded?.split(',')[0]?.trim() || req.socket?.remoteAddress || null;
}

function readAuthSession(
  req: any,
  cookieName: string,
  sessionSecret: string,
): AuthenticatedSession | { status: number; error: string } {
  const cookies = parseCookieHeader(req.headers.cookie);
  const token = cookies[cookieName];
  if (!token) {
    return { status: 401, error: 'No active session' } as const;
  }
  const session = verifySessionToken(token, sessionSecret);
  if (!session) {
    return { status: 401, error: 'Session expired' } as const;
  }
  return {
    token,
    session,
  } satisfies AuthenticatedSession;
}

function resolveCallbackUrl(req: any, config: AuthAppConfig, providerId: string) {
  const explicitCallback = resolveProviderCredentials(providerId, config).callbackUrl;
  if (explicitCallback) return explicitCallback;
  const origin = resolveRequestOrigin(req, config);
  return `${origin}/api/auth/${providerId}/callback`;
}

function applyCorsHeaders(req: any, res: any, config: AuthAppConfig) {
  const originHeader = typeof req.get === 'function' ? req.get('origin') : undefined;
  if (!originHeader) return false;

  const origin = trimTrailingSlash(originHeader);
  if (!config.allowedOrigins.includes(origin)) return false;

  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Vary', 'Origin');
  return true;
}

function requiredConsentDocs(config: AuthAppConfig) {
  return config.docs.filter((doc) => doc.required);
}

function buildAcceptedConsentDocs(config: AuthAppConfig, consent: Record<string, boolean>) {
  return requiredConsentDocs(config).map<ConsentAcceptance>((doc) => ({
    key: doc.key,
    version: doc.version,
    label: doc.label,
    url: doc.url,
    acceptedAt: new Date().toISOString(),
  })).filter((doc) => consent[doc.key] === true);
}

function missingRequiredConsent(config: AuthAppConfig, consent: Record<string, boolean>) {
  return requiredConsentDocs(config).find((doc) => consent[doc.key] !== true) ?? null;
}

/** User-facing copy when a Code user exists but has no password (OAuth-only). Not used for LIFE registry hint. */
function credentialLoginUnavailableMessage(authProvider: string | null | undefined): string {
  const p = String(authProvider || '').toLowerCase();
  if (p === 'google') {
    return 'This account uses Google sign-in. Use the Google button to continue.';
  }
  if (p === 'github') {
    return 'This account uses GitHub sign-in. Use the GitHub button to continue.';
  }
  return 'This account does not use email and password. Sign in with your linked sign-in provider.';
}

async function hasRequiredConsentForApp(
  storage: StorageAdapter,
  config: AuthAppConfig,
  userId: string,
) {
  const requiredKeys = requiredConsentDocs(config).map((doc) => doc.key);
  return storage.hasAcceptedConsentKeys(userId, config.app.id, requiredKeys);
}

async function readAuthenticatedUser(
  req: any,
  storage: StorageAdapter,
  cookieName: string,
  sessionSecret: string,
): Promise<AuthenticatedUserContext | { status: number; error: string }> {
  const authSession = readAuthSession(req, cookieName, sessionSecret);
  if ('error' in authSession) return authSession;
  const user = await storage.findUserByEmail(authSession.session.email);
  if (!user) {
    return { status: 401, error: 'Session user was not found' } as const;
  }
  return {
    ...authSession,
    user,
  } satisfies AuthenticatedUserContext;
}

function parseProviderProfile(profileJson: string) {
  try {
    const parsed = JSON.parse(profileJson) as Record<string, unknown>;
    return parsed && typeof parsed === 'object' ? parsed : {};
  } catch {
    return {};
  }
}

function githubConnectionPayload(account: {
  displayName: string | null;
  avatarUrl: string | null;
  profileJson: string;
}) {
  const profile = parseProviderProfile(account.profileJson);
  const login = typeof profile.login === 'string' ? profile.login : undefined;
  return {
    connected: true as const,
    login,
    name: account.displayName || (typeof profile.name === 'string' ? profile.name : undefined),
    avatarUrl: account.avatarUrl || undefined,
  };
}

function getHydroConstructId() {
  return (process.env.CODE_HYDRO_CONSTRUCT_ID || 'hydro-001').trim();
}

function getHydroRuntimeSelection() {
  return {
    provider: 'openai',
    model: 'gpt-4o-mini',
  };
}

function getHydroModelLabel() {
  return 'GPT-4o mini';
}

function getHydroCanonicalModeLabel(mode: string) {
  if (mode === 'chat') return 'Chat';
  if (mode === 'plan') return 'Plan';
  if (mode === 'custom') return 'Custom';
  return 'Hydro';
}

const HYDRO_TASK_COMMENT_RE = /<!--\s*hydro_task\s+({[\s\S]*?})\s*-->/i;
const HYDRO_MESSAGE_COMMENT_RE = /<!--\s*hydro_message\s+({[\s\S]*?})\s*-->/i;

function parseJsonObject(value: string) {
  try {
    const parsed = JSON.parse(value) as Record<string, unknown>;
    return parsed && typeof parsed === 'object' ? parsed : {};
  } catch {
    return {};
  }
}

function normalizeAskTaskKind(value: unknown) {
  return value === 'chat' || value === 'plan' || value === 'regular'
    ? value
    : undefined;
}

function askTaskKindForMode(mode: string) {
  if (mode === 'chat') return 'chat';
  if (mode === 'plan') return 'plan';
  return 'regular';
}

function deriveAskTaskTitle(content: string) {
  const normalized = String(content || '')
    .replace(/```[\s\S]*?```/g, ' ')
    .replace(/`[^`]+`/g, ' ')
    .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '$1')
    .replace(/[#>*_~-]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  if (!normalized) return 'New request';
  const sentence = normalized.split(/[.!?](?:\s|$)/).map((part) => part.trim()).find(Boolean) || normalized;
  return sentence.length > 72 ? `${sentence.slice(0, 69).trimEnd()}...` : sentence;
}

function createAskTaskId(startedAt: number, title: string) {
  const slug = slugifyHydroProjectName(title || 'request').slice(0, 32) || 'request';
  return `task_${startedAt}_${slug}_${crypto.randomBytes(3).toString('hex')}`;
}

function parseDecoratedTranscriptContent(content: string) {
  const taskMetadata = content.match(HYDRO_TASK_COMMENT_RE)?.[1]
    ? parseJsonObject(content.match(HYDRO_TASK_COMMENT_RE)![1]!)
    : {};
  const messageMetadata = content.match(HYDRO_MESSAGE_COMMENT_RE)?.[1]
    ? parseJsonObject(content.match(HYDRO_MESSAGE_COMMENT_RE)![1]!)
    : {};
  let stripped = String(content || '').trim();
  if (HYDRO_TASK_COMMENT_RE.test(stripped)) {
    stripped = stripped.replace(HYDRO_TASK_COMMENT_RE, '').trimStart();
    stripped = stripped.replace(/^##\s+.+$/m, '').trimStart();
  }
  if (HYDRO_MESSAGE_COMMENT_RE.test(stripped)) {
    stripped = stripped.replace(HYDRO_MESSAGE_COMMENT_RE, '').trimStart();
    stripped = stripped.replace(/^###\s+.+$/m, '').trimStart();
  }
  return {
    content: stripped.trim(),
    taskMetadata,
    messageMetadata,
  };
}

function roleHeadingForTranscript(role: 'user' | 'assistant' | 'system') {
  if (role === 'assistant') return 'Hydro';
  if (role === 'system') return 'Worklog';
  return 'You';
}

function buildTranscriptMessageContent(params: {
  role: 'user' | 'assistant' | 'system';
  content: string;
  taskId: string;
  taskTitle: string;
  taskKind: string;
  taskMode: string;
  taskStartedAt: number;
  startNewTask: boolean;
  taskCompleted?: boolean;
  workDurationMs?: number;
  checkpointSaved?: boolean;
}) {
  const lines: string[] = [];
  if (params.startNewTask) {
    lines.push(`<!-- hydro_task ${JSON.stringify({
      id: params.taskId,
      title: params.taskTitle,
      kind: params.taskKind,
      mode: params.taskMode,
      startedAt: params.taskStartedAt,
    })} -->`);
    lines.push(`## ${params.taskTitle}`);
  }
  lines.push(`<!-- hydro_message ${JSON.stringify({
    taskId: params.taskId,
    taskTitle: params.taskTitle,
    taskKind: params.taskKind,
    taskMode: params.taskMode,
    taskStartedAt: params.taskStartedAt,
    ...(typeof params.taskCompleted === 'boolean' ? { taskCompleted: params.taskCompleted } : {}),
    ...(typeof params.workDurationMs === 'number' ? { workDurationMs: params.workDurationMs } : {}),
    ...(typeof params.checkpointSaved === 'boolean' ? { checkpointSaved: params.checkpointSaved } : {}),
  })} -->`);
  lines.push(`### ${roleHeadingForTranscript(params.role)}`);
  lines.push(params.content.trim());
  return lines.join('\n');
}

function resolveStoredTaskMetadata(message: any) {
  const metadata = parseAskMetadata(message?.metadata);
  const decorated = parseDecoratedTranscriptContent(String(message?.content || ''));
  const merged = { ...decorated.taskMetadata, ...decorated.messageMetadata, ...metadata };
  return {
    taskId: typeof merged.taskId === 'string' && merged.taskId.trim() ? merged.taskId.trim() : undefined,
    taskTitle: typeof merged.taskTitle === 'string' && merged.taskTitle.trim() ? merged.taskTitle.trim() : typeof merged.title === 'string' && merged.title.trim() ? merged.title.trim() : undefined,
    taskKind: normalizeAskTaskKind(merged.taskKind ?? merged.kind),
    taskMode: typeof merged.taskMode === 'string' && merged.taskMode.trim() ? merged.taskMode.trim() : typeof merged.mode === 'string' && merged.mode.trim() ? merged.mode.trim() : undefined,
    taskStartedAt: Number.isFinite(merged.taskStartedAt) ? Number(merged.taskStartedAt) : Number.isFinite(merged.startedAt) ? Number(merged.startedAt) : undefined,
    taskCompleted: typeof merged.taskCompleted === 'boolean' ? merged.taskCompleted : undefined,
    workDurationMs: Number.isFinite(merged.workDurationMs) ? Number(merged.workDurationMs) : undefined,
    checkpointSaved: typeof merged.checkpointSaved === 'boolean' ? merged.checkpointSaved : undefined,
    displayContent: decorated.content,
  };
}

function resolveTaskAssignment(params: { transcriptPayload: any; content: string; askMode: string; now: number }) {
  const history = Array.isArray(params.transcriptPayload?.messages) ? params.transcriptPayload.messages : [];
  const lastMessage = [...history]
    .reverse()
    .find((message) => String(resolveStoredTaskMetadata(message).displayContent || '').trim().length > 0 || String(message?.content || '').trim().length > 0);
  const lastMetadata = lastMessage ? resolveStoredTaskMetadata(lastMessage) : null;
  const shouldStartNewTask = !lastMessage || lastMetadata?.taskCompleted !== false && lastMessage?.role === 'assistant';
  if (!shouldStartNewTask && lastMetadata?.taskId && lastMetadata.taskTitle) {
    return {
      taskId: lastMetadata.taskId,
      taskTitle: lastMetadata.taskTitle,
      taskKind: lastMetadata.taskKind || askTaskKindForMode(params.askMode),
      taskMode: lastMetadata.taskMode || params.askMode,
      taskStartedAt: lastMetadata.taskStartedAt || params.now,
      startNewTask: false,
    };
  }
  const taskTitle = deriveAskTaskTitle(params.content);
  return {
    taskId: createAskTaskId(params.now, taskTitle),
    taskTitle,
    taskKind: askTaskKindForMode(params.askMode),
    taskMode: params.askMode,
    taskStartedAt: params.now,
    startNewTask: true,
  };
}

function isClarifyingAssistantResponse(content: string) {
  const trimmed = String(content || '').trim();
  if (!trimmed) return false;
  if (/<hydro_question_card>/i.test(trimmed)) return true;
  if (/<proposed_plan>/i.test(trimmed)) return false;
  if (/\?$/.test(trimmed)) return true;
  return /\b(could you clarify|which option|what should|what would you like|tell hydro|tell codex|before i plan|before i answer)\b/i.test(trimmed);
}

function normalizeAskMode(value: unknown, chatMode?: unknown, planMode?: unknown) {
  if (value === 'hydro' || value === 'chat' || value === 'plan' || value === 'custom') {
    return value;
  }
  if (planMode === true) return 'plan';
  if (chatMode === true) return 'chat';
  return 'hydro';
}

function slugifyHydroProjectName(value: string) {
  const slug = value
    .trim()
    .replace(/[^a-zA-Z0-9]+/g, '_')
    .replace(/_+/g, '_')
    .replace(/^_+|_+$/g, '');
  return slug || 'workspace';
}

function inferProjectName(rootPath: string | null | undefined) {
  if (!rootPath) return null;
  const trimmed = rootPath.trim().replace(/\/+$/, '');
  if (!trimmed) return null;
  const basename = path.posix.basename(trimmed);
  return basename && basename !== '.' && basename !== '/' ? basename : null;
}

function resolveAskProjectName(source?: { projectName?: unknown; rootPath?: unknown }) {
  if (typeof source?.projectName === 'string' && source.projectName.trim()) {
    return source.projectName.trim();
  }
  if (typeof source?.rootPath === 'string' && source.rootPath.trim()) {
    return inferProjectName(source.rootPath) || source.rootPath.trim();
  }
  return null;
}

type HydroAskTarget = {
  constructId: string;
  threadId: string;
  filename: string;
  storagePath: string;
  title: string;
  projectName: string | null;
  projectSlug: string | null;
};

type AskAttachmentPayload = {
  id: string;
  name: string;
  mimeType: string;
  size: number;
  category: 'image' | 'document';
  storagePath?: string;
  sha256?: string;
  dataUrl?: string;
  textContent?: string;
};

function parseAskAttachments(value: unknown) {
  if (!Array.isArray(value)) return [] as AskAttachmentPayload[];
  return value
    .map((entry, index) => {
      if (!entry || typeof entry !== 'object') return null;
      const raw = entry as Record<string, unknown>;
      const name = typeof raw.name === 'string' && raw.name.trim() ? raw.name.trim() : `attachment-${index + 1}`;
      const mimeType = typeof raw.mimeType === 'string' && raw.mimeType.trim() ? raw.mimeType.trim() : 'application/octet-stream';
      const size = Number.isFinite(raw.size) ? Number(raw.size) : 0;
      return {
        id: typeof raw.id === 'string' && raw.id.trim() ? raw.id.trim() : `${Date.now()}-${index + 1}`,
        name,
        mimeType,
        size,
        category: raw.category === 'image' || raw.category === 'document'
          ? raw.category
          : mimeType.startsWith('image/')
            ? 'image'
            : 'document',
        storagePath: typeof raw.storagePath === 'string' && raw.storagePath.trim() ? raw.storagePath.trim() : undefined,
        sha256: typeof raw.sha256 === 'string' && raw.sha256.trim() ? raw.sha256.trim() : undefined,
        dataUrl: typeof raw.dataUrl === 'string' && raw.dataUrl.trim() ? raw.dataUrl.trim() : undefined,
        textContent: typeof raw.textContent === 'string' ? raw.textContent : undefined,
      } satisfies AskAttachmentPayload;
    })
    .filter(Boolean) as AskAttachmentPayload[];
}

function parseAskMetadata(value: unknown) {
  if (!value || typeof value !== 'object') return {} as Record<string, unknown>;
  return value as Record<string, unknown>;
}

function extractResponseText(payload: any) {
  if (typeof payload?.output_text === 'string' && payload.output_text.trim()) {
    return payload.output_text.trim();
  }
  const parts: string[] = [];
  if (Array.isArray(payload?.output)) {
    payload.output.forEach((item: any) => {
      if (!Array.isArray(item?.content)) return;
      item.content.forEach((content: any) => {
        if (typeof content?.text === 'string' && content.text.trim()) {
          parts.push(content.text.trim());
          return;
        }
        if (typeof content?.refusal === 'string' && content.refusal.trim()) {
          parts.push(content.refusal.trim());
        }
      });
    });
  }
  return parts.join('\n\n').trim();
}

function sanitizeAskAttachment(entry: AskAttachmentPayload | Record<string, unknown>, index: number) {
  const raw = entry as Record<string, unknown>;
  const mimeType = typeof raw.mimeType === 'string' && raw.mimeType.trim() ? raw.mimeType.trim() : 'application/octet-stream';
  return {
    id: typeof raw.id === 'string' && raw.id.trim() ? raw.id.trim() : `attachment-${index + 1}`,
    name: typeof raw.name === 'string' && raw.name.trim() ? raw.name.trim() : `attachment-${index + 1}`,
    mimeType,
    size: Number.isFinite(raw.size) ? Number(raw.size) : 0,
    category: raw.category === 'image' || raw.category === 'document'
      ? raw.category
      : mimeType.startsWith('image/')
        ? 'image'
        : 'document',
    storagePath: typeof raw.storagePath === 'string' && raw.storagePath.trim() ? raw.storagePath.trim() : undefined,
    sha256: typeof raw.sha256 === 'string' && raw.sha256.trim() ? raw.sha256.trim() : undefined,
  };
}

function buildHydroSystemWrapper() {
  return [
    'You are Hydro, the automated software team inside Code.',
    'Speak in one unified Hydro voice with the Project Manager as the primary conversational surface.',
    'Stay honest, calm, and collaborative.',
    'Do not claim edits, commands, file writes, delegation, or completed implementation unless those actions truly happened.',
    'Treat Ask as conversational-first and non-mutating unless explicit write behavior is actually implemented.',
    'If a request is ambiguous, conflicting, or high-impact, ask clarifying follow-up questions before you answer or propose a plan.',
    'Keep clarification inside the same ongoing task until you have enough context to respond well.',
  ].join(' ');
}

function buildModeInstruction(mode: string, modeLabel?: unknown, modePrompt?: unknown) {
  const customPrompt = typeof modePrompt === 'string' ? modePrompt.trim() : '';
  if (mode === 'plan') {
    return 'Mode: Plan. First clarify anything underspecified or risky. Once you have enough context, respond with a concise implementation plan, key risks, and recommended next steps. Do not pretend work has already been done.';
  }
  if (mode === 'chat') {
    return 'Mode: Chat. Keep the response conversational, helpful, and read-only unless the user explicitly asks for implementation details.';
  }
  if (mode === 'custom' && customPrompt) {
    const customLabel = typeof modeLabel === 'string' && modeLabel.trim() ? modeLabel.trim() : 'Custom';
    return `Mode: ${customLabel}. Follow this extra instruction layer while staying on the same OpenAI runtime: ${customPrompt}`;
  }
  return 'Mode: Hydro. Act as the Project Manager front door for Hydro, routing specialist thinking internally without asking the user to shuttle prompts between team members. Answer simple clear asks directly, but clarify first when the request is underspecified.';
}

function buildWorkerInstruction(agentLabel?: unknown, agentPrompt?: unknown) {
  const label = typeof agentLabel === 'string' && agentLabel.trim() ? agentLabel.trim() : null;
  const prompt = typeof agentPrompt === 'string' && agentPrompt.trim() ? agentPrompt.trim() : null;
  if (prompt) {
    return `Focused worker guidance${label ? ` for ${label}` : ''}: ${prompt}`;
  }
  if (!label || label.toLowerCase() === 'code' || label.toLowerCase() === 'hydro') return '';
  return `Focused worker guidance: emphasize ${label} expertise while still responding as Hydro.`;
}

function buildWorkspaceContextText(source: {
  projectName?: string | null;
  rootPath?: unknown;
  workspaceSummary?: unknown;
}) {
  const lines: string[] = ['Workspace context:'];
  if (source.projectName) lines.push(`Project: ${source.projectName}`);
  if (typeof source.rootPath === 'string' && source.rootPath.trim()) lines.push(`Root path: ${source.rootPath.trim()}`);
  if (source.workspaceSummary && typeof source.workspaceSummary === 'object') {
    lines.push(`Workspace summary: ${JSON.stringify(source.workspaceSummary)}`);
  } else if (typeof source.workspaceSummary === 'string' && source.workspaceSummary.trim()) {
    lines.push(`Workspace summary: ${source.workspaceSummary.trim()}`);
  }
  return lines.join('\n');
}

function buildUserInputParts(content: string, attachments: AskAttachmentPayload[]) {
  const textSections: string[] = [];
  if (content.trim()) {
    textSections.push(content.trim());
  }
  if (attachments.length > 0) {
    textSections.push([
      'Attachments:',
      ...attachments.map((attachment) => {
        const lines = [
          `- ${attachment.name} (${attachment.mimeType}, ${attachment.size} bytes, ${attachment.category})`,
        ];
        if (attachment.textContent?.trim()) {
          lines.push(`  Text excerpt: ${attachment.textContent.trim().slice(0, 4000)}`);
        }
        return lines.join('\n');
      }),
    ].join('\n'));
  }
  const parts: Array<Record<string, unknown>> = [];
  const text = textSections.join('\n\n').trim() || 'The user sent attachments without additional text. Please acknowledge them and respond helpfully.';
  parts.push({ type: 'input_text', text });
  attachments
    .filter((attachment) => attachment.category === 'image' && attachment.dataUrl)
    .forEach((attachment) => {
      parts.push({
        type: 'input_image',
        image_url: attachment.dataUrl,
        detail: 'auto',
      });
    });
  return parts;
}

function buildOpenAiInputFromTranscript(params: {
  transcriptPayload: any;
  content: string;
  attachments: AskAttachmentPayload[];
  projectName?: string | null;
  rootPath?: unknown;
  workspaceSummary?: unknown;
}) {
  const history = Array.isArray(params.transcriptPayload?.messages) ? params.transcriptPayload.messages : [];
  const input: Array<Record<string, unknown>> = [
    {
      type: 'message',
      role: 'developer',
      content: [
        {
          type: 'input_text',
          text: buildWorkspaceContextText({
            projectName: params.projectName,
            rootPath: params.rootPath,
            workspaceSummary: params.workspaceSummary,
          }),
        },
      ],
    },
  ];

  history.forEach((message: any) => {
    const role = message?.role === 'assistant' || message?.role === 'system' ? message.role : 'user';
    const text = parseDecoratedTranscriptContent(String(message?.content || '')).content.trim();
    if (!text) return;
    input.push({
      type: 'message',
      role,
      content: [{ type: 'input_text', text }],
    });
  });

  input.push({
    type: 'message',
    role: 'user',
    content: buildUserInputParts(params.content, params.attachments),
  });
  return input;
}

function resolveHydroAskTarget(source?: { projectName?: unknown; rootPath?: unknown }): HydroAskTarget {
  const constructId = getHydroConstructId();
  const projectName = resolveAskProjectName(source);
  if (constructId === 'hydro-001' && projectName) {
    const projectSlug = slugifyHydroProjectName(projectName);
    const filename = `${projectSlug}_hydro_chat.md`;
    return {
      constructId,
      threadId: `${constructId}_${projectSlug}_hydro_chat`,
      filename,
      storagePath: `instances/${constructId}/code/${filename}`,
      title: `${projectName} Hydro`,
      projectName,
      projectSlug,
    };
  }

  return {
    constructId,
    threadId: `${constructId}_chat_with_${constructId}`,
    filename: `chat_with_${constructId}.md`,
    storagePath: `instances/${constructId}/chatty/chat_with_${constructId}.md`,
    title: 'Ask Hydro',
    projectName,
    projectSlug: null,
  };
}

function resolveCanonicalTranscriptPath(userId: string, target: HydroAskTarget) {
  return `/vvault_files/users/shard_0000/${userId}/${target.storagePath}`;
}

async function fetchHydroTranscriptPayload(params: {
  baseUrl: string;
  headers: Record<string, string>;
  target: HydroAskTarget;
  rootPath?: unknown;
}) {
  const requestUrl = new URL(`${params.baseUrl}/api/chatty/transcript/${params.target.constructId}`);
  if (params.target.projectName) {
    requestUrl.searchParams.set('projectName', params.target.projectName);
  }
  if (typeof params.rootPath === 'string' && params.rootPath.trim()) {
    requestUrl.searchParams.set('rootPath', params.rootPath.trim());
  }
  const upstream = await fetch(requestUrl.toString(), {
    method: 'GET',
    headers: params.headers,
  });
  if (upstream.status === 404) {
    return { messages: [], content: '', storageMode: 'canonical' };
  }
  if (!upstream.ok) {
    const details = await upstream.text().catch(() => 'Failed to fetch Hydro transcript');
    throw Object.assign(new Error(details || 'Failed to fetch Hydro transcript'), { status: upstream.status });
  }
  return upstream.json().catch(() => ({}));
}

async function appendHydroTranscriptMessage(params: {
  baseUrl: string;
  headers: Record<string, string>;
  target: HydroAskTarget;
  role: 'user' | 'assistant' | 'system';
  content: string;
  rootPath?: unknown;
  name?: string;
  metadata?: Record<string, unknown>;
  attachments?: AskAttachmentPayload[];
}) {
  const upstream = await fetch(`${params.baseUrl}/api/chatty/transcript/${params.target.constructId}/message`, {
    method: 'POST',
    headers: params.headers,
    body: JSON.stringify({
      role: params.role,
      content: params.content,
      name: params.name,
      timestamp: new Date().toISOString(),
      projectName: params.target.projectName,
      rootPath: typeof params.rootPath === 'string' ? params.rootPath : undefined,
      transcriptPath: params.target.storagePath,
      title: params.target.title,
      metadata: params.metadata,
      attachments: params.attachments,
    }),
  });
  if (!upstream.ok && upstream.status !== 202) {
    const details = await upstream.text().catch(() => 'Failed to append Hydro transcript message');
    throw Object.assign(new Error(details || 'Failed to append Hydro transcript message'), { status: upstream.status });
  }
  return upstream.json().catch(() => ({}));
}

async function callOpenAiHydroResponse(params: {
  instructions: string;
  input: Array<Record<string, unknown>>;
}) {
  const apiKey = (process.env.OPENAI_API_KEY || '').trim();
  if (!apiKey) {
    throw Object.assign(new Error('OPENAI_API_KEY is not configured for Ask Hydro.'), { status: 503 });
  }
  const runtime = getHydroRuntimeSelection();
  const response = await fetch('https://api.openai.com/v1/responses', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${apiKey}`,
    },
    body: JSON.stringify({
      model: runtime.model,
      instructions: params.instructions,
      input: params.input,
      max_output_tokens: 900,
    }),
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const message =
      typeof payload?.error?.message === 'string' && payload.error.message.trim()
        ? payload.error.message.trim()
        : response.statusText || `OpenAI request failed (${response.status})`;
    throw Object.assign(new Error(message), { status: response.status });
  }
  const text = extractResponseText(payload);
  if (!text) {
    throw Object.assign(new Error('OpenAI returned an empty response.'), { status: 502 });
  }
  return { payload, text };
}

function getVvaultRelayConfig() {
  const baseUrl = (process.env.VVAULT_API_BASE_URL || '').trim().replace(/\/+$/, '');
  const serviceToken = (process.env.VVAULT_SERVICE_TOKEN || '').trim();
  return {
    baseUrl,
    serviceToken,
  };
}

function getHydroAskStatusPayload(userId: string, target: HydroAskTarget) {
  const { baseUrl } = getVvaultRelayConfig();
  const openAiConfigured = Boolean((process.env.OPENAI_API_KEY || '').trim());
  const relayConfigured = Boolean(baseUrl);
  const configured = relayConfigured && openAiConfigured;
  return {
    configured,
    relayConfigured,
    openAiConfigured,
    canonicalTranscriptPath: resolveCanonicalTranscriptPath(userId, target),
    projectName: target.projectName,
    threadId: target.threadId,
    setupMessage: configured
      ? 'Ask Hydro is ready.'
      : !relayConfigured
        ? 'Ask Hydro needs the VVAULT relay configured before canonical project chat can load.'
        : 'Ask Hydro needs OPENAI_API_KEY configured before project chat can respond.',
  };
}

function createVvaultHeaders(userEmail: string | null, serviceToken: string) {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  if (serviceToken) headers['X-Chatty-Key'] = serviceToken;
  if (userEmail) headers['X-Chatty-User'] = userEmail;
  return headers;
}

function parseTranscriptMessages(content: string) {
  const lines = String(content || '').split('\n');
  const messages: Array<{ id: string; role: 'user' | 'assistant' | 'system'; content: string; createdAt: number }> = [];
  let currentRole: 'user' | 'assistant' | 'system' | null = null;
  let currentContent: string[] = [];
  let currentTimestamp = Date.now();

  const commitCurrent = () => {
    if (!currentRole) return;
    const body = currentContent.join('\n').trim();
    if (!body) return;
    messages.push({
      id: `msg-${messages.length + 1}`,
      role: currentRole,
      content: body,
      createdAt: currentTimestamp,
    });
  };

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#') || trimmed === '---') continue;
    const simpleMatch = trimmed.match(/^(You|User|Assistant|Hydro|Zen|Lin|Nova)\s+said:\s*(.*)$/i);
    if (simpleMatch) {
      commitCurrent();
      currentRole = /you|user/i.test(simpleMatch[1]) ? 'user' : 'assistant';
      currentContent = [simpleMatch[2] || ''];
      currentTimestamp = Date.now() + messages.length;
      continue;
    }
    const markdownMatch = trimmed.match(/^\*\*(User|Assistant|Hydro|Zen|Lin|Nova)\*\*:\s*(.*)$/i);
    if (markdownMatch) {
      commitCurrent();
      currentRole = /user/i.test(markdownMatch[1]) ? 'user' : 'assistant';
      currentContent = [markdownMatch[2] || ''];
      currentTimestamp = Date.now() + messages.length;
      continue;
    }
    const transcriptHeadingMatch = trimmed.match(/^###\s+(You|Hydro|Worklog|Assistant|User)\s*$/i);
    if (transcriptHeadingMatch) {
      commitCurrent();
      currentRole = /user|you/i.test(transcriptHeadingMatch[1]) ? 'user' : /worklog/i.test(transcriptHeadingMatch[1]) ? 'system' : 'assistant';
      currentContent = [];
      currentTimestamp = Date.now() + messages.length;
      continue;
    }
    if (/^##\s+/.test(trimmed) || HYDRO_TASK_COMMENT_RE.test(trimmed) || HYDRO_MESSAGE_COMMENT_RE.test(trimmed)) continue;
    if (currentRole) {
      currentContent.push(line);
    }
  }

  commitCurrent();
  return messages;
}

function mapTranscriptPayloadToAskMessages(payload: any, target: HydroAskTarget) {
  const runtime = getHydroRuntimeSelection();
  const runtimeModelLabel = getHydroModelLabel();
  return Array.isArray(payload?.messages)
    ? payload.messages.map((message: any, index: number) => {
        const metadata = parseAskMetadata(message?.metadata);
        const storedTask = resolveStoredTaskMetadata(message);
        const attachments = Array.isArray(message?.attachments)
          ? message.attachments.map((attachment: Record<string, unknown>, attachmentIndex: number) => sanitizeAskAttachment(attachment, attachmentIndex))
          : Array.isArray(metadata.attachments)
            ? (metadata.attachments as Record<string, unknown>[]).map((attachment, attachmentIndex: number) => sanitizeAskAttachment(attachment, attachmentIndex))
            : undefined;
        return {
          id: String(message?.id || `msg-${index + 1}`),
          threadId: target.threadId,
          role: message?.role === 'assistant' || message?.role === 'system' ? message.role : 'user',
          content: storedTask.displayContent || '',
          createdAt: Date.parse(message?.timestamp || '') || Date.now() + index,
          status: 'completed' as const,
          ...(attachments?.length ? { attachments } : {}),
          ...(storedTask.taskId ? { taskId: storedTask.taskId } : {}),
          ...(storedTask.taskTitle ? { taskTitle: storedTask.taskTitle } : {}),
          ...(storedTask.taskKind ? { taskKind: storedTask.taskKind } : {}),
          ...(typeof storedTask.checkpointSaved === 'boolean'
            ? { checkpointSaved: storedTask.checkpointSaved }
            : message?.role === 'assistant'
              ? { checkpointSaved: true }
              : {}),
          ...(typeof storedTask.workDurationMs === 'number' ? { workDurationMs: storedTask.workDurationMs } : {}),
          ...(typeof metadata.agentId === 'string' ? { agentId: metadata.agentId } : {}),
          ...(typeof metadata.agentLabel === 'string'
            ? { agentLabel: metadata.agentLabel }
            : message?.role === 'assistant'
              ? { agentLabel: 'Hydro' }
              : {}),
          ...(typeof metadata.askMode === 'string' ? { askMode: metadata.askMode } : {}),
          ...(typeof metadata.modeLabel === 'string'
            ? { modeLabel: metadata.modeLabel }
            : typeof metadata.askMode === 'string'
              ? { modeLabel: getHydroCanonicalModeLabel(metadata.askMode) }
              : {}),
          ...(typeof metadata.provider === 'string'
            ? { provider: metadata.provider }
            : message?.role === 'assistant'
              ? { provider: runtime.provider }
              : {}),
          ...(typeof metadata.model === 'string'
            ? { model: metadata.model }
            : message?.role === 'assistant'
              ? { model: runtime.model }
              : {}),
          ...(typeof metadata.modelKey === 'string'
            ? { modelKey: metadata.modelKey }
            : message?.role === 'assistant'
              ? { modelKey: runtime.model }
              : {}),
          ...(typeof metadata.modelLabel === 'string'
            ? { modelLabel: metadata.modelLabel }
            : message?.role === 'assistant'
              ? { modelLabel: runtimeModelLabel }
              : {}),
        };
      })
    : parseTranscriptMessages(String(payload?.content || '')).map((message) => ({
        ...message,
        threadId: target.threadId,
        status: 'completed' as const,
      }));
}

function mapTranscriptPayloadToAskThread(payload: any, target: HydroAskTarget) {
  const messages = mapTranscriptPayloadToAskMessages(payload, target);
  return {
    id: target.threadId,
    constructId: target.constructId,
    title: target.title,
    updatedAt: messages[messages.length - 1]?.createdAt || Date.now(),
    messages,
    storageMode: 'canonical',
    runtime: getHydroRuntimeSelection(),
  };
}

type CreateAuthAppOptions = {
  storage?: StorageAdapter;
  configStore?: AppConfigStore;
  providers?: Record<string, OAuthProviderClient>;
  turnstileVerifier?: TurnstileVerifier;
  sessionSecret?: string;
  cookieName?: string;
  resolveLifeProfile?: (input: ResolveLifeProfileInput) => Promise<LifeProfileResult>;
  /** Override for tests; default checks Supabase `users` by email. */
  isEmailInLifeRegistry?: (email: string) => Promise<boolean>;
  githubFetchImpl?: typeof fetch;
  githubRepoSessions?: GitHubRepoSessionStore;
};

export function createDefaultStorage() {
  return process.env.AUTH_STORAGE_ADAPTER === 'memory'
    ? new MemoryStorageAdapter()
    : new SqliteStorageAdapter(getDbPath());
}

function resolveProviderClients(config: AuthAppConfig, overrides?: Record<string, OAuthProviderClient>) {
  if (overrides) return overrides;
  return {
    google: createGoogleProviderClient(config),
    github: createGitHubProviderClient(config),
  };
}

function getCookieDomain() {
  const value = String(process.env.AUTH_COOKIE_DOMAIN || '').trim();
  return value || null;
}

function requestUsesSecureCookie(req: any) {
  const protoHeader = typeof req.get === 'function' ? req.get('x-forwarded-proto') : undefined;
  const forwardedProto = protoHeader ? String(protoHeader).split(',')[0].trim().toLowerCase() : '';
  if (forwardedProto) {
    return forwardedProto === 'https';
  }
  return Boolean(req?.secure);
}

function resolveSessionCookieHeaderOptions(req: any) {
  return {
    secure: requestUsesSecureCookie(req),
    domain: getCookieDomain(),
  };
}

export async function createAuthApp(options: CreateAuthAppOptions = {}) {
  const storage = options.storage || createDefaultStorage();
  const configStore = options.configStore || new FileAppConfigStore();
  const turnstileVerifier = options.turnstileVerifier || verifyTurnstileToken;
  const sessionSecret = options.sessionSecret || getSessionSecret();
  const providerTokenSecret = process.env.AUTH_PROVIDER_TOKEN_SECRET || options.sessionSecret || getProviderTokenSecret();
  const cookieName = options.cookieName || getCookieName();
  const resolveProfile = options.resolveLifeProfile ?? defaultResolveLifeProfile;
  const checkLifeRegistry = options.isEmailInLifeRegistry ?? defaultIsEmailInLifeRegistry;
  const githubFetchImpl = options.githubFetchImpl ?? fetch.bind(globalThis);
  const githubRepoSessions = options.githubRepoSessions ?? new GitHubRepoSessionStore();
  const oauthState = new OAuthStateStore();
  const exchangeCodes = new Map<string, ExchangeCodeRecord>();

  await storage.initialize();

  async function buildSessionForUser(user: StoredUser): Promise<SessionUser> {
    const resolved = await resolveProfile({
      email: user.email,
      displayName: user.displayName,
      cachedLifeUserId: user.lifeUserId,
      cachedSupabaseUserId: user.supabaseUserId,
    });
    await storage.updateUserLifeAnchors(user.id, resolved.lifeUserId, resolved.supabaseUserId);
    const uid = resolved.supabaseUserId || resolved.lifeUserId;
    return {
      id: resolved.lifeUserId,
      sub: resolved.lifeUserId,
      uid,
      email: user.email,
      name: user.displayName,
      picture: user.avatarUrl || undefined,
      auth_provider: user.authProvider,
    };
  }

  const app = express();
  app.set('trust proxy', true);
  app.disable('x-powered-by');
  app.use(express.json({ limit: '12mb' }));
  app.use(async (req, res, next) => {
    const config = await configStore.getConfig();
    applyCorsHeaders(req, res, config);
    if (req.method === 'OPTIONS') {
      return res.sendStatus(204);
    }
    return next();
  });

  app.get('/health', (_req, res) => {
    res.json({ ok: true, service: 'auth' });
  });

  app.get('/api/health', (_req, res) => {
    res.json({ ok: true, service: 'auth' });
  });

  app.get('/api/me', async (req, res) => {
    const authSession = readAuthSession(req, cookieName, sessionSecret);
    if ('error' in authSession) {
      return res.status(authSession.status).json({ ok: false, error: authSession.error });
    }
    return res.json({ ok: true, user: authSession.session });
  });

  app.get('/api/auth/google/health', async (req, res) => {
    const config = await configStore.getConfig();
    const providers = resolveProviderClients(config, options.providers);
    const configuredProvider = config.providers.find((provider) => provider.provider === 'google');
    const client = providers.google;
    const callbackUrl = resolveCallbackUrl(req, config, 'google');
    const cookieOptions = resolveSessionCookieHeaderOptions(req);

    return res.json({
      oauth_configured: Boolean(client?.isConfigured()),
      redirect_uri: callbackUrl,
      environment: process.env.NODE_ENV || 'development',
      client_id_present: Boolean(resolveProviderCredentials('google', config).clientId),
      client_secret_present: Boolean(resolveProviderCredentials('google', config).clientSecret),
      validation_passed: Boolean(configuredProvider?.enabled && client?.isConfigured()),
      allowed_origins: [...config.allowedOrigins],
      auth_public_origin: getPublicOriginFallback(),
      auth_cookie_name: cookieName,
      auth_cookie_domain: cookieOptions.domain,
      auth_cookie_secure: cookieOptions.secure,
    });
  });

  app.get('/api/code/ask/status', async (req, res) => {
    const authUser = await readAuthenticatedUser(req, storage, cookieName, sessionSecret);
    if ('error' in authUser) {
      return res.status(authUser.status).json({ ok: false, error: authUser.error });
    }

    const target = resolveHydroAskTarget({
      projectName: req.query?.projectName,
      rootPath: req.query?.rootPath,
    });
    return res.json(getHydroAskStatusPayload(authUser.session.uid || authUser.session.id, target));
  });

  app.post('/api/code/projects/scratch', async (req, res) => {
    const authUser = await readAuthenticatedUser(req, storage, cookieName, sessionSecret);
    if ('error' in authUser) {
      return res.status(authUser.status).json({ ok: false, error: authUser.error });
    }

    const name = String(req.body?.name || '').trim();
    if (!name) {
      return res.status(400).json({ ok: false, error: 'Project name is required.' });
    }
    const initialPrompt = String(req.body?.initialPrompt || '').trim() || null;
    const projectSlug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') || 'project';
    const rootPath = typeof req.body?.rootPath === 'string' && req.body.rootPath.trim()
      ? req.body.rootPath.trim()
      : `/workspaces/${projectSlug}`;
    const target = resolveHydroAskTarget({ projectName: name, rootPath });
    const ask = getHydroAskStatusPayload(authUser.session.uid || authUser.session.id, target);
    const { baseUrl, serviceToken } = getVvaultRelayConfig();

    if (ask.relayConfigured) {
      try {
        await fetchHydroTranscriptPayload({
          baseUrl,
          headers: createVvaultHeaders(authUser.session.email, serviceToken),
          target,
          rootPath,
        });
      } catch {
        // A scratch project can still be created even if the transcript bootstrap probe fails.
      }
    }

    return res.status(201).json({
      ok: true,
      project: {
        rootPath,
        name,
        source: 'generated',
        starterIntent: initialPrompt,
        hydroInterestTags: [],
        hydroInterestSummary: initialPrompt,
        hydroInterestUpdatedAt: initialPrompt ? Date.now() : null,
        createdAt: Date.now(),
        lastOpenedAt: Date.now(),
      },
      ask,
    });
  });

  app.get('/api/code/ask/thread', async (req, res) => {
    const authUser = await readAuthenticatedUser(req, storage, cookieName, sessionSecret);
    if ('error' in authUser) {
      return res.status(authUser.status).json({ ok: false, error: authUser.error });
    }

    const { baseUrl, serviceToken } = getVvaultRelayConfig();
    if (!baseUrl) {
      return res.status(503).json({ ok: false, error: 'VVAULT relay is not configured for Ask Hydro.' });
    }

    const target = resolveHydroAskTarget({
      projectName: req.query?.projectName,
      rootPath: req.query?.rootPath,
    });
    try {
      const payload = await fetchHydroTranscriptPayload({
        baseUrl,
        headers: createVvaultHeaders(authUser.session.email, serviceToken),
        target,
        rootPath: req.query?.rootPath,
      });
      return res.json(mapTranscriptPayloadToAskThread(payload, target));
    } catch (error) {
      const status = typeof (error as { status?: unknown })?.status === 'number' ? Number((error as { status: number }).status) : 502;
      return res.status(status).json({ ok: false, error: error instanceof Error ? error.message : 'Failed to fetch Hydro thread' });
    }
  });

  app.get('/api/code/ask/messages', async (req, res) => {
    const authUser = await readAuthenticatedUser(req, storage, cookieName, sessionSecret);
    if ('error' in authUser) {
      return res.status(authUser.status).json({ ok: false, error: authUser.error });
    }

    const { baseUrl, serviceToken } = getVvaultRelayConfig();
    if (!baseUrl) {
      return res.status(503).json({ ok: false, error: 'VVAULT relay is not configured for Ask Hydro.' });
    }

    const target = resolveHydroAskTarget({
      projectName: req.query?.projectName,
      rootPath: req.query?.rootPath,
    });
    try {
      const payload = await fetchHydroTranscriptPayload({
        baseUrl,
        headers: createVvaultHeaders(authUser.session.email, serviceToken),
        target,
        rootPath: req.query?.rootPath,
      });
      return res.json({ messages: mapTranscriptPayloadToAskMessages(payload, target) });
    } catch (error) {
      const status = typeof (error as { status?: unknown })?.status === 'number' ? Number((error as { status: number }).status) : 502;
      return res.status(status).json({ ok: false, error: error instanceof Error ? error.message : 'Failed to fetch Hydro messages' });
    }
  });

  app.post('/api/code/ask/messages', async (req, res) => {
    const authUser = await readAuthenticatedUser(req, storage, cookieName, sessionSecret);
    if ('error' in authUser) {
      return res.status(authUser.status).json({ ok: false, error: authUser.error });
    }

    const attachments = parseAskAttachments(req.body?.attachments);
    const content = String(req.body?.content || '').trim();
    if (!content && attachments.length === 0) {
      return res.status(400).json({ ok: false, error: 'Ask message is required.' });
    }

    const { baseUrl, serviceToken } = getVvaultRelayConfig();
    if (!baseUrl) {
      return res.status(503).json({ ok: false, error: 'VVAULT relay is not configured for Ask Hydro.' });
    }

    const target = resolveHydroAskTarget({
      projectName: req.body?.projectName,
      rootPath: req.body?.rootPath,
    });
    const headers = createVvaultHeaders(authUser.session.email, serviceToken);
    const askMode = normalizeAskMode(req.body?.askMode, req.body?.chatMode, req.body?.planMode);
    const modeLabel = typeof req.body?.modeLabel === 'string' && req.body.modeLabel.trim()
      ? req.body.modeLabel.trim()
      : getHydroCanonicalModeLabel(askMode);
    const canonicalTranscriptPath = resolveCanonicalTranscriptPath(authUser.session.uid || authUser.session.id, target);
    const runtime = getHydroRuntimeSelection();
    const runtimeModelLabel = getHydroModelLabel();
    const baseMessageMetadata = {
      provider: runtime.provider,
      model: runtime.model,
      modelKey: runtime.model,
      modelLabel: runtimeModelLabel,
      askMode,
      modeLabel,
      transcriptPath: target.storagePath,
      canonicalTranscriptPath,
      projectName: target.projectName,
      rootPath: typeof req.body?.rootPath === 'string' ? req.body.rootPath : undefined,
      ...(typeof req.body?.agentId === 'string' && req.body.agentId.trim() ? { agentId: req.body.agentId.trim() } : {}),
      ...(typeof req.body?.agentLabel === 'string' && req.body.agentLabel.trim() ? { agentLabel: req.body.agentLabel.trim() } : {}),
    } satisfies Record<string, unknown>;

    try {
      const turnStartedAt = Date.now();
      const transcriptPayload = await fetchHydroTranscriptPayload({
        baseUrl,
        headers,
        target,
        rootPath: req.body?.rootPath,
      });
      const taskAssignment = resolveTaskAssignment({
        transcriptPayload,
        content,
        askMode,
        now: turnStartedAt,
      });
      const userContent = buildTranscriptMessageContent({
        role: 'user',
        content,
        taskId: taskAssignment.taskId,
        taskTitle: taskAssignment.taskTitle,
        taskKind: taskAssignment.taskKind,
        taskMode: taskAssignment.taskMode,
        taskStartedAt: taskAssignment.taskStartedAt,
        startNewTask: taskAssignment.startNewTask,
        checkpointSaved: true,
      });

      await appendHydroTranscriptMessage({
        baseUrl,
        headers,
        target,
        role: 'user',
        content: userContent,
        rootPath: req.body?.rootPath,
        name: authUser.user.displayName || authUser.session.email || 'You',
        metadata: {
          ...baseMessageMetadata,
          attachments,
          taskId: taskAssignment.taskId,
          taskTitle: taskAssignment.taskTitle,
          taskKind: taskAssignment.taskKind,
          taskMode: taskAssignment.taskMode,
          taskStartedAt: taskAssignment.taskStartedAt,
          taskCompleted: false,
          checkpointSaved: true,
        },
        attachments,
      });

      const instructions = [
        buildHydroSystemWrapper(),
        buildModeInstruction(askMode, req.body?.modeLabel, req.body?.modePrompt),
        buildWorkerInstruction(req.body?.agentLabel, req.body?.agentPrompt),
      ].filter(Boolean).join('\n\n');

      const { text } = await callOpenAiHydroResponse({
        instructions,
        input: buildOpenAiInputFromTranscript({
          transcriptPayload,
          content,
          attachments,
          projectName: target.projectName,
          rootPath: req.body?.rootPath,
          workspaceSummary: req.body?.workspaceSummary,
        }),
      });
      const workDurationMs = Math.max(0, Date.now() - turnStartedAt);
      const taskCompleted = !isClarifyingAssistantResponse(text);
      const assistantContent = buildTranscriptMessageContent({
        role: 'assistant',
        content: text,
        taskId: taskAssignment.taskId,
        taskTitle: taskAssignment.taskTitle,
        taskKind: taskAssignment.taskKind,
        taskMode: taskAssignment.taskMode,
        taskStartedAt: taskAssignment.taskStartedAt,
        startNewTask: false,
        taskCompleted,
        workDurationMs,
        checkpointSaved: true,
      });

      await appendHydroTranscriptMessage({
        baseUrl,
        headers,
        target,
        role: 'assistant',
        content: assistantContent,
        rootPath: req.body?.rootPath,
        name: 'Hydro',
        metadata: {
          ...baseMessageMetadata,
          agentLabel: 'Hydro',
          taskId: taskAssignment.taskId,
          taskTitle: taskAssignment.taskTitle,
          taskKind: taskAssignment.taskKind,
          taskMode: taskAssignment.taskMode,
          taskStartedAt: taskAssignment.taskStartedAt,
          taskCompleted,
          workDurationMs,
          checkpointSaved: true,
        },
      });

      const payload = await fetchHydroTranscriptPayload({
        baseUrl,
        headers,
        target,
        rootPath: req.body?.rootPath,
      });
      const thread = mapTranscriptPayloadToAskThread(payload, target);
      return res.json({
        thread,
        message: thread.messages[thread.messages.length - 1] || {
          id: `msg-${Date.now()}`,
          threadId: target.threadId,
          role: 'assistant',
          content: text,
          createdAt: Date.now(),
          status: 'completed',
          taskId: taskAssignment.taskId,
          taskTitle: taskAssignment.taskTitle,
          taskKind: taskAssignment.taskKind,
          checkpointSaved: true,
          workDurationMs,
          provider: runtime.provider,
          model: runtime.model,
          modelKey: runtime.model,
          modelLabel: runtimeModelLabel,
          askMode,
          modeLabel,
          agentLabel: 'Hydro',
        },
      });
    } catch (error) {
      const status = typeof (error as { status?: unknown })?.status === 'number' ? Number((error as { status: number }).status) : 502;
      return res.status(status).json({ ok: false, error: error instanceof Error ? error.message : 'Ask Hydro relay failed' });
    }
  });

  app.get('/api/github/status', async (req, res) => {
    const authContext = await readAuthenticatedUser(req, storage, cookieName, sessionSecret);
    if ('error' in authContext) {
      return res.status(authContext.status).json({ ok: false, error: authContext.error });
    }
    const githubAccount = await storage.findProviderAccount(authContext.user.id, 'github');
    if (!githubAccount?.accessTokenEncrypted) {
      return res.json({ connected: false });
    }
    return res.json(githubConnectionPayload(githubAccount));
  });

  app.post('/api/github/connect', async (req, res) => {
    const authContext = await readAuthenticatedUser(req, storage, cookieName, sessionSecret);
    if ('error' in authContext) {
      return res.status(authContext.status).json({ ok: false, error: authContext.error });
    }

    const existing = await storage.findProviderAccount(authContext.user.id, 'github');
    if (existing?.accessTokenEncrypted) {
      return res.json(githubConnectionPayload(existing));
    }

    const config = await configStore.getConfig();
    const githubProvider = config.providers.find((provider) => provider.provider === 'github');
    if (!githubProvider || !githubProvider.enabled) {
      return res.status(404).json({ ok: false, error: 'GitHub repo access is not available for this app.' });
    }

    const { clientId, clientSecret, callbackUrl: configuredCallbackUrl } = resolveGitHubOAuthCredentials(config);
    const callbackUrl = configuredCallbackUrl || resolveCallbackUrl(req, config, 'github');
    if (!clientId || !clientSecret || !callbackUrl) {
      return res.status(503).json({ ok: false, error: 'GitHub repo access is not configured yet.' });
    }

    const origin = resolveRequestOrigin(req, config);
    const state = oauthState.issue('github', origin, callbackUrl, { mode: 'repo_connect' });

    return res.json({
      url: buildGitHubAuthorizationUrl({
        clientId,
        callbackUrl,
        state,
        scope: 'repo read:org',
      }),
    });
  });

  app.post('/api/github/disconnect', async (req, res) => {
    const authContext = await readAuthenticatedUser(req, storage, cookieName, sessionSecret);
    if ('error' in authContext) {
      return res.status(authContext.status).json({ ok: false, error: authContext.error });
    }
    await storage.clearProviderAccountConnection(authContext.user.id, 'github');
    githubRepoSessions.delete(authContext.user.id);
    return res.json({ ok: true });
  });

  app.get('/api/github/owners', async (req, res) => {
    const authContext = await readAuthenticatedUser(req, storage, cookieName, sessionSecret);
    if ('error' in authContext) {
      return res.status(authContext.status).json({ ok: false, error: authContext.error });
    }
    const githubAccount = await storage.findProviderAccount(authContext.user.id, 'github');
    if (!githubAccount?.accessTokenEncrypted) {
      return res.status(401).json({ ok: false, error: 'GitHub is not connected. Connect GitHub to continue.' });
    }

    try {
      const cachedOwners = githubRepoSessions.getCachedOwners(authContext.user.id);
      if (cachedOwners) return res.json(cachedOwners);
      const owners = await listGitHubOwners(
        decryptProviderToken(githubAccount.accessTokenEncrypted, providerTokenSecret),
        githubFetchImpl,
      );
      githubRepoSessions.setCachedOwners(authContext.user.id, owners);
      return res.json(owners);
    } catch (error) {
      const status = (error as Error & { status?: number }).status;
      if (status === 401 || status === 403) {
        await storage.clearProviderAccountConnection(authContext.user.id, 'github');
        githubRepoSessions.delete(authContext.user.id);
        return res.status(401).json({ ok: false, error: 'GitHub connection expired. Reconnect GitHub to continue.' });
      }
      return res.status(502).json({ ok: false, error: error instanceof Error ? error.message : 'Failed to load GitHub owners' });
    }
  });

  app.get('/api/github/repos', async (req, res) => {
    const authContext = await readAuthenticatedUser(req, storage, cookieName, sessionSecret);
    if ('error' in authContext) {
      return res.status(authContext.status).json({ ok: false, error: authContext.error });
    }
    const githubAccount = await storage.findProviderAccount(authContext.user.id, 'github');
    if (!githubAccount?.accessTokenEncrypted) {
      return res.status(401).json({ ok: false, error: 'GitHub is not connected. Connect GitHub to continue.' });
    }

    const providerProfile = parseProviderProfile(githubAccount.profileJson);
    const viewerLogin = typeof providerProfile.login === 'string' ? providerProfile.login : '';
    const owner = String(req.query.owner || '').trim() || viewerLogin;
    const query = String(req.query.query || '').trim().toLowerCase();
    const page = Math.max(1, Number.parseInt(String(req.query.page || '1'), 10) || 1);
    const perPage = Math.min(100, Math.max(20, Number.parseInt(String(req.query.perPage || '50'), 10) || 50));
    const cacheKey = `${owner.toLowerCase()}::${page}::${perPage}`;

    try {
      const cached = githubRepoSessions.getCachedRepos(authContext.user.id, cacheKey);
      const result = cached ?? await listGitHubRepos({
        accessToken: decryptProviderToken(githubAccount.accessTokenEncrypted, providerTokenSecret),
        viewerLogin,
        owner,
        page,
        perPage,
        fetchImpl: githubFetchImpl,
      });

      if (!cached) {
        githubRepoSessions.setCachedRepos(authContext.user.id, cacheKey, result);
      }

      return res.json({
        repos: query
          ? result.repos.filter((repo) => (
            repo.name.toLowerCase().includes(query) || repo.fullName.toLowerCase().includes(query)
          ))
          : result.repos,
        nextPage: result.nextPage,
      });
    } catch (error) {
      const status = (error as Error & { status?: number }).status;
      if (status === 401 || status === 403) {
        await storage.clearProviderAccountConnection(authContext.user.id, 'github');
        githubRepoSessions.delete(authContext.user.id);
        return res.status(401).json({ ok: false, error: 'GitHub connection expired. Reconnect GitHub to continue.' });
      }
      return res.status(502).json({ ok: false, error: error instanceof Error ? error.message : 'Failed to load GitHub repositories' });
    }
  });

  app.get('/api/auth/config', async (_req, res) => {
    const config = await configStore.getConfig();
    const providers = resolveProviderClients(config, options.providers);
    const providerStatuses: AuthProviderConfig[] = config.providers.map((provider) => {
      const client = providers[provider.provider];
      const available = provider.enabled && Boolean(client?.isConfigured());
      return {
        provider: provider.provider,
        label: provider.label,
        enabled: provider.enabled,
        available,
        reason: available ? undefined : client ? 'Provider is not configured' : 'Provider is not implemented',
      };
    });

    return res.json({
      ok: true,
      app: config.app,
      credentials: config.credentials,
      docs: config.docs,
      turnstile: config.turnstile,
      providers: providerStatuses,
    });
  });

  app.get('/api/auth/providers/:provider/status', async (req, res) => {
    const config = await configStore.getConfig();
    const providers = resolveProviderClients(config, options.providers);
    const providerId = String(req.params.provider || '').toLowerCase();
    const configuredProvider = config.providers.find((provider) => provider.provider === providerId);
    if (!configuredProvider) {
      return res.status(404).json({ ok: false, error: 'Unknown auth provider' });
    }

    const client = providers[providerId];
    const available = configuredProvider.enabled && Boolean(client?.isConfigured());
    return res.json({
      ok: true,
      provider: providerId,
      label: configuredProvider.label,
      enabled: configuredProvider.enabled,
      available,
      reason: available ? undefined : client ? 'Provider is not configured' : 'Provider is not implemented',
    });
  });

  app.post('/api/auth/login', async (req, res) => {
    const config = await configStore.getConfig();
    const email = String(req.body?.email || '').trim().toLowerCase();
    const password = String(req.body?.password || '');
    if (!email || !password) {
      return res.status(400).json({ ok: false, error: 'Email and password are required' });
    }

    const user = await storage.findUserByEmail(email);
    if (!user?.passwordHash) {
      if (!user && (await checkLifeRegistry(email))) {
        return res.status(401).json({
          ok: false,
          error:
            'This email was found in the LIFE Technology user registry. Finish Code sign-up below and your account will be connected.',
          lifeRegistryMatch: true,
        });
      }
      if (user && !user.passwordHash) {
        const authProvider = user.authProvider?.trim() || undefined;
        return res.status(401).json({
          ok: false,
          error: credentialLoginUnavailableMessage(authProvider),
          oauthOnly: true,
          credentialLoginUnavailable: true,
          ...(authProvider ? { authProvider } : {}),
        });
      }
      return res.status(401).json({ ok: false, error: 'Invalid email or password' });
    }

    const passwordOk = await verifyPassword(password, user.passwordHash);
    if (!passwordOk) {
      return res.status(401).json({ ok: false, error: 'Invalid email or password' });
    }

    const hasRequiredConsent = await hasRequiredConsentForApp(storage, config, user.id);
    if (!hasRequiredConsent) {
      return res.status(403).json({
        ok: false,
        error: `Please complete ${config.app.name} signup before continuing.`,
        requiresProductSignup: true,
      });
    }

    await storage.updateUserLogin(user.id);
    const sessionUser = await buildSessionForUser(user);
    res.setHeader(
      'Set-Cookie',
      createSetCookieHeader(
        cookieName,
        createSessionToken(sessionUser, sessionSecret, SESSION_MAX_AGE_SECONDS),
        SESSION_MAX_AGE_SECONDS,
        resolveSessionCookieHeaderOptions(req),
      ),
    );
    return res.json({ ok: true, user: sessionUser });
  });

  app.post('/api/auth/register', async (req, res) => {
    const config = await configStore.getConfig();
    if (!config.credentials.enabled) {
      return res.status(403).json({ ok: false, error: 'Credential sign-up is disabled for this app' });
    }

    const name = String(req.body?.name || '').trim();
    const email = String(req.body?.email || '').trim().toLowerCase();
    const password = String(req.body?.password || '');
    const confirmPassword = String(req.body?.confirmPassword || '');
    const turnstileToken = String(req.body?.turnstileToken || '').trim();
    const consent = (req.body?.consent && typeof req.body.consent === 'object') ? req.body.consent as Record<string, boolean> : {};

    if (!name || !email || !password || !confirmPassword) {
      return res.status(400).json({ ok: false, error: 'Name, email, password, and password confirmation are required' });
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ ok: false, error: 'Enter a valid email address' });
    }
    if (password !== confirmPassword) {
      return res.status(400).json({ ok: false, error: 'Passwords do not match' });
    }
    const passwordError = validatePasswordStrength(password);
    if (passwordError) {
      return res.status(400).json({ ok: false, error: passwordError });
    }

    const missingConsent = missingRequiredConsent(config, consent);
    if (missingConsent) {
      return res.status(400).json({ ok: false, error: `Please accept ${missingConsent.label}` });
    }

    if (config.turnstile.required) {
      if (!config.turnstile.enabled) {
        return res.status(503).json({ ok: false, error: 'Turnstile is required but not configured' });
      }
      if (!turnstileToken) {
        return res.status(400).json({ ok: false, error: 'Turnstile verification is required' });
      }
      const turnstileOk = await turnstileVerifier(turnstileToken, getClientIp(req));
      if (!turnstileOk) {
        return res.status(400).json({ ok: false, error: 'Turnstile verification failed' });
      }
    }

    const existing = await storage.findUserByEmail(email);
    if (existing) {
      return res.status(409).json({ ok: false, error: 'Email already in use' });
    }

    const passwordHash = await hashPassword(password);
    const user = await storage.createCredentialUser({
      email,
      displayName: name,
      passwordHash,
    });
    await storage.replaceConsentAcceptances(user.id, config.app.id, buildAcceptedConsentDocs(config, consent));
    const sessionUser = await buildSessionForUser(user);
    res.setHeader(
      'Set-Cookie',
      createSetCookieHeader(
        cookieName,
        createSessionToken(sessionUser, sessionSecret, SESSION_MAX_AGE_SECONDS),
        SESSION_MAX_AGE_SECONDS,
        resolveSessionCookieHeaderOptions(req),
      ),
    );
    return res.status(201).json({ ok: true, user: sessionUser });
  });

  const logoutHandler = (_req: any, res: any) => {
    res.setHeader('Set-Cookie', createClearCookieHeader(cookieName, resolveSessionCookieHeaderOptions(_req)));
    return res.json({ ok: true });
  };
  app.post('/api/logout', logoutHandler);
  // Aliases for clients that expect `/api/auth/*` (matches sign-out fallbacks in Code host).
  app.post('/api/auth/logout', logoutHandler);
  app.get('/api/auth/logout', logoutHandler);

  app.get('/api/auth/set-session', async (req, res) => {
    const code = String(req.query.code || '');
    const config = await configStore.getConfig();
    const entry = exchangeCodes.get(code);
    if (!code || !entry) {
      return res.redirect(`${config.allowedOrigins[0] || getPublicOriginFallback()}${config.redirects.postLoginPath}?error=invalid_or_expired_code`);
    }
    exchangeCodes.delete(code);
    if (Date.now() - entry.createdAt > EXCHANGE_CODE_TTL_MS) {
      return res.redirect(`${entry.origin}${config.redirects.postLoginPath}?error=expired_code`);
    }
    res.setHeader(
      'Set-Cookie',
      createSetCookieHeader(
        cookieName,
        entry.token,
        SESSION_MAX_AGE_SECONDS,
        resolveSessionCookieHeaderOptions(req),
      ),
    );
    return res.redirect(`${entry.origin}${config.redirects.postLoginPath}`);
  });

  app.get('/api/auth/:provider', async (req, res) => {
    const config = await configStore.getConfig();
    const providers = resolveProviderClients(config, options.providers);
    const providerId = String(req.params.provider || '').toLowerCase();
    const configuredProvider = config.providers.find((provider) => provider.provider === providerId);
    const client = providers[providerId];
    if (!configuredProvider || !configuredProvider.enabled || !client) {
      return res.status(404).json({ ok: false, error: 'Unknown auth provider' });
    }
    if (!client.isConfigured()) {
      return res.status(503).json({ ok: false, error: `${providerId} sign-in is not configured yet.` });
    }

    const origin = resolveRequestOrigin(req, config);
    const callbackUrl = resolveCallbackUrl(req, config, providerId);
    const state = oauthState.issue(providerId, origin, callbackUrl, { mode: 'identity_login' });
    return res.redirect(client.buildAuthorizationUrl({ origin, callbackUrl, state }));
  });

  app.get('/api/auth/:provider/callback', async (req, res) => {
    const config = await configStore.getConfig();
    const providers = resolveProviderClients(config, options.providers);
    const providerId = String(req.params.provider || '').toLowerCase();
    const oauthError = String(req.query.error || '');
    const code = String(req.query.code || '');
    const state = String(req.query.state || '');
    const fallbackOrigin = resolveRequestOrigin(req, config);
    if (oauthError) {
      return res.redirect(`${fallbackOrigin}${config.redirects.postLoginPath}?error=${encodeURIComponent(oauthError)}`);
    }

    const stateRecord = oauthState.consume(providerId, state);
    if (!stateRecord) {
      return res.redirect(`${fallbackOrigin}${config.redirects.postLoginPath}?error=invalid_state`);
    }
    if (stateRecord.mode === 'repo_connect') {
      if (providerId !== 'github') {
        return res.redirect(`${stateRecord.origin}${config.redirects.postLoginPath}?error=unsupported_provider`);
      }
      if (!code) {
        return res.redirect(`${stateRecord.origin}${config.redirects.postLoginPath}?error=missing_code`);
      }
      const authContext = await readAuthenticatedUser(req, storage, cookieName, sessionSecret);
      if ('error' in authContext) {
        return res.redirect(`${stateRecord.origin}${config.redirects.postLoginPath}?error=missing_session`);
      }

      const { clientId, clientSecret, callbackUrl: configuredCallbackUrl } = resolveGitHubOAuthCredentials(config);
      const callbackUrl = configuredCallbackUrl || stateRecord.callbackUrl;
      if (!clientId || !clientSecret || !callbackUrl) {
        return res.redirect(`${stateRecord.origin}${config.redirects.postLoginPath}?error=github_not_configured`);
      }

      try {
        const exchange = await exchangeGitHubCodeForAccessToken({
          fetchImpl: githubFetchImpl,
          clientId,
          clientSecret,
          code,
          callbackUrl,
        });
        const viewer = await fetchGitHubViewer(exchange.accessToken, githubFetchImpl);
        await storage.upsertProviderAccountConnection({
          userId: authContext.user.id,
          provider: 'github',
          providerUserId: viewer.providerId,
          displayName: viewer.name || viewer.login,
          avatarUrl: viewer.avatarUrl || null,
          email: null,
          profile: {
            id: viewer.providerId,
            login: viewer.login,
            name: viewer.name,
            avatar_url: viewer.avatarUrl,
          },
          accessTokenEncrypted: encryptProviderToken(exchange.accessToken, providerTokenSecret),
          accessTokenScope: exchange.scope,
        });
        githubRepoSessions.delete(authContext.user.id);
        return res.redirect(`${stateRecord.origin}${config.redirects.postLoginPath}`);
      } catch (error) {
        const message = error instanceof Error ? error.message : 'github_connect_failed';
        return res.redirect(`${stateRecord.origin}${config.redirects.postLoginPath}?error=${encodeURIComponent(message)}`);
      }
    }

    const client = providers[providerId];
    if (!client) {
      return res.redirect(`${stateRecord.origin}${config.redirects.postLoginPath}?error=unsupported_provider`);
    }
    if (!code) {
      return res.redirect(`${stateRecord.origin}${config.redirects.postLoginPath}?error=missing_code`);
    }

    try {
      const profile = await client.exchangeCodeForProfile({
        code,
        callbackUrl: stateRecord.callbackUrl,
      });
      const user = await storage.upsertOAuthUser({
        provider: providerId,
        providerUserId: profile.providerUserId,
        email: profile.email,
        displayName: profile.displayName,
        avatarUrl: profile.avatarUrl || null,
        profile: profile.raw,
      });
      const hasRequiredConsent = await hasRequiredConsentForApp(storage, config, user.id);
      if (!hasRequiredConsent) {
        const query = new URLSearchParams({ authModal: 'signup', reason: 'missing_consent' });
        return res.redirect(`${stateRecord.origin}${config.redirects.postLoginPath}?${query.toString()}`);
      }
      await storage.updateUserLogin(user.id);
      const sessionUser = await buildSessionForUser(user);
      const sessionToken = createSessionToken(sessionUser, sessionSecret, SESSION_MAX_AGE_SECONDS);
      const callbackOrigin = new URL(stateRecord.callbackUrl).origin;
      if (callbackOrigin !== stateRecord.origin) {
        const exchangeCode = crypto.randomUUID();
        exchangeCodes.set(exchangeCode, {
          token: sessionToken,
          origin: stateRecord.origin,
          createdAt: Date.now(),
        });
        return res.redirect(`${stateRecord.origin}/api/auth/set-session?code=${encodeURIComponent(exchangeCode)}`);
      }
      res.setHeader(
        'Set-Cookie',
        createSetCookieHeader(
          cookieName,
          sessionToken,
          SESSION_MAX_AGE_SECONDS,
          resolveSessionCookieHeaderOptions(req),
        ),
      );
      return res.redirect(`${stateRecord.origin}${config.redirects.postLoginPath}`);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'oauth_failed';
      return res.redirect(`${stateRecord.origin}${config.redirects.postLoginPath}?error=${encodeURIComponent(message)}`);
    }
  });

  return app;
}
