import type { AuthAppConfig } from '../types.js';
import { resolveProviderCredentials } from '../auth/oauth.js';

type FetchLike = typeof fetch;

type HeaderLike = {
  get: (name: string) => string | null;
};

type GitHubViewerResponse = {
  id: number;
  login: string;
  name?: string;
  avatar_url?: string;
};

type GitHubOrgResponse = {
  login: string;
  avatar_url?: string;
};

type GitHubRepoResponse = {
  id: number;
  name: string;
  full_name: string;
  private: boolean;
  html_url: string;
  clone_url: string;
  ssh_url: string;
  default_branch?: string;
  updated_at: string;
  pushed_at?: string;
  owner?: {
    login?: string;
  };
};

export type GitHubViewer = {
  providerId: string;
  login: string;
  name?: string;
  avatarUrl?: string;
};

export type GitHubOwner = {
  login: string;
  name?: string;
  avatarUrl?: string;
  type: 'user' | 'org';
};

export type GitHubRepoRecord = {
  id: number;
  name: string;
  fullName: string;
  ownerLogin: string;
  private: boolean;
  htmlUrl: string;
  cloneUrl: string;
  sshUrl: string;
  defaultBranch?: string;
  updatedAt: string;
  pushedAt?: string;
};

export type GitHubRepoListResult = {
  repos: GitHubRepoRecord[];
  nextPage: number | null;
};

export type GitHubAccessTokenExchangeResult = {
  accessToken: string;
  scope: string | null;
};

function jsonHeaders(extra: Record<string, string> = {}) {
  return {
    Accept: 'application/vnd.github+json',
    'User-Agent': 'quantum-auth',
    ...extra,
  };
}

async function requestJson<T>(fetchImpl: FetchLike, url: string, accessToken: string, init: RequestInit = {}) {
  const response = await fetchImpl(url, {
    ...init,
    headers: jsonHeaders({
      Authorization: `Bearer ${accessToken}`,
      ...(init.headers as Record<string, string> | undefined),
    }),
  });

  if (!response.ok) {
    const message = await response.text().catch(() => `GitHub request failed (${response.status})`);
    const error = new Error(message || `GitHub request failed (${response.status})`);
    (error as Error & { status?: number }).status = response.status;
    throw error;
  }

  return {
    body: await response.json() as T,
    headers: response.headers as HeaderLike,
  };
}

export function buildGitHubAuthorizationUrl(params: {
  clientId: string;
  callbackUrl: string;
  state: string;
  scope: string;
}) {
  const url = new URL('https://github.com/login/oauth/authorize');
  url.searchParams.set('client_id', params.clientId);
  url.searchParams.set('redirect_uri', params.callbackUrl);
  url.searchParams.set('scope', params.scope);
  url.searchParams.set('state', params.state);
  return url.toString();
}

export function resolveGitHubOAuthCredentials(config?: AuthAppConfig) {
  return resolveProviderCredentials('github', config);
}

export async function exchangeGitHubCodeForAccessToken(params: {
  fetchImpl?: FetchLike;
  clientId: string;
  clientSecret: string;
  code: string;
  callbackUrl: string;
}): Promise<GitHubAccessTokenExchangeResult> {
  const fetchImpl = params.fetchImpl ?? fetch.bind(globalThis);
  const response = await fetchImpl('https://github.com/login/oauth/access_token', {
    method: 'POST',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      client_id: params.clientId,
      client_secret: params.clientSecret,
      code: params.code,
      redirect_uri: params.callbackUrl,
    }).toString(),
  });

  const payload = await response.json().catch(() => null) as {
    access_token?: string;
    scope?: string;
    error?: string;
    error_description?: string;
  } | null;
  if (!response.ok || !payload?.access_token) {
    throw new Error(payload?.error_description || payload?.error || 'GitHub token exchange failed');
  }

  return {
    accessToken: payload.access_token,
    scope: typeof payload.scope === 'string' && payload.scope.trim() ? payload.scope.trim() : null,
  };
}

export async function fetchGitHubViewer(accessToken: string, fetchImpl: FetchLike = fetch.bind(globalThis)): Promise<GitHubViewer> {
  const { body } = await requestJson<GitHubViewerResponse>(fetchImpl, 'https://api.github.com/user', accessToken);
  return {
    providerId: String(body.id),
    login: body.login,
    name: body.name || undefined,
    avatarUrl: body.avatar_url || undefined,
  };
}

export async function listGitHubOwners(accessToken: string, fetchImpl: FetchLike = fetch.bind(globalThis)): Promise<GitHubOwner[]> {
  const viewer = await fetchGitHubViewer(accessToken, fetchImpl);
  const { body: orgs } = await requestJson<GitHubOrgResponse[]>(
    fetchImpl,
    'https://api.github.com/user/orgs?per_page=100',
    accessToken,
  );

  return [
    {
      login: viewer.login,
      name: viewer.name,
      avatarUrl: viewer.avatarUrl,
      type: 'user',
    },
    ...orgs
      .filter((org) => Boolean(org.login))
      .map((org) => ({
        login: org.login,
        name: org.login,
        avatarUrl: org.avatar_url,
        type: 'org' as const,
      })),
  ];
}

export function parseGitHubLinkHeader(linkHeader: string | null) {
  if (!linkHeader) return {};
  const out: Record<string, string> = {};
  for (const part of linkHeader.split(',')) {
    const match = part.match(/<([^>]+)>;\s*rel="([^"]+)"/);
    if (!match) continue;
    out[match[2]] = match[1];
  }
  return out;
}

export function extractGitHubNextPage(linkHeader: string | null) {
  const next = parseGitHubLinkHeader(linkHeader).next;
  if (!next) return null;
  try {
    const url = new URL(next);
    const page = Number(url.searchParams.get('page'));
    return Number.isFinite(page) && page > 0 ? page : null;
  } catch {
    return null;
  }
}

export function normalizeGitHubRepoRecord(repo: GitHubRepoResponse, fallbackOwnerLogin = ''): GitHubRepoRecord {
  return {
    id: repo.id,
    name: repo.name,
    fullName: repo.full_name,
    ownerLogin: repo.owner?.login || fallbackOwnerLogin,
    private: Boolean(repo.private),
    htmlUrl: repo.html_url,
    cloneUrl: repo.clone_url,
    sshUrl: repo.ssh_url,
    defaultBranch: repo.default_branch,
    updatedAt: repo.updated_at,
    pushedAt: repo.pushed_at,
  };
}

export async function listGitHubRepos(
  params: {
    accessToken: string;
    viewerLogin?: string;
    owner?: string;
    query?: string;
    page?: number;
    perPage?: number;
    fetchImpl?: FetchLike;
  },
): Promise<GitHubRepoListResult> {
  const fetchImpl = params.fetchImpl ?? fetch.bind(globalThis);
  const viewerLogin = (params.viewerLogin || '').trim();
  const page = Math.max(1, params.page ?? 1);
  const perPage = Math.min(100, Math.max(20, params.perPage ?? 50));
  const owner = (params.owner || viewerLogin).trim();
  const query = (params.query || '').trim().toLowerCase();

  const endpoint = owner.toLowerCase() === viewerLogin.toLowerCase()
    ? `https://api.github.com/user/repos?sort=updated&direction=desc&per_page=${perPage}&page=${page}&affiliation=owner,collaborator,organization_member`
    : `https://api.github.com/orgs/${encodeURIComponent(owner)}/repos?sort=updated&direction=desc&per_page=${perPage}&page=${page}&type=all`;

  const { body, headers } = await requestJson<GitHubRepoResponse[]>(fetchImpl, endpoint, params.accessToken);
  const repos = body
    .map((repo) => normalizeGitHubRepoRecord(repo, owner))
    .filter((repo) => {
      if (!query) return true;
      return repo.name.toLowerCase().includes(query) || repo.fullName.toLowerCase().includes(query);
    });

  return {
    repos,
    nextPage: extractGitHubNextPage(headers.get('link')),
  };
}
