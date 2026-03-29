import type { GitHubOwner, GitHubRepoListResult } from './api.js';

const CACHE_TTL_MS = 20_000;

type CachedValue<T> = {
  value: T;
  at: number;
};

type GitHubRepoCacheRecord = {
  ownersCache: CachedValue<GitHubOwner[]> | null;
  reposCache: Map<string, CachedValue<GitHubRepoListResult>>;
};

export class GitHubRepoSessionStore {
  private readonly sessions = new Map<string, GitHubRepoCacheRecord>();

  constructor(private readonly now: () => number = () => Date.now()) {}

  delete(sessionKeyHash: string) {
    this.sessions.delete(sessionKeyHash);
  }

  getCachedOwners(sessionKeyHash: string) {
    const session = this.sessions.get(sessionKeyHash);
    if (!session?.ownersCache) return null;
    if (this.now() - session.ownersCache.at > CACHE_TTL_MS) {
      session.ownersCache = null;
      return null;
    }
    return session.ownersCache.value;
  }

  setCachedOwners(sessionKeyHash: string, owners: GitHubOwner[]) {
    const session = this.getOrCreate(sessionKeyHash);
    session.ownersCache = { value: owners, at: this.now() };
  }

  getCachedRepos(sessionKeyHash: string, cacheKey: string) {
    const session = this.sessions.get(sessionKeyHash);
    const cached = session?.reposCache.get(cacheKey);
    if (!session || !cached) return null;
    if (this.now() - cached.at > CACHE_TTL_MS) {
      session.reposCache.delete(cacheKey);
      return null;
    }
    return cached.value;
  }

  setCachedRepos(sessionKeyHash: string, cacheKey: string, value: GitHubRepoListResult) {
    const session = this.getOrCreate(sessionKeyHash);
    session.reposCache.set(cacheKey, { value, at: this.now() });
  }

  private getOrCreate(sessionKeyHash: string) {
    const existing = this.sessions.get(sessionKeyHash);
    if (existing) return existing;
    const created: GitHubRepoCacheRecord = {
      ownersCache: null,
      reposCache: new Map(),
    };
    this.sessions.set(sessionKeyHash, created);
    return created;
  }
}
