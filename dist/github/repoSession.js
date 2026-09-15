const CACHE_TTL_MS = 20_000;
export class GitHubRepoSessionStore {
    now;
    sessions = new Map();
    constructor(now = () => Date.now()) {
        this.now = now;
    }
    delete(sessionKeyHash) {
        this.sessions.delete(sessionKeyHash);
    }
    getCachedOwners(sessionKeyHash) {
        const session = this.sessions.get(sessionKeyHash);
        if (!session?.ownersCache)
            return null;
        if (this.now() - session.ownersCache.at > CACHE_TTL_MS) {
            session.ownersCache = null;
            return null;
        }
        return session.ownersCache.value;
    }
    setCachedOwners(sessionKeyHash, owners) {
        const session = this.getOrCreate(sessionKeyHash);
        session.ownersCache = { value: owners, at: this.now() };
    }
    getCachedRepos(sessionKeyHash, cacheKey) {
        const session = this.sessions.get(sessionKeyHash);
        const cached = session?.reposCache.get(cacheKey);
        if (!session || !cached)
            return null;
        if (this.now() - cached.at > CACHE_TTL_MS) {
            session.reposCache.delete(cacheKey);
            return null;
        }
        return cached.value;
    }
    setCachedRepos(sessionKeyHash, cacheKey, value) {
        const session = this.getOrCreate(sessionKeyHash);
        session.reposCache.set(cacheKey, { value, at: this.now() });
    }
    getOrCreate(sessionKeyHash) {
        const existing = this.sessions.get(sessionKeyHash);
        if (existing)
            return existing;
        const created = {
            ownersCache: null,
            reposCache: new Map(),
        };
        this.sessions.set(sessionKeyHash, created);
        return created;
    }
}
