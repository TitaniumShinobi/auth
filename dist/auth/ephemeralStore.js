function nowMs() {
    return Date.now();
}
function ttlToMs(ttlSeconds) {
    return Math.max(1, Math.floor(ttlSeconds)) * 1000;
}
export class MemoryEphemeralAuthStore {
    entries = new Map();
    async initialize() { }
    async getJson(key) {
        const value = this.getRaw(key);
        if (!value)
            return null;
        try {
            return JSON.parse(value);
        }
        catch {
            return null;
        }
    }
    async takeJson(key) {
        const value = this.getRaw(key);
        if (!value)
            return null;
        this.entries.delete(key);
        try {
            return JSON.parse(value);
        }
        catch {
            return null;
        }
    }
    async setJson(key, value, ttlSeconds) {
        this.setRaw(key, JSON.stringify(value), ttlSeconds);
    }
    async delete(key) {
        this.entries.delete(key);
    }
    async deleteIfValue(key, value) {
        if (this.getRaw(key) !== value)
            return false;
        this.entries.delete(key);
        return true;
    }
    async setIfNotExists(key, value, ttlSeconds) {
        if (this.getRaw(key) !== null)
            return false;
        this.setRaw(key, value, ttlSeconds);
        return true;
    }
    async setRevokedAccess(jti, ttlSeconds) {
        this.setRaw(`auth:access:revoked:${jti}`, '1', ttlSeconds);
    }
    async isAccessRevoked(jti) {
        return this.getRaw(`auth:access:revoked:${jti}`) !== null;
    }
    async setRevokedSession(sessionId, ttlSeconds) {
        this.setRaw(`auth:session:revoked:${sessionId}`, '1', ttlSeconds);
    }
    async isSessionRevoked(sessionId) {
        return this.getRaw(`auth:session:revoked:${sessionId}`) !== null;
    }
    setRaw(key, value, ttlSeconds) {
        this.entries.set(key, {
            value,
            expiresAt: nowMs() + ttlToMs(ttlSeconds),
        });
    }
    getRaw(key) {
        const entry = this.entries.get(key);
        if (!entry)
            return null;
        if (entry.expiresAt <= nowMs()) {
            this.entries.delete(key);
            return null;
        }
        return entry.value;
    }
}
export class RedisEphemeralAuthStore {
    url;
    client = null;
    constructor(url) {
        this.url = url;
    }
    async initialize() {
        if (this.client?.isOpen)
            return;
        const { createClient } = await Function('specifier', 'return import(specifier)')('redis');
        this.client = createClient({ url: this.url });
        await this.client.connect();
    }
    async getJson(key) {
        const value = await this.requireClient().get(key);
        if (!value)
            return null;
        try {
            return JSON.parse(value);
        }
        catch {
            return null;
        }
    }
    async takeJson(key) {
        const client = this.requireClient();
        const value = typeof client.getDel === 'function'
            ? await client.getDel(key)
            : await client.sendCommand(['GETDEL', key]);
        if (!value)
            return null;
        try {
            return JSON.parse(value);
        }
        catch {
            return null;
        }
    }
    async setJson(key, value, ttlSeconds) {
        await this.requireClient().set(key, JSON.stringify(value), { EX: Math.max(1, Math.floor(ttlSeconds)) });
    }
    async delete(key) {
        await this.requireClient().del(key);
    }
    async deleteIfValue(key, value) {
        const script = `
      if redis.call("get", KEYS[1]) == ARGV[1] then
        return redis.call("del", KEYS[1])
      end
      return 0
    `;
        const result = await this.requireClient().eval(script, {
            keys: [key],
            arguments: [value],
        });
        return result === 1;
    }
    async setIfNotExists(key, value, ttlSeconds) {
        const result = await this.requireClient().set(key, value, {
            EX: Math.max(1, Math.floor(ttlSeconds)),
            NX: true,
        });
        return result === 'OK';
    }
    async setRevokedAccess(jti, ttlSeconds) {
        await this.requireClient().set(`auth:access:revoked:${jti}`, '1', {
            EX: Math.max(1, Math.floor(ttlSeconds)),
        });
    }
    async isAccessRevoked(jti) {
        return (await this.requireClient().exists(`auth:access:revoked:${jti}`)) === 1;
    }
    async setRevokedSession(sessionId, ttlSeconds) {
        await this.requireClient().set(`auth:session:revoked:${sessionId}`, '1', {
            EX: Math.max(1, Math.floor(ttlSeconds)),
        });
    }
    async isSessionRevoked(sessionId) {
        return (await this.requireClient().exists(`auth:session:revoked:${sessionId}`)) === 1;
    }
    requireClient() {
        if (!this.client?.isOpen) {
            throw new Error('Redis auth store is not connected');
        }
        return this.client;
    }
}
export function createDefaultEphemeralAuthStore() {
    const redisUrl = (process.env.AUTH_REDIS_URL || process.env.REDIS_URL || '').trim();
    return redisUrl ? new RedisEphemeralAuthStore(redisUrl) : new MemoryEphemeralAuthStore();
}
