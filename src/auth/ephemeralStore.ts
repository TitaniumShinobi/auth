type Entry = {
  value: string;
  expiresAt: number;
};

function nowMs() {
  return Date.now();
}

function ttlToMs(ttlSeconds: number) {
  return Math.max(1, Math.floor(ttlSeconds)) * 1000;
}

export interface EphemeralAuthStore {
  initialize(): Promise<void>;
  getJson<T>(key: string): Promise<T | null>;
  takeJson<T>(key: string): Promise<T | null>;
  setJson(key: string, value: unknown, ttlSeconds: number): Promise<void>;
  delete(key: string): Promise<void>;
  deleteIfValue(key: string, value: string): Promise<boolean>;
  setIfNotExists(key: string, value: string, ttlSeconds: number): Promise<boolean>;
  setRevokedAccess(jti: string, ttlSeconds: number): Promise<void>;
  isAccessRevoked(jti: string): Promise<boolean>;
  setRevokedSession(sessionId: string, ttlSeconds: number): Promise<void>;
  isSessionRevoked(sessionId: string): Promise<boolean>;
}

export class MemoryEphemeralAuthStore implements EphemeralAuthStore {
  private readonly entries = new Map<string, Entry>();

  async initialize() {}

  async getJson<T>(key: string) {
    const value = this.getRaw(key);
    if (!value) return null;
    try {
      return JSON.parse(value) as T;
    } catch {
      return null;
    }
  }

  async takeJson<T>(key: string) {
    const value = this.getRaw(key);
    if (!value) return null;
    this.entries.delete(key);
    try { return JSON.parse(value) as T; } catch { return null; }
  }

  async setJson(key: string, value: unknown, ttlSeconds: number) {
    this.setRaw(key, JSON.stringify(value), ttlSeconds);
  }

  async delete(key: string) {
    this.entries.delete(key);
  }

  async deleteIfValue(key: string, value: string) {
    if (this.getRaw(key) !== value) return false;
    this.entries.delete(key);
    return true;
  }

  async setIfNotExists(key: string, value: string, ttlSeconds: number) {
    if (this.getRaw(key) !== null) return false;
    this.setRaw(key, value, ttlSeconds);
    return true;
  }

  async setRevokedAccess(jti: string, ttlSeconds: number) {
    this.setRaw(`auth:access:revoked:${jti}`, '1', ttlSeconds);
  }

  async isAccessRevoked(jti: string) {
    return this.getRaw(`auth:access:revoked:${jti}`) !== null;
  }

  async setRevokedSession(sessionId: string, ttlSeconds: number) {
    this.setRaw(`auth:session:revoked:${sessionId}`, '1', ttlSeconds);
  }

  async isSessionRevoked(sessionId: string) {
    return this.getRaw(`auth:session:revoked:${sessionId}`) !== null;
  }

  private setRaw(key: string, value: string, ttlSeconds: number) {
    this.entries.set(key, {
      value,
      expiresAt: nowMs() + ttlToMs(ttlSeconds),
    });
  }

  private getRaw(key: string) {
    const entry = this.entries.get(key);
    if (!entry) return null;
    if (entry.expiresAt <= nowMs()) {
      this.entries.delete(key);
      return null;
    }
    return entry.value;
  }
}

export class RedisEphemeralAuthStore implements EphemeralAuthStore {
  private client: any = null;

  constructor(private readonly url: string) {}

  async initialize() {
    if (this.client?.isOpen) return;
    const { createClient } = await Function('specifier', 'return import(specifier)')('redis');
    this.client = createClient({ url: this.url });
    await this.client.connect();
  }

  async getJson<T>(key: string) {
    const value = await this.requireClient().get(key);
    if (!value) return null;
    try {
      return JSON.parse(value) as T;
    } catch {
      return null;
    }
  }

  async takeJson<T>(key: string) {
    const client = this.requireClient();
    const value = typeof client.getDel === 'function'
      ? await client.getDel(key)
      : await client.sendCommand(['GETDEL', key]);
    if (!value) return null;
    try { return JSON.parse(value) as T; } catch { return null; }
  }

  async setJson(key: string, value: unknown, ttlSeconds: number) {
    await this.requireClient().set(key, JSON.stringify(value), { EX: Math.max(1, Math.floor(ttlSeconds)) });
  }

  async delete(key: string) {
    await this.requireClient().del(key);
  }

  async deleteIfValue(key: string, value: string) {
    const script = `
      if redis.call("get", KEYS[1]) == ARGV[1] then
        return redis.call("del", KEYS[1])
      end
      return 0
    `;
    const result = await (this.requireClient() as any).eval(script, {
      keys: [key],
      arguments: [value],
    });
    return result === 1;
  }

  async setIfNotExists(key: string, value: string, ttlSeconds: number) {
    const result = await this.requireClient().set(key, value, {
      EX: Math.max(1, Math.floor(ttlSeconds)),
      NX: true,
    });
    return result === 'OK';
  }

  async setRevokedAccess(jti: string, ttlSeconds: number) {
    await this.requireClient().set(`auth:access:revoked:${jti}`, '1', {
      EX: Math.max(1, Math.floor(ttlSeconds)),
    });
  }

  async isAccessRevoked(jti: string) {
    return (await this.requireClient().exists(`auth:access:revoked:${jti}`)) === 1;
  }

  async setRevokedSession(sessionId: string, ttlSeconds: number) {
    await this.requireClient().set(`auth:session:revoked:${sessionId}`, '1', {
      EX: Math.max(1, Math.floor(ttlSeconds)),
    });
  }

  async isSessionRevoked(sessionId: string) {
    return (await this.requireClient().exists(`auth:session:revoked:${sessionId}`)) === 1;
  }

  private requireClient() {
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
