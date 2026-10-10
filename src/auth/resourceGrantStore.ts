import { chmodSync, closeSync, existsSync, lstatSync, mkdirSync, openSync } from 'node:fs';
import { dirname, isAbsolute, parse, resolve } from 'node:path';
import { execFileSync } from 'node:child_process';

export type ResourceGrantRecord = {
  id: string; jti: string; tokenDigest: string; issuer: string; subject: string;
  sessionId: string; sourceAccessJti: string; clientId: string; applicationId: string;
  audience: string; ownerId: string; capabilities: string[]; issuedAt: number;
  expiresAt: number; admissionVersion: string;
};
export interface ResourceGrantStore {
  initialize(): Promise<void>;
  put(record: ResourceGrantRecord): Promise<void>;
  get(id: string): Promise<(ResourceGrantRecord & { revoked: boolean }) | null>;
  revoke(id: string): Promise<void>;
}

const APPLICATION_ID = 0x41554752;
const q = (value: string) => `'${value.replace(/'/g, "''")}'`;
const FIELDS = ['id', 'jti', 'tokenDigest', 'issuer', 'subject', 'sessionId', 'sourceAccessJti', 'clientId', 'applicationId', 'audience', 'ownerId', 'admissionVersion'] as const;

function sanitizeRecord(record: ResourceGrantRecord): ResourceGrantRecord {
  if (!record || typeof record !== 'object') throw new Error('RESOURCE_GRANT_INVALID');
  for (const key of FIELDS) {
    if (typeof record[key] !== 'string' || !record[key].length || record[key].length > 1024 || /[\x00-\x1f]/.test(record[key])) throw new Error('RESOURCE_GRANT_INVALID');
  }
  if (!/^[a-f0-9]{64}$/.test(record.tokenDigest)
    || !Number.isSafeInteger(record.issuedAt) || !Number.isSafeInteger(record.expiresAt)
    || record.issuedAt < 0 || record.expiresAt <= record.issuedAt || record.expiresAt - record.issuedAt > 60
    || !Array.isArray(record.capabilities) || record.capabilities.length < 1 || record.capabilities.length > 64
    || record.capabilities.some(value => typeof value !== 'string' || !value.length || value.length > 128 || /[\x00-\x20]/.test(value))
    || new Set(record.capabilities).size !== record.capabilities.length) throw new Error('RESOURCE_GRANT_INVALID');
  // Project known fields: unexpected token/credential properties are never persisted.
  return { ...Object.fromEntries(FIELDS.map(key => [key, record[key]])), capabilities: [...record.capabilities], issuedAt: record.issuedAt, expiresAt: record.expiresAt } as ResourceGrantRecord;
}

/** Dedicated local durable grant state. Never opens an account/session database by default. */
export class SqliteResourceGrantStore implements ResourceGrantStore {
  private initialized = false;
  constructor(private readonly path: string) {
    if (!isAbsolute(path) || resolve(path) !== path) throw new Error('RESOURCE_GRANT_STORE_ABSOLUTE_PATH_REQUIRED');
  }

  private assertProtectedPath() {
    let component = this.path;
    const root = parse(component).root;
    while (component !== root) {
      if (existsSync(component) && lstatSync(component).isSymbolicLink()) throw new Error('RESOURCE_GRANT_STORE_SYMLINK_REJECTED');
      component = dirname(component);
    }
    const parent = lstatSync(dirname(this.path));
    const file = lstatSync(this.path);
    const uid = typeof process.getuid === 'function' ? process.getuid() : undefined;
    if (!parent.isDirectory() || (parent.mode & 0o077) !== 0 || (uid !== undefined && parent.uid !== uid)
      || !file.isFile() || file.nlink !== 1 || (file.mode & 0o077) !== 0 || (uid !== undefined && file.uid !== uid)) {
      throw new Error('RESOURCE_GRANT_STORE_PROTECTION_REQUIRED');
    }
  }

  private sql(statement: string): any[] {
    this.assertProtectedPath();
    try {
      const out = execFileSync('sqlite3', ['-batch', '-bail', '-json', this.path], {
        input: `.timeout 1500\n${statement}`, encoding: 'utf8', timeout: 5000,
        maxBuffer: 1024 * 1024, stdio: ['pipe', 'pipe', 'pipe'],
      }).trim();
      return out ? JSON.parse(out) : [];
    } catch {
      // sqlite diagnostics can include SQL values; callers receive only a reason code.
      throw new Error('RESOURCE_GRANT_STORE_OPERATION_FAILED');
    }
  }

  async initialize(): Promise<void> {
    // Check every existing component before any directory/file creation.
    let component = this.path;
    while (component !== parse(component).root) {
      try { if (lstatSync(component).isSymbolicLink()) throw new Error('RESOURCE_GRANT_STORE_SYMLINK_REJECTED'); }
      catch (error: any) { if (error.code !== 'ENOENT') throw error; }
      component = dirname(component);
    }
    mkdirSync(dirname(this.path), { recursive: true, mode: 0o700 });
    try { closeSync(openSync(this.path, 'wx', 0o600)); }
    catch (error: any) { if (error.code !== 'EEXIST') throw error; }
    this.assertProtectedPath();
    const applicationId = this.sql('PRAGMA application_id;')[0]?.application_id;
    const objects = this.sql('SELECT count(*) AS count FROM sqlite_master;')[0]?.count;
    if (applicationId !== APPLICATION_ID && (applicationId !== 0 || objects !== 0)) throw new Error('RESOURCE_GRANT_STORE_FOREIGN_DATABASE');
    this.sql(`BEGIN IMMEDIATE;
      PRAGMA application_id=${APPLICATION_ID};
      CREATE TABLE IF NOT EXISTS resource_session_bindings (
        sid TEXT PRIMARY KEY, subject TEXT NOT NULL, client TEXT NOT NULL, application TEXT NOT NULL,
        UNIQUE(sid, subject, client, application));
      CREATE TABLE IF NOT EXISTS resource_grants (
        id TEXT PRIMARY KEY, jti TEXT NOT NULL UNIQUE, record TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0,
        sid TEXT NOT NULL, subject TEXT NOT NULL, client TEXT NOT NULL, application TEXT NOT NULL);
      CREATE TRIGGER IF NOT EXISTS resource_binding_guard BEFORE INSERT ON resource_grants
      WHEN NOT EXISTS (SELECT 1 FROM resource_session_bindings WHERE sid=NEW.sid AND subject=NEW.subject AND client=NEW.client AND application=NEW.application)
      BEGIN SELECT RAISE(ABORT, 'RESOURCE_SESSION_BINDING_CONFLICT'); END;
      COMMIT;`);
    chmodSync(this.path, 0o600);
    this.initialized = true;
  }

  private requireInitialized() { if (!this.initialized) throw new Error('RESOURCE_GRANT_STORE_NOT_INITIALIZED'); }

  async put(input: ResourceGrantRecord): Promise<void> {
    this.requireInitialized();
    const record = sanitizeRecord(input);
    this.sql(`BEGIN IMMEDIATE;
      INSERT INTO resource_session_bindings(sid,subject,client,application) VALUES(${q(record.sessionId)},${q(record.subject)},${q(record.clientId)},${q(record.applicationId)}) ON CONFLICT(sid) DO NOTHING;
      INSERT INTO resource_grants(id,jti,record,sid,subject,client,application) VALUES(${q(record.id)},${q(record.jti)},${q(JSON.stringify(record))},${q(record.sessionId)},${q(record.subject)},${q(record.clientId)},${q(record.applicationId)});
      COMMIT;`);
  }
  async get(id: string): Promise<(ResourceGrantRecord & { revoked: boolean }) | null> {
    this.requireInitialized();
    const row = this.sql(`SELECT record,revoked FROM resource_grants WHERE id=${q(id)};`)[0];
    return row ? { ...sanitizeRecord(JSON.parse(row.record)), revoked: row.revoked !== 0 } : null;
  }
  async revoke(id: string): Promise<void> {
    this.requireInitialized();
    this.sql(`UPDATE resource_grants SET revoked=1 WHERE id=${q(id)};`);
  }
}
