import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { execFileSync } from 'node:child_process';

function escapeSqlString(value: string) {
  return `'${value.replace(/'/g, "''")}'`;
}

export function sqlString(value: string | null | undefined) {
  return value == null ? 'NULL' : escapeSqlString(value);
}

export function sqlBoolean(value: boolean) {
  return value ? '1' : '0';
}

export function ensureSqlitePath(dbPath: string) {
  mkdirSync(dirname(dbPath), { recursive: true });
}

export class SqlitePersistenceError extends Error {
  readonly code = 'AUTH_PERSISTENCE_UNAVAILABLE';
  constructor(readonly reason: string) { super('Authentication persistence is unavailable'); this.name = 'SqlitePersistenceError'; }
}

export function classifySqliteFailure(error: unknown): string {
  const e = error as { code?: string; stderr?: Buffer | string; signal?: string };
  if (e?.code === 'ENOENT') return 'SQLITE_EXECUTABLE_MISSING';
  if (e?.code === 'EACCES' || e?.code === 'EPERM') return 'SQLITE_ACCESS_DENIED';
  if (e?.code === 'ETIMEDOUT' || e?.signal) return 'SQLITE_OPERATION_TIMEOUT';
  const stderr = String(e?.stderr || '').toLowerCase();
  if (/database is locked|database is busy/.test(stderr)) return 'SQLITE_BUSY';
  if (/readonly|read-only/.test(stderr)) return 'SQLITE_READ_ONLY';
  if (/unable to open/.test(stderr)) return 'SQLITE_OPEN_FAILED';
  if (/no such table|no such column|has no column/.test(stderr)) return 'SQLITE_SCHEMA_MISMATCH';
  if (/constraint failed/.test(stderr)) return 'SQLITE_CONSTRAINT_FAILED';
  return 'SQLITE_OPERATION_FAILED';
}

function runSql(dbPath: string, sql: string, json = false) {
  try {
    ensureSqlitePath(dbPath);
    // SQL may contain profile/session data. Keep it off process arguments and errors.
    return execFileSync('sqlite3', [...(json ? ['-json'] : []), '-bail', dbPath], {
      input: `.timeout 5000\n${sql}\n`, encoding: 'utf8', timeout: 10_000,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
  } catch (error) { throw new SqlitePersistenceError(classifySqliteFailure(error)); }
}

export function execSql(dbPath: string, sql: string) { runSql(dbPath, sql); }

export function querySql<T>(dbPath: string, sql: string): T[] {
  const output = runSql(dbPath, sql, true).trim();
  if (!output) return [];
  return JSON.parse(output) as T[];
}
