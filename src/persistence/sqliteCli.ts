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

export function execSql(dbPath: string, sql: string) {
  ensureSqlitePath(dbPath);
  execFileSync('sqlite3', [dbPath, sql], { encoding: 'utf8' });
}

export function querySql<T>(dbPath: string, sql: string): T[] {
  ensureSqlitePath(dbPath);
  const output = execFileSync('sqlite3', ['-json', dbPath, sql], { encoding: 'utf8' }).trim();
  if (!output) return [];
  return JSON.parse(output) as T[];
}
