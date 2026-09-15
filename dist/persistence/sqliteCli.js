import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { execFileSync } from 'node:child_process';
function escapeSqlString(value) {
    return `'${value.replace(/'/g, "''")}'`;
}
export function sqlString(value) {
    return value == null ? 'NULL' : escapeSqlString(value);
}
export function sqlBoolean(value) {
    return value ? '1' : '0';
}
export function ensureSqlitePath(dbPath) {
    mkdirSync(dirname(dbPath), { recursive: true });
}
export function execSql(dbPath, sql) {
    ensureSqlitePath(dbPath);
    execFileSync('sqlite3', [dbPath, sql], { encoding: 'utf8' });
}
export function querySql(dbPath, sql) {
    ensureSqlitePath(dbPath);
    const output = execFileSync('sqlite3', ['-json', dbPath, sql], { encoding: 'utf8' }).trim();
    if (!output)
        return [];
    return JSON.parse(output);
}
