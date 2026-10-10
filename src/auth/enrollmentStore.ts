import { chmodSync, mkdirSync, openSync, closeSync, lstatSync } from 'node:fs';
import { dirname, isAbsolute } from 'node:path';
import { execFileSync } from 'node:child_process';
const q = (value: unknown) => `'${String(value).replace(/'/g, "''")}'`;
/** One shared local-host durable database, never a canonical account registry. */
export class EnrollmentStore {
  constructor(private path: string) {
    if (!isAbsolute(path)) throw new Error('ENROLLMENT_STORE_ABSOLUTE_PATH_REQUIRED');
    mkdirSync(dirname(path), { recursive:true, mode:0o700 });
    try { closeSync(openSync(path,'wx',0o600)); } catch(error: any) { if(error.code!=='EEXIST')throw error; }
    const stat=lstatSync(path);
    if (!stat.isFile() || stat.isSymbolicLink() || (typeof process.getuid==='function' && stat.uid!==process.getuid())) throw new Error('ENROLLMENT_STORE_PROTECTION_REQUIRED');
    chmodSync(path,0o600);
    this.sql(`CREATE TABLE IF NOT EXISTS enrollment_transactions(id TEXT PRIMARY KEY, record TEXT NOT NULL, expires INTEGER NOT NULL, consumed INTEGER NOT NULL DEFAULT 0);
      CREATE TABLE IF NOT EXISTS enrollment_admissions(session TEXT PRIMARY KEY, record TEXT NOT NULL, expires INTEGER NOT NULL);`);
    chmodSync(path, 0o600);
  }
  private sql(sql: string): any[] {
    const out = execFileSync('sqlite3', ['-json', this.path], { input: `.timeout 5000\n${sql}`, encoding: 'utf8', stdio: ['pipe','pipe','pipe'] }).trim();
    return out ? JSON.parse(out) : [];
  }
  async put(id: string, record: any) {
    this.sql(`BEGIN IMMEDIATE; DELETE FROM enrollment_transactions WHERE expires <= unixepoch(); DELETE FROM enrollment_admissions WHERE expires <= unixepoch(); INSERT INTO enrollment_transactions(id,record,expires) VALUES(${q(id)},${q(JSON.stringify(record))},${Number(record.expiresAt)}); COMMIT;`);
  }
  async get(id: string) {
    const row=this.sql(`SELECT record FROM enrollment_transactions WHERE id=${q(id)} AND consumed=0 AND expires>unixepoch();`)[0];
    return row ? JSON.parse(row.record) : null;
  }
  async consume(id: string, expected: any, notAfter: number) {
    const rows=this.sql(`BEGIN IMMEDIATE; UPDATE enrollment_transactions SET consumed=1 WHERE id=${q(id)} AND record=${q(JSON.stringify(expected))} AND consumed=0 AND expires>unixepoch() AND unixepoch()<${Number(notAfter)}; SELECT changes() AS changed; COMMIT;`);
    return rows[0]?.changed===1;
  }
  async saveAdmission(admission: any) {
    this.sql(`INSERT INTO enrollment_admissions(session,record,expires) VALUES(${q(admission.sessionBinding)},${q(JSON.stringify(admission))},${Number(admission.expiresAt)}) ON CONFLICT(session) DO UPDATE SET record=excluded.record,expires=excluded.expires;`);
  }
  async retireOwnerAdmission(subject: string, ownerId: string) {
    if(!subject || !/^[0-9a-f-]{36}$/i.test(ownerId))throw new Error('RETIREMENT_SCOPE_REQUIRED');
    this.sql(`BEGIN IMMEDIATE;
      UPDATE enrollment_transactions SET consumed=1,expires=0 WHERE json_extract(record,'$.identity.subject')=${q(subject)} AND json_extract(record,'$.ownerId')=${q(ownerId)};
      UPDATE enrollment_admissions SET expires=0 WHERE json_extract(record,'$.identity.subject')=${q(subject)} AND json_extract(record,'$.ownerId')=${q(ownerId)};
      COMMIT;`);
  }
  async admission(session: string) {
    const row=this.sql(`SELECT record FROM enrollment_admissions WHERE session=${q(session)} AND expires>unixepoch();`)[0];
    return row ? JSON.parse(row.record) : null;
  }
}
