import test from 'node:test';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { EnrollmentStore } from '../auth/enrollmentStore.js';
test('durable insert, restart, comparison, one redemption, and expiry', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'auth-enrollment-'));
    try {
        const path = join(dir, 'tx.sqlite');
        const a = new EnrollmentStore(path);
        const record = { expiresAt: Math.floor(Date.now() / 1000) + 60, sessionBinding: 'session-a' };
        await a.put('tx', record);
        await assert.rejects(a.put('tx', record));
        const b = new EnrollmentStore(path);
        assert.deepEqual(await b.get('tx'), record);
        assert.equal(await b.consume('tx', { ...record, sessionBinding: 'b' }, record.expiresAt), false);
        assert.equal(await b.consume('tx', record, 0), false);
        assert.deepEqual(await Promise.all([a.consume('tx', record, record.expiresAt), b.consume('tx', record, record.expiresAt)]), [true, false]);
        assert.equal(await new EnrollmentStore(path).get('tx'), null);
        await a.put('concurrent', record);
        const moduleUrl = new URL('../auth/enrollmentStore.js', import.meta.url).href;
        const run = promisify(execFile);
        const program = `import {EnrollmentStore} from ${JSON.stringify(moduleUrl)}; const store=new EnrollmentStore(process.argv[1]); console.log(await store.consume('concurrent',JSON.parse(process.argv[2]),Number(process.argv[3])));`;
        const races = await Promise.all(Array.from({ length: 4 }, () => run(process.execPath, ['--input-type=module', '-e', program, path, JSON.stringify(record), String(record.expiresAt)])));
        assert.equal(races.filter(r => r.stdout.trim() === 'true').length, 1);
        assert.equal(await new EnrollmentStore(path).get('concurrent'), null);
        await a.saveAdmission({ ...record, admission: 'AUTHORIZED' });
        assert.equal((await b.admission('session-a')).admission, 'AUTHORIZED');
        assert.equal(await b.admission('session-b'), null);
        await a.saveAdmission({ ...record, expiresAt: 0 });
        assert.equal(await b.admission('session-a'), null);
    }
    finally {
        rmSync(dir, { recursive: true, force: true });
    }
});
