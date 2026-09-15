import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { getDbPath } from '../config.js';
test('defaults auth sqlite to a local non-synced path', () => {
    const originalAuthDbPath = process.env.AUTH_DB_PATH;
    try {
        delete process.env.AUTH_DB_PATH;
        const dbPath = getDbPath();
        assert.ok(path.isAbsolute(dbPath));
        assert.ok(!dbPath.endsWith(path.join('data', 'auth.sqlite')));
        const expectedPath = path.join(os.tmpdir(), 'chatty-auth', 'auth.sqlite');
        assert.equal(dbPath, expectedPath);
    }
    finally {
        if (originalAuthDbPath === undefined) {
            delete process.env.AUTH_DB_PATH;
        }
        else {
            process.env.AUTH_DB_PATH = originalAuthDbPath;
        }
    }
});
