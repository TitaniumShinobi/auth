import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { MemoryRefreshTokenStore } from '../auth/refreshTokenStore.js';
import { EnrollmentStore } from '../auth/enrollmentStore.js';
import { retireProductAdmission } from '../auth/retireProductAdmission.js';
test('retirement revokes exact product sessions while preserving LIFE identity and other owners', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'auth-retirement-test-'));
    const store = new EnrollmentStore(path.join(dir, 'state.sqlite'));
    const refresh = new MemoryRefreshTokenStore();
    try {
        for (const [sessionId, userId, appId] of [['old', 'account-a', 'chatty'], ['other', 'account-b', 'chatty'], ['different-product', 'account-a', 'other']])
            await refresh.createSession({ sessionId, userId, appId, refreshTokenId: sessionId, refreshTokenJti: sessionId, refreshTokenHash: sessionId, refreshExpiresAt: new Date(Date.now() + 60000) });
        const owner = '11111111-1111-4111-8111-111111111111', newOwner = '22222222-2222-4222-8222-222222222222', expiresAt = Math.floor(Date.now() / 1000) + 60;
        const old = { sessionBinding: 'old', identity: { subject: 'life-a' }, ownerId: owner, expiresAt };
        await store.put('old-transaction', old);
        await store.saveAdmission(old);
        const other = { sessionBinding: 'other', identity: { subject: 'life-b' }, ownerId: newOwner, expiresAt };
        await store.saveAdmission(other);
        const user = { id: 'account-a', lifeUserId: 'life-a', email: 'unchanged@example.test' }, before = JSON.stringify(user);
        const result = await retireProductAdmission({ userId: user.id, lifeSubject: user.lifeUserId, retiredOwnerId: owner, authorized: true }, { storage: { findUserById: async () => user }, refresh, enrollment: store });
        assert.equal(result.revokedSessions, 1);
        assert.equal(JSON.stringify(user), before);
        assert.equal(await refresh.getSessionStatus('old'), 'revoked');
        assert.equal(await refresh.getSessionStatus('other'), 'active');
        assert.equal(await refresh.getSessionStatus('different-product'), 'active');
        assert.equal(await store.get('old-transaction'), null);
        assert.equal(await store.admission('old'), null);
        assert.ok(await store.admission('other'));
        // A late old completion cannot revive the revoked session. New owner is a
        // separate admission bound to its own new session, retaining the LIFE subject.
        await store.saveAdmission(old);
        assert.equal(await refresh.getSessionStatus('old'), 'revoked');
        await store.saveAdmission({ ...old, sessionBinding: 'new', ownerId: newOwner });
        assert.equal((await store.admission('new')).ownerId, newOwner);
        await assert.rejects(retireProductAdmission({ userId: user.id, lifeSubject: 'different', retiredOwnerId: owner, authorized: true }, { storage: { findUserById: async () => user }, refresh, enrollment: store }));
    }
    finally {
        fs.rmSync(dir, { recursive: true, force: true });
    }
});
