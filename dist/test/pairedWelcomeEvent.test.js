import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { pairedWelcomeEvent, submitPairedWelcome } from '../auth/pairedWelcomeEvent.js';
test('welcome event requires completed admission and submits only to configured authority', async () => {
    const key = crypto.generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
    const admission = { admission: 'AUTHORIZED', relyingParty: 'chatty', expiresAt: 1060, identity: { subject: 'life' }, ownerId: '11111111-1111-4111-8111-111111111111', sessionBinding: 'session', transaction: 'transaction' };
    assert.throws(() => pairedWelcomeEvent({ ...admission, admission: 'PENDING' }, key, 'quantum-auth', 1000));
    const event = pairedWelcomeEvent(admission, key, 'quantum-auth', 1000);
    assert.equal(await submitPairedWelcome(event, 'https://vvault.example', async (url, init) => { assert.equal(String(url), 'https://vvault.example/api/auth/enrollment/welcome-event'); assert.equal(init?.redirect, 'error'); assert.equal((init?.headers).cookie, undefined); return new Response('{}', { status: 202 }); }), 'QUEUED');
    await assert.rejects(submitPairedWelcome(event, 'https://user:password@vvault.example'));
});
