import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';
import { accountContextProfileForSession, canIssueAccountContextAssertion, createAccountContextAssertion, verifyAccountContextAssertion, } from '../auth/accountContextAssertion.js';
const keyPair = crypto.generateKeyPairSync('ed25519');
const privateKeyPem = keyPair.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
const publicKeyPem = keyPair.publicKey.export({ type: 'spki', format: 'pem' }).toString();
const config = {
    privateKeyPem,
    publicKeyPem,
    issuer: 'quantum-auth',
    audience: 'vvault',
    keyId: crypto.createHash('sha256').update(publicKeyPem).digest('hex'),
    ttlSeconds: 60,
};
function verifiedCanary(ageAssurance) {
    const subject = 'canary_owner_1770000000000';
    const vvaultOwnerId = 'aaaaaaaa-bbbb-4ccc-9ddd-eeeeeeeeeeee';
    return {
        id: subject,
        sub: subject,
        uid: 'aaaaaaaa-bbbb-4ccc-9ddd-eeeeeeeeeeee',
        lifeUserId: subject,
        vvaultUserId: vvaultOwnerId,
        supabaseUserId: vvaultOwnerId,
        email: 'private-canary@example.com',
        name: 'Canary Owner',
        picture: 'https://private.example/canary.png',
        auth_provider: 'credentials',
        actorAttestation: {
            version: 'life-auth-actor-attestation/v1',
            subject,
            vvaultOwnerId,
            issuer: 'quantum-auth',
            ...(ageAssurance ? { ageAssurance } : {}),
        },
        accountContextReadiness: {
            version: 'life-auth-account-context-readiness/v1',
            ready: true,
            subject,
            reason: 'canonical_owner_verified',
            vvaultOwnerId,
            evidenceSource: 'supabase_found',
        },
    };
}
test('account-context assertion is owner-bound, audience-bound, and contains only approved profile fields', async () => {
    const issued = await createAccountContextAssertion(verifiedCanary('adult'), 'canary-session', config);
    const verified = await verifyAccountContextAssertion(issued.token, config);
    assert.deepEqual(verified?.accountContext, {
        displayName: 'Canary Owner',
        ageAssurance: 'adult',
    });
    assert.equal(verified?.subject, 'canary_owner_1770000000000');
    assert.equal(verified?.vvaultOwnerId, 'aaaaaaaa-bbbb-4ccc-9ddd-eeeeeeeeeeee');
    assert.notEqual(verified?.vvaultOwnerId, verified?.subject);
    assert.equal(verified?.sessionId, 'canary-session');
    const payload = JSON.parse(Buffer.from(issued.token.split('.')[1], 'base64url').toString('utf8'));
    assert.deepEqual(Object.keys(payload.account_context).sort(), ['ageAssurance', 'displayName']);
    for (const forbidden of ['email', 'picture', 'provider', 'token', 'birth', 'supabase']) {
        assert.equal(JSON.stringify(payload).toLowerCase().includes(forbidden), false);
    }
});
test('unknown age assurance is not projected into construct-visible account context', async () => {
    const session = verifiedCanary('unknown');
    assert.deepEqual(accountContextProfileForSession(session), { displayName: 'Canary Owner' });
    const issued = await createAccountContextAssertion(session, 'canary-session', config);
    assert.deepEqual(issued.assertion.accountContext, { displayName: 'Canary Owner' });
});
test('local-only and mismatched owner identities cannot mint an assertion', async () => {
    const localOnly = verifiedCanary();
    delete localOnly.actorAttestation;
    localOnly.uid = localOnly.sub;
    localOnly.vvaultUserId = localOnly.sub;
    localOnly.supabaseUserId = undefined;
    localOnly.accountContextReadiness = {
        version: 'life-auth-account-context-readiness/v1',
        ready: false,
        subject: localOnly.sub,
        reason: 'canonical_owner_unverified',
    };
    assert.equal(canIssueAccountContextAssertion(localOnly), false);
    await assert.rejects(createAccountContextAssertion(localOnly, 'local-session', config), /canonical_owner_unverified/);
    const mismatched = verifiedCanary();
    mismatched.actorAttestation.vvaultOwnerId = 'another_owner_1770000000000';
    assert.equal(canIssueAccountContextAssertion(mismatched), false);
});
