import assert from 'node:assert/strict';
import test from 'node:test';
import { createAccessToken, resolveJwtTokenConfig, verifyAccessToken } from '../auth/jwtTokens.js';
const config = resolveJwtTokenConfig('actor-attestation-test-secret');
function user(ageAssurance) {
    return {
        id: 'canary_user_1770000000000',
        sub: 'canary_user_1770000000000',
        uid: 'canary_user_1770000000000',
        lifeUserId: 'canary_user_1770000000000',
        vvaultUserId: 'canary_user_1770000000000',
        email: 'canary@example.com',
        name: 'Canary',
        auth_provider: 'credentials',
        actorAttestation: {
            version: 'life-auth-actor-attestation/v1',
            subject: 'canary_user_1770000000000',
            vvaultOwnerId: 'canary_user_1770000000000',
            issuer: 'quantum-auth',
            ...(ageAssurance ? { ageAssurance } : {}),
        },
    };
}
test('access token carries an additive owner-bound actor attestation', async () => {
    const issued = await createAccessToken(user('adult'), 'session-1', config);
    const verified = await verifyAccessToken(issued.token, config);
    assert.equal(verified?.session.actorAttestation?.vvaultOwnerId, 'canary_user_1770000000000');
    assert.equal(verified?.session.actorAttestation?.ageAssurance, 'adult');
    assert.equal(JSON.stringify(verified).includes('birth'), false);
});
test('age assurance is optional and no date of birth claim is introduced', async () => {
    const issued = await createAccessToken(user(), 'session-2', config);
    const verified = await verifyAccessToken(issued.token, config);
    assert.equal(verified?.session.actorAttestation?.ageAssurance, undefined);
    assert.deepEqual(Object.keys(verified?.session.actorAttestation || {}).sort(), [
        'issuer', 'subject', 'version', 'vvaultOwnerId',
    ]);
});
