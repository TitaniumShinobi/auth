import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { resolveVvaultAccessAssertionConfig } from '../auth/vvaultAccessAssertion.js';
test('explicit access public/key ID preserves its pair when account signer differs', () => {
    const original = { ...process.env };
    const access = crypto.generateKeyPairSync('ed25519');
    const account = crypto.generateKeyPairSync('ed25519');
    const pub = access.publicKey.export({ type: 'spki', format: 'pem' }).toString();
    const accountPub = account.publicKey.export({ type: 'spki', format: 'pem' }).toString();
    const kid = crypto.createHash('sha256').update(pub).digest('hex');
    try {
        process.env.AUTH_VVAULT_ACCESS_ASSERTION_PRIVATE_KEY_PEM = access.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
        process.env.AUTH_VVAULT_ACCOUNT_ASSERTION_PUBLIC_KEY_PEM = accountPub;
        process.env.AUTH_VVAULT_ACCOUNT_ASSERTION_KEY_ID = crypto.createHash('sha256').update(accountPub).digest('hex');
        delete process.env.AUTH_VVAULT_ACCESS_ASSERTION_PUBLIC_KEY_PEM;
        delete process.env.AUTH_VVAULT_ACCESS_ASSERTION_KEY_ID;
        const mixed = resolveVvaultAccessAssertionConfig();
        assert.ok(mixed);
        const message = Buffer.from('synthetic assertion signed bytes');
        assert.equal(crypto.verify(null, message, mixed.publicKeyPem, crypto.sign(null, message, mixed.privateKeyPem)), false);
        process.env.AUTH_VVAULT_ACCESS_ASSERTION_PUBLIC_KEY_PEM = pub;
        process.env.AUTH_VVAULT_ACCESS_ASSERTION_KEY_ID = kid;
        const correct = resolveVvaultAccessAssertionConfig();
        assert.ok(correct);
        assert.equal(correct.keyId, kid);
        assert.equal(crypto.verify(null, message, correct.publicKeyPem, crypto.sign(null, message, correct.privateKeyPem)), true);
        assert.equal(process.env.AUTH_VVAULT_ACCOUNT_ASSERTION_PUBLIC_KEY_PEM, accountPub);
    }
    finally {
        process.env = original;
    }
});
