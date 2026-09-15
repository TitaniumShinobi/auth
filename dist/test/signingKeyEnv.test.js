import test from 'node:test';
import assert from 'node:assert/strict';
import { loadSigningKeyFromKeychain } from '../signingKeyEnv.js';
test('preserves plain PEM and decodes macOS hexadecimal PEM output', () => {
    const pem = '-----BEGIN PRIVATE KEY-----\nsynthetic-fixture\n-----END PRIVATE KEY-----';
    for (const value of [pem, Buffer.from(pem).toString('hex'), Buffer.from(pem).toString('hex').toUpperCase()]) {
        const env = {};
        loadSigningKeyFromKeychain(env, 'darwin', () => ` ${value}\n`);
        assert.equal(env.AUTH_VVAULT_ACCESS_ASSERTION_PRIVATE_KEY_PEM, pem);
    }
});
test('does not partially decode malformed hexadecimal input', () => {
    for (const value of ['abc', 'aaZZ', 'aa bb']) {
        const env = {};
        loadSigningKeyFromKeychain(env, 'darwin', () => value);
        assert.equal(env.AUTH_VVAULT_ACCESS_ASSERTION_PRIVATE_KEY_PEM, value);
    }
});
test('loads the established Keychain identity for direct service startup', () => {
    const env = {};
    loadSigningKeyFromKeychain(env, 'darwin', (service, account) => {
        assert.equal(service, 'life-auth-vvault-access-assertion-v1');
        assert.equal(account, 'auth-local');
        return ' synthetic-key\n';
    });
    assert.equal(env.AUTH_VVAULT_ACCESS_ASSERTION_PRIVATE_KEY_PEM, 'synthetic-key');
});
test('preserves either explicit signer and skips non-macOS hosts', () => {
    for (const env of [
        { AUTH_VVAULT_ACCESS_ASSERTION_PRIVATE_KEY_PEM: 'configured' },
        { AUTH_VVAULT_ACCOUNT_ASSERTION_PRIVATE_KEY_PEM: 'configured' },
    ]) {
        let read = false;
        loadSigningKeyFromKeychain(env, 'darwin', () => { read = true; return 'replacement'; });
        assert.equal(read, false);
        assert.ok(Object.values(env).includes('configured'));
    }
    const env = {};
    let called = false;
    loadSigningKeyFromKeychain(env, 'linux', () => { called = true; return 'key'; });
    assert.equal(called, false);
    assert.deepEqual(env, {});
});
test('honors configured Keychain reference and leaves unavailable keys absent', () => {
    const env = { AUTH_VVAULT_ACCESS_ASSERTION_KEYCHAIN_SERVICE: 'service', AUTH_VVAULT_ACCESS_ASSERTION_KEYCHAIN_ACCOUNT: 'account' };
    loadSigningKeyFromKeychain(env, 'darwin', (service, account) => {
        assert.equal(service, 'service');
        assert.equal(account, 'account');
        throw new Error('private subprocess output');
    });
    assert.equal(env.AUTH_VVAULT_ACCESS_ASSERTION_PRIVATE_KEY_PEM, undefined);
    loadSigningKeyFromKeychain(env, 'darwin', () => '');
    assert.equal(env.AUTH_VVAULT_ACCESS_ASSERTION_PRIVATE_KEY_PEM, undefined);
});
test('explicit account reference loads separately without changing access key', () => {
    const env = {
        AUTH_VVAULT_ACCESS_ASSERTION_PRIVATE_KEY_PEM: 'access-original',
        AUTH_VVAULT_ACCOUNT_ASSERTION_KEYCHAIN_SERVICE: 'life-auth-vvault-account-assertion-v1',
        AUTH_VVAULT_ACCOUNT_ASSERTION_KEYCHAIN_ACCOUNT: 'auth-local',
    };
    loadSigningKeyFromKeychain(env, 'darwin', (service, account) => {
        assert.equal(service, 'life-auth-vvault-account-assertion-v1');
        assert.equal(account, 'auth-local');
        return Buffer.from('account-fixture').toString('hex');
    });
    assert.equal(env.AUTH_VVAULT_ACCESS_ASSERTION_PRIVATE_KEY_PEM, 'access-original');
    assert.equal(env.AUTH_VVAULT_ACCOUNT_ASSERTION_PRIVATE_KEY_PEM, 'account-fixture');
});
test('account reference failure never substitutes access key', () => {
    const env = {
        AUTH_VVAULT_ACCESS_ASSERTION_PRIVATE_KEY_PEM: 'access-original',
        AUTH_VVAULT_ACCOUNT_ASSERTION_KEYCHAIN_SERVICE: 'account-service',
        AUTH_VVAULT_ACCOUNT_ASSERTION_KEYCHAIN_ACCOUNT: 'auth-local',
    };
    loadSigningKeyFromKeychain(env, 'darwin', () => { throw new Error('private'); });
    assert.equal(env.AUTH_VVAULT_ACCOUNT_ASSERTION_PRIVATE_KEY_PEM, undefined);
    assert.equal(env.AUTH_VVAULT_ACCESS_ASSERTION_PRIVATE_KEY_PEM, 'access-original');
});
test('slow authorized account read has separate bounded budget; access remains five seconds', async () => {
    const childProcess = (await import('node:child_process')).default;
    const { syncBuiltinESMExports } = await import('node:module');
    const original = childProcess.execFileSync;
    const budgets = [];
    childProcess.execFileSync = ((_file, _args, options) => {
        budgets.push(options.timeout);
        // Model the measured 28-second Keychain response without sleeping or reading secrets.
        if (options.timeout < 28000)
            throw new Error('synthetic timeout');
        return 'synthetic-account-key';
    });
    syncBuiltinESMExports();
    try {
        const env = {
            AUTH_VVAULT_ACCOUNT_ASSERTION_KEYCHAIN_SERVICE: 'account-fixture',
            AUTH_VVAULT_ACCOUNT_ASSERTION_KEYCHAIN_ACCOUNT: 'auth-local',
        };
        loadSigningKeyFromKeychain(env, 'darwin');
        assert.deepEqual(budgets, [5000, 60000]);
        assert.equal(env.AUTH_VVAULT_ACCESS_ASSERTION_PRIVATE_KEY_PEM, undefined);
        assert.equal(env.AUTH_VVAULT_ACCOUNT_ASSERTION_PRIVATE_KEY_PEM, 'synthetic-account-key');
    }
    finally {
        childProcess.execFileSync = original;
        syncBuiltinESMExports();
    }
});
