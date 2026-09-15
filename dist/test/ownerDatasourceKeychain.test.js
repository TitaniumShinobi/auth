import test from 'node:test';
import assert from 'node:assert/strict';
import { ownerDatasourceFromKeychain } from '../auth/ownerDatasourceKeychain.js';
const env = { AUTH_CANONICAL_OWNER_DATASOURCE_REF: 'env:AUTH_CANONICAL_OWNER_DATABASE_URL',
    AUTH_OWNER_KEYCHAIN_SERVICE: 'fixture', AUTH_OWNER_KEYCHAIN_ACCOUNT: 'fixture', AUTH_OWNER_TUNNEL_PORT: '25432' };
test('existing protected item feeds only dedicated lookup and preserves database/path/options', () => {
    const before = { ...env };
    const value = ownerDatasourceFromKeychain(env, () => 'postgresql://fixture:synthetic@db.invalid:5432/canonical?sslmode=require');
    const url = new URL(value);
    assert.equal(url.hostname, '127.0.0.1');
    assert.equal(url.port, '25432');
    assert.equal(url.pathname, '/canonical');
    assert.equal(url.search, '?sslmode=require');
    assert.deepEqual(env, before);
});
test('unselected or incomplete configuration never reads Keychain', () => {
    for (const entry of [{}, { ...env, AUTH_CANONICAL_OWNER_DATASOURCE_REF: 'invalid' }, { ...env, AUTH_OWNER_KEYCHAIN_ACCOUNT: '' }]) {
        assert.equal(ownerDatasourceFromKeychain(entry, () => { throw new Error('must not read'); }), null);
    }
});
test('invalid protocol, tunnel port and inaccessible item fail closed', () => {
    assert.equal(ownerDatasourceFromKeychain(env, () => 'https://invalid'), null);
    assert.equal(ownerDatasourceFromKeychain({ ...env, AUTH_OWNER_TUNNEL_PORT: '65536' }, () => 'postgres://fixture/db'), null);
    assert.equal(ownerDatasourceFromKeychain(env, () => { throw new Error('secret'); }), null);
});
