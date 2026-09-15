import { spawnSync } from 'node:child_process';
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { normalizeVerifiedProviderIdentity, resolveCanonicalOwner } from '../auth/canonicalOwner.js';
import { verifyVvaultSessionProof } from '../auth/vvaultSessionFederation.js';
const subject = '11111111-1111-4111-8111-111111111111', owner = '22222222-2222-4222-8222-222222222222';
const identity = { provider: 'email', subject, issuer: 'https://vvault.thewreck.org', verifiedEmail: 'fixture@example.test' };
test('email owner lookup uses immutable existing identity, verified contact and active owner', async () => {
    let calls = 0;
    assert.equal(await resolveCanonicalOwner('ignored@example.test', async (sql, ...args) => {
        calls++;
        assert.match(sql, /identities\.id=\$1::uuid/);
        assert.match(sql, /identities\.provider='email'/);
        assert.match(sql, /identities\.verified_at is not null/);
        assert.match(sql, /contact_source\.id=emails\.identity_id/);
        assert.match(sql, /contact_source\.user_id=identities\.user_id/);
        assert.match(sql, /contact_source\.revoked_at is null/);
        assert.match(sql, /contact_source\.verified_at is not null/);
        assert.match(sql, /identities\.provider_subject=\$2/);
        assert.match(sql, /emails\.revoked_at is null/);
        assert.match(sql, /users\.account_state='ACTIVE'/);
        assert.deepEqual(args, [subject, identity.verifiedEmail]);
        return [{ id: owner }];
    }, identity), owner);
    assert.equal(calls, 1);
    for (const rows of [[], [{ id: owner }, { id: owner }], [{ id: 'not-uuid' }]])
        assert.equal(await resolveCanonicalOwner(identity.verifiedEmail, async () => rows, identity), null);
    for (const bad of [{ ...identity, subject: identity.verifiedEmail }, { ...identity, issuer: 'https://evil.example' }, { ...identity, verifiedEmail: undefined }])
        assert.equal(normalizeVerifiedProviderIdentity(bad), null);
});
test('pinned native email proof still enforces session, gates and audience', () => {
    const pair = crypto.generateKeyPairSync('ed25519'), now = Math.floor(Date.now() / 1000);
    const proof = { version: 'auth.vvault-native-session.v1', kind: 'IDENTITY', issuer: 'vvault', audience: 'quantum-auth', product_id: 'chatty', relyingParty: 'chatty', client_id: 'chatty-web-link', issuedAt: now, expiresAt: now + 60, authorization_request: 'request-fixture-long', nonce: 'nonce-fixture-long', authoritySessionBinding: 'session-fixture-long', ownerId: owner, provider_identity: identity, email: identity.verifiedEmail, name: 'Fixture', requirements: { enrollment: 'SATISFIED', session: 'SATISFIED', device: 'SATISFIED', policy: 'SATISFIED' }, chattyConsents: ['terms', 'privacy', 'eeccd'].map(key => ({ key: 'chatty:' + key, version: 'v1', sha256: 'a'.repeat(64), acceptedAt: new Date(now * 1000).toISOString() })) };
    const verify = (data) => { const encoded = Buffer.from(JSON.stringify(data)).toString('base64url'); return verifyVvaultSessionProof(encoded + '.' + crypto.sign(null, Buffer.from(encoded), pair.privateKey).toString('base64url'), { publicKeyPem: pair.publicKey.export({ type: 'spki', format: 'pem' }).toString(), audience: 'quantum-auth', now }); };
    assert.equal(verify(proof).provider_identity.subject, subject);
    for (const patch of [{ audience: 'other' }, { ownerId: 'invalid' }, { authoritySessionBinding: '' }, { requirements: { ...proof.requirements, device: 'PENDING' } }, { provider_identity: { ...identity, subject: 'email@example.test' } }])
        assert.throws(() => verify({ ...proof, ...patch }));
});
test('actual relational owner predicate rejects conflicting or revoked contact provenance', async () => {
    const script = `import json,sys,sqlite3
p=json.load(sys.stdin);d=sqlite3.connect(':memory:');d.row_factory=sqlite3.Row
d.execute("ATTACH DATABASE ':memory:' AS ovvaults")
d.executescript("CREATE TABLE ovvaults.users(id text,account_state text);CREATE TABLE ovvaults.external_identities(id text,user_id text,provider text,provider_subject text,revoked_at text,verified_at text);CREATE TABLE ovvaults.managed_emails(identity_id text,user_id text,normalized_email text,revoked_at text,verified_at text);")
owner='22222222-2222-4222-8222-222222222222';subject='11111111-1111-4111-8111-111111111111';email='fixture@example.test';case=p['case']
d.execute('INSERT INTO ovvaults.users VALUES (?,?)',(owner,'REJECTED' if case=='inactive' else 'ACTIVE'))
d.execute('INSERT INTO ovvaults.external_identities VALUES (?,?,?,?,?,?)',(subject,owner,'email','wrong@example.test' if case=='contact' else email,'revoked' if case=='identity-revoked' else None,'verified'))
d.execute('INSERT INTO ovvaults.external_identities VALUES (?,?,?,?,?,?)',('source','other' if case=='source-owner' else owner,'google','google-subject','revoked' if case=='source-revoked' else None,'verified'))
row=('source','other' if case=='managed-owner' else owner,email,None,'verified');d.execute('INSERT INTO ovvaults.managed_emails VALUES (?,?,?,?,?)',row)
if case=='duplicate':d.execute('INSERT INTO ovvaults.managed_emails VALUES (?,?,?,?,?)',row)
sql=p['sql'].replace('::uuid','').replace('::text','').replace('$1','?').replace('$2','?')
# $2 appears twice in this exact prepared predicate.
args=p['args'];print(json.dumps([dict(r) for r in d.execute(sql,[args[0],args[1],args[1]])]))
`;
    for (const scenario of ['valid', 'inactive', 'contact', 'identity-revoked', 'source-owner', 'source-revoked', 'managed-owner', 'duplicate']) {
        const result = await resolveCanonicalOwner(identity.verifiedEmail, async (sql, ...args) => {
            const child = spawnSync('python3', ['-c', script], { input: JSON.stringify({ sql, args, case: scenario }), encoding: 'utf8' });
            assert.equal(child.status, 0, child.stderr);
            return JSON.parse(child.stdout);
        }, identity);
        assert.equal(result, scenario === 'valid' ? owner : null, scenario);
    }
});
