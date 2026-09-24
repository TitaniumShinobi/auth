import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import test from 'node:test';

import {
  createVvaultAccessAssertion,
  verifyVvaultAccessAssertion,
  type VvaultAccessAssertionConfig,
} from '../auth/vvaultAccessAssertion.js';
import type { SessionUser } from '../types.js';

const keyPair = crypto.generateKeyPairSync('ed25519');
const privateKeyPem = keyPair.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
const publicKeyPem = keyPair.publicKey.export({ type: 'spki', format: 'pem' }).toString();
const config: VvaultAccessAssertionConfig = {
  privateKeyPem,
  publicKeyPem,
  issuer: 'quantum-auth',
  audience: 'vvault',
  keyId: crypto.createHash('sha256').update(publicKeyPem).digest('hex'),
  ttlSeconds: 60,
};

function verifiedSession(): SessionUser {
  const subject = 'canary_owner_1770000000000';
  const owner = 'aaaaaaaa-bbbb-4ccc-9ddd-eeeeeeeeeeee';
  return {
    id: subject,
    sub: subject,
    uid: owner,
    vvaultUserId: owner,
    supabaseUserId: owner,
    email: 'must-not-appear@example.com',
    name: 'Must Not Appear',
    auth_provider: 'credentials',
    actorAttestation: {
      version: 'life-auth-actor-attestation/v1',
      subject,
      vvaultOwnerId: owner,
      issuer: 'quantum-auth',
    },
    accountContextReadiness: {
      version: 'life-auth-account-context-readiness/v1',
      ready: true,
      subject,
      reason: 'canonical_owner_verified',
      vvaultOwnerId: owner,
      evidenceSource: 'supabase_found',
    },
  };
}

test('access assertion is short-lived, owner-bound, scoped, and excludes profile data', async () => {
  const issued = await createVvaultAccessAssertion(verifiedSession(), 'canary-session', config, 'chatty-cli', 1_700_000_000);
  assert.equal(issued.assertion.expiresAt - issued.assertion.issuedAt, 60);
  assert.ok(issued.assertion.scopes.includes('transcripts:append'));
  assert.ok(issued.assertion.scopes.includes('work:read'));
  assert.equal((issued.assertion.scopes as string[]).includes('work:append'), false);
  assert.equal(issued.assertion.relyingPartyId, 'chatty-cli');
  const payloadText = Buffer.from(issued.token.split('.')[1]!, 'base64url').toString('utf8');
  for (const forbidden of ['email', 'picture', 'provider', 'credential', 'profile']) {
    assert.equal(payloadText.toLowerCase().includes(forbidden), false);
  }
});

test('access assertion verifies only for its issuer, audience, key, and lifetime', async () => {
  const now = Math.floor(Date.now() / 1000);
  const issued = await createVvaultAccessAssertion(verifiedSession(), 'canary-session', config, 'chatty', now);
  assert.equal((await verifyVvaultAccessAssertion(issued.token, config))?.vvaultOwnerId,
    'aaaaaaaa-bbbb-4ccc-9ddd-eeeeeeeeeeee');
  const tamperedParts = issued.token.split('.');
  const signature = Buffer.from(tamperedParts[2]!, 'base64url');
  signature[0] = signature[0]! ^ 1;
  tamperedParts[2] = signature.toString('base64url');
  assert.equal(await verifyVvaultAccessAssertion(tamperedParts.join('.'), config), null);
  assert.equal(await verifyVvaultAccessAssertion(issued.token, { ...config, audience: 'vvault' as const, issuer: 'wrong' }), null);

  const other = crypto.generateKeyPairSync('ed25519');
  const otherPublic = other.publicKey.export({ type: 'spki', format: 'pem' }).toString();
  assert.equal(await verifyVvaultAccessAssertion(issued.token, {
    ...config,
    privateKeyPem: other.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    publicKeyPem: otherPublic,
    keyId: crypto.createHash('sha256').update(otherPublic).digest('hex'),
  }), null);
});

test('unverified or mismatched canonical owner cannot mint an assertion', async () => {
  const session = verifiedSession();
  session.accountContextReadiness = {
    version: 'life-auth-account-context-readiness/v1',
    ready: false,
    subject: session.sub,
    reason: 'canonical_owner_unverified',
  };
  await assert.rejects(createVvaultAccessAssertion(session, 'canary-session', config, 'chatty'), /canonical_owner_unverified/);
});
