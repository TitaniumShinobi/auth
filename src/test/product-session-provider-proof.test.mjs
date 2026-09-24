import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFileSync } from 'node:fs';
import ts from 'typescript';
const compile = path => ts.transpileModule(readFileSync(new URL(path, import.meta.url), 'utf8'), { compilerOptions: { module: ts.ModuleKind.ES2022, target: ts.ScriptTarget.ES2022 } }).outputText;
const data = source => 'data:text/javascript;base64,' + Buffer.from(source).toString('base64');
const owner = data(compile('../auth/canonicalOwner.ts'));
const mod = await import(data(compile('../auth/productSessionFederation.ts').replace("from './canonicalOwner.js'", `from '${owner}'`)));
const { canonicalizeProductSessionAssertion: canonical, signProductSessionAssertion: sign, verifyProductSessionAssertionSignature: verify, validateProductSessionAssertion: validate } = mod;
const secret = 'synthetic-federation-fixture-secret-only';
const now = 1800000000;
const base = { product_id: 'fixture', authorization_request: 'a'.repeat(32), subject: 'product-subject', email: 'fixture@example.test', name: 'Fixture', issued_at: now, expires_at: now + 45, nonce: 'b'.repeat(32) };
const proof = { provider: 'google', subject: 'provider-subject', issuer: 'https://accounts.google.com' };

test('legacy v1 bytes and signature remain unchanged without provider proof', () => {
  const legacyBytes = JSON.stringify({ product_id: base.product_id, authorization_request: base.authorization_request, subject: base.subject, email: base.email, name: base.name, picture: '', issued_at: now, expires_at: now + 45, nonce: base.nonce });
  assert.equal(canonical(base), legacyBytes);
  assert.equal(sign(base, secret), 'v1=' + crypto.createHmac('sha256', secret).update(legacyBytes).digest('base64url'));
  assert.equal(verify(base, sign(base, secret), secret), true);
  assert.equal(validate(base, now), true);
});
test('v2 signs normalized provider proof separately from product subject', () => {
  const input = { ...base, provider_identity: proof };
  assert.equal(validate(input, now), true);
  assert.match(sign(input, secret), /^v2=/);
  assert.equal(verify(input, sign(input, secret), secret), true);
  assert.equal(JSON.parse(canonical(input)).subject, 'product-subject');
  assert.deepEqual(JSON.parse(canonical(input)).provider_identity, proof);
});
test('injection tampering removal and version downgrade cannot retain proof', () => {
  const input = { ...base, provider_identity: proof };
  const signature = sign(input, secret);
  assert.equal(verify(input, sign(base, secret), secret), false);
  assert.equal(verify({ ...input, provider_identity: { ...proof, subject: 'attacker' } }, signature, secret), false);
  assert.equal(verify(base, signature, secret), false);
  assert.equal(verify(input, signature.replace(/^v2=/, 'v1='), secret), false);
  const extra = { ...base, providerIdentity: proof };
  assert.equal(canonical(extra), canonical(base));
  assert.equal(JSON.parse(canonical(extra)).provider_identity, undefined);
});
test('unknown provider issuer and malformed proof fail closed', () => {
  for (const provider_identity of [null, 'google', {}, { ...proof, provider: 'unknown' }, { ...proof, issuer: 'https://attacker.test' }, { ...proof, subject: '' }]) {
    const input = { ...base, provider_identity };
    assert.equal(validate(input, now), false);
    assert.equal(verify(input, 'v2=invalid', secret), false);
    assert.throws(() => sign(input, secret), /INVALID_PROVIDER_IDENTITY/);
  }
});
