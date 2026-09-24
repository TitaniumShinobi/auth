import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { runControlledFixture } from '../../scripts/auth-conformance-fixture.mjs';

test('compiled AUTH fixture demonstrates protocol enforcement with cleanup and no secret output', () => {
  const before=readdirSync(tmpdir()).filter(n=>n.startsWith('auth-fixture-')).sort();
  const r=runControlledFixture(process.cwd());
  assert.equal(r.completed,true,JSON.stringify(r));
  for(const name of ['pkce_verifier_rejected','authorization_code_replay_rejected','refresh_rotation','refresh_replay_rejected','revoked_access_rejected','revoked_refresh_rejected','expired_access_rejected','expired_refresh_rejected','userinfo_authorized','isolated_identity']) assert.equal(r.results[name],true,name);
  assert.equal(r.cleanup,true);assert.equal(r.serverClosed,true);
  assert.deepEqual(readdirSync(tmpdir()).filter(n=>n.startsWith('auth-fixture-')).sort(),before);
  assert.doesNotMatch(JSON.stringify(r),/Bearer |eyJ|password|access_token|refresh_token/);
});
test('fixture is CLI-only and injects all data stores; no product/production route is added', () => {
  const worker=readFileSync('scripts/auth-conformance-fixture-worker.mjs','utf8');
  const app=readFileSync('src/app.ts','utf8');
  assert.doesNotMatch(app,/AUTH_CONFORMANCE_CHILD|fixture\.sock|conformance-fixture/);
  assert.match(worker,/storage,refreshTokenStore,ephemeralStore/);
  assert.match(worker,/resolveVvaultOwnerId:async\(\)=>null/);
  assert.match(worker,/server.listen\(socketPath/);
  assert.doesNotMatch(worker,/chatty|localhost:1111/i);
});
test('failed child fixture is cleaned up and never establishes PASS', () => {
  const before=readdirSync(tmpdir()).filter(n=>n.startsWith('auth-fixture-')).sort();
  const r=runControlledFixture(process.cwd(),'/usr/bin/false');
  assert.equal(r.completed,false);assert.equal(r.cleanup,true);assert.deepEqual(r.results,{});
  assert.deepEqual(readdirSync(tmpdir()).filter(n=>n.startsWith('auth-fixture-')).sort(),before);
});
