import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import ts from 'typescript';
const compile = name => ts.transpileModule(readFileSync(new URL(name, import.meta.url), 'utf8'), { compilerOptions: { module: ts.ModuleKind.ES2022, target: ts.ScriptTarget.ES2022 } }).outputText;
const data = source => 'data:text/javascript;base64,' + Buffer.from(source).toString('base64');
const authorization = data(compile('../auth/authorizationCode.ts'));
const { DesktopHandoff, desktopCompletionPage, desktopRecoveryPage } = await import(data(compile('../auth/desktopHandoff.ts').replace("'./authorizationCode.js'", JSON.stringify(authorization))));
const issuer = 'https://auth.example.test';
const callback = 'http://127.0.0.1:34567/callback';
const client = { appId: 'desktop-product', clientId: 'desktop-test', loopback: { hosts: ['127.0.0.1'], path: '/callback', allowDynamicPorts: true }, redirectUris: ['com.example.app:/callback'] };
function fixture() {
  let pending = null, generation = 0, clock = 1000, session = null;
  const calls = [];
  const host = {
    generation: () => generation, loadPending: () => pending, savePending: p => { pending = { ...p }; },
    invalidate: () => { generation++; pending = null; },
    openSystemBrowser: async url => { calls.push(['browser', url]); },
    exchange: async (request, code) => { calls.push(['exchange']); return { issuer, clientId: client.clientId, session: { sub: 'synthetic-user' } }; },
    commitSession: (p, s) => { if (p.generation !== generation || p.transaction !== pending?.transaction) return false; session = s; pending = null; return true; },
    restoreWorkspace: async (ref, gen) => { assert.equal(gen, generation); calls.push(['workspace', ref]); },
    activateExistingInstance: async gen => { assert.equal(gen, generation); calls.push(['activate']); return 'foreground'; },
    restoreSession: async () => !!session, clearSession: () => { session = null; },
  };
  const flow = new DesktopHandoff(host, issuer, client, () => clock);
  return { flow, host, calls, tick: ms => { clock += ms; }, session: () => session,
    url: (values = {}) => { const p = host.loadPending(); const url = new URL(p.redirectUri); url.search = new URLSearchParams({ code: 'synthetic-code', state: p.state, ...values }).toString(); return url.toString(); } };
}
async function started() { const f = fixture(); assert.equal((await f.flow.begin(callback, 'opaque-local-workspace')).state, 'pending'); return f; }

test('system browser + PKCE; same instance restores original workspace exactly once', async () => {
  const f = await started(); const p = f.host.loadPending(); const browser = new URL(f.calls[0][1]);
  assert.equal(browser.searchParams.get('code_challenge_method'), 'S256');
  assert.equal(browser.searchParams.get('app'), client.appId);
  assert.equal(browser.searchParams.get('state'), p.state);
  assert.equal(browser.searchParams.get('code_challenge'), p.challenge);
  assert.ok(!browser.toString().includes(p.verifier)); assert.ok(!browser.toString().includes(p.resumeReference));
  const url = f.url(); assert.deepEqual(await f.flow.callback(url), { state: 'authenticated', focus: 'foreground' });
  assert.equal((await f.flow.callback(url)).reason, 'STALE_CALLBACK');
  assert.deepEqual(f.calls.slice(1), [['exchange'], ['workspace', 'opaque-local-workspace'], ['activate']]);
  assert.equal(f.host.loadPending(), null);
});
for (const variant of ['state', 'issuer', 'callback', 'duplicate-state', 'pkce', 'client', 'generation', 'empty-code', 'code-and-error']) {
  test(`${variant} mismatch cannot admit a session`, async () => {
    const f = await started(); let url = f.url();
    if (variant === 'state') url = f.url({ state: 'wrong' });
    if (variant === 'issuer') url = f.url({ iss: 'https://wrong.example.test' });
    if (variant === 'callback') url = url.replace('/callback?', '/wrong?');
    if (variant === 'duplicate-state') url += '&state=other';
    if (variant === 'pkce') f.host.savePending({ ...f.host.loadPending(), verifier: 'x'.repeat(43) });
    if (variant === 'client') f.host.savePending({ ...f.host.loadPending(), clientId: 'other' });
    if (variant === 'generation') f.host.savePending({ ...f.host.loadPending(), generation: -1 });
    if (variant === 'empty-code') url = f.url({ code: '' });
    if (variant === 'code-and-error') url = f.url({ error: 'access_denied' });
    assert.equal((await f.flow.callback(url)).state, 'recoverable-error'); assert.equal(f.session(), null);
    assert.equal(f.calls.filter(c => c[0] === 'exchange').length, 0);
  });
}
test('registered deep link uses the same validation and session path', async () => {
  const f = fixture(); await f.flow.begin('com.example.app:/callback', 'workspace');
  assert.equal((await f.flow.callback(f.url())).state, 'authenticated');
  assert.equal((await f.flow.begin('other:/callback', 'workspace')).reason, 'UNREGISTERED_CALLBACK');
});
test('cancel, deny, timeout and sign-out reject late callbacks', async () => {
  for (const action of ['cancel', 'deny', 'timeout', 'signout']) {
    const f = await started(); const url = f.url();
    if (action === 'cancel') f.flow.cancel();
    if (action === 'signout') f.flow.signOut();
    if (action === 'timeout') { f.tick(600001); assert.equal(f.flow.expire().state, 'timed-out'); }
    if (action === 'deny') { const denied = new URL(url); denied.searchParams.delete('code'); denied.searchParams.set('error', 'access_denied'); assert.equal((await f.flow.callback(denied.toString())).state, 'denied'); }
    assert.equal((await f.flow.callback(url)).reason, 'STALE_CALLBACK'); assert.equal(f.session(), null);
  }
});
test('single-flight exchange; sign-out during exchange cannot re-admit', async () => {
  const f = await started(); let resolve; f.host.exchange = () => new Promise(r => { resolve = r; });
  const url = f.url(); const result = f.flow.callback(url);
  assert.equal((await f.flow.callback(url)).reason, 'STALE_CALLBACK');
  f.flow.signOut(); resolve({ issuer, clientId: client.clientId, session: {} });
  assert.equal((await result).reason, 'STALE_CALLBACK'); assert.equal(f.session(), null);
});
test('expiry during exchange prevents session commit', async () => {
  const f = await started(); f.host.exchange = async () => { f.tick(600001); return { issuer, clientId: client.clientId, session: {} }; };
  assert.equal((await f.flow.callback(f.url())).state, 'timed-out'); assert.equal(f.session(), null);
});
test('untrusted exchange binding and exchange errors fail closed', async () => {
  for (const kind of ['issuer', 'client', 'throw']) {
    const f = await started(); f.host.exchange = async () => { if (kind === 'throw') throw Error('secret must not escape'); return { issuer: kind === 'issuer' ? 'other' : issuer, clientId: kind === 'client' ? 'other' : client.clientId, session: {} }; };
    const result = await f.flow.callback(f.url()); assert.equal(result.reason, 'SESSION_COMPLETION_FAILED'); assert.equal(f.session(), null); assert.equal(f.host.loadPending(), null);
  }
});
test('browser failure clears secrets; duplicate start does not spawn another browser', async () => {
  const f = await started(); assert.equal((await f.flow.begin(callback, 'other')).reason, 'SIGNIN_ALREADY_PENDING'); assert.equal(f.calls.length, 1);
  f.flow.cancel(); f.host.openSystemBrowser = async () => { throw Error('failed'); };
  assert.equal((await f.flow.begin(callback, 'workspace')).reason, 'BROWSER_LAUNCH_FAILED'); assert.equal(f.host.loadPending(), null);
});
test('crash/reboot invalidates pending exchange and restarts, or restores existing session', async () => {
  const f = await started(); const old = f.url(); f.host.savePending({ ...f.host.loadPending(), phase: 'exchanging' });
  assert.equal((await f.flow.recover(callback, 'opaque-local-workspace')).state, 'pending');
  assert.equal((await f.flow.callback(old)).state, 'recoverable-error');
  assert.equal((await f.flow.callback(f.url())).state, 'authenticated');
  const browserCount = f.calls.filter(c => c[0] === 'browser').length;
  assert.equal((await f.flow.recover(callback, 'opaque-local-workspace')).state, 'authenticated');
  assert.equal(f.calls.filter(c => c[0] === 'browser').length, browserCount);
});
test('account switch during restore cannot launch or activate stale account', async () => {
  const f = fixture(); f.host.restoreSession = async () => { f.flow.signOut(); return false; };
  assert.equal((await f.flow.recover(callback, 'workspace')).state, 'cancelled'); assert.equal(f.calls.length, 0);
});
test('focus restrictions are reported instead of claiming foreground success', async () => {
  const f = await started(); f.host.activateExistingInstance = async () => 'user-action-required';
  assert.equal((await f.flow.callback(f.url())).focus, 'user-action-required');
});
test('completion page escapes app name and has secret-free explicit fallback and no-store/CSP', () => {
  const page = desktopCompletionPage('<Example & App>', 'com.example.app://auth-complete');
  assert.ok(page.body.includes('Open &lt;Example &amp; App&gt;')); assert.ok(page.body.includes('window.location.replace'));
  assert.equal(page.headers['Cache-Control'], 'no-store'); assert.equal(page.headers['Referrer-Policy'], 'no-referrer');
  assert.ok(page.headers['Content-Security-Policy'].includes("default-src 'none'"));
  for (const uri of ['javascript:alert(1)', 'https://example.test', 'com.example.app://auth-complete?code=secret', 'com.example.app://auth-complete#token', 'com.example.app://auth-complete/workspace', 'com.example.app://user:password@auth-complete']) assert.throws(() => desktopCompletionPage('App', uri));
});
test('host operations time out; a late exchange cannot commit', async () => {
  const f = fixture(); const flow = new DesktopHandoff(f.host, issuer, client, () => 1000, 5);
  await flow.begin(callback, 'workspace'); let finish, signal;
  f.host.exchange = (_p, _code, s) => { signal = s; return new Promise(r => { finish = r; }); };
  assert.equal((await flow.callback(f.url())).reason, 'SESSION_COMPLETION_FAILED');
  assert.equal(signal.aborted, true); assert.equal(f.host.loadPending(), null);
  finish({ issuer, clientId: client.clientId, session: {} }); await Promise.resolve(); assert.equal(f.session(), null);
});
test('workspace failure is recoverable without replaying code or denying persisted session', async () => {
  const f = await started(); f.host.restoreWorkspace = async () => { throw Error('unavailable'); };
  assert.equal((await f.flow.callback(f.url())).reason, 'SESSION_COMPLETION_FAILED');
  assert.ok(f.session()); assert.equal(f.host.loadPending(), null);
  f.host.restoreWorkspace = async () => {};
  assert.equal((await f.flow.recover(callback, 'workspace')).state, 'authenticated');
});
test('authority persistence error is recoverable, never treated as user denial or admission', async () => {
  const f = await started(); const url = new URL(f.url()); url.searchParams.delete('code'); url.searchParams.set('error', 'temporarily_unavailable');
  assert.deepEqual(await f.flow.callback(url.toString()), { state: 'recoverable-error', reason: 'AUTHORIZATION_FAILED', focus: 'foreground' });
  assert.equal(f.session(), null); assert.equal(f.host.loadPending(), null);
});

test('failure page offers safe existing-instance activation without claiming success', () => {
  const page = desktopRecoveryPage('Example', 'com.example.app://auth-complete');
  assert.ok(page.body.includes('Sign-in could not complete'));
  assert.ok(page.body.includes('Open Example'));
  assert.ok(!page.body.includes('Sign-in complete.'));
});
