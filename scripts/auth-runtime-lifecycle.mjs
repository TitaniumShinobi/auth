/** Authenticated runtime baseline, read-only verification, repair, upgrade, and crash recovery. */
import { cp, lstat, mkdir, readFile, rename, rm, rmdir, stat, writeFile } from 'node:fs/promises';
import { createHash, randomUUID } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import net from 'node:net';
import path from 'node:path';
import { installProductAuthRuntime, inspectProductAuthRuntime } from './auth-runtime-installer.mjs';

const RUNTIME = '.auth-runtime/auth-system';
const BASELINE = '.auth-kit/runtime-baseline';
const STATE = '.auth-kit/runtime-baseline/state.json';
const JOURNAL = '.auth-runtime-lifecycle-journal.json';
const sha = (v) => createHash('sha256').update(v).digest('hex');
const canonical = (v) => Array.isArray(v) ? v.map(canonical) : v && typeof v === 'object'
  ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, canonical(v[k])])) : v;
const digest = (v) => sha(Buffer.from(JSON.stringify(canonical(v))));
const json = (v) => `${JSON.stringify(v, null, 2)}\n`;
const identity = (s) => ({ dev: s.dev, ino: s.ino });
const sameIdentity = (a, b) => a && b && a.dev === b.dev && a.ino === b.ino;
async function exists(p) { try { return await lstat(p); } catch (e) { if (e?.code === 'ENOENT') return null; throw e; } }
async function atomicJson(target, value) { const tmp = `${target}.tmp-${randomUUID()}`; await writeFile(tmp, json(value), { flag: 'wx' }); await rename(tmp, target); }
function fail(code) { throw Object.assign(new Error(code), { code }); }
function abruptAt(point) {
  if (process.env.AUTH_RUNTIME_TEST_MODE === '1' && process.env.AUTH_RUNTIME_TEST_ABRUPT_POINT === point) process.exit(87);
}
const UUID = '[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}';
function validateSwapJournal(journal) {
  if (journal.contract !== 'life.auth.runtime-swap/1' || !Number.isInteger(journal.revision) || !['PREPARED', 'OLD_QUARANTINED', 'NEW_PUBLISHED', 'BASELINE_ADVANCING', 'BASELINE_ADVANCED'].includes(journal.state)) fail('RUNTIME_SWAP_JOURNAL_INVALID');
  if (!(new RegExp(`^\\.auth-runtime-candidate-${UUID}$`, 'i')).test(journal.holder || '')) fail('RUNTIME_SWAP_JOURNAL_INVALID');
  if (journal.candidate !== `${journal.holder}/.auth-runtime/auth-system`) fail('RUNTIME_SWAP_JOURNAL_INVALID');
  if (!(new RegExp(`^\\.auth-runtime-previous-${UUID}$`, 'i')).test(journal.backup || '')) fail('RUNTIME_SWAP_JOURNAL_INVALID');
  if (journal.baselineBackup && !(new RegExp(`^\\.auth-kit/runtime-baseline\\.previous-${UUID}$`, 'i')).test(journal.baselineBackup)) fail('RUNTIME_SWAP_JOURNAL_INVALID');
  if (journal.baselineNext && !(new RegExp(`^\\.auth-kit/runtime-baseline\\.next-${UUID}$`, 'i')).test(journal.baselineNext)) fail('RUNTIME_SWAP_JOURNAL_INVALID');
  for (const value of [journal.productId, journal.previousInstallationId, journal.targetInstallationId]) if (typeof value !== 'string' || !value) fail('RUNTIME_SWAP_JOURNAL_INVALID');
  if (journal.state === 'BASELINE_ADVANCING' || journal.state === 'BASELINE_ADVANCED') {
    if (!/^[0-9a-f]{64}$/i.test(journal.targetBaselineDigest || '')) fail('RUNTIME_SWAP_JOURNAL_INVALID');
  }
  for (const value of [journal.previousIdentity, journal.candidateIdentity]) if (!value || !Number.isInteger(value.dev) || !Number.isInteger(value.ino)) fail('RUNTIME_SWAP_JOURNAL_INVALID');
}
async function cleanupEmptyHolder(root, relative) {
  const holder = path.join(root, relative), nested = path.join(holder, '.auth-runtime');
  if (await exists(nested)) await rmdir(nested);
  if (await exists(holder)) await rmdir(holder);
}
async function assertRuntimeIdentity(runtimeRoot, expectedIdentity, installationId) {
  const entry = await lstat(runtimeRoot);
  if (entry.isSymbolicLink() || !entry.isDirectory() || !sameIdentity(identity(await stat(runtimeRoot)), expectedIdentity)) fail('RUNTIME_SWAP_IDENTITY_AMBIGUOUS');
  const manifest = JSON.parse(await readFile(path.join(runtimeRoot, 'AUTH-RUNTIME-MANIFEST.json'), 'utf8'));
  if (manifest.installationId !== installationId) fail('RUNTIME_SWAP_DIGEST_AMBIGUOUS');
}

export async function acceptRuntimeOperational(runtimeRoot) {
  for (const args of [['ci', '--no-audit', '--no-fund'], ['run', 'prisma:generate'], ['run', 'build']]) {
    const result = spawnSync('npm', args, { cwd: runtimeRoot, encoding: 'utf8', timeout: 120_000 });
    if (result.status !== 0) return { verification: 'FAIL', error: `RUNTIME_${args[0] === 'ci' ? 'LOCKED_INSTALL' : args.at(-1).toUpperCase()}_FAILED` };
  }
  const server = net.createServer();
  await new Promise((resolve, reject) => server.listen(0, '127.0.0.1', resolve).once('error', reject));
  const port = server.address().port;
  await new Promise((resolve) => server.close(resolve));
  const child = spawn(process.execPath, ['dist/index.js'], { cwd: runtimeRoot, stdio: 'ignore', env: {
    PATH: process.env.PATH, AUTH_HOST: '127.0.0.1', AUTH_PORT: String(port), AUTH_STORAGE_ADAPTER: 'memory', AUTH_APP_CONFIG_PATH: 'config/example-app.json',
    AUTH_SESSION_SECRET: 'acceptance-session-secret-32-characters', AUTH_ACCESS_TOKEN_SECRET: 'acceptance-access-secret-32-characters',
    AUTH_REFRESH_TOKEN_SECRET: 'acceptance-refresh-secret-32-characters', AUTH_REFRESH_TOKEN_HASH_SECRET: 'acceptance-refresh-hash-secret-32-chars',
  } });
  try {
    const deadline = Date.now() + 20_000;
    while (Date.now() < deadline) {
      if (child.exitCode !== null) return { verification: 'FAIL', error: 'RUNTIME_STARTUP_FAILED' };
      try {
        const ready = await fetch(`http://127.0.0.1:${port}/ready`);
        if (ready.status === 200 && (await ready.json()).ready === true) {
          const config = await fetch(`http://127.0.0.1:${port}/api/auth/config`);
          const callback = await fetch(`http://127.0.0.1:${port}/api/auth/google/callback`);
          if (config.status === 404 || callback.status === 404) return { verification: 'FAIL', error: 'RUNTIME_ROUTES_MISSING' };
          return { verification: 'PASS', checks: ['locked_install', 'prisma_generate', 'build', 'startup', 'readiness', 'auth_routes'], acceptedAt: new Date().toISOString() };
        }
      } catch {}
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    return { verification: 'FAIL', error: 'RUNTIME_READINESS_TIMEOUT' };
  } finally {
    if (child.exitCode === null) { child.kill('SIGTERM'); await new Promise((resolve) => child.once('exit', resolve)); }
  }
}

async function copyBaselineFiles(runtime, baseline, manifest) {
  await mkdir(baseline, { recursive: false });
  for (const relative of Object.keys(manifest.files).sort()) {
    const source = path.join(runtime, relative), target = path.join(baseline, 'files', relative);
    const entry = await lstat(source);
    if (!entry.isFile() || entry.isSymbolicLink()) fail('RUNTIME_BASELINE_SOURCE_INVALID');
    await mkdir(path.dirname(target), { recursive: true });
    await cp(source, target, { errorOnExist: true, force: false });
  }
  await writeFile(path.join(baseline, 'AUTH-RUNTIME-MANIFEST.json'), json(manifest), { flag: 'wx' });
}

async function validateBaseline(root) {
  const state = JSON.parse(await readFile(path.join(root, STATE), 'utf8'));
  if (state.contract !== 'life.auth.runtime-state/1' || !state.baselineDigest) fail('RUNTIME_BASELINE_STATE_INVALID');
  const baselineRoot = path.join(root, BASELINE);
  const manifest = JSON.parse(await readFile(path.join(baselineRoot, 'AUTH-RUNTIME-MANIFEST.json'), 'utf8'));
  for (const [relative, expected] of Object.entries(manifest.files || {})) {
    const bytes = await readFile(path.join(baselineRoot, 'files', relative));
    if (sha(bytes) !== expected.sha256 || bytes.length !== expected.bytes) fail('RUNTIME_BASELINE_BYTES_INVALID');
  }
  const payload = { installationId: manifest.installationId, manifestDigest: digest(manifest), source: manifest.source, previousInstallationId: state.previousInstallationId ?? null, lineage: state.lineage || [] };
  if (digest(payload) !== state.baselineDigest || state.installationId !== manifest.installationId) fail('RUNTIME_BASELINE_DIGEST_INVALID');
  return { state, manifest, baselineRoot, payload };
}

export async function verifyRuntimeLifecycle(root, productId, { acceptance } = {}) {
  const checks = [];
  try {
    const inspected = await inspectProductAuthRuntime(root, productId);
    checks.push({ id: 'runtime_integrity', result: 'PASS' }, { id: 'immutable_source', result: 'PASS' }, { id: 'lock_integrity', result: 'PASS' });
    const baseline = await validateBaseline(root);
    if (baseline.manifest.installationId !== inspected.manifest.installationId) fail('RUNTIME_BASELINE_MISMATCH');
    checks.push({ id: 'baseline_integrity', result: 'PASS' }, { id: 'version_binding', result: 'PASS' });
    if (acceptance) {
      const result = await acceptance(path.join(root, RUNTIME), inspected.manifest);
      if (result?.verification !== 'PASS') fail(result?.error || 'RUNTIME_ACCEPTANCE_FAILED');
      checks.push({ id: 'build_start_readiness', result: 'PASS' }, { id: 'source_independence', result: 'PASS' });
    }
    return { contract: 'life.auth.runtime-verification/1', verification: 'PASS', installationId: inspected.manifest.installationId, checks };
  } catch (error) {
    return { contract: 'life.auth.runtime-verification/1', verification: 'FAIL', error: error?.code || error?.message || 'RUNTIME_VERIFY_FAILED', checks };
  }
}

export async function establishRuntimeBaseline(root, productId, { authorized = false, acceptance } = {}) {
  if (!authorized) fail('RUNTIME_ESTABLISH_AUTHORIZATION_REQUIRED');
  if (await exists(path.join(root, STATE)) || await exists(path.join(root, BASELINE))) fail('RUNTIME_BASELINE_ALREADY_EXISTS');
  const inspected = await inspectProductAuthRuntime(root, productId);
  if (!acceptance) fail('RUNTIME_ACCEPTANCE_REQUIRED');
  const accepted = await acceptance(path.join(root, RUNTIME), inspected.manifest);
  if (accepted?.verification !== 'PASS') fail(accepted?.error || 'RUNTIME_ACCEPTANCE_FAILED');
  const temp = path.join(root, `.auth-runtime-baseline-${randomUUID()}`);
  await copyBaselineFiles(path.join(root, RUNTIME), temp, inspected.manifest);
  const payload = { installationId: inspected.manifest.installationId, manifestDigest: digest(inspected.manifest), source: inspected.manifest.source, previousInstallationId: null, lineage: [] };
  const state = { contract: 'life.auth.runtime-state/1', lifecycleState: 'ESTABLISHED', productId, installationId: inspected.manifest.installationId, previousInstallationId: null, lineage: [], baselineDigest: digest(payload), acceptedAt: new Date().toISOString(), acceptance: accepted };
  await writeFile(path.join(temp, 'state.json'), json(state), { flag: 'wx' });
  await rename(temp, path.join(root, BASELINE));
  return state;
}

async function writeJournal(root, journal) { journal.revision += 1; await atomicJson(path.join(root, JOURNAL), journal); }

export async function recoverRuntimeLifecycle(root) {
  const journalPath = path.join(root, JOURNAL);
  if (!await exists(journalPath)) return { recovered: false };
  const journalEntry = await lstat(journalPath);
  if (journalEntry.isSymbolicLink() || !journalEntry.isFile()) fail('RUNTIME_SWAP_JOURNAL_INVALID');
  const journal = JSON.parse(await readFile(journalPath, 'utf8'));
  validateSwapJournal(journal);
  const runtime = path.join(root, RUNTIME), candidate = path.join(root, journal.candidate), backup = path.join(root, journal.backup);
  if (journal.state === 'BASELINE_ADVANCING') {
    const currentState = await readFile(path.join(root, STATE), 'utf8').then(JSON.parse).catch(() => null);
    if (currentState?.installationId === journal.targetInstallationId && currentState?.baselineDigest === journal.targetBaselineDigest) journal.state = 'BASELINE_ADVANCED';
    else if (currentState?.installationId === journal.previousInstallationId) {
      if (journal.baselineNext && await exists(path.join(root, journal.baselineNext))) await rm(path.join(root, journal.baselineNext), { recursive: true, force: false });
      journal.state = 'NEW_PUBLISHED';
    } else if (!currentState && journal.baselineBackup && await exists(path.join(root, journal.baselineBackup))) {
      const baseline = path.join(root, BASELINE), baselineBackup = path.join(root, journal.baselineBackup);
      if (await exists(baseline)) fail('RUNTIME_SWAP_BASELINE_AMBIGUOUS');
      await rename(baselineBackup, baseline);
      if (journal.baselineNext && await exists(path.join(root, journal.baselineNext))) await rm(path.join(root, journal.baselineNext), { recursive: true, force: false });
      journal.state = 'NEW_PUBLISHED';
    } else fail('RUNTIME_SWAP_BASELINE_AMBIGUOUS');
  }
  if (journal.state === 'BASELINE_ADVANCED') {
    const verified = await verifyRuntimeLifecycle(root, journal.productId);
    if (verified.verification !== 'PASS' || verified.installationId !== journal.targetInstallationId) fail('RUNTIME_SWAP_FINALIZE_REFUSED');
    if (await exists(backup)) { await assertRuntimeIdentity(backup, journal.previousIdentity, journal.previousInstallationId); await rm(backup, { recursive: true, force: false }); }
    if (await exists(candidate)) { await assertRuntimeIdentity(candidate, journal.candidateIdentity, journal.targetInstallationId); await rm(candidate, { recursive: true, force: false }); }
    await cleanupEmptyHolder(root, journal.holder);
    if (journal.baselineBackup && await exists(path.join(root, journal.baselineBackup))) await rm(path.join(root, journal.baselineBackup), { recursive: true, force: false });
    if (journal.baselineNext && await exists(path.join(root, journal.baselineNext))) await rm(path.join(root, journal.baselineNext), { recursive: true, force: false });
    await rm(journalPath);
    return { recovered: true, action: 'finalized' };
  }
  if (await exists(runtime) && journal.state === 'NEW_PUBLISHED') { await assertRuntimeIdentity(runtime, journal.candidateIdentity, journal.targetInstallationId); await rename(runtime, candidate); }
  if (await exists(backup) && !await exists(runtime)) { await assertRuntimeIdentity(backup, journal.previousIdentity, journal.previousInstallationId); await rename(backup, runtime); }
  if (await exists(candidate)) { await assertRuntimeIdentity(candidate, journal.candidateIdentity, journal.targetInstallationId); await rm(candidate, { recursive: true, force: false }); }
  await cleanupEmptyHolder(root, journal.holder);
  await rm(journalPath);
  return { recovered: true, action: 'rolled_back' };
}

async function prepareCandidate(root, productId, sourceRoot, sourceRevision, config, acceptance) {
  const holderName = `.auth-runtime-candidate-${randomUUID()}`;
  const holder = path.join(root, holderName);
  await mkdir(holder);
  try {
    await installProductAuthRuntime(holder, { sourceRoot, sourceRevision, productId, config, authorized: true });
    const candidateRuntime = path.join(holder, RUNTIME);
    const accepted = await acceptance(candidateRuntime);
    if (accepted?.verification !== 'PASS') fail(accepted?.error || 'RUNTIME_CANDIDATE_REJECTED');
    return { holderName, holder, candidateRuntime, manifest: (await inspectProductAuthRuntime(holder, productId)).manifest, accepted };
  } catch (error) {
    await rm(holder, { recursive: true, force: false });
    throw error;
  }
}

async function swapRuntime(root, productId, operation, candidate, previous, acceptance, testHook) {
  const runtime = path.join(root, RUNTIME);
  const candidateRelative = path.relative(root, candidate.candidateRuntime);
  const backupRelative = `.auth-runtime-previous-${randomUUID()}`;
  const backup = path.join(root, backupRelative);
  const journal = { contract: 'life.auth.runtime-swap/1', revision: 0, state: 'PREPARED', operation, productId, candidate: candidateRelative, holder: path.relative(root, candidate.holder), backup: backupRelative, previousInstallationId: previous.manifest.installationId, targetInstallationId: candidate.manifest.installationId, previousIdentity: identity(await stat(runtime)), candidateIdentity: identity(await stat(candidate.candidateRuntime)) };
  await writeJournal(root, journal);
  abruptAt('PREPARED');
  await rename(runtime, backup); journal.state = 'OLD_QUARANTINED'; await writeJournal(root, journal); await testHook?.('after-old-quarantine');
  abruptAt('OLD_QUARANTINED');
  await mkdir(path.dirname(runtime), { recursive: true });
  await rename(candidate.candidateRuntime, runtime); journal.state = 'NEW_PUBLISHED'; await writeJournal(root, journal); await testHook?.('after-runtime-publication');
  abruptAt('NEW_PUBLISHED');
  const verified = await acceptance(runtime, candidate.manifest);
  if (verified?.verification !== 'PASS') fail(verified?.error || 'RUNTIME_POST_PUBLICATION_VERIFY_FAILED');
  await testHook?.('after-post-verify');
  return { journal, backup, holder: candidate.holder, verified };
}

async function advanceBaseline(root, swap, candidate, previousState, operation) {
  const oldBaseline = path.join(root, BASELINE), oldBaselineBackup = `${oldBaseline}.previous-${randomUUID()}`;
  const nextBaseline = `${oldBaseline}.next-${randomUUID()}`;
  await copyBaselineFiles(path.join(root, RUNTIME), nextBaseline, candidate.manifest);
  const lineage = [...(previousState.lineage || []), { operation, from: previousState.installationId, to: candidate.manifest.installationId }];
  const payload = { installationId: candidate.manifest.installationId, manifestDigest: digest(candidate.manifest), source: candidate.manifest.source, previousInstallationId: previousState.installationId, lineage };
  const state = { ...previousState, installationId: candidate.manifest.installationId, previousInstallationId: previousState.installationId, lineage, baselineDigest: digest(payload), acceptedAt: new Date().toISOString() };
  await writeFile(path.join(nextBaseline, 'state.json'), json(state), { flag: 'wx' });
  swap.journal.state = 'BASELINE_ADVANCING';
  swap.journal.baselineBackup = path.relative(root, oldBaselineBackup);
  swap.journal.baselineNext = path.relative(root, nextBaseline);
  swap.journal.previousState = previousState;
  swap.journal.targetBaselineDigest = state.baselineDigest;
  await writeJournal(root, swap.journal);
  abruptAt('BASELINE_ADVANCING');
  await rename(oldBaseline, oldBaselineBackup); await rename(nextBaseline, oldBaseline);
  abruptAt('BASELINE_PUBLISHED');
  swap.journal.state = 'BASELINE_ADVANCED'; await writeJournal(root, swap.journal);
  abruptAt('BASELINE_ADVANCED');
  return state;
}

export async function repairRuntime(root, productId, { authorized = false, sourceRoot, acceptance, testHook } = {}) {
  if (!authorized) fail('RUNTIME_REPAIR_AUTHORIZATION_REQUIRED');
  await recoverRuntimeLifecycle(root);
  const baseline = await validateBaseline(root);
  const before = await verifyRuntimeLifecycle(root, productId);
  if (before.verification === 'PASS') return { operation: 'repair', changed: false, verification: 'PASS', installationId: before.installationId };
  if (!['AUTH_RUNTIME_FILE_DRIFT', 'AUTH_RUNTIME_INVENTORY_DRIFT'].some((code) => String(before.error).startsWith(code))) fail('RUNTIME_REPAIR_NOT_AUTHORIZED_FOR_FAILURE');
  const config = JSON.parse(await readFile(path.join(baseline.baselineRoot, 'files/config/example-app.json'), 'utf8'));
  const candidate = await prepareCandidate(root, productId, sourceRoot, baseline.manifest.source.revision, config, acceptance);
  if (candidate.manifest.installationId !== baseline.manifest.installationId) fail('RUNTIME_REPAIR_VERSION_CHANGE_REFUSED');
  let swap;
  try {
    swap = await swapRuntime(root, productId, 'REPAIR', candidate, baseline, acceptance, testHook);
    const state = await advanceBaseline(root, swap, candidate, baseline.state, 'REPAIR');
    await testHook?.('after-baseline-advance');
    await recoverRuntimeLifecycle(root);
    return { operation: 'repair', changed: true, verification: 'PASS', installationId: state.installationId };
  } catch (error) { await recoverRuntimeLifecycle(root).catch(() => {}); throw error; }
}

export async function upgradeRuntime(root, productId, { authorized = false, sourceRoot, targetRevision, acceptance, testHook } = {}) {
  if (!authorized) fail('RUNTIME_UPGRADE_AUTHORIZATION_REQUIRED');
  if (!targetRevision) fail('RUNTIME_UPGRADE_TARGET_REQUIRED');
  await recoverRuntimeLifecycle(root);
  const baseline = await validateBaseline(root);
  const config = JSON.parse(await readFile(path.join(baseline.baselineRoot, 'files/config/example-app.json'), 'utf8'));
  const candidate = await prepareCandidate(root, productId, sourceRoot, targetRevision, config, acceptance);
  if (candidate.manifest.installationId === baseline.manifest.installationId) fail('RUNTIME_UPGRADE_TARGET_UNCHANGED');
  let swap;
  try {
    swap = await swapRuntime(root, productId, 'UPGRADE', candidate, baseline, acceptance, testHook);
    const state = await advanceBaseline(root, swap, candidate, baseline.state, 'UPGRADE');
    await testHook?.('after-baseline-advance');
    await recoverRuntimeLifecycle(root);
    return { operation: 'upgrade', verification: 'PASS', previousInstallationId: baseline.state.installationId, installationId: state.installationId, lineage: state.lineage };
  } catch (error) { await recoverRuntimeLifecycle(root).catch(() => {}); throw error; }
}
