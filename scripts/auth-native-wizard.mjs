/** Transient target-native AUTH wizard. It leaves product source and an optional receipt, never an AUTH control plane. */
import { createHash, randomUUID } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { lstat, mkdir, readFile, readdir, realpath, rename, rm, rmdir, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';

export const NATIVE_PROFILE = 'typescript-node-express-prisma/1';
export const RECEIPT_SCHEMA = 'life.auth.receipt/1';
const TX_PREFIX = '.auth-native-transaction-';
const UUID = '[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}';
const JOURNAL_PATTERN = new RegExp(`^${TX_PREFIX}(${UUID})\\.json$`, 'i');
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const canonical = value => Array.isArray(value) ? value.map(canonical) : value && typeof value === 'object'
  ? Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])])) : value;
const digestJson = value => sha(Buffer.from(JSON.stringify(canonical(value))));
const json = value => `${JSON.stringify(value, null, 2)}\n`;
const exists = async target => { try { return await lstat(target); } catch (error) { if (error?.code === 'ENOENT') return null; throw error; } };
const safeRelative = relative => {
  if (typeof relative !== 'string' || !relative || path.isAbsolute(relative) || relative.includes('\\') || relative.split('/').some(part => !part || part === '..')) throw new Error('UNSAFE_TARGET_PATH');
  return relative;
};
const inside = (root, relative) => path.join(root, safeRelative(relative));
const identity = entry => ({ dev: entry.dev, ino: entry.ino });
const sameIdentity = (left, right) => Boolean(left && right && Number.isInteger(left.dev) && Number.isInteger(left.ino) && left.dev === right.dev && left.ino === right.ino);
let atomicWriteCount = 0;
const testCrash = point => {
  if (process.env.AUTH_NATIVE_TEST_MODE === '1' && process.env.AUTH_NATIVE_TEST_CRASH_AT === point) process.exit(86);
};

async function atomicWriteJson(target, value) {
  const temp = `${target}.tmp-${randomUUID()}`;
  await writeFile(temp, json(value), { flag: 'wx', mode: 0o600 });
  atomicWriteCount += 1;
  testCrash(`journal-temp-written-${atomicWriteCount}`);
  await rename(temp, target);
}

async function fileProof(target) {
  const entry = await lstat(target);
  if (entry.isSymbolicLink() || !entry.isFile()) throw new Error('NATIVE_TRANSACTION_OBJECT_UNSAFE');
  return { ...identity(entry), sha256: sha(await readFile(target)) };
}

function validateProof(proof) {
  return proof && Number.isInteger(proof.dev) && Number.isInteger(proof.ino) && /^[0-9a-f]{64}$/.test(proof.sha256 || '');
}

function validateNativeJournal(journal, id) {
  if (!journal || journal.schema !== 'life.auth.native-transaction/2' || journal.transactionId !== id || !Number.isInteger(journal.revision) || journal.revision < 1) throw new Error('NATIVE_TRANSACTION_JOURNAL_INVALID');
  if (!['APPLY', 'REPAIR'].includes(journal.operation) || !['STAGING', 'PUBLISHING', 'VERIFYING', 'COMPLETE', 'ROLLBACK_REFUSED'].includes(journal.state)) throw new Error('NATIVE_TRANSACTION_JOURNAL_UNSUPPORTED');
  if (!Array.isArray(journal.entries) || new Set(journal.entries.map(item => item.path)).size !== journal.entries.length) throw new Error('NATIVE_TRANSACTION_JOURNAL_INVALID');
  if (!Array.isArray(journal.parents || []) || new Set((journal.parents || []).map(item => item.path)).size !== (journal.parents || []).length) throw new Error('NATIVE_TRANSACTION_JOURNAL_INVALID');
  for (const parent of journal.parents || []) {
    safeRelative(parent.path);
    if (!Number.isInteger(parent.dev) || !Number.isInteger(parent.ino)) throw new Error('NATIVE_TRANSACTION_JOURNAL_INVALID');
  }
  if (journal.stageProof && (!Number.isInteger(journal.stageProof.dev) || !Number.isInteger(journal.stageProof.ino))) throw new Error('NATIVE_TRANSACTION_JOURNAL_INVALID');
  if (journal.quarantineProof && (!Number.isInteger(journal.quarantineProof.dev) || !Number.isInteger(journal.quarantineProof.ino))) throw new Error('NATIVE_TRANSACTION_JOURNAL_INVALID');
  for (const item of journal.entries) {
    safeRelative(item.path);
    if (!['PLANNED', 'STAGED', 'PUBLISHED'].includes(item.state) || !/^[0-9a-f]{64}$/.test(item.sha256 || '')) throw new Error('NATIVE_TRANSACTION_JOURNAL_INVALID');
    if (item.state !== 'PLANNED' && !validateProof(item.stagedProof)) throw new Error('NATIVE_TRANSACTION_JOURNAL_INVALID');
    if (item.publishedProof && !validateProof(item.publishedProof)) throw new Error('NATIVE_TRANSACTION_JOURNAL_INVALID');
    if (item.preimageProof && !validateProof(item.preimageProof)) throw new Error('NATIVE_TRANSACTION_JOURNAL_INVALID');
  }
  return journal;
}

async function persistNativeJournal(journalPath, journal) {
  journal.revision += 1;
  await atomicWriteJson(journalPath, journal);
}

function git(root, args, encoding = 'utf8') {
  try { return execFileSync('git', args, { cwd: root, encoding, maxBuffer: 32 * 1024 * 1024 }); }
  catch { throw new Error('AUTHORITATIVE_PROFILE_SOURCE_REQUIRED'); }
}

function authoritativeSource(sourceRoot, revision = 'HEAD') {
  const commit = git(sourceRoot, ['rev-parse', '--verify', `${revision}^{commit}`]).trim();
  return { mode: 'git-commit', revision: commit, tree: git(sourceRoot, ['rev-parse', `${commit}^{tree}`]).trim() };
}

function profilePaths(sourceRoot, revision) {
  const listed = git(sourceRoot, ['ls-tree', '-r', '--name-only', revision, '--', 'src', 'prisma/schema.prisma']).split('\n').filter(Boolean);
  return listed.filter(name => !name.startsWith('src/test/') && !name.endsWith('.test.ts') && !name.endsWith('.test.mjs')).sort();
}

function profileBytes(sourceRoot, revision, sourcePath) {
  return git(sourceRoot, ['show', `${revision}:${sourcePath}`], null);
}

async function targetInventory(root) {
  const candidates = ['package.json', 'package-lock.json', 'tsconfig.json', 'src', 'prisma/schema.prisma'];
  const result = {};
  for (const relative of candidates) {
    const entry = await exists(path.join(root, relative));
    result[relative] = entry ? (entry.isDirectory() ? 'directory' : entry.isFile() ? 'file' : 'special') : 'missing';
  }
  return result;
}

async function boundedAuthEvidence(root) {
  const candidates = ['src/auth', 'src/app.ts', 'src/routes/auth.ts', 'server/auth', 'app/api/auth', 'prisma/schema.prisma'];
  const found = [];
  for (const relative of candidates) if (await exists(path.join(root, relative))) found.push(relative);
  return found;
}

export async function discoverNativeTarget(targetRoot) {
  const root = await realpath(targetRoot);
  const inventory = await targetInventory(root);
  const authEvidence = await boundedAuthEvidence(root);
  let packageJson = null;
  if (inventory['package.json'] === 'file') {
    try { packageJson = JSON.parse(await readFile(path.join(root, 'package.json'), 'utf8')); } catch { throw new Error('TARGET_PACKAGE_JSON_INVALID'); }
  }
  const dependencies = { ...(packageJson?.dependencies || {}), ...(packageJson?.devDependencies || {}) };
  const stack = {
    language: dependencies.typescript || inventory['tsconfig.json'] === 'file' ? 'typescript' : packageJson ? 'javascript' : 'unknown',
    runtime: packageJson ? 'node' : 'unknown', express: Boolean(dependencies.express), prisma: Boolean(dependencies.prisma || dependencies['@prisma/client']),
  };
  const prohibited = [];
  for (const relative of ['.auth-runtime', '.auth-kit']) if (await exists(path.join(root, relative))) prohibited.push(relative);
  const classification = prohibited.length ? 'NONCONFORMANT' : authEvidence.length ? 'COMPATIBLE'
    : packageJson && stack.language === 'typescript' && stack.express && stack.prisma ? 'GREENFIELD' : packageJson ? 'AUTH_DEVELOPMENT_REQUIRED' : 'GREENFIELD';
  return { schemaVersion: 1, operation: 'DISCOVER', targetRoot: root, classification, stack, authEvidence, prohibitedPersistentArtifacts: prohibited, inventory };
}

function generatedPackage(productId) {
  return {
    name: productId.replace(/[^a-z0-9._-]/gi, '-').toLowerCase(), version: '0.1.0', private: true, type: 'module',
    scripts: { build: 'tsc -p tsconfig.json', 'prisma:generate': 'prisma generate', start: 'node dist/index.js' },
    engines: { node: '>=20' },
    dependencies: { '@prisma/client': '6.12.0', express: '^5.1.0', jose: '^6.1.2', redis: '^5.10.0' },
    devDependencies: { '@types/node': '^26.0.0', prisma: '6.12.0', typescript: '^6.0.3' },
  };
}

const generatedTsconfig = { compilerOptions: { target: 'ES2022', module: 'NodeNext', moduleResolution: 'NodeNext', lib: ['ES2022'], types: ['node'], rootDir: 'src', outDir: 'dist', strict: true, noImplicitAny: false, skipLibCheck: true, esModuleInterop: true, forceConsistentCasingInFileNames: true, resolveJsonModule: true }, include: ['src/**/*.ts', 'src/**/*.d.ts'] };

export async function planNativeTarget(targetRoot, { sourceRoot, sourceRevision = 'HEAD', productId = 'product', receiptPath, mode = 'create' } = {}) {
  const discovery = await discoverNativeTarget(targetRoot);
  if (discovery.prohibitedPersistentArtifacts.length) throw new Error('PERSISTENT_AUTH_ARTIFACT_MIGRATION_REQUIRED');
  if (!sourceRoot || !receiptPath) throw new Error('SOURCE_AND_RECEIPT_REQUIRED');
  const source = authoritativeSource(sourceRoot, sourceRevision);
  const paths = profilePaths(sourceRoot, source.revision);
  paths.push('package-lock.json');
  const operations = [];
  for (const sourcePath of paths) {
    const bytes = profileBytes(sourceRoot, source.revision, sourcePath);
    const existing = await exists(path.join(discovery.targetRoot, sourcePath));
    if (existing) {
      if (!existing.isFile()) throw new Error(`TARGET_PATH_COLLISION:${sourcePath}`);
      const current = await readFile(path.join(discovery.targetRoot, sourcePath));
      if (sha(current) !== sha(bytes)) throw new Error(`EXISTING_AUTH_REVIEW_REQUIRED:${sourcePath}`);
      operations.push({ path: sourcePath, action: 'retain', owner: 'product', preimageSha256: sha(current), postimageSha256: sha(bytes), sourcePath });
    } else operations.push({ path: sourcePath, action: 'create', owner: 'product', preimageSha256: null, postimageSha256: sha(bytes), sourcePath });
  }
  for (const [relative, bytes] of [
    ['package.json', Buffer.from(json(generatedPackage(productId)))],
    ['tsconfig.json', Buffer.from(json(generatedTsconfig))],
    ['auth-standards.json', Buffer.from(json({ schema: 'life.auth.native-contract/1', profile: NATIVE_PROFILE, productId, capabilities: ['oauth-oidc','pkce','callbacks','credentials','magic-email','sessions','cookies','refresh-rotation','replay-protection','revocation','logout','prisma-persistence','native-cli','mcp-resource-server'] }))],
  ]) {
    const existing = await exists(path.join(discovery.targetRoot, relative));
    if (existing) {
      if (!existing.isFile() || sha(await readFile(path.join(discovery.targetRoot, relative))) !== sha(bytes)) throw new Error(`EXISTING_PRODUCT_FILE_REVIEW_REQUIRED:${relative}`);
      operations.push({ path: relative, action: 'retain', owner: 'product', preimageSha256: sha(bytes), postimageSha256: sha(bytes), generated: true });
    } else operations.push({ path: relative, action: 'create', owner: 'product', preimageSha256: null, postimageSha256: sha(bytes), generated: true });
  }
  const plan = { schema: 'life.auth.native-plan/1', profile: NATIVE_PROFILE, mode, productId, targetRoot: discovery.targetRoot, receiptPath: path.resolve(receiptPath), source, classification: discovery.classification, operations, limitations: ['power-loss-fsync-not-proven','irreversible-migrations-not-supported'] };
  plan.planDigest = digestJson(plan);
  return plan;
}

async function bytesFor(plan, operation, sourceRoot) {
  if (operation.sourcePath) return profileBytes(sourceRoot, plan.source.revision, operation.sourcePath);
  if (operation.path === 'package.json') return Buffer.from(json(generatedPackage(plan.productId)));
  if (operation.path === 'tsconfig.json') return Buffer.from(json(generatedTsconfig));
  if (operation.path === 'auth-standards.json') return Buffer.from(json({ schema: 'life.auth.native-contract/1', profile: NATIVE_PROFILE, productId: plan.productId, capabilities: ['oauth-oidc','pkce','callbacks','credentials','magic-email','sessions','cookies','refresh-rotation','replay-protection','revocation','logout','prisma-persistence','native-cli','mcp-resource-server'] }));
  throw new Error('PLAN_SOURCE_UNSUPPORTED');
}

export async function applyNativePlan(plan, { sourceRoot, authorized = false, dryRun = false } = {}) {
  if (dryRun) return { operation: 'APPLY', state: 'DRY_RUN', planDigest: plan.planDigest, changed: [] };
  if (!authorized) throw new Error('EXPLICIT_AUTHORIZATION_REQUIRED');
  const root = await realpath(plan.targetRoot);
  const { planDigest, ...planPayload } = plan;
  if (root !== plan.targetRoot || plan.profile !== NATIVE_PROFILE || plan.schema !== 'life.auth.native-plan/1' || digestJson(planPayload) !== planDigest) throw new Error('NATIVE_PLAN_INVALID');
  const transactionId = randomUUID();
  const stageName = `${TX_PREFIX}${transactionId}`;
  const stage = path.join(root, `${stageName}-stage`);
  const journalPath = path.join(root, `${stageName}.json`);
  const entries = plan.operations.filter(item => item.action === 'create').map(item => ({ path: item.path, sha256: item.postimageSha256, state: 'PLANNED' }));
  const journal = { schema: 'life.auth.native-transaction/2', transactionId, revision: 1, operation: 'APPLY', state: 'STAGING', planDigest: plan.planDigest, receiptPath: path.resolve(plan.receiptPath), entries, parents: [] };
  await writeFile(journalPath, json(journal), { flag: 'wx', mode: 0o600 });
  testCrash('apply-journal-created');
  await mkdir(stage, { mode: 0o700 });
  await writeFile(path.join(stage, '.transaction-id'), `${transactionId}\n`, { flag: 'wx', mode: 0o600 });
  journal.stageProof = identity(await stat(stage));
  await persistNativeJournal(journalPath, journal);
  try {
    for (const operation of plan.operations.filter(item => item.action === 'create')) {
      const bytes = await bytesFor(plan, operation, sourceRoot);
      if (sha(bytes) !== operation.postimageSha256) throw new Error(`PLAN_SOURCE_DRIFT:${operation.path}`);
      const staged = inside(stage, operation.path);
      await mkdir(path.dirname(staged), { recursive: true });
      await writeFile(staged, bytes, { flag: 'wx' });
      const item = journal.entries.find(entry => entry.path === operation.path);
      item.stagedProof = await fileProof(staged); item.state = 'STAGED';
      await persistNativeJournal(journalPath, journal);
    }
    const parentPaths = [...new Set(journal.entries.flatMap(item => {
      const parts = item.path.split('/').slice(0, -1); const values = [];
      for (let index = 1; index <= parts.length; index += 1) values.push(parts.slice(0, index).join('/'));
      return values;
    }))].sort((a, b) => a.split('/').length - b.split('/').length || a.localeCompare(b));
    for (const relative of parentPaths) {
      const target = inside(root, relative);
      if (await exists(target)) continue;
      await mkdir(target);
      const proof = identity(await stat(target)); journal.parents.push({ path: relative, ...proof });
      await persistNativeJournal(journalPath, journal);
    }
    journal.state = 'PUBLISHING'; await persistNativeJournal(journalPath, journal);
    for (const operation of plan.operations.filter(item => item.action === 'create')) {
      const destination = inside(root, operation.path);
      if (await exists(destination)) throw new Error(`TARGET_CHANGED_AFTER_PLAN:${operation.path}`);
      await mkdir(path.dirname(destination), { recursive: true });
      await rename(inside(stage, operation.path), destination);
      testCrash(`apply-published:${operation.path}`);
      const item = journal.entries.find(entry => entry.path === operation.path);
      item.publishedProof = await fileProof(destination); item.state = 'PUBLISHED';
      await persistNativeJournal(journalPath, journal);
    }
    journal.state = 'VERIFYING'; await persistNativeJournal(journalPath, journal);
    const verification = await verifyNativeTarget(root, plan);
    if (verification.verification !== 'PASS') throw new Error('POST_APPLY_VERIFY_FAILED');
    testCrash('apply-verified');
    const receipt = { schema: RECEIPT_SCHEMA, profile: plan.profile, productId: plan.productId, targetBinding: verification.targetBinding, source: plan.source, planDigest: plan.planDigest, files: verification.files, capabilities: JSON.parse(await readFile(path.join(root, 'auth-standards.json'), 'utf8')).capabilities, verification: 'PASS', priorReceiptDigest: null, limitations: plan.limitations };
    receipt.receiptDigest = digestJson(receipt);
    const receiptTarget = path.resolve(plan.receiptPath);
    if (await exists(receiptTarget)) throw new Error('RECEIPT_DESTINATION_EXISTS');
    await mkdir(path.dirname(receiptTarget), { recursive: true });
    await writeFile(receiptTarget, json(receipt), { flag: 'wx', mode: 0o600 });
    journal.receiptProof = await fileProof(receiptTarget);
    journal.state = 'COMPLETE'; await persistNativeJournal(journalPath, journal);
    testCrash('apply-complete');
    await rm(stage, { recursive: true }); await rm(journalPath);
    return { operation: 'APPLY', state: 'COMPLETE', receipt: receiptTarget, verification };
  } catch (error) {
    for (const created of [...journal.entries].reverse()) {
      if (!created.stagedProof) continue;
      const destination = inside(root, created.path);
      const entry = await exists(destination);
      if (!entry || entry.isSymbolicLink() || !entry.isFile()) continue;
      const proof = await fileProof(destination);
      if (!sameIdentity(proof, created.stagedProof) || proof.sha256 !== created.sha256) { journal.state = 'ROLLBACK_REFUSED'; await persistNativeJournal(journalPath, journal).catch(() => {}); throw new Error(`ROLLBACK_REFUSED:${created.path}`); }
      const quarantine = path.join(root, `${stageName}-quarantine-${journal.entries.indexOf(created)}`);
      await rename(destination, quarantine);
      const quarantined = await fileProof(quarantine);
      if (!sameIdentity(quarantined, created.stagedProof) || quarantined.sha256 !== created.sha256) { await rename(quarantine, destination).catch(() => {}); throw new Error(`ROLLBACK_REFUSED:${created.path}`); }
      await rm(quarantine);
    }
    for (const parent of [...journal.parents].reverse()) {
      const target = inside(root, parent.path), entry = await exists(target);
      if (!entry) continue;
      if (entry.isSymbolicLink() || !entry.isDirectory() || !sameIdentity(identity(await stat(target)), parent)) throw new Error(`ROLLBACK_REFUSED:${parent.path}`);
      try { await rmdir(target); } catch (parentError) { if (parentError?.code !== 'ENOTEMPTY') throw parentError; }
    }
    const stageEntry = await exists(stage);
    if (stageEntry) {
      const marker = await readFile(path.join(stage, '.transaction-id'), 'utf8').then(value => value.trim()).catch(() => null);
      if (stageEntry.isSymbolicLink() || !stageEntry.isDirectory() || !sameIdentity(identity(await stat(stage)), journal.stageProof) || marker !== transactionId) throw new Error('ROLLBACK_REFUSED:stage');
      await rm(stage, { recursive: true });
    }
    await rm(journalPath, { force: true });
    throw error;
  }
}

export async function verifyNativeTarget(targetRoot, planOrReceipt) {
  const root = await realpath(targetRoot);
  const files = {};
  const expected = planOrReceipt.files || Object.fromEntries(planOrReceipt.operations.map(item => [item.path, item.postimageSha256]));
  const failures = [];
  for (const [relative, expectedDigest] of Object.entries(expected)) {
    const entry = await exists(inside(root, relative));
    if (!entry || entry.isSymbolicLink() || !entry.isFile()) { failures.push({ path: relative, error: 'MISSING_OR_UNSAFE' }); continue; }
    const actual = sha(await readFile(inside(root, relative))); files[relative] = actual;
    if (actual !== expectedDigest) failures.push({ path: relative, error: 'DIGEST_MISMATCH' });
  }
  const prohibited = [];
  for (const relative of ['.auth-runtime', '.auth-kit']) if (await exists(path.join(root, relative))) prohibited.push(relative);
  if (prohibited.length) failures.push({ error: 'PERSISTENT_AUTH_FOOTPRINT', paths: prohibited });
  return { operation: 'VERIFY', verification: failures.length ? 'FAIL' : 'PASS', targetBinding: sha(Buffer.from(root)), files, failures, prohibitedPersistentArtifacts: prohibited };
}

export async function verifyNativeReceipt(targetRoot, receiptPath) {
  const receipt = JSON.parse(await readFile(receiptPath, 'utf8'));
  const { receiptDigest, ...payload } = receipt;
  if (receipt.schema !== RECEIPT_SCHEMA || digestJson(payload) !== receiptDigest) throw new Error('RECEIPT_INVALID');
  return verifyNativeTarget(targetRoot, receipt);
}

export async function repairNativeTarget(targetRoot, receiptPath, { sourceRoot, authorized = false } = {}) {
  if (!authorized) throw new Error('EXPLICIT_AUTHORIZATION_REQUIRED');
  const receipt = JSON.parse(await readFile(receiptPath, 'utf8'));
  if (receipt.profile !== NATIVE_PROFILE) throw new Error('REPAIR_VERSION_MISMATCH');
  const before = await verifyNativeReceipt(targetRoot, receiptPath);
  if (before.verification === 'PASS') return { operation: 'REPAIR', state: 'NO_CHANGES', verification: before };
  if (before.failures.some(item => item.error === 'PERSISTENT_AUTH_FOOTPRINT')) throw new Error('REPAIR_REFUSES_ARCHITECTURE_MIGRATION');
  const root = await realpath(targetRoot);
  const source = authoritativeSource(sourceRoot, receipt.source.revision);
  if (source.revision !== receipt.source.revision || source.tree !== receipt.source.tree) throw new Error('REPAIR_SOURCE_PROVENANCE_INVALID');
  const repairable = before.failures.filter(item => item.path).map(item => item.path);
  const tx = randomUUID(), prefix = `${TX_PREFIX}${tx}`, stage = path.join(root, `${prefix}-stage`), quarantine = path.join(root, `${prefix}-quarantine`), journalPath = path.join(root, `${prefix}.json`);
  const journal = { schema: 'life.auth.native-transaction/2', transactionId: tx, revision: 1, operation: 'REPAIR', state: 'STAGING', receiptPath: path.resolve(receiptPath), receiptProof: await fileProof(path.resolve(receiptPath)), profile: receipt.profile, entries: repairable.map(relative => ({ path: relative, sha256: receipt.files[relative], state: 'PLANNED' })), parents: [] };
  await writeFile(journalPath, json(journal), { flag: 'wx', mode: 0o600 });
  await mkdir(stage, { mode: 0o700 }); await writeFile(path.join(stage, '.transaction-id'), `${tx}\n`, { flag: 'wx' }); journal.stageProof = identity(await stat(stage));
  await mkdir(quarantine, { mode: 0o700 }); await writeFile(path.join(quarantine, '.transaction-id'), `${tx}\n`, { flag: 'wx' }); journal.quarantineProof = identity(await stat(quarantine));
  await persistNativeJournal(journalPath, journal);
  try {
    for (const relative of repairable) {
      const operation = { path: relative, ...(relative.startsWith('src/') || relative === 'prisma/schema.prisma' || relative === 'package-lock.json' ? { sourcePath: relative } : { generated: true }) };
      const bytes = await bytesFor({ ...receipt, productId: receipt.productId }, operation, sourceRoot);
      if (sha(bytes) !== receipt.files[relative]) throw new Error(`REPAIR_SOURCE_DIGEST_MISMATCH:${relative}`);
      const staged = inside(stage, relative); await mkdir(path.dirname(staged), { recursive: true }); await writeFile(staged, bytes, { flag: 'wx' });
      const item = journal.entries.find(entry => entry.path === relative); item.stagedProof = await fileProof(staged); item.state = 'STAGED'; await persistNativeJournal(journalPath, journal);
    }
    journal.state = 'PUBLISHING'; await persistNativeJournal(journalPath, journal);
    for (const relative of repairable) {
      const item = journal.entries.find(entry => entry.path === relative);
      const staged = inside(stage, relative), destination = inside(root, relative), old = inside(quarantine, relative);
      const oldEntry = await exists(destination);
      if (oldEntry) {
        if (oldEntry.isSymbolicLink() || !oldEntry.isFile()) throw new Error(`REPAIR_TARGET_UNSAFE:${relative}`);
        item.preimageProof = await fileProof(destination); await persistNativeJournal(journalPath, journal);
        await mkdir(path.dirname(old), { recursive: true }); await rename(destination, old); testCrash(`repair-quarantined:${relative}`);
      }
      await mkdir(path.dirname(destination), { recursive: true }); await rename(staged, destination);
      testCrash(`repair-published:${relative}`);
      item.publishedProof = await fileProof(destination); item.state = 'PUBLISHED'; await persistNativeJournal(journalPath, journal);
    }
    journal.state = 'VERIFYING'; await persistNativeJournal(journalPath, journal);
    const verification = await verifyNativeReceipt(root, receiptPath);
    if (verification.verification !== 'PASS') throw new Error('POST_REPAIR_VERIFY_FAILED');
    testCrash('repair-verified');
    journal.state = 'COMPLETE'; await persistNativeJournal(journalPath, journal); testCrash('repair-complete');
    await rm(stage, { recursive: true }); await rm(quarantine, { recursive: true }); await rm(journalPath);
    return { operation: 'REPAIR', state: 'COMPLETE', profile: receipt.profile, versionChanged: false, repaired: repairable, verification };
  } catch (error) {
    await recoverNativeTransactions(root);
    throw error;
  }
}

export async function recoverNativeTransactions(targetRoot) {
  const root = await realpath(targetRoot);
  const names = (await readdir(root)).filter(name => name.startsWith(TX_PREFIX));
  if (!names.length) return { operation: 'RECOVER', state: 'CLEAN' };
  const journals = names.filter(name => JOURNAL_PATTERN.test(name));
  if (journals.length !== 1) throw new Error('AMBIGUOUS_NATIVE_TRANSACTION_RESIDUE');
  const journalName = journals[0];
  const id = JOURNAL_PATTERN.exec(journalName)[1];
  const allowedPrefixes = [`${TX_PREFIX}${id}.json`, `${TX_PREFIX}${id}-stage`, `${TX_PREFIX}${id}-quarantine`];
  if (names.some(name => !allowedPrefixes.some(prefix => name === prefix || name.startsWith(prefix)))) throw new Error('AMBIGUOUS_NATIVE_TRANSACTION_RESIDUE');
  const journalPath = path.join(root, journalName);
  const journalEntry = await lstat(journalPath);
  if (journalEntry.isSymbolicLink() || !journalEntry.isFile()) throw new Error('NATIVE_TRANSACTION_JOURNAL_INVALID');
  let journal;
  try { journal = validateNativeJournal(JSON.parse(await readFile(journalPath, 'utf8')), id); }
  catch { throw new Error('NATIVE_TRANSACTION_JOURNAL_INVALID'); }
  if (journal.operation === 'REPAIR') {
    const quarantineRoot = path.join(root, `${TX_PREFIX}${id}-quarantine`);
    const rollback = journal.state !== 'COMPLETE';
    if (rollback) {
      for (const item of [...journal.entries].reverse()) {
        const destination = inside(root, item.path), old = inside(quarantineRoot, item.path);
        const current = await exists(destination);
        if (current && item.stagedProof) {
          const proof = await fileProof(destination).catch(() => null);
          if (proof && sameIdentity(proof, item.stagedProof) && proof.sha256 === item.sha256) {
            const discard = path.join(root, `${TX_PREFIX}${id}-quarantine-new-${journal.entries.indexOf(item)}`);
            await rename(destination, discard);
            const checked = await fileProof(discard);
            if (!sameIdentity(checked, item.stagedProof) || checked.sha256 !== item.sha256) { await rename(discard, destination).catch(() => {}); throw new Error(`NATIVE_TRANSACTION_PUBLICATION_AMBIGUOUS:${item.path}`); }
            await rm(discard);
          } else if (item.preimageProof && proof && sameIdentity(proof, item.preimageProof) && proof.sha256 === item.preimageProof.sha256) {
            // The crash happened after intent was journaled but before quarantine rename.
          } else throw new Error(`NATIVE_TRANSACTION_PUBLICATION_AMBIGUOUS:${item.path}`);
        }
        const oldEntry = await exists(old);
        if (oldEntry) {
          const oldProof = await fileProof(old).catch(() => null);
          if (!item.preimageProof || !oldProof || !sameIdentity(oldProof, item.preimageProof) || oldProof.sha256 !== item.preimageProof.sha256 || await exists(destination)) throw new Error(`NATIVE_TRANSACTION_PREIMAGE_AMBIGUOUS:${item.path}`);
          await mkdir(path.dirname(destination), { recursive: true }); await rename(old, destination);
        }
      }
    } else {
      const receiptProof = await fileProof(journal.receiptPath).catch(() => null);
      if (!receiptProof || !sameIdentity(receiptProof, journal.receiptProof) || receiptProof.sha256 !== journal.receiptProof.sha256) throw new Error('NATIVE_TRANSACTION_COMPLETE_AMBIGUOUS');
      for (const item of journal.entries) {
        const proof = await fileProof(inside(root, item.path)).catch(() => null);
        if (!proof || !sameIdentity(proof, item.stagedProof) || proof.sha256 !== item.sha256) throw new Error(`NATIVE_TRANSACTION_COMPLETE_AMBIGUOUS:${item.path}`);
      }
    }
    const quarantineEntry = await exists(quarantineRoot);
    if (quarantineEntry) {
      const marker = await readFile(path.join(quarantineRoot, '.transaction-id'), 'utf8').then(value => value.trim()).catch(() => null);
      if (quarantineEntry.isSymbolicLink() || !quarantineEntry.isDirectory() || !sameIdentity(identity(await stat(quarantineRoot)), journal.quarantineProof) || marker !== id) throw new Error('NATIVE_TRANSACTION_QUARANTINE_AMBIGUOUS');
      await rm(quarantineRoot, { recursive: true });
    }
  }
  if (journal.state === 'COMPLETE') {
    if (!validateProof(journal.receiptProof)) throw new Error('NATIVE_TRANSACTION_COMPLETE_INVALID');
    const receiptProof = await fileProof(journal.receiptPath).catch(() => null);
    if (!receiptProof || !sameIdentity(receiptProof, journal.receiptProof) || receiptProof.sha256 !== journal.receiptProof.sha256) throw new Error('NATIVE_TRANSACTION_COMPLETE_AMBIGUOUS');
    for (const item of journal.entries) {
      const proof = await fileProof(inside(root, item.path)).catch(() => null);
      if (!proof || !sameIdentity(proof, item.stagedProof) || proof.sha256 !== item.sha256) throw new Error(`NATIVE_TRANSACTION_COMPLETE_AMBIGUOUS:${item.path}`);
    }
  } else if (journal.operation === 'APPLY') {
    for (const item of [...journal.entries].reverse()) {
      if (!item.stagedProof) continue;
      const destination = inside(root, item.path);
      const present = await exists(destination);
      if (!present) continue;
      const quarantine = path.join(root, `${TX_PREFIX}${id}-quarantine-${journal.entries.indexOf(item)}`);
      if (await exists(quarantine)) throw new Error('NATIVE_TRANSACTION_QUARANTINE_AMBIGUOUS');
      await rename(destination, quarantine);
      const proof = await fileProof(quarantine).catch(() => null);
      if (!proof || !sameIdentity(proof, item.stagedProof) || proof.sha256 !== item.sha256) {
        await rename(quarantine, destination).catch(() => {});
        throw new Error(`NATIVE_TRANSACTION_PUBLICATION_AMBIGUOUS:${item.path}`);
      }
      await rm(quarantine);
    }
    for (const parent of [...journal.parents].reverse()) {
      const target = inside(root, parent.path), entry = await exists(target);
      if (!entry) continue;
      if (entry.isSymbolicLink() || !entry.isDirectory() || !sameIdentity(identity(await stat(target)), parent)) throw new Error(`NATIVE_TRANSACTION_PARENT_AMBIGUOUS:${parent.path}`);
      try { await rmdir(target); } catch (error) { if (error?.code !== 'ENOTEMPTY') throw error; }
    }
  }
  const stage = path.join(root, `${TX_PREFIX}${id}-stage`);
  const stageEntry = await exists(stage);
  if (stageEntry) {
    const marker = await readFile(path.join(stage, '.transaction-id'), 'utf8').then(value => value.trim()).catch(() => null);
    const stageIdentity = identity(await stat(stage));
    if (stageEntry.isSymbolicLink() || !stageEntry.isDirectory() || !sameIdentity(stageIdentity, journal.stageProof) || marker !== id) throw new Error('NATIVE_TRANSACTION_STAGE_AMBIGUOUS');
    await rm(stage, { recursive: true });
  }
  for (const name of await readdir(root)) {
    if (!name.startsWith(`${journalName}.tmp-`)) continue;
    const target = path.join(root, name), entry = await lstat(target);
    if (entry.isSymbolicLink() || !entry.isFile()) throw new Error('NATIVE_TRANSACTION_TEMP_AMBIGUOUS');
    let candidate;
    try { candidate = validateNativeJournal(JSON.parse(await readFile(target, 'utf8')), id); }
    catch { throw new Error('NATIVE_TRANSACTION_TEMP_AMBIGUOUS'); }
    if (candidate.revision <= journal.revision) throw new Error('NATIVE_TRANSACTION_TEMP_AMBIGUOUS');
    await rm(target);
  }
  await rm(journalPath);
  return { operation: 'RECOVER', state: journal.state === 'COMPLETE' ? 'FINALIZED' : 'ROLLED_BACK', transactionId: id };
}
