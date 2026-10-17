/** Transient target-native AUTH wizard. It leaves product source and an optional receipt, never an AUTH control plane. */
import { createHash, randomUUID } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { lstat, mkdir, readFile, readdir, realpath, rename, rm, rmdir, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';

export const NATIVE_PROFILE = 'typescript-node-express-prisma/2';
export const PYTHON_FLASK_SQLITE_PROFILE = 'python-flask-sqlite/1';
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
  if (!['APPLY', 'REPAIR', 'MIGRATE'].includes(journal.operation) || !['STAGING', 'PUBLISHING', 'VERIFYING', 'ADVANCING', 'COMPLETE', 'ROLLBACK_REFUSED'].includes(journal.state)) throw new Error('NATIVE_TRANSACTION_JOURNAL_UNSUPPORTED');
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

function profileEntries(sourceRoot, revision) {
  const prefix = 'profiles/typescript-node-express-prisma/';
  const listed = git(sourceRoot, ['ls-tree', '-r', '--name-only', revision, '--', prefix]).split('\n').filter(Boolean);
  const entries = listed.filter(name => name !== `${prefix}profile.json`).map(sourcePath => ({ sourcePath, path: sourcePath.slice(prefix.length) })).sort((a, b) => a.path.localeCompare(b.path));
  if (!entries.some(item => item.path === 'src/index.ts') || !entries.some(item => item.path === 'prisma/schema.prisma')) throw new Error('AUTHORITATIVE_NATIVE_PROFILE_INCOMPLETE');
  return entries;
}

function profileBytes(sourceRoot, revision, sourcePath) {
  return git(sourceRoot, ['show', `${revision}:${sourcePath}`], null);
}

async function targetInventory(root) {
  const candidates = ['package.json', 'package-lock.json', 'tsconfig.json', 'src', 'prisma/schema.prisma', 'requirements.txt', 'requirements-core.txt', 'pyproject.toml', 'backend', 'models'];
  const result = {};
  for (const relative of candidates) {
    const entry = await exists(path.join(root, relative));
    result[relative] = entry ? (entry.isDirectory() ? 'directory' : entry.isFile() ? 'file' : 'special') : 'missing';
  }
  return result;
}

async function boundedAuthEvidence(root) {
  const candidates = ['src/auth', 'src/index.ts', 'src/app.ts', 'src/routes/auth.ts', 'server/auth', 'app/api/auth', 'prisma/schema.prisma', 'backend/api/auth.py', 'backend/server.py', 'models/user_model.py', 'models/database.py'];
  const found = [];
  for (const relative of candidates) if (await exists(path.join(root, relative))) found.push(relative);
  return found;
}

const ALIGNMENT_PROBES = Object.freeze([
  ['oauth-oidc', /oauth|openid|authorization[_ -]?code/i, ['OAuth/OIDC authorization and callback evidence']],
  ['pkce', /code_challenge|code_verifier|S256/, ['S256 PKCE evidence']],
  ['state-nonce-callback-validation', /\bstate\b[\s\S]{0,300}\bnonce\b|nonce[\s\S]{0,300}state/i, ['state and nonce validation evidence']],
  ['credentials', /password_?hash|passwordHash|scrypt|argon2|bcrypt/i, ['password hashing evidence']],
  ['magic-email', /magic.{0,20}(link|email|challenge|token)/i, ['single-use expiring magic-email evidence']],
  ['sessions-secure-cookies', /HttpOnly|httpOnly|SESSION_COOKIE_HTTPONLY/i, ['HttpOnly session cookie evidence']],
  ['refresh-rotation-replay-protection', /refresh.{0,80}(rotate|rotation|replay|usedAt)/i, ['refresh rotation and replay evidence']],
  ['revocation-logout', /revoke|revocation|logout/i, ['server revocation and logout evidence']],
  ['product-native-persistence', /PrismaClient|schema\.prisma|model\s+User|sqlite3|CREATE TABLE|identity\/auth\.json/i, ['product-native persistence evidence']],
  ['native-cli-authorization', /127\.0\.0\.1|localhost|loopback|code_verifier/i, ['native/CLI redirect binding evidence']],
  ['mcp-resource-server', /oauth-protected-resource|resource_metadata|\bmcp\b/i, ['MCP protected-resource authorization evidence']],
]);
const PYTHON_ALIGNMENT_PROBES = Object.freeze([
  ['oauth-authorization-code', /oauth|authorization[_ -]?code/i, ['OAuth authorization and callback evidence']],
  ['pkce', /code_challenge|code_verifier|S256/, ['S256 PKCE evidence']],
  ['session-bound-expiring-state', /oauth_states[\s\S]{0,600}(created_at|expires)|created_at[\s\S]{0,600}oauth_states/i, ['session-bound expiring state evidence']],
  ['credentials', /password_?hash|bcrypt/i, ['password hashing evidence']],
  ['account-recovery', /recovery_tokens|consume_recovery|issue_recovery/i, ['single-use expiring recovery evidence']],
  ['server-sessions-secure-cookies', /SESSION_COOKIE_HTTPONLY|httponly/i, ['HttpOnly server-session evidence']],
  ['revocation-logout', /session\.clear|logout|revok/i, ['complete logout evidence']],
  ['product-native-persistence', /sqlite3|CREATE TABLE|identity\/auth\.json/i, ['product-native persistence evidence']],
]);

async function boundedSourceEvidence(root) {
  const roots = ['src', 'server', 'app/api/auth', 'prisma/schema.prisma', 'backend/api/auth.py', 'backend/server.py', 'backend/utils', 'models/user_model.py', 'models/database.py'];
  const files = [];
  async function visit(relative, depth = 0) {
    if (files.length >= 200 || depth > 6) return;
    const target = path.join(root, relative), entry = await exists(target); if (!entry || entry.isSymbolicLink()) return;
    if (entry.isFile()) { if (/\.(?:[cm]?[jt]s|tsx|prisma|json|py)$/.test(relative)) files.push(relative); return; }
    if (!entry.isDirectory()) return;
    for (const child of (await readdir(target, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name))) await visit(path.posix.join(relative, child.name), depth + 1);
  }
  for (const relative of roots) await visit(relative);
  let total = 0; const evidence = [];
  for (const relative of [...new Set(files)].sort()) {
    const bytes = await readFile(path.join(root, relative)); total += bytes.length;
    if (total > 2 * 1024 * 1024) throw new Error('AUTH_ASSESSMENT_SOURCE_BOUND_EXCEEDED');
    evidence.push({ path: relative, text: bytes.toString('utf8') });
  }
  return evidence;
}

export async function assessNativeTarget(targetRoot, ownership = {}) {
  const discovery = await discoverNativeTarget(targetRoot);
  if (ownership.runtime) {
    if (!["node", "python"].includes(ownership.runtime)) throw new Error("AUTH_RUNTIME_INVALID");
    discovery.stack.runtime = ownership.runtime;
    discovery.stack.language = ownership.runtime === "python" ? "python" : discovery.stack.language;
  }
  if (!discovery.authEvidence.length) return { ...discovery, operation: 'ASSESS', classification: discovery.classification, capabilities: [], executionClassification: discovery.classification === 'GREENFIELD' ? 'AUTO_REPAIR_AVAILABLE' : 'AUTH_DEVELOPMENT_REQUIRED' };
  const sources = (await boundedSourceEvidence(discovery.targetRoot)).filter(item => discovery.stack.runtime === 'python' ? item.path.endsWith('.py') : discovery.stack.runtime === 'node' ? !item.path.endsWith('.py') : false);
  const probes = discovery.stack.runtime === 'python' ? PYTHON_ALIGNMENT_PROBES : ALIGNMENT_PROBES;
  const capabilities = probes.map(([id, pattern, expectedEvidence]) => {
    const paths = sources.filter(item => pattern.test(item.text)).map(item => item.path);
    return { id, status: paths.length ? 'OBSERVED_NOT_VERIFIED' : 'NOT_OBSERVED', evidence: paths, expectedEvidence };
  });
  const missing = capabilities.filter(item => item.status === 'NOT_OBSERVED');
  const supportedStack = (discovery.stack.runtime === 'node' && discovery.stack.language === 'typescript') || (discovery.stack.runtime === 'python' && discovery.stack.framework === 'flask');
  const classification = discovery.prohibitedPersistentArtifacts.length ? 'NONCONFORMANT' : !supportedStack ? 'MIGRATION_REQUIRED' : missing.length ? 'DEGRADED' : 'COMPATIBLE';
  return { ...discovery, operation: 'ASSESS', classification, capabilities, executionClassification: classification === 'COMPATIBLE' ? 'AGENT_INTEGRATION_REQUIRED' : classification === 'DEGRADED' ? 'AGENT_INTEGRATION_REQUIRED' : 'AUTH_DEVELOPMENT_REQUIRED', limitation: 'Static observations are leads, not runtime conformance proof.' };
}

function alignmentTestSource(role) {
  if (role === "RELYING_PARTY") return `import test from 'node:test';\nimport assert from 'node:assert/strict';\nimport { readFile } from 'node:fs/promises';\ntest('relying-party declared acceptance requires product-owned runtime test', async()=>{const contract=JSON.parse(await readFile('auth-standards.json','utf8'));assert.equal(contract.authenticationRole,'RELYING_PARTY');assert.fail('PRODUCT_RUNTIME_TEST_REQUIRED: implement session/callback acceptance in this product-owned test');});\n`;
  return `import test from 'node:test';\nimport assert from 'node:assert/strict';\nconst base=process.env.AUTH_BASE_URL;\ntest('authority metadata smoke only, not runtime acceptance',async()=>{assert.ok(base,'AUTH_BASE_URL is required');const health=await fetch(new URL('/health',base));assert.equal(health.ok,true);const metadata=await fetch(new URL('/.well-known/oauth-authorization-server',base));assert.equal(metadata.ok,true);const body=await metadata.json();assert.equal(new URL(body.issuer).origin,new URL(base).origin);assert.ok(body.code_challenge_methods_supported?.includes('S256'));});\n`;
}

function regressionWorkflow(existing = false) {
  return `name: Authentication regression
on: [push, pull_request, workflow_dispatch]
permissions:
  contents: read
jobs:
  authentication-regression:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
        with:
          persist-credentials: false
      - name: Require supported Node
        run: node -e "if (Number(process.versions.node.split('.')[0]) < 20) process.exit(1)"
${existing ? `      - name: Verify product authentication contracts
        run: node --test test/auth-entrypoint.test.mjs test/auth-contract.test.mjs
` : `      - run: npm ci
      - run: npm test
`}`;
}

function entrypointTestSource(contract) {
  const expected = JSON.stringify({ authenticationRole: contract.authenticationRole, authenticationRuntime: contract.authenticationRuntime, authenticationEntrypoint: contract.authenticationEntrypoint, productId: contract.productId });
  return `import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, lstat, realpath } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const expected = ${expected};
test('authentication ownership and entrypoint remain established', async () => {
  const contract = JSON.parse(await readFile(path.join(root, 'auth-standards.json'), 'utf8'));
  for (const [key, value] of Object.entries(expected)) assert.equal(contract[key], value, 'AUTH_CONTRACT_DRIFT: ' + key);
  const entrypoint = path.join(root, expected.authenticationEntrypoint);
  assert.ok((await lstat(entrypoint)).isFile(), 'AUTH_ENTRYPOINT_NOT_REGULAR');
  assert.equal(await realpath(entrypoint), entrypoint, 'AUTH_ENTRYPOINT_REDIRECTED');
});
`;
}

export async function planNativeAlignment(targetRoot, { sourceRoot, sourceRevision = 'HEAD', productId = 'product', receiptPath, authenticationRole, authenticationRuntime, authenticationEntrypoint } = {}) {
  if (!sourceRoot || !receiptPath) throw new Error('SOURCE_AND_RECEIPT_REQUIRED');
  if (!['IDENTITY_AUTHORITY','RELYING_PARTY'].includes(authenticationRole)) throw new Error('AUTHENTICATION_ROLE_REQUIRED');
  const assessment = await assessNativeTarget(targetRoot, { runtime: authenticationRuntime });
  if (assessment.stack.runtime === 'ambiguous') throw new Error('AUTHENTICATION_RUNTIME_AMBIGUOUS');
  if (!authenticationEntrypoint || !(await exists(inside(assessment.targetRoot, authenticationEntrypoint)))?.isFile()) throw new Error('AUTHENTICATION_ENTRYPOINT_REQUIRED');
  if (assessment.stack.runtime === 'python' ? !authenticationEntrypoint.endsWith('.py') : !/\.[cm]?[jt]sx?$/.test(authenticationEntrypoint)) throw new Error('AUTHENTICATION_ENTRYPOINT_RUNTIME_MISMATCH');
  if ((await realpath(inside(assessment.targetRoot, authenticationEntrypoint))) !== inside(assessment.targetRoot, authenticationEntrypoint)) throw new Error('AUTHENTICATION_ENTRYPOINT_UNSAFE');
  if (!assessment.authEvidence.length) throw new Error('ALIGNMENT_REQUIRES_EXISTING_AUTH');
  if (assessment.prohibitedPersistentArtifacts.length) throw new Error('PERSISTENT_AUTH_ARTIFACT_MIGRATION_REQUIRED');
  const contract = { schema: 'life.auth.existing-contract/1', profile: assessment.stack.runtime === 'python' ? PYTHON_FLASK_SQLITE_PROFILE : NATIVE_PROFILE, authenticationRole, authenticationRuntime: assessment.stack.runtime, authenticationEntrypoint, productId, classification: assessment.classification, capabilities: assessment.capabilities.map(item => item.id), observations: assessment.capabilities, verification: 'PENDING_RUNTIME_EVIDENCE' };
  const generated = [['auth-standards.json', Buffer.from(json(contract))], ['test/auth-contract.test.mjs', Buffer.from(alignmentTestSource(authenticationRole))], ['test/auth-entrypoint.test.mjs', Buffer.from(entrypointTestSource(contract))], ['.github/workflows/authentication-regression.yml', Buffer.from(regressionWorkflow(true))]];
  const operations = [];
  for (const [relative, bytes] of generated) {
    if (await exists(inside(assessment.targetRoot, relative))) throw new Error(`EXISTING_PRODUCT_FILE_REVIEW_REQUIRED:${relative}`);
    operations.push({ path: relative, action: 'create', owner: 'product', preimageSha256: null, postimageSha256: sha(bytes), inlineBase64: bytes.toString('base64') });
  }
  const plan = { schema: 'life.auth.native-plan/1', profile: NATIVE_PROFILE, mode: 'align-existing', productId, targetRoot: assessment.targetRoot, receiptPath: path.resolve(receiptPath), source: authoritativeSource(sourceRoot, sourceRevision), classification: assessment.classification, assessmentDigest: digestJson(assessment), operations, limitations: ['static-assessment-not-runtime-proof','product-auth-source-not-overwritten','power-loss-fsync-not-proven'] };
  plan.planDigest = digestJson(plan); return plan;
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
  const pythonRequirements = [];
  for (const relative of ['requirements.txt', 'requirements-core.txt', 'pyproject.toml']) {
    if (inventory[relative] === 'file') pythonRequirements.push((await readFile(path.join(root, relative), 'utf8')).toLowerCase());
  }
  const python = pythonRequirements.length > 0 || inventory.backend === 'directory';
  const stack = {
    language: dependencies.typescript || inventory['tsconfig.json'] === 'file' ? 'typescript' : packageJson ? 'javascript' : python ? 'python' : 'unknown',
    runtime: packageJson && python ? 'ambiguous' : packageJson ? 'node' : python ? 'python' : 'unknown',
    framework: pythonRequirements.some(value => value.includes('flask')) ? 'flask' : null,
    persistence: pythonRequirements.length && (await exists(path.join(root, 'models', 'database.py'))) ? 'sqlite' : null,
    express: Boolean(dependencies.express), prisma: Boolean(dependencies.prisma || dependencies['@prisma/client']),
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
    scripts: { build: 'tsc -p tsconfig.json', 'prisma:generate': 'prisma generate', 'prisma:migrate': 'node scripts/prepare-database.mjs && prisma migrate deploy', start: 'node dist/index.js', pretest: 'npm run prisma:generate && npm run build', test: 'node --test test/*.test.mjs' },
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
  const paths = [...profileEntries(sourceRoot, source.revision), { path: 'package-lock.json', sourcePath: 'package-lock.json' }];
  const operations = [];
  for (const { path: targetPath, sourcePath } of paths) {
    const bytes = profileBytes(sourceRoot, source.revision, sourcePath);
    const existing = await exists(path.join(discovery.targetRoot, targetPath));
    if (existing) {
      if (!existing.isFile()) throw new Error(`TARGET_PATH_COLLISION:${targetPath}`);
      const current = await readFile(path.join(discovery.targetRoot, targetPath));
      if (sha(current) !== sha(bytes)) throw new Error(`EXISTING_AUTH_REVIEW_REQUIRED:${targetPath}`);
      operations.push({ path: targetPath, action: 'retain', owner: 'product', preimageSha256: sha(current), postimageSha256: sha(bytes), sourcePath });
    } else operations.push({ path: targetPath, action: 'create', owner: 'product', preimageSha256: null, postimageSha256: sha(bytes), sourcePath });
  }
  for (const [relative, bytes] of [
    ['package.json', Buffer.from(json(generatedPackage(productId)))],
    ['.github/workflows/authentication-regression.yml', Buffer.from(regressionWorkflow())],
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
  if (operation.inlineBase64) {
    const bytes = Buffer.from(operation.inlineBase64, 'base64');
    if (bytes.length > 256 * 1024 || bytes.toString('base64') !== operation.inlineBase64) throw new Error('PLAN_INLINE_CONTENT_INVALID');
    return bytes;
  }
  if (operation.sourcePath) return profileBytes(sourceRoot, plan.source.revision, operation.sourcePath);
  if (operation.path === '.github/workflows/authentication-regression.yml') return Buffer.from(regressionWorkflow());
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
  return { operation: 'VERIFY', verification_scope: 'SOURCE_INTEGRITY', assurance: { source_integrity: failures.length ? 'FAIL' : 'PASS', capability_conformance: 'INDETERMINATE', runtime_acceptance: 'INDETERMINATE', historical_continuity: 'INDETERMINATE' }, verification: failures.length ? 'FAIL' : 'PASS', targetBinding: sha(Buffer.from(root)), files, failures, prohibitedPersistentArtifacts: prohibited };
}

export async function verifyNativeReceipt(targetRoot, receiptPath) {
  const receipt = JSON.parse(await readFile(receiptPath, 'utf8'));
  const { receiptDigest, ...payload } = receipt;
  if (receipt.schema !== RECEIPT_SCHEMA || digestJson(payload) !== receiptDigest) throw new Error('RECEIPT_INVALID');
  if (receipt.targetBinding !== sha(Buffer.from(await realpath(targetRoot)))) throw new Error('RECEIPT_TARGET_MISMATCH');
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
      const mapped = [...profileEntries(sourceRoot, receipt.source.revision), { path: 'package-lock.json', sourcePath: 'package-lock.json' }].find(item => item.path === relative);
      const operation = { path: relative, ...(mapped ? { sourcePath: mapped.sourcePath } : { generated: true }) };
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

export async function migrateNativeTarget(targetRoot, receiptPath, { sourceRoot, targetRevision, newReceiptPath, authorized = false } = {}) {
  if (!authorized) throw new Error('EXPLICIT_AUTHORIZATION_REQUIRED');
  if (!targetRevision || !newReceiptPath) throw new Error('MIGRATION_TARGET_AND_RECEIPT_REQUIRED');
  const root = await realpath(targetRoot);
  const prior = JSON.parse(await readFile(receiptPath, 'utf8'));
  if (prior.profile !== NATIVE_PROFILE || (await verifyNativeReceipt(root, receiptPath)).verification !== 'PASS') throw new Error('MIGRATION_REQUIRES_VALID_BASELINE');
  const targetSource = authoritativeSource(sourceRoot, targetRevision);
  if (targetSource.revision === prior.source.revision) throw new Error('MIGRATION_TARGET_MUST_DIFFER');
  const priorPaths = Object.keys(prior.files).sort();
  const targetEntries = [...profileEntries(sourceRoot, targetSource.revision), { path: 'package-lock.json', sourcePath: 'package-lock.json' }];
  const targetSourcePaths = new Set(targetEntries.map(item => item.path));
  const priorSourcePaths = new Set(priorPaths.filter(relative => !['package.json', 'tsconfig.json', 'auth-standards.json', '.github/workflows/authentication-regression.yml'].includes(relative)));
  if (targetSourcePaths.size !== priorSourcePaths.size || [...targetSourcePaths].some(relative => !priorSourcePaths.has(relative))) throw new Error('MIGRATION_FILESET_CHANGE_REQUIRES_REVIEWED_PROFILE');
  const targetFiles = {}, operations = [];
  for (const relative of priorPaths) {
    const current = await fileProof(inside(root, relative));
    if (current.sha256 !== prior.files[relative]) throw new Error(`MIGRATION_PREIMAGE_MISMATCH:${relative}`);
    const mapped = targetEntries.find(item => item.path === relative);
    const operation = { path: relative, ...(mapped ? { sourcePath: mapped.sourcePath } : { generated: true }) };
    const bytes = await bytesFor({ ...prior, source: targetSource, productId: prior.productId }, operation, sourceRoot);
    const targetDigest = sha(bytes); targetFiles[relative] = targetDigest;
    operations.push({ ...operation, bytes, targetDigest, current });
  }
  const schemaOperation = operations.find(item => item.path === 'prisma/schema.prisma');
  if (schemaOperation && schemaOperation.targetDigest !== prior.files['prisma/schema.prisma']) throw new Error('IRREVERSIBLE_SCHEMA_MIGRATION_REQUIRES_OWNER');
  const changed = operations.filter(item => item.targetDigest !== prior.files[item.path]);
  if (!changed.length) throw new Error('MIGRATION_TARGET_HAS_NO_RUNTIME_CHANGE');
  const newReceiptTarget = path.resolve(newReceiptPath);
  if (await exists(newReceiptTarget)) throw new Error('RECEIPT_DESTINATION_EXISTS');
  const tx = randomUUID(), prefix = `${TX_PREFIX}${tx}`, stage = path.join(root, `${prefix}-stage`), quarantine = path.join(root, `${prefix}-quarantine`), journalPath = path.join(root, `${prefix}.json`);
  const journal = { schema: 'life.auth.native-transaction/2', transactionId: tx, revision: 1, operation: 'MIGRATE', state: 'STAGING', receiptPath: path.resolve(receiptPath), receiptProof: await fileProof(path.resolve(receiptPath)), newReceiptPath: newReceiptTarget, profile: prior.profile, targetSource, entries: changed.map(item => ({ path: item.path, sha256: item.targetDigest, state: 'PLANNED' })), parents: [] };
  await writeFile(journalPath, json(journal), { flag: 'wx', mode: 0o600 });
  await mkdir(stage, { mode: 0o700 }); await writeFile(path.join(stage, '.transaction-id'), `${tx}\n`, { flag: 'wx' }); journal.stageProof = identity(await stat(stage));
  await mkdir(quarantine, { mode: 0o700 }); await writeFile(path.join(quarantine, '.transaction-id'), `${tx}\n`, { flag: 'wx' }); journal.quarantineProof = identity(await stat(quarantine));
  await persistNativeJournal(journalPath, journal);
  try {
    for (const operation of changed) {
      const staged = inside(stage, operation.path); await mkdir(path.dirname(staged), { recursive: true }); await writeFile(staged, operation.bytes, { flag: 'wx' });
      const item = journal.entries.find(entry => entry.path === operation.path); item.stagedProof = await fileProof(staged); item.state = 'STAGED'; await persistNativeJournal(journalPath, journal);
    }
    journal.state = 'PUBLISHING'; await persistNativeJournal(journalPath, journal);
    for (const operation of changed) {
      const item = journal.entries.find(entry => entry.path === operation.path), destination = inside(root, operation.path), old = inside(quarantine, operation.path), staged = inside(stage, operation.path);
      item.preimageProof = await fileProof(destination); await persistNativeJournal(journalPath, journal);
      await mkdir(path.dirname(old), { recursive: true }); await rename(destination, old); testCrash(`migrate-quarantined:${operation.path}`);
      await rename(staged, destination); testCrash(`migrate-published:${operation.path}`);
      item.publishedProof = await fileProof(destination); item.state = 'PUBLISHED'; await persistNativeJournal(journalPath, journal);
    }
    journal.state = 'VERIFYING'; await persistNativeJournal(journalPath, journal);
    const targetReceipt = { schema: RECEIPT_SCHEMA, profile: prior.profile, productId: prior.productId, targetBinding: prior.targetBinding, source: targetSource, planDigest: digestJson({ operation: 'MIGRATE', from: prior.receiptDigest, to: targetSource }), files: targetFiles, capabilities: prior.capabilities, verification: 'PASS', priorReceiptDigest: prior.receiptDigest, limitations: prior.limitations };
    targetReceipt.receiptDigest = digestJson(targetReceipt);
    const verification = await verifyNativeTarget(root, targetReceipt);
    if (verification.verification !== 'PASS') throw new Error('POST_MIGRATION_VERIFY_FAILED');
    testCrash('migrate-verified');
    const stagedReceipt = path.join(stage, '.next-receipt.json'); await writeFile(stagedReceipt, json(targetReceipt), { flag: 'wx', mode: 0o600 });
    journal.newReceiptStagedProof = await fileProof(stagedReceipt); journal.state = 'ADVANCING'; await persistNativeJournal(journalPath, journal);
    await mkdir(path.dirname(newReceiptTarget), { recursive: true }); await rename(stagedReceipt, newReceiptTarget); testCrash('migrate-receipt-published');
    journal.newReceiptProof = await fileProof(newReceiptTarget); journal.state = 'COMPLETE'; await persistNativeJournal(journalPath, journal); testCrash('migrate-complete');
    await rm(stage, { recursive: true }); await rm(quarantine, { recursive: true }); await rm(journalPath);
    return { operation: 'MIGRATE', state: 'COMPLETE', from: prior.source.revision, to: targetSource.revision, changed: changed.map(item => item.path), receipt: newReceiptTarget, verification };
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
  if (journal.operation === 'REPAIR' || journal.operation === 'MIGRATE') {
    const quarantineRoot = path.join(root, `${TX_PREFIX}${id}-quarantine`);
    const rollback = journal.state !== 'COMPLETE';
    if (rollback) {
      if (journal.operation === 'MIGRATE' && journal.newReceiptPath && await exists(journal.newReceiptPath)) {
        const receiptProof = await fileProof(journal.newReceiptPath).catch(() => null);
        if (!journal.newReceiptStagedProof || !receiptProof || !sameIdentity(receiptProof, journal.newReceiptStagedProof) || receiptProof.sha256 !== journal.newReceiptStagedProof.sha256) throw new Error('NATIVE_TRANSACTION_NEW_RECEIPT_AMBIGUOUS');
        await rm(journal.newReceiptPath);
      }
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
      const finalReceiptPath = journal.operation === 'MIGRATE' ? journal.newReceiptPath : journal.receiptPath;
      const expectedReceiptProof = journal.operation === 'MIGRATE' ? journal.newReceiptProof : journal.receiptProof;
      const receiptProof = await fileProof(finalReceiptPath).catch(() => null);
      if (!receiptProof || !sameIdentity(receiptProof, expectedReceiptProof) || receiptProof.sha256 !== expectedReceiptProof.sha256) throw new Error('NATIVE_TRANSACTION_COMPLETE_AMBIGUOUS');
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
    const finalReceiptPath = journal.operation === 'MIGRATE' ? journal.newReceiptPath : journal.receiptPath;
    const expectedReceiptProof = journal.operation === 'MIGRATE' ? journal.newReceiptProof : journal.receiptProof;
    if (!validateProof(expectedReceiptProof)) throw new Error('NATIVE_TRANSACTION_COMPLETE_INVALID');
    const receiptProof = await fileProof(finalReceiptPath).catch(() => null);
    if (!receiptProof || !sameIdentity(receiptProof, expectedReceiptProof) || receiptProof.sha256 !== expectedReceiptProof.sha256) throw new Error('NATIVE_TRANSACTION_COMPLETE_AMBIGUOUS');
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
