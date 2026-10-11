/** Install a complete product-local AUTH runtime from an immutable Git commit. */
import { lstat, mkdir, readFile, readdir, rename, rm, writeFile } from 'node:fs/promises';
import { createHash, randomUUID } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import path from 'node:path';

export const AUTH_RUNTIME_DIRECTORY = '.auth-runtime/auth-system';
export const AUTH_RUNTIME_CONTRACT_VERSION = 2;

const SOURCE_TREES = ['src/auth', 'src/github', 'src/persistence'];
const SOURCE_FILES = [
  'src/app.ts', 'src/config.ts', 'src/env.ts', 'src/express-shim.d.ts',
  'src/identityDiagnostics.ts', 'src/index.ts', 'src/lifeProfile.ts',
  'src/signingKeyEnv.ts', 'src/types.ts', 'prisma/schema.prisma',
];
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const canonical = (value) => Array.isArray(value) ? value.map(canonical) : value && typeof value === 'object'
  ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])])) : value;
const canonicalDigest = (value) => sha256(Buffer.from(JSON.stringify(canonical(value))));

async function exists(filePath) {
  try { return await lstat(filePath); }
  catch (error) { if (error?.code === 'ENOENT') return null; throw error; }
}

function git(sourceRoot, args, encoding = 'utf8') {
  try { return execFileSync('git', args, { cwd: sourceRoot, encoding, maxBuffer: 32 * 1024 * 1024 }); }
  catch { throw new Error('AUTH_RUNTIME_AUTHORITATIVE_SOURCE_REQUIRED'); }
}

export function resolveAuthoritativeSource(sourceRoot, requestedRevision = 'HEAD') {
  const revision = git(sourceRoot, ['rev-parse', '--verify', `${requestedRevision}^{commit}`]).trim();
  const tree = git(sourceRoot, ['rev-parse', `${revision}^{tree}`]).trim();
  return { mode: 'git-commit', revision, tree };
}

function readGitBlob(sourceRoot, revision, relativePath) {
  return git(sourceRoot, ['show', `${revision}:${relativePath}`], null);
}

function sourceFiles(root, revision, relativeDirectory) {
  return git(root, ['ls-tree', '-r', '--name-only', revision, '--', relativeDirectory]).split('\n')
    .filter((entry) => entry && !entry.includes('/test/')).sort();
}

async function installedFiles(root, relative = '') {
  const files = [];
  for (const entry of await readdir(path.join(root, relative), { withFileTypes: true })) {
    const child = relative ? path.posix.join(relative, entry.name) : entry.name;
    if (entry.isSymbolicLink()) throw new Error(`AUTH_RUNTIME_INSTALLED_SYMLINK:${child}`);
    if (!relative && ['node_modules', 'dist'].includes(entry.name)) continue;
    if (entry.isDirectory()) files.push(...await installedFiles(root, child));
    else if (entry.isFile()) files.push(child);
    else throw new Error(`AUTH_RUNTIME_INSTALLED_SPECIAL_FILE:${child}`);
  }
  return files.sort();
}

async function writeBytes(destinationRoot, relativePath, bytes, manifestFiles) {
  const destination = path.join(destinationRoot, relativePath);
  await mkdir(path.dirname(destination), { recursive: true });
  await writeFile(destination, bytes, { flag: 'wx' });
  manifestFiles[relativePath] = { sha256: sha256(bytes), bytes: bytes.length };
}

function runtimePackage(productId) {
  return {
    name: `@life-auth/${productId.replace(/[^a-z0-9._-]/g, '-')}-runtime`, version: '1.0.0', private: true, type: 'module',
    scripts: { build: 'tsc -p tsconfig.json', 'deps:locked': 'npm ci', 'prisma:generate': 'prisma generate', start: 'node dist/index.js', dev: 'npm run build && npm run start' },
    engines: { node: '>=20' },
    dependencies: { '@prisma/client': '6.12.0', express: '^5.1.0', jose: '^6.1.2', redis: '^5.10.0' },
    devDependencies: { '@types/node': '^26.0.0', prisma: '6.12.0', typescript: '^6.0.3' },
  };
}

const runtimeTsconfig = {
  compilerOptions: {
    target: 'ES2022', module: 'NodeNext', moduleResolution: 'NodeNext', lib: ['ES2022'], types: ['node'],
    rootDir: 'src', outDir: 'dist', strict: true, noImplicitAny: false, skipLibCheck: true,
    esModuleInterop: true, forceConsistentCasingInFileNames: true, resolveJsonModule: true,
  }, include: ['src/**/*.ts', 'src/**/*.d.ts'],
};

function runtimeReadme(productId) {
  return `# ${productId} authentication system\n\nThis product-local runtime was installed from the immutable Git commit recorded in \`AUTH-RUNTIME-MANIFEST.json\`. It does not read the source AUTH checkout at build or runtime.\n\n## Build and run\n\n\`\`\`sh\ncd .auth-runtime/auth-system\nnpm ci\nnpm run prisma:generate\nnpm run build\nAUTH_SESSION_SECRET=... npm start\n\`\`\`\n\nUse \`npm ci\`; lockfile drift is a verification failure. Runtime state and secrets belong to the consuming product and must not be committed.\n`;
}

function envExample(config) {
  const prefix = String(config.oauth?.envPrefix || config.app?.id || '').trim().toUpperCase();
  const lines = ['AUTH_PORT=1111', 'AUTH_HOST=127.0.0.1', 'AUTH_STORAGE_ADAPTER=sqlite', 'AUTH_DB_PATH=', 'AUTH_SESSION_SECRET=', 'AUTH_ACCESS_TOKEN_SECRET=', 'AUTH_REFRESH_TOKEN_SECRET=', 'AUTH_REFRESH_TOKEN_HASH_SECRET='];
  for (const provider of (config.providers || []).filter((item) => item.enabled !== false)) {
    const name = String(provider.provider).toUpperCase();
    lines.push(`${prefix}_${name}_CLIENT_ID=`, `${prefix}_${name}_CLIENT_SECRET=`, `${prefix}_${name}_CALLBACK_URL=`);
  }
  return `${lines.join('\n')}\n`;
}

export async function installProductAuthRuntime(targetRoot, { sourceRoot, sourceRevision = 'HEAD', productId, config, authorized = false, installedAt } = {}) {
  if (!authorized) throw new Error('AUTH_RUNTIME_INSTALL_AUTHORIZATION_REQUIRED');
  if (!sourceRoot || !productId || config?.app?.id !== productId) throw new Error('AUTH_RUNTIME_INSTALL_INPUT_INVALID');
  const runtimeParent = path.join(targetRoot, '.auth-runtime');
  const finalRoot = path.join(targetRoot, AUTH_RUNTIME_DIRECTORY);
  if (await exists(finalRoot)) throw new Error('AUTH_RUNTIME_ALREADY_EXISTS');
  await mkdir(runtimeParent, { recursive: true });
  const stagingRoot = path.join(runtimeParent, `.auth-system.install-${randomUUID()}`);
  const manifestFiles = {};
  try {
    const source = resolveAuthoritativeSource(sourceRoot, sourceRevision);
    await mkdir(stagingRoot, { recursive: false });
    const runtimeSources = [...SOURCE_FILES];
    for (const tree of SOURCE_TREES) runtimeSources.push(...sourceFiles(sourceRoot, source.revision, tree));
    for (const relativePath of [...new Set(runtimeSources)].sort()) await writeBytes(stagingRoot, relativePath, readGitBlob(sourceRoot, source.revision, relativePath), manifestFiles);
    await writeBytes(stagingRoot, 'config/example-app.json', Buffer.from(`${JSON.stringify(config, null, 2)}\n`), manifestFiles);
    await writeBytes(stagingRoot, 'package.json', Buffer.from(`${JSON.stringify(runtimePackage(productId), null, 2)}\n`), manifestFiles);
    await writeBytes(stagingRoot, 'package-lock.json', readGitBlob(sourceRoot, source.revision, 'package-lock.json'), manifestFiles);
    await writeBytes(stagingRoot, 'tsconfig.json', Buffer.from(`${JSON.stringify(runtimeTsconfig, null, 2)}\n`), manifestFiles);
    await writeBytes(stagingRoot, '.env.example', Buffer.from(envExample(config)), manifestFiles);
    await writeBytes(stagingRoot, 'README.md', Buffer.from(runtimeReadme(productId)), manifestFiles);
    const runtimeArtifactDigest = canonicalDigest(manifestFiles);
    const manifest = {
      contract: 'life.auth.product-local-runtime', contractVersion: AUTH_RUNTIME_CONTRACT_VERSION, manifestSchemaVersion: 1,
      productId, lifecycleState: 'INSTALLED_UNESTABLISHED', entrypoint: 'dist/index.js', config: 'config/example-app.json', sourceIndependent: true,
      installedAt: installedAt || new Date().toISOString(), installer: { name: '@quantum/auth', version: '0.1.0' },
      source: { ...source, contentDigest: canonicalDigest(Object.fromEntries([...new Set(runtimeSources)].sort().map((name) => [name, manifestFiles[name].sha256]))), developmentMode: false },
      runtimeArtifactDigest, dependencyLockfileDigest: manifestFiles['package-lock.json'].sha256,
      configurationDigest: manifestFiles['config/example-app.json'].sha256,
      previousInstallationId: null, upgradeLineage: [], compatibility: { node: '>=20', contractVersion: AUTH_RUNTIME_CONTRACT_VERSION }, files: manifestFiles,
    };
    manifest.installationId = canonicalDigest({ productId, source: manifest.source, runtimeArtifactDigest, dependencyLockfileDigest: manifest.dependencyLockfileDigest, configurationDigest: manifest.configurationDigest });
    await writeFile(path.join(stagingRoot, 'AUTH-RUNTIME-MANIFEST.json'), `${JSON.stringify(manifest, null, 2)}\n`, { flag: 'wx' });
    await rename(stagingRoot, finalRoot);
    return { runtimeRoot: AUTH_RUNTIME_DIRECTORY, manifest };
  } catch (error) {
    await rm(stagingRoot, { recursive: true, force: true });
    throw error;
  }
}

export async function inspectProductAuthRuntime(targetRoot, expectedProductId) {
  const runtimeRoot = path.join(targetRoot, AUTH_RUNTIME_DIRECTORY);
  const manifest = JSON.parse(await readFile(path.join(runtimeRoot, 'AUTH-RUNTIME-MANIFEST.json'), 'utf8'));
  if (manifest.contract !== 'life.auth.product-local-runtime' || manifest.contractVersion !== AUTH_RUNTIME_CONTRACT_VERSION || manifest.manifestSchemaVersion !== 1) throw new Error('AUTH_RUNTIME_CONTRACT_INVALID');
  if (expectedProductId && manifest.productId !== expectedProductId) throw new Error('AUTH_RUNTIME_PRODUCT_MISMATCH');
  const expectedInventory = [...Object.keys(manifest.files || {}), 'AUTH-RUNTIME-MANIFEST.json'].sort();
  if (canonicalDigest(await installedFiles(runtimeRoot)) !== canonicalDigest(expectedInventory)) throw new Error('AUTH_RUNTIME_INVENTORY_DRIFT');
  for (const [relativePath, expected] of Object.entries(manifest.files || {})) {
    const bytes = await readFile(path.join(runtimeRoot, relativePath));
    if (sha256(bytes) !== expected.sha256 || bytes.length !== expected.bytes) throw new Error(`AUTH_RUNTIME_FILE_DRIFT:${relativePath}`);
  }
  if (canonicalDigest(manifest.files) !== manifest.runtimeArtifactDigest) throw new Error('AUTH_RUNTIME_MANIFEST_DIGEST_INVALID');
  if (manifest.files['package-lock.json']?.sha256 !== manifest.dependencyLockfileDigest) throw new Error('AUTH_RUNTIME_LOCKFILE_DRIFT');
  if (manifest.files['config/example-app.json']?.sha256 !== manifest.configurationDigest) throw new Error('AUTH_RUNTIME_CONFIGURATION_DRIFT');
  if (manifest.source?.mode !== 'git-commit' || !/^[0-9a-f]{40}$/.test(manifest.source.revision || '') || manifest.source.developmentMode !== false) throw new Error('AUTH_RUNTIME_SOURCE_PROVENANCE_INVALID');
  return { runtimeRoot: AUTH_RUNTIME_DIRECTORY, manifest };
}

export async function rollbackProductAuthRuntime(targetRoot, expectedManifest) {
  const inspected = await inspectProductAuthRuntime(targetRoot, expectedManifest?.productId);
  if (canonicalDigest(inspected.manifest) !== canonicalDigest(expectedManifest)) throw new Error('AUTH_RUNTIME_ROLLBACK_REFUSED');
  await rm(path.join(targetRoot, AUTH_RUNTIME_DIRECTORY), { recursive: true, force: false });
}
