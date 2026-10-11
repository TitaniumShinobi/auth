/** Crash-recoverable transactional publication for initial product-local AUTH setup. */
import { lstat, mkdir, readFile, readdir, realpath, rename, rm, rmdir, stat, writeFile } from 'node:fs/promises';
import { createHash, randomUUID } from 'node:crypto';
import path from 'node:path';
import { installProductAuthRuntime } from './auth-runtime-installer.mjs';
import { installProductBundle } from './auth-product-contract.mjs';

const CONTRACT = 'life.auth.setup-transaction/2';
const STAGING_PREFIX = '.auth-setup-staging-';
const JOURNAL_PREFIX = '.auth-setup-journal-';
const QUARANTINE_PREFIX = '.auth-setup-quarantine-';
const UUID = '[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}';
const JOURNAL_PATTERN = new RegExp(`^${JOURNAL_PREFIX}(${UUID})\\.json$`, 'i');
const STATES = new Set(['STAGING', 'PUBLISHING', 'COMPLETING', 'COMPLETE', 'ROLLBACK_REFUSED']);
const PUBLICATIONS = new Map([
  ['.auth-runtime/auth-system', { stagePath: '.auth-runtime/auth-system', kind: 'tree' }],
  ['.auth-kit', { stagePath: '.auth-kit', kind: 'tree' }],
  ['.github/workflows/auth-product-contract.yml', { stagePath: '.github/workflows/auth-product-contract.yml', kind: 'file' }],
]);
const PARENTS = new Set(['.auth-runtime', '.github', '.github/workflows']);
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const json = (value) => `${JSON.stringify(value, null, 2)}\n`;

async function exists(target) {
  try { return await lstat(target); }
  catch (error) { if (error?.code === 'ENOENT') return null; throw error; }
}

function safeTarget(root, relative) {
  if (!relative || path.isAbsolute(relative) || relative.includes('\\') || relative.split('/').some((part) => !part || part === '..')) throw new Error('AUTH_SETUP_UNSAFE_PATH');
  const target = path.resolve(root, relative);
  if (!target.startsWith(`${root}${path.sep}`)) throw new Error('AUTH_SETUP_UNSAFE_PATH');
  return target;
}

function filesystemIdentity(metadata) {
  return { dev: metadata.dev, ino: metadata.ino };
}

function sameIdentity(left, right) {
  return Boolean(left && right && Number.isInteger(left.dev) && Number.isInteger(left.ino) && left.dev === right.dev && left.ino === right.ino);
}

async function assertDirectoryChain(root, relative, allowMissing = true) {
  let current = root;
  for (const part of relative.split('/')) {
    current = path.join(current, part);
    const entry = await exists(current);
    if (!entry && allowMissing) return;
    if (!entry || entry.isSymbolicLink() || !entry.isDirectory()) throw new Error('AUTH_SETUP_UNSAFE_PARENT');
  }
}

async function treeEntries(root, relative = '') {
  const directory = relative ? path.join(root, relative) : root;
  const entries = await readdir(directory, { withFileTypes: true });
  const result = [];
  for (const entry of entries.sort((a, b) => a.name.localeCompare(b.name))) {
    const child = relative ? path.posix.join(relative, entry.name) : entry.name;
    if (entry.isSymbolicLink()) throw new Error(`AUTH_SETUP_SYMLINK:${child}`);
    if (entry.isDirectory()) result.push(...await treeEntries(root, child));
    else if (entry.isFile()) result.push([child, sha256(await readFile(path.join(root, child)))]);
    else throw new Error(`AUTH_SETUP_SPECIAL_FILE:${child}`);
  }
  return result;
}

async function digest(target, kind) {
  if (kind === 'file') return sha256(await readFile(target));
  return sha256(Buffer.from(JSON.stringify(await treeEntries(target))));
}

function testEnabled() {
  return process.env.AUTH_SETUP_TEST_MODE === '1';
}

function exceptionAt(point) {
  if (testEnabled() && process.env.AUTH_SETUP_TEST_FAILURE_POINT === point) throw new Error(`INJECTED_SETUP_FAILURE:${point}`);
}

function abruptAt(point) {
  if (testEnabled() && process.env.AUTH_SETUP_TEST_ABRUPT_POINT === point) process.exit(86);
}

async function writeExclusive(target, content) {
  await mkdir(path.dirname(target), { recursive: true });
  await writeFile(target, content, { flag: 'wx' });
}

function validateIdentity(value, code) {
  if (!value || !Number.isInteger(value.dev) || !Number.isInteger(value.ino) || value.dev < 0 || value.ino < 0) throw new Error(code);
}

function validateJournal(journal, transactionIdFromName) {
  if (!journal || typeof journal !== 'object' || Array.isArray(journal)) throw new Error('AUTH_SETUP_JOURNAL_MALFORMED');
  if (journal.contract !== CONTRACT) throw new Error('AUTH_SETUP_JOURNAL_UNSUPPORTED');
  if (journal.transactionId !== transactionIdFromName || !(new RegExp(`^${UUID}$`, 'i')).test(journal.transactionId)) throw new Error('AUTH_SETUP_JOURNAL_ID_MISMATCH');
  if (!Number.isInteger(journal.revision) || journal.revision < 1 || !STATES.has(journal.state)) throw new Error('AUTH_SETUP_JOURNAL_MALFORMED');
  if (typeof journal.productId !== 'string' || !journal.productId.trim() || journal.stage !== `${STAGING_PREFIX}${journal.transactionId}`) throw new Error('AUTH_SETUP_JOURNAL_MALFORMED');
  validateIdentity(journal.stagingIdentity, 'AUTH_SETUP_JOURNAL_MALFORMED');
  if (!Array.isArray(journal.publications) || !Array.isArray(journal.createdParents)) throw new Error('AUTH_SETUP_JOURNAL_MALFORMED');
  const publicationPaths = new Set();
  for (const publication of journal.publications) {
    const expected = PUBLICATIONS.get(publication?.path);
    if (!expected || publicationPaths.has(publication.path) || publication.stagePath !== expected.stagePath || publication.kind !== expected.kind) throw new Error('AUTH_SETUP_JOURNAL_PUBLICATION_INVALID');
    if (!['PLANNED', 'PUBLISHED'].includes(publication.state) || !/^[0-9a-f]{64}$/.test(publication.digest || '')) throw new Error('AUTH_SETUP_JOURNAL_PUBLICATION_INVALID');
    validateIdentity(publication.expectedIdentity, 'AUTH_SETUP_JOURNAL_PUBLICATION_INVALID');
    if (publication.state === 'PUBLISHED') validateIdentity(publication.publishedIdentity, 'AUTH_SETUP_JOURNAL_PUBLICATION_INVALID');
    publicationPaths.add(publication.path);
  }
  const parentPaths = new Set();
  for (const parent of journal.createdParents) {
    if (!PARENTS.has(parent?.path) || parentPaths.has(parent.path)) throw new Error('AUTH_SETUP_JOURNAL_PARENT_INVALID');
    if (!['PLANNED', 'CREATED'].includes(parent.state)) throw new Error('AUTH_SETUP_JOURNAL_PARENT_INVALID');
    if (parent.state === 'CREATED') validateIdentity(parent.identity, 'AUTH_SETUP_JOURNAL_PARENT_INVALID');
    parentPaths.add(parent.path);
  }
  if (journal.state === 'COMPLETE' && (publicationPaths.size !== PUBLICATIONS.size || journal.publications.some((item) => item.state !== 'PUBLISHED'))) throw new Error('AUTH_SETUP_JOURNAL_COMPLETE_INVALID');
  return journal;
}

async function readValidatedJournal(root, journalName) {
  const match = JOURNAL_PATTERN.exec(journalName);
  if (!match) throw new Error('AUTH_SETUP_JOURNAL_NAME_INVALID');
  const journalPath = safeTarget(root, journalName);
  const entry = await lstat(journalPath);
  if (entry.isSymbolicLink() || !entry.isFile()) throw new Error('AUTH_SETUP_JOURNAL_FILE_INVALID');
  let journal;
  try { journal = JSON.parse(await readFile(journalPath, 'utf8')); }
  catch { throw new Error('AUTH_SETUP_JOURNAL_MALFORMED'); }
  validateJournal(journal, match[1]);
  return { journal, journalPath, journalIdentity: filesystemIdentity(entry), journalDigest: sha256(await readFile(journalPath)) };
}

async function atomicPersistJournal(root, journalPath, journal) {
  journal.revision += 1;
  const tempName = `${path.basename(journalPath)}.tmp-${journal.revision}-${randomUUID()}`;
  const tempPath = safeTarget(root, tempName);
  await writeFile(tempPath, json(journal), { flag: 'wx' });
  abruptAt(`journal-temp-write-${journal.revision}`);
  await rename(tempPath, journalPath);
}

async function cleanupJournalTemps(root, transactionId, remove = true) {
  const prefix = `${JOURNAL_PREFIX}${transactionId}.json.tmp-`;
  for (const name of await readdir(root)) {
    if (!name.startsWith(prefix)) continue;
    const match = new RegExp(`^${JOURNAL_PREFIX}${transactionId}\\.json\\.tmp-([1-9][0-9]*)-(${UUID})$`, 'i').exec(name);
    if (!match) throw new Error('AUTH_SETUP_JOURNAL_TEMP_INVALID');
    const target = safeTarget(root, name);
    const entry = await lstat(target);
    if (entry.isSymbolicLink() || !entry.isFile()) throw new Error('AUTH_SETUP_JOURNAL_TEMP_INVALID');
    let candidate;
    try { candidate = JSON.parse(await readFile(target, 'utf8')); }
    catch { throw new Error('AUTH_SETUP_JOURNAL_TEMP_INVALID'); }
    validateJournal(candidate, transactionId);
    if (candidate.revision !== Number(match[1])) throw new Error('AUTH_SETUP_JOURNAL_TEMP_INVALID');
    if (remove) await rm(target);
  }
}

async function cleanupStaging(root, journal) {
  const stageRoot = safeTarget(root, journal.stage);
  const entry = await exists(stageRoot);
  if (!entry) return;
  const currentIdentity = filesystemIdentity(await stat(stageRoot));
  const marker = await readFile(path.join(stageRoot, '.transaction-id'), 'utf8').then((value) => value.trim()).catch(() => null);
  if (entry.isSymbolicLink() || !entry.isDirectory() || !sameIdentity(currentIdentity, journal.stagingIdentity) || marker !== journal.transactionId) throw new Error(`AUTH_SETUP_STAGING_IDENTITY_AMBIGUOUS:${journal.stage}`);
  await rm(stageRoot, { recursive: true, force: false });
}

async function quarantineAndDelete(root, journal, publication, index) {
  const destination = safeTarget(root, publication.path);
  if (!await exists(destination)) return;
  const quarantineRelative = `${QUARANTINE_PREFIX}${journal.transactionId}-${index}`;
  const quarantine = safeTarget(root, quarantineRelative);
  if (await exists(quarantine)) throw new Error(`AUTH_SETUP_QUARANTINE_EXISTS:${quarantineRelative}`);
  await rename(destination, quarantine);
  let safeToDelete = false;
  try {
    const entry = await lstat(quarantine);
    const kindMatches = !entry.isSymbolicLink() && (publication.kind === 'file' ? entry.isFile() : entry.isDirectory());
    const recordedIdentity = publication.publishedIdentity || publication.expectedIdentity;
    const identityMatches = kindMatches && sameIdentity(filesystemIdentity(await stat(quarantine)), recordedIdentity);
    const digestMatches = kindMatches && await digest(quarantine, publication.kind).then((value) => value === publication.digest).catch(() => false);
    safeToDelete = identityMatches && digestMatches;
    if (safeToDelete) {
      if (publication.kind === 'file') await rm(quarantine);
      else await rm(quarantine, { recursive: true, force: false });
      return;
    }
  } finally {
    if (!safeToDelete && await exists(quarantine) && !await exists(destination)) await rename(quarantine, destination).catch(() => {});
  }
  throw new Error(`AUTH_SETUP_PUBLICATION_IDENTITY_AMBIGUOUS:${publication.path}`);
}

async function rollbackParents(root, journal) {
  const ambiguous = [];
  for (const parent of [...journal.createdParents].reverse()) {
    const target = safeTarget(root, parent.path);
    const entry = await exists(target);
    if (!entry) continue;
    try {
      const current = filesystemIdentity(await stat(target));
      if (parent.state !== 'CREATED' || entry.isSymbolicLink() || !entry.isDirectory() || !sameIdentity(current, parent.identity)) { ambiguous.push(parent.path); continue; }
      await rmdir(target);
    } catch (error) { if (error?.code !== 'ENOTEMPTY') ambiguous.push(parent.path); }
  }
  if (ambiguous.length) throw new Error(`AUTH_SETUP_PARENT_IDENTITY_AMBIGUOUS:${ambiguous.join(',')}`);
}

async function removeValidatedJournal(root, journalPath, journalIdentity, journalDigest, transactionId) {
  const quarantineRelative = `${QUARANTINE_PREFIX}${transactionId}-journal`;
  const quarantine = safeTarget(root, quarantineRelative);
  if (await exists(quarantine)) throw new Error('AUTH_SETUP_JOURNAL_QUARANTINE_EXISTS');
  await rename(journalPath, quarantine);
  let valid = false;
  try {
    const entry = await lstat(quarantine);
    valid = !entry.isSymbolicLink() && entry.isFile() && sameIdentity(filesystemIdentity(entry), journalIdentity) && sha256(await readFile(quarantine)) === journalDigest;
    if (valid) { await rm(quarantine); return; }
  } finally {
    if (!valid && await exists(quarantine) && !await exists(journalPath)) await rename(quarantine, journalPath).catch(() => {});
  }
  throw new Error('AUTH_SETUP_JOURNAL_IDENTITY_AMBIGUOUS');
}

async function verifiedRollback(root, loaded) {
  const { journal, journalPath } = loaded;
  try {
    for (let index = journal.publications.length - 1; index >= 0; index -= 1) await quarantineAndDelete(root, journal, journal.publications[index], index);
    await rollbackParents(root, journal);
    await cleanupStaging(root, journal);
    await cleanupJournalTemps(root, journal.transactionId);
    const refreshed = await readValidatedJournal(root, path.basename(journalPath));
    await removeValidatedJournal(root, refreshed.journalPath, refreshed.journalIdentity, refreshed.journalDigest, journal.transactionId);
  } catch (error) {
    journal.state = 'ROLLBACK_REFUSED';
    journal.ambiguous = [String(error?.message || error)];
    await atomicPersistJournal(root, journalPath, journal).catch(() => {});
    throw error;
  }
}

async function finalizeComplete(root, loaded) {
  const { journal, journalPath } = loaded;
  for (const publication of journal.publications) {
    const target = safeTarget(root, publication.path);
    const entry = await exists(target);
    const kindMatches = entry && !entry.isSymbolicLink() && (publication.kind === 'file' ? entry.isFile() : entry.isDirectory());
    if (!kindMatches || !sameIdentity(filesystemIdentity(await stat(target)), publication.publishedIdentity) || await digest(target, publication.kind) !== publication.digest) throw new Error(`AUTH_SETUP_COMPLETE_ARTIFACT_AMBIGUOUS:${publication.path}`);
  }
  await cleanupStaging(root, journal);
  await cleanupJournalTemps(root, journal.transactionId);
  const refreshed = await readValidatedJournal(root, path.basename(journalPath));
  await removeValidatedJournal(root, refreshed.journalPath, refreshed.journalIdentity, refreshed.journalDigest, journal.transactionId);
}

export async function recoverAbandonedSetup(root) {
  root = await realpath(root);
  const names = await readdir(root);
  const journals = names.filter((name) => JOURNAL_PATTERN.test(name));
  if (journals.length > 1) throw new Error('AUTH_SETUP_MULTIPLE_ACTIVE_TRANSACTIONS');
  const exactResidue = names.filter((name) => name.startsWith(STAGING_PREFIX) || name.startsWith(QUARANTINE_PREFIX) || name.startsWith(JOURNAL_PREFIX));
  if (journals.length === 0) {
    if (exactResidue.length) throw new Error(`AUTH_SETUP_ORPHAN_RESIDUE:${exactResidue.join(',')}`);
    return { recovered: false };
  }
  const loaded = await readValidatedJournal(root, journals[0]);
  const allowedJournalPrefix = `${path.basename(loaded.journalPath)}.tmp-`;
  const ambiguousResidue = names.filter((name) => (
    (name.startsWith(STAGING_PREFIX) && name !== loaded.journal.stage)
    || name.startsWith(QUARANTINE_PREFIX)
    || (name.startsWith(JOURNAL_PREFIX) && name !== path.basename(loaded.journalPath) && !name.startsWith(allowedJournalPrefix))
  ));
  if (ambiguousResidue.length) throw new Error(`AUTH_SETUP_AMBIGUOUS_RESIDUE:${ambiguousResidue.join(',')}`);
  await cleanupJournalTemps(root, loaded.journal.transactionId, false);
  if (loaded.journal.state === 'COMPLETE') await finalizeComplete(root, loaded);
  else await verifiedRollback(root, loaded);
  return { recovered: true, transactionId: loaded.journal.transactionId, action: loaded.journal.state === 'COMPLETE' ? 'finalized' : 'rolled_back' };
}

export async function preflightInitialSetup(root) {
  root = await realpath(root);
  await assertDirectoryChain(root, '.auth-runtime');
  await assertDirectoryChain(root, '.github/workflows');
  for (const relative of PUBLICATIONS.keys()) if (await exists(safeTarget(root, relative))) throw new Error(`AUTH_SETUP_DESTINATION_EXISTS:${relative}`);
  return root;
}

export async function installInitialSetupTransaction(root, options = {}) {
  if (options.authorized !== true) throw new Error('SETUP_AUTHORIZATION_REQUIRED');
  root = await realpath(root);
  await recoverAbandonedSetup(root);
  root = await preflightInitialSetup(root);
  const transactionId = randomUUID();
  const stageRelative = `${STAGING_PREFIX}${transactionId}`;
  const journalRelative = `${JOURNAL_PREFIX}${transactionId}.json`;
  const stageRoot = safeTarget(root, stageRelative);
  const journalPath = safeTarget(root, journalRelative);
  const markerPath = path.join(stageRoot, '.transaction-id');
  const journal = { contract: CONTRACT, revision: 0, transactionId, productId: options.productId, state: 'STAGING', stage: stageRelative, stagingIdentity: null, publications: [], createdParents: [] };

  const hooks = options.testMode === true ? options.testHooks || {} : {};
  const persist = () => atomicPersistJournal(root, journalPath, journal);

  async function ensureParent(relativeDirectory) {
    const target = safeTarget(root, relativeDirectory);
    if (await exists(target)) return;
    const record = { path: relativeDirectory, state: 'PLANNED', identity: null };
    journal.createdParents.push(record);
    await persist();
    await mkdir(target);
    record.identity = filesystemIdentity(await stat(target));
    record.state = 'CREATED';
    await persist();
  }

  async function planAndPublish(stageRelativePath, destinationRelativePath, kind) {
    const staged = safeTarget(stageRoot, stageRelativePath);
    const destination = safeTarget(root, destinationRelativePath);
    if (await exists(destination)) throw new Error(`AUTH_SETUP_CONCURRENT_DESTINATION:${destinationRelativePath}`);
    const stagedEntry = await lstat(staged);
    const publication = { path: destinationRelativePath, stagePath: stageRelativePath, kind, digest: await digest(staged, kind), expectedIdentity: filesystemIdentity(stagedEntry), publishedIdentity: null, state: 'PLANNED' };
    journal.publications.push(publication);
    await persist();
    await rename(staged, destination);
    publication.publishedIdentity = filesystemIdentity(await stat(destination));
    if (!sameIdentity(publication.expectedIdentity, publication.publishedIdentity)) throw new Error(`AUTH_SETUP_PUBLICATION_IDENTITY_CHANGED:${destinationRelativePath}`);
    await hooks.afterPublication?.({ root, stageRoot, journal, publication, destination });
    const abruptPoint = destinationRelativePath === '.auth-runtime/auth-system' ? 'after-runtime-publication'
      : destinationRelativePath === '.auth-kit' ? 'after-lifecycle-publication' : 'after-workflow-publication';
    abruptAt(abruptPoint);
    publication.state = 'PUBLISHED';
    await persist();
  }

  try {
    await mkdir(stageRoot, { recursive: false });
    journal.stagingIdentity = filesystemIdentity(await stat(stageRoot));
    await writeFile(markerPath, `${transactionId}\n`, { flag: 'wx' });
    await persist();
    await installProductAuthRuntime(stageRoot, { sourceRoot: options.sourceRoot, productId: options.productId, config: options.config, authorized: true });
    await installProductBundle(stageRoot, { authorized: true, productId: options.productId, adapterSource: options.adapterSource, gateSource: options.gateSource, inputs: options.inputs, profile: options.profile });
    await writeExclusive(path.join(stageRoot, '.auth-kit/auth.config.json'), options.authConfig);
    exceptionAt('auth-config-write');
    await writeExclusive(path.join(stageRoot, '.auth-kit/SYSTEM.md'), options.systemInstructions);
    exceptionAt('system-write');
    await writeExclusive(path.join(stageRoot, '.auth-kit/reports/latest.md'), options.report);
    exceptionAt('report-write');
    exceptionAt('before-runtime-publication');

    journal.state = 'PUBLISHING';
    await persist();
    await ensureParent('.auth-runtime');
    await planAndPublish('.auth-runtime/auth-system', '.auth-runtime/auth-system', 'tree');
    exceptionAt('after-runtime-publication');
    await planAndPublish('.auth-kit', '.auth-kit', 'tree');
    exceptionAt('during-lifecycle-bundle-publication');
    await ensureParent('.github');
    await ensureParent('.github/workflows');
    await planAndPublish('.github/workflows/auth-product-contract.yml', '.github/workflows/auth-product-contract.yml', 'file');
    exceptionAt('workflow-publication');
    journal.state = 'COMPLETING';
    await persist();
    exceptionAt('final-completion');

    await hooks.beforeStagingCleanup?.({ root, stageRoot, markerPath, journal });
    await cleanupStaging(root, journal);
    journal.state = 'COMPLETE';
    await persist();
    abruptAt('after-complete-journal');
    await cleanupJournalTemps(root, transactionId);
    const refreshed = await readValidatedJournal(root, journalRelative);
    await removeValidatedJournal(root, refreshed.journalPath, refreshed.journalIdentity, refreshed.journalDigest, transactionId);
    return { transactionId, publications: journal.publications.map(({ path: publishedPath }) => publishedPath) };
  } catch (error) {
    try {
      const loaded = await readValidatedJournal(root, journalRelative);
      await verifiedRollback(root, loaded);
    } catch (rollbackError) {
      throw new AggregateError([error, rollbackError], 'AUTH_SETUP_TRANSACTION_ROLLBACK_FAILED');
    }
    throw error;
  }
}

export const setupTransactionResiduePrefixes = [STAGING_PREFIX, JOURNAL_PREFIX, QUARANTINE_PREFIX];
