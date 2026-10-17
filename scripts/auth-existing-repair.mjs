import fs from 'node:fs/promises';
import path from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';
import { CAPABILITIES } from './auth-capability-catalog.mjs';

const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const fail = code => { throw Object.assign(new Error(code), { code }); };
const sha = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);

// Reviewed host code supplies this factory; manifests never acquire an ambient shell.
export async function createExistingRepair({ root, spec, adapter }) {
  spec = structuredClone(spec); adapter = structuredClone(adapter);
  const capability = CAPABILITIES.find(item => item.id === spec?.capabilityId);
  if (spec?.schemaVersion !== 1 || spec.productId !== adapter?.productId || spec.revision !== adapter?.revision ||
      !capability || !Array.isArray(spec.checks) || !spec.checks.length || new Set(spec.checks).size !== spec.checks.length ||
      spec.checks.some(id => !capability.checks.includes(id)) || !sha(spec.beforeSha256) || !sha(spec.afterSha256) ||
      typeof spec.replacement !== 'string' || hash(spec.replacement) !== spec.afterSha256 ||
      !Array.isArray(spec.evidenceFiles) || !spec.evidenceFiles.length || spec.evidenceFiles.some(item => !sha(item.sha256))) fail('INVALID_REPAIR_SPEC');
  const command = spec.command;
  if (!command || !path.isAbsolute(command.executable || '') || !Array.isArray(command.args) || command.args.some(arg => typeof arg !== 'string') ||
      !Number.isInteger(command.timeoutMs) || command.timeoutMs < 1 || command.timeoutMs > 120000 ||
      !Number.isInteger(command.maxOutputBytes) || command.maxOutputBytes < 1 || command.maxOutputBytes > 4194304) fail('INVALID_REPAIR_COMMAND');
  const base = await fs.realpath(root);
  async function safeFile(relative) {
    if (typeof relative !== 'string' || !relative || path.isAbsolute(relative) || relative.includes('\\') || relative.split('/').some(part => !part || part === '.' || part === '..' || part === '.git')) fail('UNSAFE_REPAIR_PATH');
    let current = base;
    const parts = relative.split('/');
    for (const [index, part] of parts.entries()) {
      current = path.join(current, part);
      const st = await fs.lstat(current);
      if (st.isSymbolicLink() || (index < parts.length - 1 ? !st.isDirectory() : !st.isFile())) fail('UNSAFE_REPAIR_PATH');
    }
    if (await fs.realpath(current) !== current) fail('UNSAFE_REPAIR_PATH');
    return current;
  }
  async function evidence() {
    for (const item of spec.evidenceFiles) {
      if (item.path === spec.file || hash(await fs.readFile(await safeFile(item.path))) !== item.sha256) fail('REPAIR_EVIDENCE_DRIFT');
    }
  }
  async function run() {
    await evidence();
    return new Promise(resolve => {
      const env = { ...process.env }; delete env.NODE_TEST_CONTEXT;
      const child = spawn(command.executable, command.args, { cwd: base, env, shell: false, stdio: ['ignore', 'pipe', 'pipe'] });
      let size = 0, reason, timer;
      const digest = createHash('sha256');
      const stop = code => { reason ||= code; child.kill('SIGKILL'); };
      for (const stream of [child.stdout, child.stderr]) stream.on('data', data => {
        size += data.length;
        if (size > command.maxOutputBytes) stop('BEHAVIOR_OUTPUT_LIMIT'); else digest.update(data);
      });
      timer = setTimeout(() => stop('BEHAVIOR_TIMEOUT'), command.timeoutMs);
      child.on('error', () => { reason ||= 'BEHAVIOR_EXECUTION_FAILED'; });
      child.on('close', code => { clearTimeout(timer); resolve({ passed: code === 0 && !reason, exitCode: code, reason: reason || (code === 0 ? 'PASS' : 'BEHAVIOR_FAILED'), outputSha256: digest.digest('hex') }); });
    });
  }
  const revision = bytes => hash(JSON.stringify({ previousRevision: spec.revision, file: spec.file, sha256: hash(bytes), evidenceFiles: spec.evidenceFiles }));
  let lastRunId, rollback, receipt;
  const handler = async context => {
    if (context.productId !== spec.productId || context.revision !== spec.revision || context.capabilityId !== spec.capabilityId || !context.runId) fail('REPAIR_SCOPE_MISMATCH');
    await evidence();
    const target = await safeFile(spec.file), previous = await fs.readFile(target), currentHash = hash(previous);
    if (![spec.beforeSha256, spec.afterSha256].includes(currentHash)) fail('REPAIR_SOURCE_DRIFT');
    const mode = (await fs.stat(target)).mode;
    const replace = async bytes => {
      const temporary = `${target}.auth-repair-${randomUUID()}`;
      try { await fs.writeFile(temporary, bytes, { flag: 'wx', mode }); await fs.rename(temporary, target); }
      finally { await fs.rm(temporary, { force: true }); }
    };
    let changed = false;
    try {
      if (currentHash !== spec.afterSha256) {
        await evidence();
        if (hash(await fs.readFile(await safeFile(spec.file))) !== currentHash) fail('REPAIR_SOURCE_DRIFT');
        await replace(spec.replacement); changed = true;
      }
      const result = await run();
      if (!result.passed) fail(result.reason);
      if (hash(await fs.readFile(await safeFile(spec.file))) !== spec.afterSha256) fail('REPAIR_SOURCE_DRIFT');
      lastRunId = context.runId;
      rollback = changed ? async () => { if (hash(await fs.readFile(await safeFile(spec.file))) !== spec.afterSha256) fail('ROLLBACK_SOURCE_DRIFT'); await replace(previous); } : undefined;
      receipt = { changedFiles: changed ? [spec.file] : [], checks: [...spec.checks], behavior: result, rolledBack: false };
      return { revision: revision(Buffer.from(spec.replacement)), changed, behavior: result };
    } catch (error) {
      if (changed) {
        if (hash(await fs.readFile(await safeFile(spec.file))) !== spec.afterSha256) fail('ROLLBACK_SOURCE_DRIFT');
        await replace(previous);
      }
      throw error;
    }
  };
  const observe = async challenge => {
    let result;
    try { result = await run(); }
    catch (error) { if (rollback) { await rollback(); rollback = undefined; } throw error; }
    if (!result.passed && rollback) { await rollback(); rollback = undefined; receipt = { ...receipt, changedFiles: [], behavior: result, rolledBack: true }; }
    const bytes = await fs.readFile(await safeFile(spec.file));
    if (lastRunId === challenge.runId && !receipt?.rolledBack && hash(bytes) !== spec.afterSha256) {
      receipt = { ...receipt, behavior: { ...result, passed: false, reason: 'ROLLBACK_SOURCE_DRIFT' } };
      fail('ROLLBACK_SOURCE_DRIFT');
    }
    const observed = structuredClone(adapter);
    observed.revision = hash(bytes) === spec.afterSha256 ? revision(bytes) : adapter.revision;
    const entry = observed.capabilities[spec.capabilityId];
    if (!entry || entry.applicability !== 'TRUE') fail('REPAIR_APPLICABILITY_REQUIRED');
    entry.checks = { ...entry.checks, ...Object.fromEntries(spec.checks.map(check => [check, result.passed])) };
    entry.evidence = [...(entry.evidence || []), `reviewed-behavior:${result.outputSha256}`];
    observed.postRepairProof = { runId: lastRunId === challenge.runId ? challenge.runId : undefined, capabilityId: spec.capabilityId,
      revision: observed.revision, observedAt: Date.now(), checks: result.passed ? [...spec.checks] : [] };
    return observed;
  };
  return { handlers: new Map([[spec.capabilityId, handler]]), observe, run, getResult: () => structuredClone(receipt || { changedFiles: [], checks: [...spec.checks], behavior: null }) };
}
