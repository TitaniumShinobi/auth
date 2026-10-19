import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { spawn } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { CAPABILITIES } from './auth-capability-catalog.mjs';
import { digest } from './auth-conformance-binding.mjs';

export const LANES = Object.freeze(['build', 'regression', 'behavioral', 'security', 'recovery', 'integration', 'acceptance']);
const issuedReports = new WeakMap();
export const verifiedLane = (report, expected = {}) => {
  const issued = issuedReports.get(report);
  return !!issued && issued.result === 'VERIFIED' && issued.digest === digest(report) &&
    Object.entries(expected).every(([key, value]) => report[key] === value);
};
const fail = code => { throw new Error(code); };
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const nonempty = x => typeof x === 'string' && x.trim().length > 0;
export function validateLaneSpec(input, binding) {
  const spec = structuredClone(input);
  if (spec?.schema !== 'life.auth.verification-lane/1' || !nonempty(spec.requestedOutcome) ||
      spec.productId !== binding.productId || spec.revision !== binding.revision ||
      !Array.isArray(spec.authorizedPaths) || !spec.authorizedPaths.length ||
      !Array.isArray(spec.inputs) || !spec.inputs.length || !Array.isArray(spec.lanes) || spec.lanes.length !== LANES.length) fail('LANE_BINDING_INVALID');
  if (!['isolated', 'live'].includes(spec.evidenceScope) || !spec.lanes.some(x => x.required)) fail('LANE_SCOPE_REQUIRED');
  const knownChecks = new Set(CAPABILITIES.flatMap(c => c.checks.map(check => `${c.id}/${check}`)));
  const seen = new Set();
  for (const lane of spec.lanes) {
    if (!LANES.includes(lane.id) || seen.has(lane.id) || typeof lane.required !== 'boolean') fail('LANE_COVERAGE_INVALID');
    seen.add(lane.id);
    if (!lane.required && !nonempty(lane.exclusionReason)) fail('LANE_EXCLUSION_REQUIRED');
    if (!Array.isArray(lane.checks) || (lane.required && !lane.checks.length) || lane.checks.some(x => !knownChecks.has(x))) fail('LANE_CHECK_MAPPING_REQUIRED');
    if (lane.command) validateCommand(lane.command);
  }
  const covered = new Set(spec.lanes.filter(x => x.required).flatMap(x => x.checks));
  if ((binding.requiredChecks || []).some(x => !covered.has(x))) fail('LANE_CHECK_COVERAGE_INCOMPLETE');
  validateCommand(spec.normalBuild);
  if (!nonempty(spec.normalBuildGate) || !spec.inputs.some(x => x.path === spec.normalBuildGate)) fail('NORMAL_BUILD_GATE_PIN_REQUIRED');
  for (const item of spec.inputs) if (!nonempty(item.path) || !/^[a-f0-9]{64}$/.test(item.sha256)) fail('LANE_INPUT_INVALID');
  for (const p of [...spec.authorizedPaths, ...spec.inputs.map(x => x.path)]) safeRelative(p);
  return spec;
}
function safeRelative(p) {
  if (!nonempty(p) || path.isAbsolute(p) || p.includes('\\') || p.split('/').some(x => !x || ['.', '..', '.git'].includes(x))) fail('LANE_PATH_INVALID');
}
function validateCommand(c) {
  if (!c || !Array.isArray(c.argv) || !c.argv.length || c.argv.some(x => !nonempty(x) || x.includes('\0')) ||
      !Number.isInteger(c.timeoutMs) || c.timeoutMs < 1 || c.timeoutMs > 600000 ||
      !Number.isInteger(c.maxOutputBytes) || c.maxOutputBytes < 1 || c.maxOutputBytes > 4194304) fail('LANE_COMMAND_INVALID');
}
async function candidate(root, paths) {
  const entries = [];
  for (const relative of paths) {
    let p = root;
    try {
      for (const part of relative.split('/')) { p = path.join(p, part); if ((await fs.lstat(p)).isSymbolicLink()) fail('LANE_INPUT_UNSAFE'); }
      if (!(await fs.stat(p)).isFile()) fail('LANE_INPUT_UNSAFE');
      entries.push([relative, sha(await fs.readFile(p))]);
    } catch (e) { if (e.code === 'ENOENT') entries.push([relative, null]); else throw e; }
  }
  return digest(entries.sort((a,b)=>a[0].localeCompare(b[0])));
}
async function checkInputs(root, inputs) {
  for (const item of inputs) {
    let p = root;
    for (const part of item.path.split('/')) { p = path.join(p, part); if ((await fs.lstat(p)).isSymbolicLink()) fail('LANE_INPUT_UNSAFE'); }
    if (!(await fs.stat(p)).isFile() || sha(await fs.readFile(p)) !== item.sha256) fail('LANE_INPUT_DRIFT');
  }
}
async function command(root, c, overrides = {}) {
  const startedAt = new Date().toISOString();
  return new Promise(resolve => {
    const env = { ...process.env }; delete env.NODE_TEST_CONTEXT; delete env.PRODUCT_TEST_WITNESS_FILE; delete env.PRODUCT_TEST_WITNESS_NONCE; Object.assign(env, overrides);
    const child = spawn(c.argv[0] === '$NODE' ? process.execPath : c.argv[0], c.argv.slice(1), { cwd: root, shell: false, detached: process.platform !== 'win32', env, stdio: ['ignore', 'pipe', 'pipe'] });
    let reason, size = 0; const output = createHash('sha256');
    const stop = value => {
      reason ||= value;
      if (child.pid && process.platform !== 'win32') { try { process.kill(-child.pid, 'SIGKILL'); } catch { child.kill('SIGKILL'); } }
      else if (child.pid) {
        const killer = spawn('taskkill', ['/PID', String(child.pid), '/T', '/F'], { shell: false, stdio: 'ignore' });
        const fallback = setTimeout(() => { killer.kill(); child.kill('SIGKILL'); }, 2000);
        const finish = () => { clearTimeout(fallback); child.kill('SIGKILL'); };
        killer.on('error', finish); killer.on('close', finish);
      }
      // Detached or unkillable descendants must not retain our output pipes indefinitely.
      child.stdout.destroy(); child.stderr.destroy();
      if (process.platform !== 'win32' || !child.pid) child.kill('SIGKILL');
    };
    const timer = setTimeout(() => stop('TIMEOUT'), c.timeoutMs);
    for (const stream of [child.stdout, child.stderr]) stream.on('data', bytes => { size += bytes.length; if (size > c.maxOutputBytes) stop('OUTPUT_LIMIT'); else output.update(bytes); });
    child.on('error', () => { reason = 'EXECUTION_UNAVAILABLE'; });
    child.on('close', code => { clearTimeout(timer); resolve({ result: reason === 'EXECUTION_UNAVAILABLE' ? 'BLOCKED' : code === 0 && !reason ? 'PASS' : 'FAIL', reason: reason || (code === 0 ? 'EXECUTED' : 'COMMAND_FAILED'), exitCode: code, startedAt, completedAt: new Date().toISOString(), outputSha256: output.digest('hex') }); });
  });
}
/** Commands are reviewed executable authority, not a sandbox. Fixtures must isolate side effects. */
export async function runVerificationLane({ root, spec, binding, changedPaths = [], executionId, progress = id => process.stderr.write(`[auth RPTVL] ${id}\n`) }) {
  const runId = randomUUID();
  if (!spec) return { schema: 'life.auth.verification-lane-result/1', runId, result: 'NOT_VERIFIED', reason: 'VERIFICATION_SPEC_REQUIRED', lanes: LANES.map(id => ({ id, result: 'NOT_VERIFIED' })) };
  spec = validateLaneSpec(spec, binding);
  if (changedPaths.some(p => !spec.authorizedPaths.includes(p))) fail('LANE_SCOPE_DRIFT');
  root = await fs.realpath(root);
  const report = { schema: 'life.auth.verification-lane-result/1', runId, issuedAt: new Date().toISOString(), ...binding, executionId, evidenceScope: spec.evidenceScope, specDigest: digest(spec), outcomeDigest: digest(spec.requestedOutcome), scopeDigest: digest(spec.authorizedPaths), lanes: [], result: 'NOT_VERIFIED' };
  await checkInputs(root, spec.inputs);
  report.candidateDigest = await candidate(root, spec.authorizedPaths);
  for (const lane of spec.lanes) {
    progress(lane.id);
    const row = { id: lane.id, required: lane.required, checks: lane.checks, command: lane.command || null, ...(!lane.required ? { result: 'NOT_VERIFIED', exclusionReason: lane.exclusionReason } : lane.command ? await command(root, lane.command) : { result: 'NOT_VERIFIED', reason: 'EXECUTOR_REQUIRED' }) };
    report.lanes.push(row);
    await checkInputs(root, spec.inputs);
    if (await candidate(root, spec.authorizedPaths) !== report.candidateDigest) fail('LANE_CANDIDATE_DRIFT');
  }
  const witnessDirectory = await fs.mkdtemp(path.join(os.tmpdir(), 'auth-build-witness-'));
  try {
    const witness = path.join(witnessDirectory, 'executed'); const nonce = randomUUID();
    report.normalBuild = { command: spec.normalBuild, ...await command(root, spec.normalBuild, { PRODUCT_TEST_WITNESS_FILE: witness, PRODUCT_TEST_WITNESS_NONCE: nonce }) };
    let observed;
    try { observed = await fs.readFile(witness, 'utf8'); } catch { /* Missing runner is not evidence of integration. */ }
    if (report.normalBuild.result === 'PASS' && observed !== nonce) report.normalBuild = { ...report.normalBuild, result: 'NOT_VERIFIED', reason: 'NORMAL_BUILD_GATE_NOT_EXECUTED' };
  } finally { await fs.rm(witnessDirectory, { recursive: true, force: true }); }
  await checkInputs(root, spec.inputs);
  if (await candidate(root, spec.authorizedPaths) !== report.candidateDigest) fail('LANE_CANDIDATE_DRIFT');
  const results = [...report.lanes.filter(x => x.required).map(x => x.result), report.normalBuild.result];
  report.result = results.includes('FAIL') ? 'FAIL' : results.includes('BLOCKED') ? 'BLOCKED' : results.every(x => x === 'PASS') ? 'VERIFIED' : 'NOT_VERIFIED';
  report.completedAt = new Date().toISOString();
  issuedReports.set(report, { result: report.result, digest: digest(report) });
  return report;
}

export async function prepareVerificationLane(options) {
  if (!options.spec) return;
  const spec = validateLaneSpec(options.spec, options.binding);
  if ((options.changedPaths || []).some(p => !spec.authorizedPaths.includes(p))) fail('LANE_SCOPE_DRIFT');
  const pending = options.pendingInputs || [];
  const existing = [];
  for (const item of spec.inputs) {
    const planned = pending.find(x => x.path === item.path);
    if (planned) { if (planned.postimageSha256 !== item.sha256) fail('LANE_INPUT_DRIFT'); }
    else existing.push(item);
  }
  await checkInputs(await fs.realpath(options.root), existing);
}
