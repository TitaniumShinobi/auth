#!/usr/bin/env node
import { createHash } from 'node:crypto';
import { lstat, readFile, realpath, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const filename = fileURLToPath(import.meta.url), repoRoot = path.resolve(path.dirname(filename), '..');
const removed = new Set(['setup', 'validate', 'runtime', 'product', 'observer', 'acceptance']);
const value = (argv, flag) => { const index = argv.indexOf(flag); return index >= 0 ? argv[index + 1] : undefined; };
const readJson = async target => JSON.parse(await readFile(target, 'utf8'));
async function reviewedJson(filename, expected) {
  if (!filename || !/^[a-f0-9]{64}$/.test(expected || '')) throw new Error('REVIEWED_SPEC_AND_DIGEST_REQUIRED');
  const bytes = await readFile(path.resolve(filename));
  if (createHash('sha256').update(bytes).digest('hex') !== expected) throw new Error('REVIEWED_SPEC_DIGEST_MISMATCH');
  return JSON.parse(bytes);
}
const booleanFlags = new Set(['--authorize', '--dry-run', '--require-history', '--release']);
const completionFlags = ['--repo', '--objective', '--adapter', '--repair-spec', '--repair-sha256', '--verification-spec', '--verification-sha256', '--authorize'];
const nativeFlags = {
  'build-plan': ['--repo', '--repair-spec', '--repair-sha256', '--script', '--plan'],
  discover: ['--repo'], assess: ['--repo'],
  plan: ['--repo', '--product', '--receipt', '--plan', '--target-revision'],
  'align-plan': ['--repo', '--product', '--receipt', '--plan', '--target-revision', '--auth-role', '--auth-runtime', '--auth-entrypoint', '--behavior-spec', '--behavior-sha256', '--dependency-spec', '--dependency-sha256'],
  apply: ['--repo', '--plan', '--authorize', '--dry-run', '--verification-spec', '--verification-sha256'],
  verify: ['--repo', '--receipt'], repair: ['--repo', '--receipt', '--authorize', '--verification-spec', '--verification-sha256'],
  migrate: ['--repo', '--receipt', '--target-revision', '--new-receipt', '--authorize', '--verification-spec', '--verification-sha256'],
  recover: ['--repo'],
};
const wizardFlags = ['--adapter', '--baseline', '--profile', '--operator', '--act-module', '--repair-spec', '--repair-sha256', '--repo', '--outcome', '--capability', '--authority-evidence', '--authority-sha256', '--authorize', '--release', '--runtime-evidence', '--runtime-digest', '--require-history', '--baseline-digest'];
const releaseFlags = new Set(['--release', '--runtime-evidence', '--runtime-digest', '--require-history', '--baseline', '--baseline-digest', '--authority-evidence', '--authority-sha256', '--profile']);

// Validate the complete invocation before imports, file reads, or supported ACT.
function validateFlags(tokens, allowed, native = false) {
  const seen = new Set();
  for (let index = 0; index < tokens.length; index += 1) {
    const flag = tokens[index];
    if (!flag.startsWith('--')) throw new Error('UNEXPECTED_POSITIONAL_ARGUMENT');
    if (!allowed.includes(flag)) {
      if (native && releaseFlags.has(flag)) throw new Error(`UNSUPPORTED_NATIVE_RELEASE_FLAG: ${flag}; use auth wizard --operator VERIFY --release`);
      throw new Error(`UNSUPPORTED_FLAG: ${flag}`);
    }
    if (seen.has(flag)) throw new Error(`DUPLICATE_FLAG: ${flag}`);
    seen.add(flag);
    if (!booleanFlags.has(flag)) {
      const argument = tokens[++index];
      if (!argument || argument.startsWith('--')) throw new Error(`FLAG_VALUE_REQUIRED: ${flag}`);
    }
  }
}

function usage(code = 0) {
  const output = [
    'Usage:',
    '  auth native <discover|assess|plan|align-plan|apply|verify|repair|migrate|recover> --repo <path> [--product <id>] [--receipt <path>] [--new-receipt <path>] [--plan <path>] [--target-revision <commit>] [--dry-run] [--authorize]',
    '  auth wizard --adapter <json> [--baseline <json>] [--profile <profile>] [--operator OBSERVE|ASSESS|DECIDE|VERIFY|ACT] [--act-module <registered.mjs>] [--repo <path>] [--outcome <text>] [--capability <id>] [--authority-evidence <json> --authority-sha256 <digest>] [--authorize] [--release --runtime-evidence <json> --runtime-digest <canonical-sha256>] [--require-history --baseline-digest <canonical-sha256>]',
    '  auth complete --repo <path> --objective <text> [--adapter <json> --verification-spec <reviewed.json> --verification-sha256 <sha256> | --adapter <json> --repair-spec <reviewed.json> --repair-sha256 <sha256> --authorize]',
    '  align-plan requires --auth-role <IDENTITY_AUTHORITY|RELYING_PARTY> --auth-entrypoint <relative-file>; mixed stacks also require --auth-runtime <node|python>.',
    'Existing repair: wizard --operator ACT --authorize --repair-spec <reviewed.json> --repair-sha256 <sha256> --repo <product> --adapter <observations.json> --capability <id>.',
    'Native verification accepts --verification-spec <reviewed.json> --verification-sha256 <sha256>; missing proof is NOT_VERIFIED.',
    'native build-plan --repo <product> --repair-spec <reviewed-template> --repair-sha256 <sha256> --script build|test --plan <output> prepares a single-file ACT specification.',
    'Behavioral alignment: native align-plan supports --behavior-spec <reviewed.json> --behavior-sha256 <sha256>.',
    'Flags are subcommand-specific. Unknown, duplicate, misplaced, or valueless flags fail before any operation.',
    'Native verification proves source integrity only. Release acceptance uses auth wizard --operator VERIFY --release.',
    '',
    'AUTH creates or aligns product-owned authentication and exits. Persistent AUTH runtimes, kits, adapters, daemons, copied packages, and source dependencies are prohibited.',
  ].join('\n');
  (code ? console.error : console.log)(output); process.exit(code);
}

async function runComplete(argv) {
  validateFlags(argv.slice(1), completionFlags);
  const root = value(argv, '--repo'), objective = value(argv, '--objective'), adapterPath = value(argv, '--adapter');
  if (!root || !objective) throw new Error('COMPLETE_REQUIRES_REPO_OBJECTIVE');
  const { completeAuthObjective, diagnosePlainLanguageObjective, verifyExistingAuthObjective } = await import('./auth-completion-harness.mjs');
  const repairPath = value(argv, '--repair-spec'), verificationPath = value(argv, '--verification-spec');
  if (repairPath && verificationPath) throw new Error('REPAIR_AND_READ_ONLY_VERIFICATION_ARE_EXCLUSIVE');
  if (!adapterPath && !repairPath && !value(argv, '--repair-sha256') && !verificationPath && !value(argv, '--verification-sha256')) {
    const result = await diagnosePlainLanguageObjective({ root, objective });
    console.log(JSON.stringify(result, null, 2));
    process.exitCode = 2;
    return;
  }
  if (!adapterPath) throw new Error('PARTIAL_REVIEWED_COMPLETION_INPUTS');
  if (verificationPath || value(argv, '--verification-sha256')) {
    if (argv.includes('--authorize')) throw new Error('ACT_AUTHORIZATION_WITHOUT_REPAIR');
    const verificationSpec = await reviewedJson(verificationPath, value(argv, '--verification-sha256'));
    const adapter = await readJson(path.resolve(adapterPath));
    const result = await verifyExistingAuthObjective({ root, objective, adapter, verificationSpec });
    console.log(JSON.stringify(result, null, 2));
    if (result.result !== 'VERIFIED') process.exitCode = 2;
    return;
  }
  const repairSpec = await reviewedJson(repairPath, value(argv, '--repair-sha256'));
  const adapter = await readJson(path.resolve(adapterPath));
  const result = await completeAuthObjective({ root, objective, adapter, repairSpec, authorized: argv.includes('--authorize') });
  console.log(JSON.stringify(result, null, 2));
  if (result.result !== 'VERIFIED') process.exitCode = 2;
}

function parseFlags(argv) {
  validateFlags(argv.slice(1), wizardFlags);
  const args = { command: argv[0], operator: 'VERIFY', authorize: false };
  for (let index = 1; index < argv.length; index += 1) {
    const token = argv[index];
    if (['--authorize','--require-history','--release'].includes(token)) { args[token.slice(2)] = true; continue; }
    if (!token.startsWith('--') || !argv[index + 1] || argv[index + 1].startsWith('--')) usage(1);
    args[token.slice(2)] = argv[++index];
  }
  return args;
}

async function loadRegisteredActModule(modulePath, repository) {
  if (!repository) throw new Error('Registered ACT requires --repo');
  const root = await realpath(path.resolve(repository)), requested = path.resolve(modulePath), resolved = await realpath(requested);
  if (resolved !== root && !resolved.startsWith(`${root}${path.sep}`)) throw new Error('ACT_MODULE_OUTSIDE_PRODUCT');
  const entry = await lstat(requested);
  if (entry.isSymbolicLink() || !entry.isFile() || path.extname(requested) !== '.mjs') throw new Error('ACT_MODULE_INVALID');
  const registered = await import(`${pathToFileURL(resolved).href}?auth-act=${Date.now()}`);
  if (!(registered.handlers instanceof Map) || typeof registered.observe !== 'function') throw new Error('ACT_MODULE_REGISTRY_INVALID');
  return registered;
}

async function runWizard(args) {
  if (!args.adapter || !['OBSERVE', 'ASSESS', 'DECIDE', 'VERIFY', 'ACT'].includes(args.operator)) throw new Error('wizard requires --adapter and a supported --operator');
  if (args.release && args.operator === 'ACT') throw new Error('RELEASE_REQUIRES_SEPARATE_VERIFY');
  if (args.operator !== 'ACT' && (args.authorize || args['act-module'] || args['repair-spec'] || args['repair-sha256'])) throw new Error('ACT_FLAGS_REQUIRE_ACT_OPERATOR');
  if (args.operator === 'ACT' && (args['runtime-evidence'] || args['runtime-digest'])) throw new Error('RUNTIME_EVIDENCE_REQUIRES_SEPARATE_VERIFY');
  const { createBlockerHandoffs } = await import('./auth-blocker-handoff.mjs');
  if (args.capability) { const { CAPABILITIES } = await import('./auth-capability-catalog.mjs'); if (!CAPABILITIES.some(item => item.id === args.capability)) throw new Error(`Unknown capability: ${args.capability}`); }
  const commandFor = operator => {
    const command = [process.execPath, filename, 'wizard', '--adapter', path.resolve(args.adapter), '--operator', operator];
    for (const [flag, transform] of [['baseline', path.resolve], ['repo', path.resolve], ['outcome', String], ['profile', String], ['capability', String], ['baseline-digest', String], ['runtime-evidence', path.resolve], ['runtime-digest', String]]) if (args[flag]) command.push(`--${flag}`, transform(args[flag]));
    if (args['authority-evidence']) command.push('--authority-evidence', path.resolve(args['authority-evidence']), '--authority-sha256', args['authority-sha256'] || '');
    for (const flag of ['require-history','release']) if (args[flag]) command.push(`--${flag}`);
    if (args.authorize && operator === 'ACT') command.push('--authorize'); return command;
  };
  let trustedAuthorityEvidence = [];
  if (args['authority-evidence'] || args['authority-sha256']) {
    if (!args['authority-evidence'] || !args['authority-sha256']) throw new Error('Authority evidence requires a separately trusted SHA-256 digest');
    const bytes = await readFile(path.resolve(args['authority-evidence'])); if (createHash('sha256').update(bytes).digest('hex') !== args['authority-sha256']) throw new Error('Authority evidence digest mismatch'); trustedAuthorityEvidence = JSON.parse(bytes);
  }
  const context = { repository: args.repo ? path.resolve(args.repo) : null, requestedOutcome: args.outcome || null, reproductionCommand: commandFor(args.operator), verificationCommand: commandFor('VERIFY'), authorization: args.authorize, capabilityId: args.capability || null, registeredCapabilities: [] };
  if (args.operator === 'ACT') {
    if (args['repair-spec'] || args['repair-sha256']) {
      if (!args.authorize) throw new Error('EXPLICIT_AUTHORIZATION_REQUIRED');
      if (!args.repo || !args.capability || args['act-module']) throw new Error('REPAIR_SPEC_CONTEXT_INVALID');
      const spec = await reviewedJson(args['repair-spec'], args['repair-sha256']);
      if (spec.capabilityId !== args.capability) throw new Error('REPAIR_CAPABILITY_MISMATCH');
      const adapter = await readJson(path.resolve(args.adapter));
      const { createExistingRepair } = await import('./auth-existing-repair.mjs');
      const registered = await createExistingRepair({ root: path.resolve(args.repo), spec, adapter });
      const { executeRepair } = await import('./auth-wizard.mjs');
      const baseline = args.baseline ? await readJson(path.resolve(args.baseline)) : undefined;
      const report = await executeRepair(adapter, { capabilityId: args.capability,
        authorization: { authorized: true, productId: adapter.productId, revision: adapter.revision, capabilityId: args.capability },
        handlers: registered.handlers, observe: registered.observe, baseline, baselineDigest: args['baseline-digest'],
        requireHistory: args['require-history'] === true, trustedAuthorityEvidence, verificationProfile: args.profile });
      report.boundedRepair = registered.getResult();
      context.registeredCapabilities = [...registered.handlers.keys()];
      report.blockerHandoffs = createBlockerHandoffs(report, context);
      console.log(JSON.stringify(report, null, 2));
      if (report.verification !== 'PASS' || report.durableCompletion !== true) process.exitCode = 2;
      return;
    }
    if (args.authorize && args['act-module']) {
      const adapter = await readJson(path.resolve(args.adapter)), baseline = args.baseline ? await readJson(path.resolve(args.baseline)) : undefined, registered = await loadRegisteredActModule(args['act-module'], args.repo);
      context.registeredCapabilities = [...registered.handlers.keys()].sort();
      if (args.capability && registered.handlers.has(args.capability)) {
        const { executeRepair } = await import('./auth-wizard.mjs');
        const report = await executeRepair(adapter, { capabilityId: args.capability, authorization: { authorized: true, productId: adapter.productId, revision: adapter.revision, capabilityId: args.capability }, handlers: registered.handlers, observe: registered.observe, baseline, baselineDigest: args['baseline-digest'], requireHistory: args['require-history'] === true, trustedAuthorityEvidence, verificationProfile: args.profile });
        report.blockerHandoffs = createBlockerHandoffs(report, context); console.log(JSON.stringify(report, null, 2)); if (report.verification !== 'PASS' || report.durableCompletion !== true) process.exitCode = 2; return;
      }
    }
    const report = { operator: 'ACT', verification: 'INDETERMINATE', state: 'BLOCKED', error: args.authorize ? 'NO_SUPPORTED_REPAIR' : 'AUTHORIZATION_REQUIRED', changedFiles: [], capabilityId: args.capability || null, lifecycle_preservation: 'NOT_ASSESSED_USE_PRODUCT_VERIFY' };
    report.blockerHandoffs = createBlockerHandoffs(report, context); console.log(JSON.stringify(report, null, 2)); process.exitCode = 2; return;
  }
  const adapter = await readJson(path.resolve(args.adapter)), baseline = args.baseline ? await readJson(path.resolve(args.baseline)) : undefined;
  const { evaluateAdapter } = await import('./auth-wizard.mjs');
  const report = evaluateAdapter(adapter, { baseline, operator: args.operator, trustedAuthorityEvidence, verificationProfile: args.profile, baselineDigest: args['baseline-digest'], requireHistory: args['require-history'] === true });
  const { runtimeAcceptance } = await import('./auth-assurance.mjs');
  report.assurance.runtime_acceptance = runtimeAcceptance(report, args['runtime-evidence'] ? await readJson(path.resolve(args['runtime-evidence'])) : undefined, args['runtime-digest']);
  const releaseResults = [report.profile_verification, report.assurance.runtime_acceptance, ...(args['require-history'] ? [report.assurance.historical_continuity] : [])];
  report.release_acceptance = releaseResults.includes('FAIL') ? 'FAIL' : releaseResults.every(result => result === 'PASS') ? 'PASS' : 'INDETERMINATE';
  if (args.release && report.release_acceptance !== 'PASS') process.exitCode = 2; report.lifecycle_preservation = report.assurance.historical_continuity; report.blockerHandoffs = createBlockerHandoffs(report, context); console.log(JSON.stringify(report, null, 2)); if (['VERIFY', 'DECIDE'].includes(args.operator) && report.profile_verification !== 'PASS') process.exitCode = 2;
}

async function runNative(argv) {
  const operation = argv[1];
  if (!Object.hasOwn(nativeFlags, operation)) throw new Error('invalid native command');
  validateFlags(argv.slice(2), nativeFlags[operation], true);
  const rootValue = value(argv, '--repo');
  if (!rootValue || !['discover', 'assess', 'plan', 'build-plan', 'align-plan', 'apply', 'verify', 'repair', 'migrate', 'recover'].includes(operation)) throw new Error('invalid native command');
  const verificationSpec = (value(argv, '--verification-spec') || value(argv, '--verification-sha256')) ? await reviewedJson(value(argv, '--verification-spec'), value(argv, '--verification-sha256')) : undefined;
  const native = await import('./auth-native-wizard.mjs'), root = path.resolve(rootValue), receipt = value(argv, '--receipt'), planPath = value(argv, '--plan'), productId = value(argv, '--product') || path.basename(root); let result;
  if (operation === 'build-plan') {
    const { planProductBuildRepair } = await import('./auth-product-test.mjs');
    const request = await reviewedJson(value(argv, '--repair-spec'), value(argv, '--repair-sha256'));
    result = await planProductBuildRepair(root, request, value(argv, '--script'));
    if (planPath) await writeFile(path.resolve(planPath), `${JSON.stringify(result, null, 2)}\n`, { flag: 'wx' });
  }
  else if (operation === 'discover') result = await native.discoverNativeTarget(root);
  else if (operation === 'assess') result = await native.assessNativeTarget(root);
  else if (operation === 'plan' || operation === 'align-plan') { result = operation === 'plan' ? await native.planNativeTarget(root, { sourceRoot: repoRoot, sourceRevision: value(argv, '--target-revision') || 'HEAD', productId, receiptPath: receipt }) : await native.planNativeAlignment(root, { sourceRoot: repoRoot, sourceRevision: value(argv, '--target-revision') || 'HEAD', productId, receiptPath: receipt, authenticationRole: value(argv, '--auth-role'), authenticationRuntime: value(argv, '--auth-runtime'), authenticationEntrypoint: value(argv, '--auth-entrypoint'), dependencyTest: (value(argv, '--dependency-spec') || value(argv, '--dependency-sha256')) ? await reviewedJson(value(argv, '--dependency-spec'), value(argv, '--dependency-sha256')) : undefined, behavioralTest: (value(argv, '--behavior-spec') || value(argv, '--behavior-sha256')) ? await reviewedJson(value(argv, '--behavior-spec'), value(argv, '--behavior-sha256')) : undefined }); if (planPath) await writeFile(path.resolve(planPath), `${JSON.stringify(result, null, 2)}\n`, { flag: 'wx' }); }
  else if (operation === 'apply') { if (!planPath) throw new Error('native apply requires --plan'); result = await native.applyNativePlan(await readJson(path.resolve(planPath)), { sourceRoot: repoRoot, verificationSpec, authorized: argv.includes('--authorize'), dryRun: argv.includes('--dry-run') }); }
  else if (operation === 'verify') { if (!receipt) throw new Error('native verify requires --receipt'); result = await native.verifyNativeReceipt(root, path.resolve(receipt)); }
  else if (operation === 'repair') { if (!receipt) throw new Error('native repair requires --receipt'); result = await native.repairNativeTarget(root, path.resolve(receipt), { sourceRoot: repoRoot, verificationSpec, authorized: argv.includes('--authorize') }); }
  else if (operation === 'migrate') { const targetRevision = value(argv, '--target-revision'), newReceipt = value(argv, '--new-receipt'); if (!receipt || !targetRevision || !newReceipt) throw new Error('native migrate requires --receipt --target-revision --new-receipt'); result = await native.migrateNativeTarget(root, path.resolve(receipt), { sourceRoot: repoRoot, verificationSpec, targetRevision, newReceiptPath: path.resolve(newReceipt), authorized: argv.includes('--authorize') }); }
  else result = await native.recoverNativeTransactions(root);
  console.log(JSON.stringify(result, null, 2)); if (result.verification === 'FAIL' || (result.rptvl && result.rptvl.result !== 'VERIFIED')) process.exitCode = 2;
}

try {
  const argv = process.argv.slice(2); if (!argv.length || ['-h', '--help'].includes(argv[0])) usage(0); if (removed.has(argv[0])) throw new Error('LEGACY_PERSISTENT_AUTH_COMMAND_REMOVED_USE_NATIVE_WORKFLOW');
  if (argv[0] === 'native') await runNative(argv);
  else if (argv[0] === 'wizard') await runWizard(parseFlags(argv));
  else if (argv[0] === 'complete') await runComplete(argv);
  else throw new Error('UNKNOWN_AUTH_COMMAND');
} catch (error) { console.error(error instanceof Error ? error.message : String(error)); process.exit(1); }
