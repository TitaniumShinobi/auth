#!/usr/bin/env node
import { copyFile, mkdir, readFile, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const repoRoot = path.resolve(path.dirname(__filename), '..');

const LOCAL_PORTS = {
  auth: [{ port: 1111, role: 'Auth API listener' }],
  chatty: [
    { port: 5173, role: 'Frontend' },
    { port: 5050, role: 'Backend' },
  ],
  code: [{ port: 2048, role: 'App/runtime' }],
  vvault: [
    { port: 7784, role: 'Frontend' },
    { port: 8000, role: 'Backend' },
  ],
  cleanhouse: [{ port: 3333, role: 'App/runtime' }],
  mirage: [{ port: 8888, role: 'App/runtime' }],
  quantum: [{ port: 8173, role: 'App/runtime' }],
  ollama: [{ port: 11434, role: 'Local model dependency' }],
};

const TARGET_APPS = new Set(['chatty', 'cleanhouse', 'code', 'vvault']);

function usage(exitCode = 0) {
  const output = [
    'Usage:',
    '  auth acceptance --adapter <json> (read-only configured-runtime and live-acceptance report)',
    '  auth conformance --adapter <json> --app <id> --client-id <registered client> --out <new json> [--authority http://localhost:1111]',
    '  auth product <verify|maintain|establish|advance|amend> [approval.json] --repo <path>',
    '  auth setup --config <product-config.json> --inputs <input-paths.json> --adapter <observer.mjs> --repo <path> --app <id> --authorize',
    '  auth setup --repo <path> --app <chatty|cleanhouse|code|vvault> [--dry-run | --authorize]',
    '  auth validate --repo <path> --app <chatty|cleanhouse|code|vvault>',
    '  auth wizard --adapter <json> [--baseline <json>] [--profile RELYING_PARTY_CLIENT|ASSERTION_INTEGRATION|AUTHORITY_RUNTIME|FULL_AUTHORITY_CONFORMANCE] [--operator OBSERVE|ASSESS|DECIDE|VERIFY|ACT] [--authorize]',
    '              [--repo <path>] [--outcome <description>] [--capability <id>] [--authority-evidence <json> --authority-sha256 <trusted digest>]',
    '',
    'Rules:',
    '  setup copies source-kit files into the target repo and writes a report.',
    '  validate is read-only and reports missing setup evidence.',
    '  wizard defaults to VERIFY and evaluates any product adapter without modifying it.',
    '  setup writes require explicit --authorize; wizard ACT has no supported repair.',
    '  secret values are never printed or read from .env files.',
  ].join('\n');
  (exitCode === 0 ? console.log : console.error)(output);
  process.exit(exitCode);
}

function parseArgs(argv) {
  const [command, ...rest] = argv;
  if (!command || command === '-h' || command === '--help') usage(0);
  const args = { command, dryRun: false, authorize: false, operator: 'VERIFY' };
  for (let index = 0; index < rest.length; index += 1) {
    const token = rest[index];
    if (token === '--dry-run') {
      args.dryRun = true;
      continue;
    }
    if (token === '--authorize') {
      args.authorize = true;
      continue;
    }
    if (['--repo', '--app', '--adapter', '--baseline', '--operator', '--outcome', '--capability', '--authority-evidence', '--authority-sha256', '--authority', '--client-id', '--out', '--profile', '--config', '--inputs', '--gate'].includes(token)) {
      const value = rest[index + 1];
      if (!value || value.startsWith('--')) usage(1);
      args[token.slice(2)] = value;
      index += 1;
      continue;
    }
    usage(1);
  }
  if (!['setup', 'validate', 'wizard', 'conformance', 'acceptance'].includes(command)) usage(1);
  if (command === 'acceptance') {
    if (!args.adapter) throw new Error('acceptance requires --adapter <json>');
    return args;
  }
  if (command === 'conformance') {
    if (!args.adapter || !args.app || !args['client-id'] || !args.out) throw new Error('conformance requires --adapter --app --client-id --out');
    return args;
  }
  if (command === 'wizard') {
    if (!args.adapter) throw new Error('wizard requires --adapter <json>');
    if (!['OBSERVE', 'ASSESS', 'DECIDE', 'VERIFY', 'ACT'].includes(args.operator)) {
      throw new Error('Unsupported wizard operator. Expected OBSERVE, ASSESS, DECIDE, VERIFY, or ACT.');
    }
    return args;
  }
  if (!args.repo || !args.app) usage(1);
  args.app = String(args.app).trim().toLowerCase();
  if (!TARGET_APPS.has(args.app) && !args.config) {
    throw new Error(`Unsupported app "${args.app}". Expected one of: ${[...TARGET_APPS].join(', ')}`);
  }
  return args;
}

async function pathExists(targetPath) {
  try {
    await stat(targetPath);
    return true;
  } catch (error) {
    if (error && error.code === 'ENOENT') return false;
    throw error;
  }
}

async function readJson(filePath) {
  return JSON.parse(await readFile(filePath, 'utf8'));
}

function envPrefix(config) {
  return String(config.oauth?.envPrefix || config.app?.id || '').trim().toUpperCase();
}

function enabledProviders(config) {
  return (config.providers || []).filter((provider) => provider.enabled !== false);
}

function envVarNames(config) {
  const prefix = envPrefix(config);
  const names = [
    'AUTH_SESSION_SECRET',
    'AUTH_ACCESS_TOKEN_SECRET',
    'AUTH_REFRESH_TOKEN_SECRET',
    'AUTH_REFRESH_TOKEN_HASH_SECRET',
    'AUTH_COOKIE_NAME',
    'AUTH_REFRESH_COOKIE_NAME',
  ];
  for (const provider of enabledProviders(config)) {
    const providerName = String(provider.provider).toUpperCase();
    names.push(`${prefix}_${providerName}_CLIENT_ID`);
    names.push(`${prefix}_${providerName}_CLIENT_SECRET`);
    names.push(`${prefix}_${providerName}_CALLBACK_URL`);
    names.push(`${prefix}_PUBLIC_CALLBACK_BASE`);
    names.push(`${prefix}_${providerName}_CALLBACK_PATH`);
  }
  if (config.turnstile?.enabled || config.turnstile?.required) {
    names.push('TURNSTILE_SECRET_KEY');
    names.push('TURNSTILE_SITE_KEY');
  }
  return [...new Set(names)];
}

function callbackConflictEnvVarNames(config) {
  const prefix = envPrefix(config);
  const names = [
    'PUBLIC_CALLBACK_BASE',
    'CALLBACK_PATH',
  ];
  for (const provider of enabledProviders(config)) {
    const providerName = String(provider.provider).toUpperCase();
    names.push(`${providerName}_CALLBACK_URL`);
    names.push(`${providerName}_CALLBACK`);
    names.push(`${providerName}_CALLBACK_PATH`);
    if (prefix) {
      names.push(`${prefix}_${providerName}_CALLBACK_URL`);
      names.push(`${prefix}_${providerName}_CALLBACK`);
      names.push(`${prefix}_BACKEND_CALLBACK_URL`);
      names.push(`${prefix}_${providerName}_BACKEND_CALLBACK_URL`);
    }
  }
  return [...new Set(names)];
}

function callbackUrls(config) {
  const primaryOrigin = config.allowedOrigins?.[0] || '';
  return enabledProviders(config).map((provider) => ({
    provider: provider.provider,
    url: primaryOrigin ? `${primaryOrigin}/api/auth/${provider.provider}/callback` : '',
  }));
}

function trimTrailingSlash(value) {
  return String(value || '').replace(/\/+$/, '');
}

function normalizeBaseUrl(value) {
  return String(value || '').replace(/\/+$/, '');
}

function normalizeCallbackPath(value) {
  if (!value) return '';
  return value.startsWith('/') ? value : `/${value}`;
}

function adaptCallbackPathForProvider(callbackPath, provider) {
  return callbackPath.replace(/\/api\/auth\/[^/]+\/callback(?=$|[?#])/i, `/api/auth/${provider}/callback`);
}

function callbackFromBase(provider, base, callbackPath = '') {
  const rawPath = callbackPath || `/api/auth/${provider}/callback`;
  return `${normalizeBaseUrl(base)}${adaptCallbackPathForProvider(normalizeCallbackPath(rawPath), provider)}`;
}

function firstEnvEntry(keys) {
  for (const key of keys) {
    const value = process.env[key];
    if (typeof value === 'string' && value.trim()) {
      return { key, value: value.trim() };
    }
  }
  return null;
}

function firstEnvValue(keys) {
  return firstEnvEntry(keys)?.value || '';
}

function allowedCallbackUrl(url, config) {
  if (!url) return false;
  const allowedOrigins = new Set((config.allowedOrigins || []).map(trimTrailingSlash));
  if (allowedOrigins.size === 0) return true;
  try {
    return allowedOrigins.has(trimTrailingSlash(new URL(url).origin));
  } catch {
    return false;
  }
}

function resolveOAuthStartCallback({ provider, config, requestOrigin }) {
  const prefix = envPrefix(config);
  const providerName = String(provider).toUpperCase();
  const conflicts = [];
  const allowedOrigins = new Set((config.allowedOrigins || []).map(trimTrailingSlash));

  const appCallback = firstEnvEntry(prefix ? [
    `${prefix}_${providerName}_CALLBACK_URL`,
    `${prefix}_${providerName}_CALLBACK`,
  ] : []);
  if (appCallback) {
    if (allowedCallbackUrl(appCallback.value, config)) {
      return { callbackUrl: appCallback.value, source: 'app_specific_callback_env', envKey: appCallback.key, conflicts };
    }
    conflicts.push(`${appCallback.key} does not match an allowed app origin`);
  }

  const appBase = firstEnvEntry(prefix ? [`${prefix}_PUBLIC_CALLBACK_BASE`] : []);
  if (appBase) {
    const appPath = firstEnvValue(prefix ? [
      `${prefix}_${providerName}_CALLBACK_PATH`,
      `${prefix}_CALLBACK_PATH`,
    ] : []);
    const callbackUrl = callbackFromBase(provider, appBase.value, appPath);
    if (allowedCallbackUrl(callbackUrl, config)) {
      return { callbackUrl, source: 'app_specific_public_callback_base', envKey: appBase.key, conflicts };
    }
    conflicts.push(`${appBase.key} builds a callback outside allowed app origins`);
  }

  const normalizedRequestOrigin = trimTrailingSlash(requestOrigin);
  if (normalizedRequestOrigin && allowedOrigins.has(normalizedRequestOrigin)) {
    return {
      callbackUrl: `${normalizedRequestOrigin}/api/auth/${provider}/callback`,
      source: 'request_origin',
      conflicts,
    };
  }

  const genericCallback = firstEnvEntry([
    `${providerName}_CALLBACK_URL`,
    `${providerName}_CALLBACK`,
  ]);
  if (genericCallback) {
    if (allowedCallbackUrl(genericCallback.value, config)) {
      return { callbackUrl: genericCallback.value, source: 'generic_callback_env', envKey: genericCallback.key, conflicts };
    }
    conflicts.push(`${genericCallback.key} does not match an allowed app origin`);
  }

  const genericBase = firstEnvEntry(['PUBLIC_CALLBACK_BASE']);
  if (genericBase) {
    const callbackUrl = callbackFromBase(provider, genericBase.value, firstEnvValue([
      `${providerName}_CALLBACK_PATH`,
      'CALLBACK_PATH',
    ]));
    if (allowedCallbackUrl(callbackUrl, config)) {
      return { callbackUrl, source: 'generic_public_callback_base', envKey: genericBase.key, conflicts };
    }
    conflicts.push(`${genericBase.key} builds a callback outside allowed app origins`);
  }

  const backendCallback = firstEnvEntry(prefix ? [
    `${prefix}_BACKEND_CALLBACK_URL`,
    `${prefix}_${providerName}_BACKEND_CALLBACK_URL`,
  ] : []);
  if (backendCallback) {
    if (allowedCallbackUrl(backendCallback.value, config)) {
      return { callbackUrl: backendCallback.value, source: 'backend_callback_env', envKey: backendCallback.key, conflicts };
    }
    conflicts.push(`${backendCallback.key} is backend/internal and does not match an allowed app origin`);
  }

  return { callbackUrl: '', source: 'unconfigured', conflicts };
}

function oauthStartConsistency(config) {
  const expected = callbackUrls(config);
  return expected.map((entry) => {
    const runtime = resolveOAuthStartCallback({
      provider: entry.provider,
      config,
      requestOrigin: config.allowedOrigins?.[0] || '',
    });
    return {
      provider: entry.provider,
      expectedCallbackUrl: entry.url,
      runtimeCallbackUrl: runtime.callbackUrl,
      source: runtime.source,
      envKey: runtime.envKey,
      conflicts: runtime.conflicts,
      passed: entry.url === runtime.callbackUrl,
    };
  });
}

function portsFor(app) {
  return {
    auth: LOCAL_PORTS.auth,
    app: LOCAL_PORTS[app] || [],
    dependencies: app === 'chatty' || app === 'vvault'
      ? { ollama: LOCAL_PORTS.ollama }
      : {},
  };
}

function setupReport({ app, repoPath, config, changedFiles, blockers = [] }) {
  const ports = portsFor(app);
  const providerNames = enabledProviders(config).map((provider) => provider.provider);
  const consistency = oauthStartConsistency(config);
  return [
    `# Auth Setup Report: ${config.app?.name || app}`,
    '',
    `Generated: ${new Date().toISOString()}`,
    `Target repo: ${repoPath}`,
    `App id: ${config.app?.id || app}`,
    '',
    '## Doctrine',
    '',
    '- This repo owns auth after setup.',
    '- The shared `auth/` checkout is a source kit and setup authority, not a forever runtime hub.',
    '- One configured provider is enough.',
    '- Secret values were not read or printed.',
    '',
    '## Files Changed',
    '',
    ...changedFiles.map((file) => `- ${file}`),
    ...(changedFiles.length ? [] : ['- none']),
    '',
    '## Ports Recorded',
    '',
    ...ports.auth.map((entry) => `- Auth ${entry.port}: ${entry.role}`),
    ...ports.app.map((entry) => `- ${config.app?.name || app} ${entry.port}: ${entry.role}`),
    ...Object.entries(ports.dependencies).flatMap(([name, entries]) => (
      entries.map((entry) => `- ${name} ${entry.port}: ${entry.role}`)
    )),
    '',
    '## Env Var Names Needed',
    '',
    'At least one complete enabled-provider credential set is enough; do not require every listed provider.',
    '',
    ...envVarNames(config).map((name) => `- ${name}`),
    '',
    '## Env Var Names That Must Not Conflict',
    '',
    'These legacy/backend callback values must be unset or point at the same frontend-owned callback origin. They must not silently override the setup callback.',
    '',
    ...callbackConflictEnvVarNames(config).map((name) => `- ${name}`),
    '',
    '## OAuth Callback URLs',
    '',
    ...callbackUrls(config).map((entry) => `- ${entry.provider}: ${entry.url}`),
    ...(providerNames.length ? [] : ['- none']),
    '',
    '## OAuth Start Consistency Check',
    '',
    ...consistency.map((entry) => (
      `- ${entry.passed ? 'PASS' : 'FAIL'} ${entry.provider}: setup=${entry.expectedCallbackUrl || '(none)'} runtime=${entry.runtimeCallbackUrl || '(none)'} source=${entry.source}${entry.envKey ? ` env=${entry.envKey}` : ''}`
    )),
    ...consistency.flatMap((entry) => entry.conflicts.map((conflict) => `- WARN ${entry.provider}: ${conflict}`)),
    '',
    '## Proof Commands',
    '',
    '- Install dependencies in the target repo.',
    '- Start the target repo auth/runtime process using its local instructions.',
    '- `curl -i <target-origin>/api/auth/config`',
    '- `curl -i <target-origin>/api/me`',
    '- Complete one credential or OAuth login flow.',
    '- `curl -i -X POST <target-origin>/api/auth/refresh` with issued cookies.',
    '- `curl -i -X POST <target-origin>/api/auth/logout` with issued cookies.',
    '',
    '## Blockers',
    '',
    ...(blockers.length ? blockers.map((blocker) => `- ${blocker}`) : ['- none recorded by setup']),
    '',
  ].join('\n');
}

async function loadAppConfig(app) {
  const configPath = path.join(repoRoot, 'config', `${app}.json`);
  const config = await readJson(configPath);
  return { configPath, config };
}

function setupConfigPayload({ app, config }) {
  return `${JSON.stringify({
    source: '@quantum/auth',
    mode: 'one-time-setup',
    app,
    generatedAt: new Date().toISOString(),
    config,
    localPorts: portsFor(app),
    envVarNames: envVarNames(config),
    callbackConflictEnvVarNames: callbackConflictEnvVarNames(config),
    oauthCallbackUrls: callbackUrls(config),
    oauthStartConsistency: oauthStartConsistency(config),
  }, null, 2)}\n`;
}

async function setup(args) {
  if (!args.dryRun && !args.authorize) {
    throw new Error('setup writes require explicit --authorize. Use --dry-run to review without changes.');
  }
  const repoPath = path.resolve(args.repo);
  if (!await pathExists(repoPath)) {
    throw new Error(`Target repo does not exist: ${repoPath}`);
  }
  const { config } = args.config ? { config: await readJson(path.resolve(args.config)) } : await loadAppConfig(args.app);
  if (config.app?.id !== args.app) throw new Error('Product configuration identity mismatch');
  const kitDir = path.join(repoPath, '.auth-kit');
  const reportDir = path.join(kitDir, 'reports');
  const changedFiles = [
    '.auth-kit/auth.config.json',
    '.auth-kit/ADAPTER.md',
    '.auth-kit/reports/latest.md',
    '.auth-kit/contract.json', '.auth-kit/observe.mjs', '.auth-kit/verify.mjs', '.auth-kit/ci.mjs',
    '.auth-kit/provenance.json', '.auth-kit/runtime/', '.auth-kit/history/', '.auth-kit/baseline/',
    '.github/workflows/auth-product-contract.yml',
  ];
  const report = setupReport({ app: args.app, repoPath, config, changedFiles });

  if (!args.dryRun) {
    const { installProductBundle } = await import('./auth-product-contract.mjs');
    await installProductBundle(repoPath, { authorized: args.authorize, productId: args.app, adapterSource: args.adapter ? path.resolve(args.adapter) : undefined,
      gateSource: args.gate ? path.resolve(args.gate) : undefined,
      inputs: args.inputs ? await readJson(path.resolve(args.inputs)) : undefined, profile: args.profile });
    await mkdir(reportDir, { recursive: true });
    await writeFile(path.join(kitDir, 'auth.config.json'), setupConfigPayload({ app: args.app, config }), 'utf8');
    await copyFile(path.join(repoRoot, 'templates', 'auth-adapter', 'ADAPTER.md'), path.join(kitDir, 'ADAPTER.md'));
    await writeFile(path.join(reportDir, 'latest.md'), report, 'utf8');
  }

  console.log(report);
  if (args.dryRun) {
    console.log('Dry run: no files were written.');
  }
}

async function wizard(args) {
  const { createBlockerHandoffs } = await import('./auth-blocker-handoff.mjs');
  if (args.capability) {
    const { CAPABILITIES } = await import('./auth-capability-catalog.mjs');
    if (!CAPABILITIES.some(({ id }) => id === args.capability)) {
      throw new Error(`Unknown capability: ${args.capability}`);
    }
  }
  const commandFor = (operator) => {
    const command = [process.execPath, __filename, 'wizard', '--adapter', path.resolve(args.adapter), '--operator', operator];
    if (args.baseline) command.push('--baseline', path.resolve(args.baseline));
    if (args.repo) command.push('--repo', path.resolve(args.repo));
    if (args.outcome) command.push('--outcome', args.outcome);
    if (args['authority-evidence']) command.push('--authority-evidence', path.resolve(args['authority-evidence']), '--authority-sha256', args['authority-sha256'] || '');
    if (args.profile) command.push('--profile', args.profile);
    if (args.capability) command.push('--capability', args.capability);
    if (args.authorize && operator === 'ACT') command.push('--authorize');
    return command;
  };
  const context = {
    repository: args.repo ? path.resolve(args.repo) : null,
    requestedOutcome: args.outcome || null,
    reproductionCommand: commandFor(args.operator),
    verificationCommand: commandFor('VERIFY'),
    authorization: args.authorize,
    capabilityId: args.capability || null,
    registeredCapabilities: [],
  };
  if (args.operator === 'ACT') {
    const report = {
      operator: 'ACT', verification: 'INDETERMINATE', state: 'BLOCKED',
      error: args.authorize ? 'NO_SUPPORTED_REPAIR' : 'AUTHORIZATION_REQUIRED',
      message: args.authorize
        ? 'No generic repair is supported. Review the adapter evidence and repair plan before changing the product.'
        : 'ACT requires explicit --authorize; no changes were made.',
      changedFiles: [],
      capabilityId: args.capability || null,
    };
    report.lifecycle_preservation = 'NOT_ASSESSED_USE_PRODUCT_VERIFY';
  report.blockerHandoffs = createBlockerHandoffs(report, context);
    console.log(JSON.stringify(report, null, 2));
    process.exitCode = 2;
    return;
  }
  const adapter = await readJson(path.resolve(args.adapter));
  const baseline = args.baseline ? await readJson(path.resolve(args.baseline)) : undefined;
  const { evaluateAdapter } = await import('./auth-wizard.mjs');
  let trustedAuthorityEvidence = [];
  if (args['authority-evidence'] || args['authority-sha256']) {
    if (!args['authority-evidence'] || !args['authority-sha256']) throw new Error('Authority evidence requires a separately trusted SHA-256 digest');
    const bytes = await readFile(path.resolve(args['authority-evidence']));
    if (createHash('sha256').update(bytes).digest('hex') !== args['authority-sha256']) throw new Error('Authority evidence digest mismatch');
    trustedAuthorityEvidence = JSON.parse(bytes);
  }
  const report = evaluateAdapter(adapter, { baseline, operator: args.operator, trustedAuthorityEvidence, verificationProfile: args.profile });
  report.lifecycle_preservation = 'NOT_ASSESSED_USE_PRODUCT_VERIFY';
  report.blockerHandoffs = createBlockerHandoffs(report, context);
  console.log(JSON.stringify(report, null, 2));
  if (['VERIFY', 'DECIDE'].includes(args.operator) && report.profile_verification !== 'PASS') {
    process.exitCode = 2;
  }
}

async function validate(args) {
  const repoPath = path.resolve(args.repo);
  const { config } = args.config ? { config: await readJson(path.resolve(args.config)) } : await loadAppConfig(args.app);
  if (config.app?.id !== args.app) throw new Error('Product configuration identity mismatch');
  const checks = [];
  const blockers = [];

  const repoExists = await pathExists(repoPath);
  checks.push(['target repo exists', repoExists]);
  if (!repoExists) blockers.push(`Target repo does not exist: ${repoPath}`);

  const kitDir = path.join(repoPath, '.auth-kit');
  for (const relativePath of ['.auth-kit/auth.config.json', '.auth-kit/ADAPTER.md', '.auth-kit/reports/latest.md']) {
    const exists = repoExists && await pathExists(path.join(repoPath, relativePath));
    checks.push([relativePath, exists]);
    if (!exists) blockers.push(`Missing ${relativePath}; run auth setup first.`);
  }

  try {
    const { inspectProductBundle } = await import('./auth-product-contract.mjs');
    const state = await inspectProductBundle(repoPath);
    checks.push(['durable contract integrity', true]);
    if (state.contract.state !== 'ESTABLISHED') blockers.push('UNESTABLISHED: reviewed baseline required; run product establishment.');
  } catch {
    checks.push(['durable contract integrity', false]);
    blockers.push('Durable AUTH bundle missing or invalid; use auth product verify for the precise blocker.');
  }
  const providerCount = enabledProviders(config).length;
  checks.push(['at least one enabled provider in source config', providerCount > 0]);
  if (providerCount === 0) blockers.push(`config/${args.app}.json has no enabled provider.`);

  const consistency = oauthStartConsistency(config);
  for (const entry of consistency) {
    checks.push([`oauth start callback matches setup report for ${entry.provider}`, entry.passed]);
    if (!entry.passed) {
      blockers.push(
        `${entry.provider} OAuth callback mismatch: setup reports ${entry.expectedCallbackUrl || '(none)'} but runtime start would use ${entry.runtimeCallbackUrl || '(none)'}.`,
      );
    }
  }

  const report = setupReport({
    app: args.app,
    repoPath,
    config,
    changedFiles: [],
    blockers,
  });

  console.log(report);
  console.log('## Validation Checks\n');
  for (const [name, passed] of checks) {
    console.log(`- ${passed ? 'PASS' : 'FAIL'} ${name}`);
  }
  if (blockers.length) process.exitCode = 2;
}

try {
  const argv = process.argv.slice(2);
  if (argv[0] === 'product') {
    const index = argv.indexOf('--repo');
    if (index < 2 || !argv[index + 1]) throw new Error('auth product <verify|maintain|establish|advance|amend> [approval.json] --repo <product>');
    const root = path.resolve(argv[index + 1]);
    argv.splice(index, 2);
    const { runProductCli } = await import('./auth-product-contract.mjs');
    await runProductCli(argv.slice(1), root);
  } else {
  const args = parseArgs(argv);
  if (args.command === 'acceptance') {
    const { evaluateRuntimeAcceptance } = await import('./auth-runtime-acceptance.mjs');
    const { readFile } = await import('node:fs/promises');
    const report = evaluateRuntimeAcceptance(JSON.parse(await readFile(args.adapter, 'utf8')));
    console.log(JSON.stringify(report, null, 2));
    if (report.acceptance !== 'PASS') process.exitCode = 2;
  } else if (args.command === 'conformance') {
    const { generateConformance } = await import('./auth-authority-conformance.mjs');
    console.log(JSON.stringify(await generateConformance(args, repoRoot), null, 2));
  } else if (args.command === 'setup') {
    await setup(args);
  } else if (args.command === 'wizard') {
    await wizard(args);
  } else {
    await validate(args);
  }
  }
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
}
