/** Generate a product-owned runner for an explicitly reviewed behavioral command. */
export function validateProductTest(spec) {
  if (!spec || typeof spec !== 'object' || Array.isArray(spec) || Object.keys(spec).some(key => !['argv', 'timeoutMs', 'executableEnvironment'].includes(key))) throw new Error('PRODUCT_TEST_SPEC_INVALID');
  if (!Array.isArray(spec.argv) || spec.argv.length === 0 || spec.argv.some(value => typeof value !== 'string' || !value || value.includes('\0'))) throw new Error('PRODUCT_TEST_ARGV_REQUIRED');
  if (!Number.isInteger(spec.timeoutMs) || spec.timeoutMs < 100 || spec.timeoutMs > 600000) throw new Error('PRODUCT_TEST_TIMEOUT_INVALID');
  if (spec.executableEnvironment !== undefined && !/^[A-Z][A-Z0-9_]*$/.test(spec.executableEnvironment)) throw new Error('PRODUCT_TEST_ENVIRONMENT_INVALID');
  return { argv: [...spec.argv], timeoutMs: spec.timeoutMs, ...(spec.executableEnvironment ? { executableEnvironment: spec.executableEnvironment } : {}) };
}

/** Install at test/auth-behavior.mjs. No AUTH runtime or network dependency. */
export function productTestSource(input) {
  const spec = validateProductTest(input);
  return `// Product-owned behavioral acceptance. Command changes require product review.\nimport { spawnSync } from 'node:child_process';\nimport { writeFileSync } from 'node:fs';\nimport { fileURLToPath } from 'node:url';\nconst spec = ${JSON.stringify(spec, null, 2)};\nconst root = fileURLToPath(new URL('../', import.meta.url));\nconst executable = spec.executableEnvironment ? process.env[spec.executableEnvironment] : spec.argv[0] === '$NODE' ? process.execPath : spec.argv[0];\nif (!executable) { console.error('PRODUCT_TEST_EXECUTABLE_REQUIRED'); process.exit(2); }\n// Never pass a shell, interpolate arguments, or print environment contents.\nconst env = { ...process.env };\ndelete env.NODE_TEST_CONTEXT;\ndelete env.PRODUCT_TEST_WITNESS_FILE; delete env.PRODUCT_TEST_WITNESS_NONCE;\nconst result = spawnSync(executable, spec.argv.slice(1), { cwd: root, env, shell: false, stdio: 'inherit', timeout: spec.timeoutMs, killSignal: 'SIGKILL' });\nif (result.error) { console.error(result.error.code === 'ETIMEDOUT' ? 'PRODUCT_TEST_TIMEOUT' : 'PRODUCT_TEST_EXECUTION_FAILED'); process.exit(2); }\nif (result.signal || result.status === null) { console.error('PRODUCT_TEST_INTERRUPTED'); process.exit(2); }\nif (result.status === 0 && process.env.PRODUCT_TEST_WITNESS_FILE && process.env.PRODUCT_TEST_WITNESS_NONCE) writeFileSync(process.env.PRODUCT_TEST_WITNESS_FILE, process.env.PRODUCT_TEST_WITNESS_NONCE, {flag:'wx',mode:0o600});\nprocess.exit(result.status);\n`;
}

/** Exact npm script extension; never replace an existing command or lifecycle hook. */
export function integrateProductBuild(packageBytes, { script, runner = 'test/auth-behavior.mjs' }) {
  if (!['build', 'test'].includes(script) || runner !== 'test/auth-behavior.mjs') throw new Error('PRODUCT_BUILD_INTEGRATION_INVALID');
  const pkg = JSON.parse(packageBytes);
  if (typeof pkg.scripts?.[script] !== 'string' || !pkg.scripts[script].trim()) throw new Error('PRODUCT_BUILD_COMMAND_REQUIRED');
  const invocation = `node ${runner}`;
  if (pkg.scripts[script].includes(invocation)) throw new Error('PRODUCT_BUILD_ALREADY_INTEGRATED');
  const alias = `auth:original:${script}`;
  if ([alias, `pre${alias}`, `post${alias}`].some(key => Object.hasOwn(pkg.scripts, key))) throw new Error('PRODUCT_BUILD_ALIAS_COLLISION');
  // A separate npm process contains exit/comments in the original shell command.
  pkg.scripts[alias] = pkg.scripts[script];
  pkg.scripts[script] = `npm run ${alias} && ${invocation}`;
  return `${JSON.stringify(pkg, null, 2)}\n`;
}

/** Produce a reviewed single-file spec for the existing ACT handler; never mutate here. */
export async function planProductBuildRepair(root, request, script) {
  const fs = await import('node:fs/promises');
  const path = await import('node:path');
  const { createHash } = await import('node:crypto');
  const hash = x => createHash('sha256').update(x).digest('hex');
  root = await fs.realpath(root);
  const file = path.join(root, 'package.json');
  if (!(await fs.lstat(file)).isFile() || await fs.realpath(file) !== file) throw new Error('PRODUCT_BUILD_PATH_UNSAFE');
  const bytes = await fs.readFile(file);
  if (request.file !== 'package.json' || request.beforeSha256 !== hash(bytes)) throw new Error('PRODUCT_BUILD_SOURCE_DRIFT');
  const replacement = integrateProductBuild(bytes.toString('utf8'), { script });
  return { ...request, schemaVersion: 1, replacement, afterSha256: hash(replacement) };
}
