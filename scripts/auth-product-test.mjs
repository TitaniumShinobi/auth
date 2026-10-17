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
  return `// Product-owned behavioral acceptance. Command changes require product review.\nimport { spawnSync } from 'node:child_process';\nimport { fileURLToPath } from 'node:url';\nconst spec = ${JSON.stringify(spec, null, 2)};\nconst root = fileURLToPath(new URL('../', import.meta.url));\nconst executable = spec.executableEnvironment ? process.env[spec.executableEnvironment] : spec.argv[0] === '$NODE' ? process.execPath : spec.argv[0];\nif (!executable) { console.error('PRODUCT_TEST_EXECUTABLE_REQUIRED'); process.exit(2); }\n// Never pass a shell, interpolate arguments, or print environment contents.\nconst env = { ...process.env };\ndelete env.NODE_TEST_CONTEXT;\nconst result = spawnSync(executable, spec.argv.slice(1), { cwd: root, env, shell: false, stdio: 'inherit', timeout: spec.timeoutMs, killSignal: 'SIGKILL' });\nif (result.error) { console.error(result.error.code === 'ETIMEDOUT' ? 'PRODUCT_TEST_TIMEOUT' : 'PRODUCT_TEST_EXECUTION_FAILED'); process.exit(2); }\nif (result.signal || result.status === null) { console.error('PRODUCT_TEST_INTERRUPTED'); process.exit(2); }\nprocess.exit(result.status);\n`;
}
