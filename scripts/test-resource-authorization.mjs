import { mkdtempSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

// Never overwrite dist: it may be the serving AUTH artifact.
const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
const temporary = mkdtempSync(join(realpathSync(tmpdir()), 'auth-resource-tests-'));
function run(args) {
  const result = spawnSync(process.execPath, args, { cwd: root, stdio: 'inherit', timeout: 120000 });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`Resource verification command failed (${result.status})`);
}
try {
  writeFileSync(join(temporary, 'package.json'), '{"type":"module"}\n');
  for (const name of ['node_modules', 'scripts', 'config']) symlinkSync(join(root, name), join(temporary, name), 'dir');
  run(['node_modules/typescript/bin/tsc', '--outDir', join(temporary, 'dist')]);
  run(['--test', ...['resourceAuthorization', 'resourceAuthorizationRoute', 'resourceGrantStore', 'resourceRuntime', 'vvaultOwnerAdmission', 'authorizationCode', 'vvaultAccessAssertion', 'vvaultAccessAssertionRoute']
    .map(name => join(temporary, 'dist/test', `${name}.test.js`))]);
  run(['--test', 'src/test/native-client-binding.test.mjs', 'src/test/provider-identity-tokens.test.mjs', 'src/test/resource-authorization-wizard.test.mjs']);
} finally { rmSync(temporary, { recursive: true, force: true }); }
