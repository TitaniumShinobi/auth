import { execFileSync } from 'node:child_process';

// Use the same existing local Keychain identity as the standalone launcher.
// Never log the subprocess result or error: either can contain key material.
function loadAccessSigningKeyFromKeychain(
  env: NodeJS.ProcessEnv = process.env,
  platform: string = process.platform,
  readKey: (service: string, account: string) => string = (service, account) => execFileSync(
    '/usr/bin/security', ['find-generic-password', '-w', '-s', service, '-a', account],
    { encoding: 'utf8', timeout: 5000, maxBuffer: 65536, stdio: ['ignore', 'pipe', 'pipe'] },
  ),
) {
  if (platform !== 'darwin' || env.AUTH_VVAULT_ACCESS_ASSERTION_PRIVATE_KEY_PEM?.trim()
    || env.AUTH_VVAULT_ACCOUNT_ASSERTION_PRIVATE_KEY_PEM?.trim()) return;
  try {
    const raw = readKey(
      env.AUTH_VVAULT_ACCESS_ASSERTION_KEYCHAIN_SERVICE || 'life-auth-vvault-access-assertion-v1',
      env.AUTH_VVAULT_ACCESS_ASSERTION_KEYCHAIN_ACCOUNT || 'auth-local',
    ).trim();
    // macOS security may represent multiline Keychain values as hexadecimal.
    const key = /^(?:[0-9a-fA-F]{2})+$/.test(raw)
      ? Buffer.from(raw, 'hex').toString('utf8').trim()
      : raw;
    if (key) env.AUTH_VVAULT_ACCESS_ASSERTION_PRIVATE_KEY_PEM = key;
  } catch {
    // Missing or inaccessible existing key keeps assertion issuance unavailable.
  }
}

// Account signing is opt-in and separate from the established access signer.
export function loadSigningKeyFromKeychain(
  env: NodeJS.ProcessEnv = process.env,
  platform: string = process.platform,
  readKey?: (service: string, account: string) => string,
) {
  loadAccessSigningKeyFromKeychain(env, platform, readKey);
  if (platform !== 'darwin' || env.AUTH_VVAULT_ACCOUNT_ASSERTION_PRIVATE_KEY_PEM?.trim()) return;
  const service = env.AUTH_VVAULT_ACCOUNT_ASSERTION_KEYCHAIN_SERVICE?.trim();
  const account = env.AUTH_VVAULT_ACCOUNT_ASSERTION_KEYCHAIN_ACCOUNT?.trim();
  if (!service || !account) return;
  try {
    // Account Keychain authorization can outlast the access loader's five-second
    // budget. Bound only this separate startup read; never retry or change ACLs.
    const raw = (readKey ? readKey(service, account) : execFileSync(
      '/usr/bin/security', ['find-generic-password', '-w', '-s', service, '-a', account],
      { encoding: 'utf8', timeout: 60000, maxBuffer: 65536, stdio: ['ignore', 'pipe', 'pipe'] },
    )).trim();
    const key = /^(?:[0-9a-fA-F]{2})+$/.test(raw)
      ? Buffer.from(raw, 'hex').toString('utf8').trim() : raw;
    if (key) env.AUTH_VVAULT_ACCOUNT_ASSERTION_PRIVATE_KEY_PEM = key;
  } catch {
    // Missing protected account signer fails closed without access-key substitution.
  }
}
