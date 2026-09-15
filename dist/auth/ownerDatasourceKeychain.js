import { execFileSync } from 'node:child_process';
/** Reads an explicitly selected existing item; never persists credentials or changes storage env. */
export function ownerDatasourceFromKeychain(env, read = (service, account) => execFileSync('/usr/bin/security', ['find-generic-password', '-s', service, '-a', account, '-w'], { encoding: 'utf8', timeout: 5000, stdio: ['ignore', 'pipe', 'pipe'] })) {
    if (env.AUTH_CANONICAL_OWNER_DATASOURCE_REF !== 'env:AUTH_CANONICAL_OWNER_DATABASE_URL')
        return null;
    const service = env.AUTH_OWNER_KEYCHAIN_SERVICE?.trim();
    const account = env.AUTH_OWNER_KEYCHAIN_ACCOUNT?.trim();
    if (!service || !account)
        return null;
    try {
        const url = new URL(read(service, account).trim());
        if (!['postgres:', 'postgresql:'].includes(url.protocol))
            return null;
        const port = env.AUTH_OWNER_TUNNEL_PORT;
        if (port !== undefined) {
            if (!/^\d+$/.test(port) || Number(port) < 1 || Number(port) > 65535)
                return null;
            url.hostname = '127.0.0.1';
            url.port = port;
        }
        return url.toString();
    }
    catch {
        return null;
    }
}
