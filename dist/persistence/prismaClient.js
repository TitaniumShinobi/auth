import { canonicalOwnerDatasource } from '../auth/canonicalOwner.js';
import { ownerDatasourceFromKeychain } from '../auth/ownerDatasourceKeychain.js';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
let prisma = null;
export function getAuthPrismaClient() {
    if (!prisma) {
        const { PrismaClient } = require('@prisma/client');
        prisma = new PrismaClient();
    }
    return prisma;
}
let ownerClient = null;
let ownerUrl = null;
/** A separate read-only lookup client; never changes the account client or process env. */
export function getCanonicalOwnerPrismaClient() {
    const source = canonicalOwnerDatasource({ ...process.env,
        AUTH_CANONICAL_OWNER_DATABASE_URL: process.env.AUTH_CANONICAL_OWNER_DATABASE_URL
            || ownerDatasourceFromKeychain(process.env) || undefined,
    });
    if (!source)
        return null;
    if (!source.dedicated)
        return getAuthPrismaClient();
    if (!ownerClient) {
        const { PrismaClient } = require('@prisma/client');
        ownerClient = new PrismaClient({ datasources: { db: { url: source.url } }, log: [] });
        ownerUrl = source.url;
    }
    // Changing the protected datasource requires the operator's scoped service reload.
    return source.url === ownerUrl ? ownerClient : null;
}
