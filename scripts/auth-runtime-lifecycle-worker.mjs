#!/usr/bin/env node
import { repairRuntime, upgradeRuntime } from './auth-runtime-lifecycle.mjs';

const [operation, root, productId, sourceRoot, targetRevision] = process.argv.slice(2);
const acceptance = async () => ({ verification: 'PASS', checks: ['crash-fixture'] });

if (process.env.AUTH_RUNTIME_TEST_MODE !== '1') throw new Error('TEST_WORKER_DISABLED');
if (operation === 'repair') await repairRuntime(root, productId, { authorized: true, sourceRoot, acceptance });
else if (operation === 'upgrade') await upgradeRuntime(root, productId, { authorized: true, sourceRoot, targetRevision, acceptance });
else throw new Error('TEST_WORKER_OPERATION_INVALID');
