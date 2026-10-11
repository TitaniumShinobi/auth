import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { assessCleanHouse } from './readiness.mjs';

test('CleanHouse observation is read-only, keeps Python authoritative, and classifies every gap', async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'cleanhouse-observer-'));
  try {
    for (const relative of ['backend/api/auth.py','backend/auth_runtime_config.py','config/auth-runtime.json','frontend/login.html','frontend/signup.html','frontend/js/auth.js','tests/test_auth_api_validation.py','tests/test_auth_runtime_config.py']) {
      await mkdir(path.dirname(path.join(root, relative)), { recursive: true });
      await writeFile(path.join(root, relative), '# fixture\n');
    }
    const report = await assessCleanHouse(root);
    assert.equal(report.activeAuthority.status, 'SOLE_ACTIVE_AUTHORITY');
    assert.equal(report.nodeRuntime.status, 'INACTIVE_CANDIDATE');
    assert.equal(report.nodeRuntime.activationAuthorized, false);
    assert.ok(report.handoffs.length > 0);
    assert.ok(report.handoffs.every(handoff => ['AUTO_REPAIR_AVAILABLE','AGENT_INTEGRATION_REQUIRED','EXTERNAL_ACTION_REQUIRED','AUTH_DEVELOPMENT_REQUIRED'].includes(handoff.executionClassification)));
    assert.equal(report.classifications['providers.google'], 'EXTERNAL_ACTION_REQUIRED');
    assert.equal(report.classifications.signin, 'AGENT_INTEGRATION_REQUIRED');
  } finally { await rm(root, { recursive: true, force: true }); }
});
