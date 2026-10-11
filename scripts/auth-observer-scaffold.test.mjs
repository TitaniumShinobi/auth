import test from 'node:test';
import assert from 'node:assert/strict';
import { access, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { LEGACY_OBSERVER, installProductObserverScaffold, productObserverScaffold } from './auth-observer-scaffold.mjs';
import { CAPABILITIES } from './auth-capability-catalog.mjs';

async function fixture() {
  const root = await mkdtemp(path.join(os.tmpdir(), 'auth-observer-'));
  await mkdir(path.join(root, '.auth-kit'));
  await writeFile(path.join(root, '.auth-kit', 'contract.json'), JSON.stringify({ productId: 'fixture', state: 'UNESTABLISHED' }));
  await writeFile(path.join(root, '.auth-kit', 'observe.mjs'), LEGACY_OBSERVER);
  return root;
}

test('observer scaffold requires authorization and creates a complete fail-closed checklist', async () => {
  const root = await fixture();
  try {
    await assert.rejects(installProductObserverScaffold(root, 'fixture'), /AUTHORIZATION_REQUIRED/);
    await assert.rejects(access(path.join(root, '.auth-kit', 'observer-input.json')));
    const result = await installProductObserverScaffold(root, 'fixture', { authorized: true });
    assert.equal(result.state, 'SCAFFOLDED_UNESTABLISHED');
    const input = JSON.parse(await readFile(path.join(root, '.auth-kit', 'observer-input.json'), 'utf8'));
    assert.deepEqual(Object.keys(input.adapter.capabilities).sort(), CAPABILITIES.map(({ id }) => id).sort());
    assert.ok(Object.values(input.adapter.capabilities).every(entry => entry.applicability === 'INDETERMINATE'));
    assert.equal((await installProductObserverScaffold(root, 'fixture', { authorized: true })).state, 'ALREADY_SCAFFOLDED_UNESTABLISHED');
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('observer scaffold preserves custom collectors and established contracts', async () => {
  const root = await fixture();
  try {
    await writeFile(path.join(root, '.auth-kit', 'observe.mjs'), 'export const custom = true;\n');
    await assert.rejects(installProductObserverScaffold(root, 'fixture', { authorized: true }), /CUSTOM_COLLECTOR/);
    await writeFile(path.join(root, '.auth-kit', 'observe.mjs'), productObserverScaffold('fixture').source);
    await writeFile(path.join(root, '.auth-kit', 'contract.json'), JSON.stringify({ productId: 'fixture', state: 'ESTABLISHED' }));
    await assert.rejects(installProductObserverScaffold(root, 'fixture', { authorized: true }), /CONTRACT_NOT_EDITABLE/);
  } finally { await rm(root, { recursive: true, force: true }); }
});
