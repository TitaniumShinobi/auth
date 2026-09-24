import test from 'node:test';
import assert from 'node:assert/strict';
import { CAPABILITIES } from '../../scripts/auth-capability-catalog.mjs';
import { evaluateAdapter } from '../../scripts/auth-wizard.mjs';
import { verificationOwner } from '../../scripts/auth-evidence-ownership.mjs';
import { createBlockerHandoffs } from '../../scripts/auth-blocker-handoff.mjs';
function fixture() {
  const adapter = { schemaVersion: 1, productId: 'fixture-cli', revision: 'client-r1', authenticationRole: 'RELYING_PARTY',
    identityAuthority: { id: 'fixture-authority', revision: 'authority-r1' }, capabilities: {} };
  const trustedAuthorityEvidence = [];
  for (const c of CAPABILITIES) {
    if (!['session', 'relying_party', 'security', 'ux'].includes(c.family)) {
      adapter.capabilities[c.id] = { applicability: 'FALSE', reason: 'Outside fixture scope' }; continue;
    }
    adapter.capabilities[c.id] = { applicability: 'TRUE', implementation: 'ESTABLISHED', evidence: ['fixture:client-test'], checks: {} };
    for (const check of c.checks) {
      const owner = verificationOwner(c.id, check);
      if (owner !== 'EXTERNAL_AUTHORITY') adapter.capabilities[c.id].checks[check] = true;
      if (['EXTERNAL_AUTHORITY', 'SHARED'].includes(owner)) trustedAuthorityEvidence.push({
        productId: adapter.productId, revision: adapter.revision, authority: 'fixture-authority', authorityRevision: 'authority-r1',
        capabilityId: c.id, checkId: check, verification_owner: 'EXTERNAL_AUTHORITY', kind: 'CONFORMANCE', result: 'PASS', references: ['fixture:isolated-authority-test'],
      });
    }
  }
  return { adapter, trustedAuthorityEvidence };
}
test('relying-party PASS uses references, never real credential replay; PASS has no blocker', () => {
  const { adapter, trustedAuthorityEvidence } = fixture();
  const report = evaluateAdapter(adapter, { trustedAuthorityEvidence });
  assert.equal(report.verification, 'PASS');
  assert.deepEqual(createBlockerHandoffs(report), []);
  assert.equal(report.capabilities.find(c => c.id === 'session.refresh').checks.length, 3);
});
test('product source booleans and self-declared trusted evidence cannot prove authority replay/revocation', () => {
  const { adapter, trustedAuthorityEvidence } = fixture();
  adapter.trustedAuthorityEvidence = trustedAuthorityEvidence;
  for (const c of CAPABILITIES) if (adapter.capabilities[c.id].checks) for (const id of c.checks) adapter.capabilities[c.id].checks[id] = true;
  const report = evaluateAdapter(adapter);
  for (const id of ['session.refresh', 'session.revocation']) assert.equal(report.capabilities.find(c => c.id === id).verification, 'INDETERMINATE');
  const blockers = createBlockerHandoffs(report);
  assert.equal(blockers.find(b => b.capabilityId === 'session.refresh').nextOwner, 'EXTERNAL AUTHORITY');
});
test('trusted conformance is scoped; health, wrong revision, wrong authority and missing refs cannot PASS', () => {
  for (const patch of [{kind:'HEALTH'}, {revision:'old'}, {authority:'other'}, {authorityRevision:'old'}, {references:[]}]) {
    const { adapter, trustedAuthorityEvidence } = fixture();
    assert.equal(evaluateAdapter(adapter, { trustedAuthorityEvidence: trustedAuthorityEvidence.map(e => ({...e,...patch})) }).verification, 'INDETERMINATE');
  }
});
test('client failure or missing client evidence remains unresolved despite authority PASS', () => {
  const { adapter, trustedAuthorityEvidence } = fixture();
  adapter.capabilities['relying_party.callback'].checks.failure_completion_explicit = false;
  assert.equal(evaluateAdapter(adapter, {trustedAuthorityEvidence}).verification, 'FAIL');
  delete adapter.capabilities['relying_party.callback'].checks.failure_completion_explicit;
  assert.equal(evaluateAdapter(adapter, {trustedAuthorityEvidence}).verification, 'INDETERMINATE');
});
test('shared crypto requires both client and authority; negative authority evidence dominates', () => {
  const { adapter, trustedAuthorityEvidence } = fixture();
  delete adapter.capabilities['security.crypto'].checks.tokens_not_logged;
  assert.equal(evaluateAdapter(adapter, {trustedAuthorityEvidence}).verification, 'INDETERMINATE');
  trustedAuthorityEvidence.push({...trustedAuthorityEvidence[0],result:'FAIL'});
  assert.equal(evaluateAdapter(adapter, {trustedAuthorityEvidence}).verification, 'FAIL');
});

test('baseline cannot silently drop relying-party ownership', () => {
  const {adapter,trustedAuthorityEvidence}=fixture();
  const baseline=evaluateAdapter(adapter,{trustedAuthorityEvidence});
  delete adapter.authenticationRole;
  assert.throws(()=>evaluateAdapter(adapter,{baseline}), /ownership/);
});

test('CLI pins operator-approved evidence and rejects a mismatched digest', async () => {
  const {mkdtemp,writeFile,rm}=await import('node:fs/promises');
  const {tmpdir}=await import('node:os');
  const {join}=await import('node:path');
  const {createHash}=await import('node:crypto');
  const {spawnSync}=await import('node:child_process');
  const dir=await mkdtemp(join(tmpdir(),'auth-conformance-'));
  try {
    const {adapter,trustedAuthorityEvidence}=fixture();
    const data=JSON.stringify(trustedAuthorityEvidence);
    await writeFile(join(dir,'adapter.json'),JSON.stringify(adapter));
    await writeFile(join(dir,'evidence.json'),data);
    const args=['scripts/auth-cli.mjs','wizard','--adapter',join(dir,'adapter.json'),'--authority-evidence',join(dir,'evidence.json'),'--authority-sha256'];
    const good=spawnSync(process.execPath,[...args,createHash('sha256').update(data).digest('hex')],{encoding:'utf8'});
    assert.equal(good.status,0,good.stderr);
    assert.equal(JSON.parse(good.stdout).verification,'PASS');
    const bad=spawnSync(process.execPath,[...args,'0'.repeat(64)],{encoding:'utf8'});
    assert.notEqual(bad.status,0);
    assert.match(bad.stderr,/digest mismatch/);
  } finally {await rm(dir,{recursive:true,force:true});}
});

test('deployment-bound generated evidence rejects tamper, stale/config/contract mismatch and health', async () => {
  const {seal, CONFORMANCE_CONTRACT}=await import('../../scripts/auth-conformance-binding.mjs');
  const {adapter,trustedAuthorityEvidence}=fixture();
  const binding={contractVersion:CONFORMANCE_CONTRACT,configurationDigest:'a'.repeat(64),runtimeDigest:'b'.repeat(64),generatedAt:new Date(Date.now()-1000).toISOString(),expiresAt:new Date(Date.now()+60000).toISOString()};
  const records=trustedAuthorityEvidence.map(e=>seal({...e,binding}));
  assert.equal(evaluateAdapter(adapter,{trustedAuthorityEvidence:records}).verification,'PASS');
  for(const mutate of [e=>({...e,result:'FAIL'}),e=>seal({...e,authorityRevision:'wrong'}),e=>seal({...e,authority:'wrong'}),e=>seal({...e,kind:'HEALTH'}),e=>seal({...e,binding:{...binding,expiresAt:new Date(0).toISOString()}}),e=>seal({...e,binding:{...binding,contractVersion:'other'}})]) {
    assert.equal(evaluateAdapter(adapter,{trustedAuthorityEvidence:records.map(mutate)}).verification,'INDETERMINATE');
  }
  adapter.identityAuthority.configurationDigest='c'.repeat(64);
  assert.equal(evaluateAdapter(adapter,{trustedAuthorityEvidence:records}).verification,'INDETERMINATE');
});
