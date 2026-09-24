import { execFileSync } from 'node:child_process';
import { readFileSync, statSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { homedir } from 'node:os';
import { CAPABILITIES } from './auth-capability-catalog.mjs';
import { verificationOwner } from './auth-evidence-ownership.mjs';
import { runControlledFixture, fixtureArtifacts } from './auth-conformance-fixture.mjs';
import { CONFORMANCE_CONTRACT, digest, seal } from './auth-conformance-binding.mjs';
const run = (cmd, args) => execFileSync(cmd, args, {encoding:'utf8',stdio:['ignore','pipe','pipe']}).trim();

/** Local existing LaunchAgent only. No account/session creation and no real credentials. */
export async function generateConformance(args, root) {
  const adapter = JSON.parse(readFileSync(resolve(args.adapter),'utf8'));
  const origin = new URL(args.authority || 'http://localhost:1111');
  if (origin.origin !== 'http://localhost:1111' || origin.pathname !== '/' || origin.search || origin.hash || origin.username || origin.password) throw new Error('Only the established local AUTH authority is supported');
  const plist = JSON.parse(run('/usr/bin/plutil',['-convert','json','-o','-',resolve(homedir(),'Library/LaunchAgents/local.vvault.auth.plist')]));
  if (resolve(plist.WorkingDirectory) !== root || !plist.ProgramArguments?.includes('dist/index.js')) throw new Error('Authority ownership is not established');
  const snapshot = () => {
    const pid = run('/usr/sbin/lsof',['-tiTCP:1111','-sTCP:LISTEN']);
    if (!/^\d+$/.test(pid)) throw new Error('Expected one authority listener');
    const cwd = run('/usr/sbin/lsof',['-a','-p',pid,'-d','cwd','-Fn']);
    if (!cwd.split('\n').includes(`n${root}`)) throw new Error('Listener repository mismatch');
    const command = run('/bin/ps',['-p',pid,'-o','command=']);
    if (command !== plist.ProgramArguments.join(' ')) throw new Error('Listener command mismatch');
    const start = run('/bin/ps',['-p',pid,'-o','lstart=']);
    const revision = run('/usr/bin/git',['-C',root,'rev-parse','HEAD']);
    const artifactSnapshot=fixtureArtifacts(root);
    const files = ['dist/index.js',...Object.keys(artifactSnapshot)].map(f=>resolve(root,f));
    const configs = String(plist.EnvironmentVariables?.AUTH_APP_CONFIG_PATHS || '').split(':').filter(Boolean);
    if (!configs.length) throw new Error('Running configuration paths not established');
    for (const f of [...files,...configs]) if (statSync(f).mtimeMs > Date.parse(start)) throw new Error('Deployment files changed after process start; restart/review deployment before evidence');
    return {pid,start,revision,fixtureArtifactDigest:digest(artifactSnapshot),runtimeDigest:digest(files.map(f=>readFileSync(f,'utf8'))),configurationDigest:digest(configs.map(f=>readFileSync(f,'utf8')))};
  };
  const before = snapshot();
  if (adapter.identityAuthority?.id !== origin.origin || adapter.identityAuthority?.revision !== before.revision) throw new Error('Adapter must declare exact authority URL and full observed Git revision');
  const configPaths=plist.EnvironmentVariables.AUTH_APP_CONFIG_PATHS.split(':');
  const config=configPaths.map(f=>JSON.parse(readFileSync(f,'utf8'))).find(c=>c.app.id===args.app);
  const client=config?.publicClients?.find(c=>c.clientId===args['client-id']);
  if (!client) throw new Error('Registered application/client required');
  const probe = async (path, expectedStatus, expectedError, description) => {
    const res=await fetch(new URL(path,origin),{redirect:'manual',signal:AbortSignal.timeout(5000)});
    const data=await res.json();
    return res.status===expectedStatus && (expectedError ? data.error===expectedError : data.ready===true) && (!description || data.error_description===description);
  };
  if (!await probe('/ready',200)) throw new Error('Authority is not ready');
  const app=encodeURIComponent(args.app);
  const invalidClient=await probe(`/oauth/authorize?app=${app}&client_id=auth-conformance-unregistered`,400,'unauthorized_client');
  const invalidRedirect=await probe(`/oauth/authorize?app=${app}&client_id=${encodeURIComponent(client.clientId)}&redirect_uri=https%3A%2F%2Fauth-conformance.invalid%2Fcallback`,400,'invalid_request','redirect_uri is not registered');
  const invalidToken=await probe(`/oauth/userinfo?app=${app}`,401,'invalid_token');
  const fixture=runControlledFixture(root,plist.ProgramArguments[0]);
  const after=snapshot();
  if (fixture.artifactDigest !== before.fixtureArtifactDigest) throw new Error('Fixture artifact snapshot does not match observed deployment');
  if (digest(before)!==digest(after)) throw new Error('Authority deployment changed during probes');
  const generatedAt=new Date().toISOString();
  const binding={contractVersion:CONFORMANCE_CONTRACT,configurationDigest:before.configurationDigest,runtimeDigest:before.runtimeDigest,
    generatedAt,expiresAt:new Date(Date.parse(generatedAt)+3600000).toISOString(),runId:digest({before,generatedAt}),
    deploymentRevisionBasis:'Observed repository HEAD plus running process and entry/application artifact digests; not a signed build attestation',processId:before.pid};
  const proven=new Map([
    ['relying_party.authorization/client_validated',invalidClient],
    ['relying_party.authorization/redirect_validated',invalidRedirect],
    ['relying_party.callback/redirect_allowlisted',invalidRedirect],
  ]);
  // An unauthenticated userinfo rejection is evidence of that probe only, not proof
  // that every invalid/expired/revoked session is rejected. Keep broader checks unresolved.
  const fixtureChecks={
    'relying_party.pkce/verifier_checked_when_applicable':['pkce_verifier_rejected','userinfo_authorized'],
    'relying_party.authorization/replay_rejected':['authorization_code_replay_rejected','userinfo_authorized'],
    'session.refresh/token_rotated':['refresh_rotation','userinfo_authorized'],
    'session.refresh/replay_rejected':['refresh_replay_rejected','replayed_family_rejected'],
    'session.refresh/refresh_proof_verified':['wrong_client_refresh_rejected','expired_refresh_rejected'],
    'session.validation/invalid_session_rejected':['invalid_token_rejected','userinfo_unauthenticated_rejected','userinfo_authorized'],
    'session.validation/expired_session_rejected':['expired_access_rejected','expired_refresh_rejected','userinfo_authorized'],
    'session.validation/revoked_session_rejected':['revoked_access_rejected','revoked_refresh_rejected'],
    'session.revocation/revoked_access_rejected':['revoked_access_rejected'],
    'session.revocation/revoked_refresh_rejected':['revoked_refresh_rejected'],
  };
  if(fixture.completed && fixture.cleanup && fixture.serverClosed) for(const [key,checks] of Object.entries(fixtureChecks)) {
    if(checks.every(check=>typeof fixture.results[check]==='boolean')) proven.set(key,checks.every(check=>fixture.results[check]));
  }
  const records=[];
  for (const c of CAPABILITIES) for(const check of c.checks) {
    if (!['EXTERNAL_AUTHORITY','SHARED'].includes(verificationOwner(c.id,check))) continue;
    const key=`${c.id}/${check}`;
    records.push(seal({productId:adapter.productId,revision:adapter.revision,authority:origin.origin,authorityRevision:before.revision,
      capabilityId:c.id,checkId:check,verification_owner:'EXTERNAL_AUTHORITY',kind:'CONFORMANCE',
      result:proven.has(key)?(proven.get(key)?'PASS':'FAIL'):'INDETERMINATE',
      reasonCode:proven.has(key)?(fixtureChecks[key]?'ISOLATED_ARTIFACT_FIXTURE':'LIVE_SAFE_NEGATIVE_PROBE'):'DEPLOYED_STORE_OR_POLICY_CONFORMANCE_NOT_ESTABLISHED',
      references:[`auth-conformance:${binding.runId}/${key}`],binding:{...binding,fixtureArtifactDigest:fixture.artifactDigest,fixtureDigest:fixture.fixtureDigest},
      observations:{unauthenticatedUserinfoRejected:invalidToken,fixture}}));
  }
  const bytes=JSON.stringify(records,null,2)+'\n';
  writeFileSync(resolve(args.out),bytes,{flag:'wx',mode:0o600});
  return {file:resolve(args.out),authority:origin.origin,revision:before.revision,checksProven:records.filter(r=>r.result==='PASS').map(r=>`${r.capabilityId}/${r.checkId}`),
    checksIndeterminate:records.filter(r=>r.result==='INDETERMINATE').length,unauthenticatedUserinfoRejected:invalidToken};
}
