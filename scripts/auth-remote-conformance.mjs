/** Authority-side orchestration; consumes only explicitly reviewed deployment adapters. */
import {readFileSync,writeFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {resolve} from 'node:path';
import {pathToFileURL} from 'node:url';
import {CONFORMANCE_CONTRACT,digest,seal} from './auth-conformance-binding.mjs';
import {fixtureArtifacts,runControlledFixture} from './auth-conformance-fixture.mjs';
export const REQUIRED_AUTHORITY_CHECKS = Object.freeze({
 'session.validation/invalid_session_rejected':['invalid_token_rejected','userinfo_unauthenticated_rejected','userinfo_authorized'],
 'session.validation/expired_session_rejected':['expired_access_rejected','expired_refresh_rejected','userinfo_authorized'],
 'session.validation/revoked_session_rejected':['revoked_access_rejected','revoked_refresh_rejected'],
 'session.refresh/refresh_proof_verified':['wrong_client_refresh_rejected','expired_refresh_rejected'],
 'session.refresh/token_rotated':['refresh_rotation','userinfo_authorized'],
 'session.refresh/replay_rejected':['refresh_replay_rejected','replayed_family_rejected'],
 'relying_party.authorization/client_validated':null,
 'relying_party.authorization/redirect_validated':null,
 'relying_party.authorization/replay_rejected':['authorization_code_replay_rejected','userinfo_authorized'],
 'relying_party.pkce/verifier_checked_when_applicable':['pkce_verifier_rejected','userinfo_authorized'],
 'relying_party.callback/redirect_allowlisted':null
});
const sha=v=>createHash('sha256').update(v).digest('hex');
const hex=v=>typeof v==='string'&&/^[a-f0-9]{64}$/.test(v);
const nonempty=v=>typeof v==='string'&&v.length>0;
function validateSnapshot(s,origin,consumer,app,client){
 if(!s||s.authority!==origin||s.revision!==consumer.identityAuthority?.revision||!nonempty(consumer.productId)||!nonempty(consumer.revision)||consumer.identityAuthority?.id!==origin||
 !/^[a-f0-9]{40,64}$/.test(s.revision)||!['runtimeDigest','configurationDigest','processIdentityDigest','ingressBindingDigest','fixtureArtifactDigest'].every(k=>hex(s[k]))||
 !nonempty(s.root)||!nonempty(s.nodeExecutable)||s.registeredApp!==app||s.registeredClient!==client||s.servingDeploymentVerified!==true)throw new Error('REMOTE_DEPLOYMENT_BINDING_REQUIRED');
 if(consumer.identityAuthority.configurationDigest&&consumer.identityAuthority.configurationDigest!==s.configurationDigest)throw new Error('CONFIGURATION_MISMATCH');
 if(consumer.identityAuthority.runtimeDigest&&consumer.identityAuthority.runtimeDigest!==s.runtimeDigest)throw new Error('RUNTIME_MISMATCH');
}
/** Exported for controlled deterministic tests. No HTTP endpoint invokes this runner. */
export async function collectRemoteEvidence({consumer,origin,app,client,snapshot,fixture,artifactDigest,probe,adapterDigest,now=()=>Date.now()}){
 const u=new URL(origin);if(u.protocol!=='https:'||u.origin!==origin||u.username||u.password)throw new Error('EXACT_HTTPS_AUTHORITY_REQUIRED');
 if(!hex(adapterDigest))throw new Error('DEPLOYMENT_ADAPTER_TRUST_REQUIRED');
 const before=await snapshot();validateSnapshot(before,origin,consumer,app,client);
 if(await artifactDigest(before.root)!==before.fixtureArtifactDigest)throw new Error('SERVING_ARTIFACT_MISMATCH');
 const appQuery=encodeURIComponent(app),clientQuery=encodeURIComponent(client);
 const safe=async(p,status,error,description)=>{try{const r=await probe(origin+p);return r.status===status&&r.body?.error===error&&(!description||r.body?.error_description===description);}catch{return null;}};
 const clientValid=await safe(`/oauth/authorize?app=${appQuery}&client_id=auth-conformance-unregistered`,400,'unauthorized_client');
 const redirectValid=await safe(`/oauth/authorize?app=${appQuery}&client_id=${clientQuery}&redirect_uri=https%3A%2F%2Fauth-conformance.invalid%2Fcallback`,400,'invalid_request','redirect_uri is not registered');
 let f;try{f=await fixture(before.root,before.nodeExecutable);}catch{f=null;}
 const after=await snapshot();validateSnapshot(after,origin,consumer,app,client);
 if(digest(before)!==digest(after)||await artifactDigest(after.root)!==before.fixtureArtifactDigest)throw new Error('DEPLOYMENT_CHANGED_DURING_CONFORMANCE');
 const fixtureBound=f?.completed===true&&f.cleanup===true&&f.serverClosed===true&&f.artifactDigest===before.fixtureArtifactDigest;
 const live={'relying_party.authorization/client_validated':clientValid,'relying_party.authorization/redirect_validated':redirectValid,'relying_party.callback/redirect_allowlisted':redirectValid};
 const generatedAt=new Date(now()).toISOString();const binding={contractVersion:CONFORMANCE_CONTRACT,configurationDigest:before.configurationDigest,runtimeDigest:before.runtimeDigest,generatedAt,expiresAt:new Date(Date.parse(generatedAt)+3600000).toISOString(),runId:digest({adapterDigest,before,generatedAt}),deploymentAdapterDigest:adapterDigest,processIdentityDigest:before.processIdentityDigest,ingressBindingDigest:before.ingressBindingDigest,fixtureArtifactDigest:before.fixtureArtifactDigest,deploymentRevisionBasis:'Reviewed authority-side adapter verifies serving process, artifacts and public ingress; isolated fixture proves artifact behavior, not production store durability'};
 return Object.entries(REQUIRED_AUTHORITY_CHECKS).map(([key,checks])=>{
 const values=checks?(fixtureBound?checks.map(k=>f.results?.[k]):[]):[live[key]];
 const established=values.length>0&&values.every(v=>typeof v==='boolean');const result=established?(values.every(Boolean)?'PASS':'FAIL'):'INDETERMINATE';
 const [capabilityId,checkId]=key.split('/');
 return seal({productId:consumer.productId,revision:consumer.revision,authority:origin,authorityRevision:before.revision,capabilityId,checkId,verification_owner:'EXTERNAL_AUTHORITY',kind:'CONFORMANCE',result,reasonCode:!established?'DEPLOYMENT_CONFORMANCE_NOT_ESTABLISHED':checks?'ISOLATED_ARTIFACT_FIXTURE':'LIVE_SAFE_NEGATIVE_PROBE',references:[`auth-conformance:${binding.runId}/${key}`],binding});
 });
}
export async function generateRemoteConformance(args){
 const adapterPath=resolve(args['deployment-adapter']);const bytes=readFileSync(adapterPath);
 if(!hex(args['deployment-sha256'])||sha(bytes)!==args['deployment-sha256'])throw new Error('DEPLOYMENT_ADAPTER_DIGEST_MISMATCH');
 const deployment=await import(pathToFileURL(adapterPath).href);if(typeof deployment.snapshot!=='function')throw new Error('DEPLOYMENT_SNAPSHOT_REQUIRED');
 const consumer=JSON.parse(readFileSync(resolve(args.adapter),'utf8'));
 const records=await collectRemoteEvidence({consumer,origin:args.authority,app:args.app,client:args['client-id'],adapterDigest:sha(bytes),snapshot:()=>deployment.snapshot({authority:args.authority,app:args.app,client:args['client-id']}),artifactDigest:root=>digest(fixtureArtifacts(root)),fixture:runControlledFixture,probe:async url=>{
 const r=await fetch(url,{redirect:'manual',signal:AbortSignal.timeout(5000)});return {status:r.status,body:await r.json()};
 }});
 if(sha(readFileSync(adapterPath))!==sha(bytes))throw new Error('DEPLOYMENT_ADAPTER_CHANGED');
 const output=JSON.stringify(records,null,2)+'\n';writeFileSync(resolve(args.out),output,{flag:'wx',mode:0o600});
 return {file:resolve(args.out),sha256:sha(output),authority:args.authority,authorityRevision:records[0].authorityRevision,checks:records.map(r=>({capabilityId:r.capabilityId,checkId:r.checkId,result:r.result}))};
}
