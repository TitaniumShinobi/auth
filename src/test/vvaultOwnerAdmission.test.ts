import test from 'node:test';
import assert from 'node:assert/strict';
import https from 'node:https';
import { generateKeyPairSync, createPublicKey, createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { decodeJwt } from 'jose';
import { createVvaultOwnerAdmission, OWNER_ADMISSION_PATH } from '../auth/vvaultOwnerAdmission.js';
import { ResourceAuthorizationService, RESOURCE_CONTRACT } from '../auth/resourceAuthorization.js';
import type { ResourceGrantRecord } from '../auth/resourceGrantStore.js';

test('direct mTLS owner admission governs issuance and every subsequent resource status', async t => {
  const directory = mkdtempSync('/private/tmp/auth-owner-admission-');
  let server: https.Server | undefined;
  try {
    execFileSync('openssl', ['req','-x509','-newkey','rsa:2048','-nodes','-keyout',`${directory}/key.pem`,
      '-out',`${directory}/cert.pem`,'-days','1','-subj','/CN=admission-fixture','-addext','subjectAltName=IP:127.0.0.1'], { stdio:'ignore',timeout:10000 });
    const cert = readFileSync(`${directory}/cert.pem`), key = readFileSync(`${directory}/key.pem`);
    const audience = 'https://vvault.thewreck.org';
    const now = Math.floor(Date.now()/1000);
    const session = { subject:'life:fixture',sessionId:'fixture-session',accessJti:'fixture-access',clientId:'grid-windows',applicationId:'grid',expiresAt:now+300 };
    const ownerId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
    let mode = 'active', mismatch = '', calls = 0, lastRequest: any;
    server = https.createServer({cert,key,ca:cert,requestCert:true,rejectUnauthorized:true}, (req,res) => {
      calls++;
      assert.equal(req.url, OWNER_ADMISSION_PATH);
      assert.equal(req.headers.authorization, undefined);
      let data=''; req.on('data',c=>data+=c); req.on('end',()=>{
        const p=JSON.parse(data); lastRequest=p;
        assert.ok(p.expiresAt > p.issuedAt && p.expiresAt-p.issuedAt <= 30);
        const {issuedAt,expiresAt,...echo}=p;
        let body:any={...echo,admitted:true,ownerId,policyVersion:'fixture-policy/v1',expiresAt:now+20};
        const negatives:Record<string,[string,string]>={unknown:['ACCOUNT_LINK_REQUIRED','NO_OWNER_BINDING'],pending:['ENROLLMENT_REQUIRED','OWNER_ENROLLMENT_PENDING'],revoked:['REAUTH_REQUIRED','OWNER_BINDING_REVOKED'],disabled:['REAUTH_REQUIRED','OWNER_DISABLED']};
        if(negatives[mode])body={...echo,admitted:false,disposition:negatives[mode][0],reasonCode:negatives[mode][1],expiresAt:now+20};
        if(mode==='mismatch')body[mismatch]=mismatch==='capabilities'?['other:read']:'wrong';
        if(mode==='expired')body.expiresAt=now-1;
        if(mode==='long')body.expiresAt=now+1000;
        if(mode==='truthy')body.admitted='true';
        if(mode==='malformed'){res.end('{');return;}
        if(mode==='oversize'){res.end('x'.repeat(20000));return;}
        if(mode==='timeout')return;
        const status=Number(mode); if([301,401,403,409,503].includes(status)){res.writeHead(status,{location:'https://do-not-follow.invalid'});res.end('{}');return;}
        res.setHeader('content-type','application/json');res.end(JSON.stringify(body));
      });
    });
    server.listen(0,'127.0.0.1');await new Promise<void>((r,j)=>{server!.once('listening',r);server!.once('error',j);});
    const adapter=createVvaultOwnerAdmission({issuer:'fixture-auth',url:`https://127.0.0.1:${(server.address() as any).port}${OWNER_ADMISSION_PATH}`,cert,key,ca:cert});
    const records=new Map<string,ResourceGrantRecord & {revoked:boolean}>();
    const signer=generateKeyPairSync('ed25519').privateKey.export({type:'pkcs8',format:'pem'}).toString();
    const publicPem=createPublicKey(signer).export({type:'spki',format:'pem'}).toString();
    const kid=createHash('sha256').update(publicPem).digest('hex');
    const service=new ResourceAuthorizationService({issuer:'fixture-auth',keyId:kid,privateKeyPem:signer,
      store:{async initialize(){},async put(r){records.set(r.id,{...r,revoked:false});},async get(id){return records.get(id)||null;},async revoke(id){records.get(id)!.revoked=true;}},
      sessionActive:async()=>true,resolveAdmission:adapter,resolvePolicy:async()=>({enabled:true,contract:RESOURCE_CONTRACT,wireContract:'life.vvault.resource-workspace/v1',clientId:session.clientId,applicationId:session.applicationId,audience,capabilities:['workspace:resolve']})});
    const request={audience,capabilities:['workspace:resolve']};
    let grant:any;
    await t.test('admitted identity issues only exact owner with admission-bounded expiry',async()=>{
      grant=await service.issue(session,request);assert.equal(decodeJwt(grant.token).owner_id,ownerId);assert.ok(grant.expires_at<=now+20);
      assert.match(lastRequest.requestId,/^[0-9a-f-]{36}$/);assert.equal(lastRequest.subject,session.subject);
    });
    for(const [state,code] of Object.entries({unknown:'ACCOUNT_LINK_REQUIRED',pending:'ENROLLMENT_REQUIRED',revoked:'REAUTH_REQUIRED',disabled:'REAUTH_REQUIRED'})) {
      await t.test(`${state} owner has no grant`,async()=>{mode=state;const before=records.size;await assert.rejects(service.issue(session,request),{code});assert.equal(records.size,before);});
    }
    for(const state of ['301','401','403','409','503','malformed','oversize','expired','long','truthy','timeout']) {
      await t.test(`${state} response fails issuance closed`,async()=>{mode=state;const before=records.size;await assert.rejects(service.issue(session,request));assert.equal(records.size,before);});
    }
    for(const field of ['contract','issuer','subject','sessionId','clientId','applicationId','audience','capabilities','requestId']) {
      await t.test(`echoed ${field} mismatch rejects`,async()=>{mode='mismatch';mismatch=field;await assert.rejects(service.issue(session,request),/OWNER_ADMISSION_BINDING_MISMATCH/);});
    }
    await t.test('status rechecks revocation without a positive admission cache',async()=>{mode='active';const before=calls;await service.status(grant.token,audience);assert.equal(calls,before+1);mode='revoked';await assert.rejects(service.status(grant.token,audience),/REAUTH_REQUIRED/);});
    await t.test('missing workload certificate cannot issue',async()=>{
      const bad=createVvaultOwnerAdmission({issuer:'fixture-auth',url:`https://127.0.0.1:${(server!.address() as any).port}${OWNER_ADMISSION_PATH}`,cert:Buffer.alloc(0),key:Buffer.alloc(0),ca:cert});
      await assert.rejects(bad(session,audience));
    });
    await t.test('actual VVAULT request and artifact validators accept adapter output',{
      skip:!process.env.AUTH_VVAULT_SOURCE_TEST_ROOT||!process.env.AUTH_VVAULT_TEST_PYTHON,
    },async()=>{
      mode='active';grant=await service.issue(session,request);
      const root=process.env.AUTH_VVAULT_SOURCE_TEST_ROOT!;
      const script=`import sys,json\nsys.path.insert(0,sys.argv[1])\nfrom vvault.server.resource_owner_admission import validate_request\nfrom vvault.server.resource_authorization import verify_resource_assertion\np=json.load(sys.stdin)\nvalidate_request(p['request'],'fixture-auth')\nverify_resource_assertion(p['token'],issuer='fixture-auth',public_keys={p['kid']:p['public']})\nprint('PASS')`;
      assert.equal(execFileSync(process.env.AUTH_VVAULT_TEST_PYTHON!,['-B','-c',script,root],{input:JSON.stringify({request:lastRequest,token:grant.token,kid,public:publicPem}),encoding:'utf8',timeout:10000,stdio:['pipe','pipe','pipe']}).trim(),'PASS');
    });
  } finally { if(server?.listening)await new Promise<void>(r=>server!.close(()=>r()));rmSync(directory,{recursive:true,force:true}); }
});
