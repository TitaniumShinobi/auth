// Executed only in a short-lived, private artifact snapshot by the conformance CLI.
import { createServer, request } from 'node:http';
import { randomBytes, createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { join } from 'node:path';
import net from 'node:net';
import { syncBuiltinESMExports } from 'node:module';
const output = process.stdout.write.bind(process.stdout);
for (const method of ['log','warn','error','info','debug']) console[method] = () => {};
let server;
let stage='IMPORT';
const results = {};
function check(name, value) { results[name] = value === true; }
try {
  if (process.env.AUTH_CONFORMANCE_CHILD !== '1') throw new Error('fixture scope required');
  const root = process.cwd();
  const connect=net.createConnection;
  net.createConnection=net.connect=function(options,...rest) {
    if(!options || typeof options!=='object' || options.path!==join(root,'fixture.sock')) throw new Error('fixture external network denied');
    return connect.call(this,options,...rest);
  };
  syncBuiltinESMExports();
  const load = p => import(pathToFileURL(join(root,p)).href);
  const {createAuthApp}=await load('dist/app.js');
  const {MemoryStorageAdapter}=await load('dist/persistence/memoryStorage.js');
  const {MemoryRefreshTokenStore}=await load('dist/auth/refreshTokenStore.js');
  const {MemoryEphemeralAuthStore}=await load('dist/auth/ephemeralStore.js');
  const {createAccessToken,createRefreshToken,resolveJwtTokenConfig}=await load('dist/auth/jwtTokens.js');
  // Deny outbound fetch; only private Unix-socket HTTP below is permitted.
  globalThis.fetch=async()=>{throw new Error('fixture outbound fetch denied');};
  const config={app:{id:'conformance',name:'Conformance'},allowedOrigins:['http://fixture.invalid'],redirects:{postLoginPath:'/',postLogoutPath:'/login'},credentials:{enabled:true},docs:[],turnstile:{required:false,enabled:false},providers:[],publicClients:[{clientId:'fixture-native',authorizationUiUrl:'http://fixture.invalid/login',loopback:{hosts:['127.0.0.1'],path:'/callback',allowDynamicPorts:true},scopes:['openid','profile','email']}]};
  const storage=new MemoryStorageAdapter();
  const refreshTokenStore=new MemoryRefreshTokenStore();
  const ephemeralStore=new MemoryEphemeralAuthStore();
  const secret=randomBytes(48).toString('hex');
  stage='CREATE_APP';
  const app=await createAuthApp({storage,refreshTokenStore,ephemeralStore,configStore:{getConfig:async()=>config},sessionSecret:secret,
    providers:{},cookieName:'fixture_sid',resolveLifeProfile:async({email,displayName})=>({lifeUserId:'fixture-user',supabaseUserId:null,displayName,source:'local_only'}),
    resolveVvaultOwnerId:async()=>null,isEmailInLifeRegistry:async()=>true,githubFetchImpl:globalThis.fetch});
  stage='SOCKET';
  server=createServer(app);
  const socketPath=join(root,'fixture.sock');
  await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(socketPath,resolve);});
  const call=(path,body,headers={})=>new Promise((resolve,reject)=>{
    const req=request({socketPath,path,method:body===undefined?'GET':'POST',headers:{...headers,...(body===undefined?{}:{'content-type':'application/json'})}},res=>{
      let text='';res.on('data',b=>text+=b);res.on('end',()=>{let data;try{data=JSON.parse(text);}catch{data=null;}resolve({status:res.statusCode,headers:res.headers,data});});
    });req.setTimeout(5000,()=>req.destroy(new Error('fixture timeout')));req.on('error',reject);req.end(body===undefined?undefined:JSON.stringify(body));
  });
  const password=randomBytes(24).toString('hex')+'Aa!7';
  stage='REGISTER';
  const registration=await call('/api/auth/register',{email:'fixture@example.invalid',name:'Fixture',password,confirmPassword:password},{origin:'http://fixture.invalid'});
  if(registration.status!==201)throw new Error('fixture registration unavailable');
  const cookie=registration.headers['set-cookie'].map(c=>c.split(';')[0]).join('; ');
  const verifier=randomBytes(48).toString('base64url');
  const redirect_uri='http://127.0.0.1:49152/callback';
  const authorization='/oauth/authorize?'+new URLSearchParams({response_type:'code',client_id:'fixture-native',redirect_uri,state:randomBytes(32).toString('base64url'),code_challenge:createHash('sha256').update(verifier).digest('base64url'),code_challenge_method:'S256'});
  const code=async()=>{const r=await call(authorization,undefined,{cookie});if(r.status!==302)throw new Error('fixture authorization failed');return new URL(r.headers.location).searchParams.get('code');};
  const exchange=(code,proof=verifier)=>call('/oauth/token',{grant_type:'authorization_code',client_id:'fixture-native',redirect_uri,code,code_verifier:proof});
  const refresh=token=>call('/oauth/token',{grant_type:'refresh_token',client_id:'fixture-native',refresh_token:token});
  const info=token=>call('/oauth/userinfo',undefined,{authorization:`Bearer ${token}`});
  const invalidProof=await exchange('conformance-invalid-authorization-code');
  check('invalid_authorization_code_rejected',invalidProof.status===400 && invalidProof.data?.error==='invalid_grant' && !invalidProof.data?.access_token && !invalidProof.data?.refresh_token && !invalidProof.headers['set-cookie']);
  const invalidCode=await code();
  check('pkce_verifier_rejected',(await exchange(invalidCode,'x'.repeat(64))).status===400);
  const validCode=await code();const issued=await exchange(validCode);
  if(issued.status!==200)throw new Error('fixture exchange unavailable');
  check('authorization_code_replay_rejected',(await exchange(validCode)).status===400);
  check('userinfo_authorized',(await info(issued.data.access_token)).status===200);
  check('invalid_token_rejected',(await info('fixture-invalid')).status===401);
  check('userinfo_unauthenticated_rejected',(await call('/oauth/userinfo')).status===401);
  const rotated=await refresh(issued.data.refresh_token);
  check('refresh_rotation',rotated.status===200 && rotated.data.refresh_token!==issued.data.refresh_token);
  check('refresh_replay_rejected',(await refresh(issued.data.refresh_token)).status===400);
  check('replayed_family_rejected',(await info(rotated.data.access_token)).status===401);
  const fresh=await exchange(await code());
  const revoked=await call('/oauth/revoke',{token:fresh.data.refresh_token});
  check('revoked_access_rejected',revoked.status===200 && (await info(fresh.data.access_token)).status===401);
  check('revoked_refresh_rejected',(await refresh(fresh.data.refresh_token)).status===400);
  const expiry=await exchange(await code());
  const claims=JSON.parse(Buffer.from(expiry.data.access_token.split('.')[1],'base64url'));
  const configJwt=resolveJwtTokenConfig(secret);
  // Correctly signed fixture proofs with past expiry; no sleep or live-clock change.
  const expiredAccess=await createAccessToken({id:'fixture-user',sub:'fixture-user',uid:'fixture-user',email:'fixture@example.invalid',name:'Fixture'},claims.sid,{...configJwt,accessTtlSeconds:-60});
  const expiredRefresh=await createRefreshToken('fixture-user',claims.sid,{...configJwt,refreshTtlSeconds:-60},'fixture-native');
  check('expired_access_rejected',(await info(expiredAccess.token)).status===401);
  check('expired_refresh_rejected',(await refresh(expiredRefresh.token)).status===400);
  check('wrong_client_refresh_rejected',(await call('/oauth/token',{grant_type:'refresh_token',client_id:'other-client',refresh_token:expiry.data.refresh_token})).status===400);
  check('isolated_identity',Boolean(await storage.findUserByEmail('fixture@example.invalid')));
  await new Promise(resolve=>server.close(resolve));server=undefined;
  output(JSON.stringify({scope:'ISOLATED_ARTIFACT_FIXTURE',results,serverClosed:true})+'\n');
} catch {
  if(server) {server.closeAllConnections();await new Promise(resolve=>server.close(resolve));}
  output(JSON.stringify({scope:'ISOLATED_ARTIFACT_FIXTURE',results,error:'FIXTURE_FAILED',stage,serverClosed:true})+'\n');
  process.exitCode=1;
}
