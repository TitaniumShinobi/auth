import assert from 'node:assert/strict';
import test from 'node:test';
import crypto from 'node:crypto';
import { createAuthApp } from '../app.js';
import { MemoryStorageAdapter } from '../persistence/memoryStorage.js';
import { MemoryRefreshTokenStore } from '../auth/refreshTokenStore.js';
import { MemoryEphemeralAuthStore } from '../auth/ephemeralStore.js';

test('assertion HTTP requires authenticated session and derives owner/RP/scopes instead of trusting request claims', async () => {
 const variable='AUTH_VVAULT_ACCESS_ASSERTION_PRIVATE_KEY_PEM';
 const previous=process.env[variable];
 process.env[variable]=crypto.generateKeyPairSync('ed25519').privateKey.export({type:'pkcs8',format:'pem'}).toString();
 const owner='aaaaaaaa-bbbb-4ccc-9ddd-eeeeeeeeeeee';
 const storage=new MemoryStorageAdapter();await storage.createCredentialUser({email:'fixture@example.com',displayName:'Fixture',passwordHash:'unused'});
 let token='';
 const app=await createAuthApp({storage,refreshTokenStore:new MemoryRefreshTokenStore(),ephemeralStore:new MemoryEphemeralAuthStore(),sessionSecret:'fixture-only',
 resolveLifeProfile:async()=>({lifeUserId:'fixture-subject',supabaseUserId:owner,source:'local_registry'}),resolveVvaultOwnerId:async()=>owner,
 magicEmailDelivery:{isConfigured:()=>true,send:async({url})=>{token=new URLSearchParams(new URL(url).hash.slice(1)).get('magic_token')!;}},
 configStore:{getConfig:async()=>({app:{id:'chatty',name:'Fixture'},allowedOrigins:['http://localhost:5173'],redirects:{postLoginPath:'/',postLogoutPath:'/'},credentials:{enabled:true},docs:[],turnstile:{enabled:false,required:false},providers:[]})}});
 const server=app.listen(0,'127.0.0.1');await new Promise<void>(resolve=>server.once('listening',resolve));const base=`http://127.0.0.1:${(server.address() as {port:number}).port}`;
 const post=(path:string,body:object={},headers:Record<string,string>={})=>fetch(base+path,{method:'POST',headers:{'content-type':'application/json',origin:'http://localhost:5173',...headers},body:JSON.stringify(body)});
 try {
  const header={'X-Chatty-Auth-Bridge':'vvault-access-assertion/v2'};
  assert.equal((await post('/api/auth/vvault-access-assertion')).status,403);
  const anonymous=await post('/api/auth/vvault-access-assertion',{},header);assert.equal(anonymous.status,401);assert.equal((await anonymous.json() as any).errorCode,'AUTH_SESSION_REQUIRED');
  await post('/api/auth/magic/request',{email:'fixture@example.com',intent:'login',origin:'http://localhost:5173'});
  const session=await post('/api/auth/magic/consume',{token,origin:'http://localhost:5173'});
  assert.equal(session.status,200);
  const cookie=session.headers.getSetCookie().map(value=>value.split(';')[0]).join('; ');
  const response=await post('/api/auth/vvault-access-assertion',{owner:'attacker',relyingPartyId:'chatty-cli',scopes:['admin']},{...header,cookie});
  assert.equal(response.status,200);const issued=await response.json() as any;
  const claims=JSON.parse(Buffer.from(issued.assertion.split('.')[1],'base64url').toString());
  assert.equal(issued.relyingPartyId,'chatty');assert.equal(claims.vvault_owner_id,owner);assert.equal(claims.sub,'fixture-subject');assert.ok(!issued.scopes.includes('admin'));assert.equal(claims.exp-claims.iat,60);
 } finally {await new Promise<void>(resolve=>server.close(()=>resolve()));if(previous===undefined)delete process.env[variable];else process.env[variable]=previous;}
});
