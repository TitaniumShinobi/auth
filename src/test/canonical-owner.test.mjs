import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import ts from 'typescript';
const source=readFileSync(new URL('../auth/canonicalOwner.ts',import.meta.url),'utf8');
const js=ts.transpileModule(source,{compilerOptions:{module:ts.ModuleKind.ES2022,target:ts.ScriptTarget.ES2022}}).outputText;
const {canonicalOwnerDatasource,resolveCanonicalOwner,OWNER_DATASOURCE_REFERENCE}=await import('data:text/javascript;base64,'+Buffer.from(js).toString('base64'));
test('owner lookup accepts exactly one UUID and never mutates/provisions identities',async()=>{
 const uuid='11111111-1111-4111-8111-111111111111';
 assert.equal(await resolveCanonicalOwner(' A@Example.test ',async(sql,email)=>{assert.match(sql,/^select /);assert.match(sql,/limit 2$/);assert.equal(email,'a@example.test');assert.doesNotMatch(sql,/a@example/);return [{id:uuid}];}),uuid);
 for(const rows of [[],[{id:uuid},{id:uuid}],[{id:'invalid'}],[{id:null}],null,{id:uuid}])assert.equal(await resolveCanonicalOwner('a@example.test',async()=>rows),null);
 assert.equal(await resolveCanonicalOwner('a@example.test',async()=>{throw new Error('private-query-error');}),null);
});
test('dedicated lookup does not change legacy persistence variables; invalid reference fails closed',()=>{
 const env={DATABASE_URL:'postgres://account-fixture',AUTH_CANONICAL_OWNER_DATASOURCE_REF:OWNER_DATASOURCE_REFERENCE,AUTH_CANONICAL_OWNER_DATABASE_URL:'postgres://owner-fixture'};
 const before={...env};assert.deepEqual(canonicalOwnerDatasource(env),{url:'postgres://owner-fixture',dedicated:true});assert.deepEqual(env,before);
 assert.equal(canonicalOwnerDatasource({...env,AUTH_CANONICAL_OWNER_DATASOURCE_REF:'env:OTHER_PRODUCT_DATABASE'}),null);
 assert.equal(canonicalOwnerDatasource({...env,AUTH_CANONICAL_OWNER_DATABASE_URL:''}),null);
 assert.deepEqual(canonicalOwnerDatasource({DATABASE_URL:'postgres://account-fixture'}),{url:'postgres://account-fixture',dedicated:false});
});
test('actual account/refresh factories ignore dedicated owner configuration',()=>{
 const app=readFileSync(new URL('../app.ts',import.meta.url),'utf8');
 const code=app.slice(app.indexOf('export function createDefaultStorage()'),app.indexOf('async function resolveCanonicalVvaultOwnerId(')).replaceAll('export function','function');
 function choose(env){
  class MemoryStorageAdapter{};class SqliteStorageAdapter{};class PostgresStorageAdapter{};class MemoryRefreshTokenStore{};class PostgresRefreshTokenStore{};
  const f=new Function('process','MemoryStorageAdapter','SqliteStorageAdapter','PostgresStorageAdapter','MemoryRefreshTokenStore','PostgresRefreshTokenStore','getAuthPrismaClient','getDbPath',code+';return [createDefaultStorage().constructor.name,createDefaultRefreshTokenStore().constructor.name];');
  return f({env:{...env}},MemoryStorageAdapter,SqliteStorageAdapter,PostgresStorageAdapter,MemoryRefreshTokenStore,PostgresRefreshTokenStore,()=>({}),()=>':fixture:');
 }
 for(const env of [{},{AUTH_STORAGE_ADAPTER:'memory'},{AUTH_STORAGE_ADAPTER:'postgres',DATABASE_URL:'postgres://fixture'},{DATABASE_URL:'postgres://fixture'},{VVAULT_BODY_DATABASE_URL:'postgres://fixture'}])assert.deepEqual(choose(env),choose({...env,AUTH_CANONICAL_OWNER_DATASOURCE_REF:OWNER_DATASOURCE_REFERENCE,AUTH_CANONICAL_OWNER_DATABASE_URL:'postgres://owner'}));
});
test('dedicated Prisma client has isolated datasource and never retargets the account singleton',()=>{
 const created=[];class PrismaClient {constructor(options){created.push(options);}}
 const text=readFileSync(new URL('../persistence/prismaClient.ts',import.meta.url),'utf8').replace('const require =','const packageRequire =').replaceAll("require('@prisma/client')","packageRequire('@prisma/client')").replace('import.meta.url',JSON.stringify('file:///fixture/prismaClient.js'));
 const compiled=ts.transpileModule(text,{compilerOptions:{module:ts.ModuleKind.CommonJS,target:ts.ScriptTarget.ES2022}}).outputText;
 const env={AUTH_CANONICAL_OWNER_DATASOURCE_REF:OWNER_DATASOURCE_REFERENCE,AUTH_CANONICAL_OWNER_DATABASE_URL:'postgres://owner'};
 const exports={};new Function('require','exports','process',compiled)(name=>name==='node:module'?{createRequire:()=>()=>({PrismaClient})}:name.includes('ownerDatasourceKeychain')?{ownerDatasourceFromKeychain:()=> 'postgres://keychain-fixture'}:{canonicalOwnerDatasource},exports,{env});
 const account=exports.getAuthPrismaClient();const owner=exports.getCanonicalOwnerPrismaClient();assert.notEqual(account,owner);assert.equal(exports.getAuthPrismaClient(),account);assert.deepEqual(created,[undefined,{datasources:{db:{url:'postgres://owner'}},log:[]}]);assert.equal(env.DATABASE_URL,undefined);
 env.AUTH_CANONICAL_OWNER_DATABASE_URL='postgres://changed';assert.equal(exports.getCanonicalOwnerPrismaClient(),null);
});

test('Prisma Keychain fallback never writes a database environment variable',()=>{
 const text=readFileSync(new URL('../persistence/prismaClient.ts',import.meta.url),'utf8').replace('const require =','const packageRequire =').replaceAll("require('@prisma/client')","packageRequire('@prisma/client')").replace('import.meta.url',JSON.stringify('file:///fixture/prismaClient.js'));
 const compiled=ts.transpileModule(text,{compilerOptions:{module:ts.ModuleKind.CommonJS,target:ts.ScriptTarget.ES2022}}).outputText;
 const env={AUTH_CANONICAL_OWNER_DATASOURCE_REF:OWNER_DATASOURCE_REFERENCE}; const before={...env}; const created=[];
 class PrismaClient{constructor(options){created.push(options);}}
 const exports={};new Function('require','exports','process',compiled)(name=>name==='node:module'?{createRequire:()=>()=>({PrismaClient})}:name.includes('ownerDatasourceKeychain')?{ownerDatasourceFromKeychain:()=> 'postgres://keychain-fixture'}:{canonicalOwnerDatasource},exports,{env});
 exports.getCanonicalOwnerPrismaClient(); assert.deepEqual(env,before);assert.deepEqual(created,[{datasources:{db:{url:'postgres://keychain-fixture'}},log:[]}]);
});
test('verified provider subject resolves canonical binding without email disambiguation',async()=>{
 const proof={provider:'google',subject:'verified-google-subject',issuer:'https://accounts.google.com'};
 const owner='11111111-1111-4111-8111-111111111111';let calls=0;
 const query=async(sql,...values)=>{calls++;assert.match(sql,/external_identities/);assert.match(sql,/revoked_at is null/);assert.doesNotMatch(sql,/lower\(email\)|verified-google-subject/);assert.deepEqual(values,['google','verified-google-subject']);return [{id:owner}];};
 assert.equal(await resolveCanonicalOwner('duplicated@example.test',query,proof),owner);assert.equal(calls,1);
 for(const rows of [[],[{id:owner},{id:owner}],[{id:'not-uuid'}]])assert.equal(await resolveCanonicalOwner('duplicated@example.test',async()=>rows,proof),null);
 assert.equal(await resolveCanonicalOwner('duplicated@example.test',async()=>{throw Error('database');},proof),null);
});
test('invalid provider proof fails before querying and cannot downgrade to email',async()=>{
 for(const proof of [{provider:'google',subject:'x',issuer:'https://attacker.invalid'},{provider:'email',subject:'x',issuer:'https://accounts.google.com'},{provider:'google',subject:' ',issuer:'https://accounts.google.com'}]){
 let called=false;assert.equal(await resolveCanonicalOwner('valid@example.test',async()=>{called=true;return [];},proof),null);assert.equal(called,false);
 }
});
