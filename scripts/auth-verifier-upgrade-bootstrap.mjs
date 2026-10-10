/** Portable bundle entrypoint; validate package bytes before importing upgrade code. */
import {readFile,lstat} from 'node:fs/promises';
import {createHash} from 'node:crypto';
const sha=b=>createHash('sha256').update(b).digest('hex');
try{
 const manifest=JSON.parse(await readFile(new URL('./manifest.json',import.meta.url)));
 for(const required of ['upgrade.mjs','auth-verifier-upgrade.mjs','auth-verifier-upgrade-chain.mjs'])if(!Object.hasOwn(manifest.files,required))throw new Error('BUNDLE_MANIFEST_INVALID');
 for(const [name,digest] of Object.entries(manifest.files)){
  if(!/^[a-zA-Z0-9._-]+$/.test(name)||!/^[a-f0-9]{64}$/.test(digest))throw new Error('BUNDLE_MANIFEST_INVALID');
  const file=new URL(name,import.meta.url),s=await lstat(file);
  if(s.isSymbolicLink()||!s.isFile()||sha(await readFile(file))!==digest)throw new Error('BUNDLE_DIGEST_MISMATCH');
 }
 if(process.argv.slice(2).join(' ')==='--check')console.log('BUNDLE_HASHES_PASS');
 else{const {upgradeCli}=await import('./auth-verifier-upgrade.mjs');await upgradeCli(process.argv.slice(2));}
}catch(e){console.error(e.code||(/^[A-Z_]+$/.test(e.message)?e.message:'UPGRADE_BOOTSTRAP_FAILED'));process.exitCode=2;}
