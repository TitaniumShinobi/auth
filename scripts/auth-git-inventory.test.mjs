import test from 'node:test';import assert from 'node:assert/strict';
import {Readable,PassThrough} from 'node:stream';import {EventEmitter} from 'node:events';
import {parseGitPaths,inventoryPaths,inventoryArguments,filesystemPath,runGit} from './auth-git.mjs';
import {mkdtemp,writeFile,readFile,rm} from 'node:fs/promises';import {tmpdir} from 'node:os';import path from 'node:path';
import {hash} from './auth-product-contract.mjs';
async function collect(chunks){const a=[];for await(const p of parseGitPaths(chunks))a.push(p);return a;}
test('streams more than 300 MiB without an inventory-sized buffer',async()=>{
 const record=Buffer.from('deep/'+ 'x'.repeat(120)+'\0');const block=Buffer.concat(Array(512).fill(record));const blocks=5000;let count=0;
 async function* data(){for(let n=0;n<blocks;n++)yield block;}
 for await(const p of parseGitPaths(data())){assert.equal(p.length,125);count++;}assert.equal(count,blocks*512);assert.ok(blocks*block.length>300*1024*1024);
});
test('NUL and UTF-8 split at every byte preserve exact filenames',async()=>{
 const names=['space name','line\nbreak','深い/é.txt','a'];const bytes=Buffer.from(names.join('\0')+'\0');assert.deepEqual(await collect([...bytes].map(b=>Buffer.from([b]))),names);
});
test('truncated and invalid encoding fail closed',async()=>{
 await assert.rejects(collect([Buffer.from('a\0unfinished')]),{code:'GIT_INVENTORY_TRUNCATED'});
 await assert.rejects(collect([Buffer.from([255,0])]),{code:'GIT_INVENTORY_INVALID'});
});
test('very deep Windows paths survive parser and namespace conversion',async()=>{
 const p='C:\\repo\\'+('directory\\'.repeat(1500))+'file.txt';assert.ok(p.length>10000);assert.deepEqual(await collect([Buffer.from(p+'\0')]),[p]);assert.equal(filesystemPath(p,'win32'),'\\\\?\\'+p);
 assert.deepEqual(inventoryArguments('win32').slice(0,2),['-c','core.longpaths=true']);assert.equal(inventoryArguments('linux')[0],'ls-files');
});
function fake({warning=false,code=0}={}){
 return {platform:'linux',env:{PATH:'/fixture'},stat:()=>({isFile:()=>true}),spawn:()=>({status:0,stdout:'git version fixture'}),launch:(exe,args,options)=>{
 assert.equal(options.env.GIT_OPTIONAL_LOCKS,'0');assert.equal(options.shell,false);
 const child=new EventEmitter();child.stdout=Readable.from([Buffer.from('first\0second\0')]);child.stderr=new PassThrough();child.kill=()=>{};
 child.stdout.on('end',()=>setImmediate(()=>{if(warning)child.stderr.write('warning: incomplete long path');child.stderr.end();child.emit('close',code,null);}));return child;
 }};
}
for(const [label,options,code]of [['warning with successful exit',{warning:true},'GIT_INVENTORY_WARNINGS'],['nonzero exit',{code:1},'GIT_INVENTORY_INCOMPLETE']])test(label+' invalidates entire enumeration',async()=>{
 await assert.rejects(async()=>{for await(const p of inventoryPaths(fake(options))){}},{code});
});
test('streamed equivalent of buffered small fixture has identical deterministic hash',async()=>{
 const bytes=Buffer.from('z\0a\0z\0b\0');const buffered=Object.fromEntries([...new Set(bytes.toString().split('\0').filter(Boolean))].sort().map(p=>[p,hash(p)]));const streamed=Object.create(null);
 for await(const p of parseGitPaths([bytes.subarray(0,3),bytes.subarray(3)]))streamed[p]=hash(p);assert.equal(hash(buffered),hash(streamed));
});
test('real enumeration preserves staged index and mixed file bytes including .tmp',async()=>{
 const root=await mkdtemp(path.join(tmpdir(),'auth-stream-'));try{
 runGit(['init','-q'],{cwd:root});await writeFile(path.join(root,'tracked'),'staged');runGit(['add','tracked'],{cwd:root});await writeFile(path.join(root,'tracked'),'unstaged');await writeFile(path.join(root,'.tmp'),'untracked');
 const before=await readFile(path.join(root,'.git/index'));const names=[];for await(const p of inventoryPaths({cwd:root}))names.push(p);
 assert.deepEqual(names.sort(),['.tmp','tracked']);assert.deepEqual(await readFile(path.join(root,'.git/index')),before);assert.equal(await readFile(path.join(root,'tracked'),'utf8'),'unstaged');assert.equal(await readFile(path.join(root,'.tmp'),'utf8'),'untracked');
 }finally{await rm(root,{recursive:true,force:true});}
});
