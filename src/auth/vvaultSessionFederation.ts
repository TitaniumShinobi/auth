import crypto from 'node:crypto';
import {normalizeVerifiedProviderIdentity} from './canonicalOwner.js';
const fail=()=>{throw Object.assign(new Error('INVALID_VVAULT_SESSION_PROOF'),{code:'INVALID_VVAULT_SESSION_PROOF'});};
export function verifyVvaultSessionProof(token:unknown,{publicKeyPem,issuer='vvault',audience,now=Math.floor(Date.now()/1000)}:{publicKeyPem:string;issuer?:string;audience:string;now?:number}) {
 if(typeof token!=='string'||token.length>32768)return fail();
 const parts=token.split('.');if(parts.length!==2||parts.some(p=>!/^[A-Za-z0-9_-]+$/.test(p)))return fail();
 const key=crypto.createPublicKey(publicKeyPem.replace(/\\n/g,'\n'));
 if(key.asymmetricKeyType!=='ed25519'||!crypto.verify(null,Buffer.from(parts[0]),key,Buffer.from(parts[1],'base64url')))return fail();
 let p:any;try{p=JSON.parse(Buffer.from(parts[0],'base64url').toString());}catch{return fail();}
 if(p.version!=='auth.vvault-native-session.v1'||p.kind!=='IDENTITY'||p.issuer!==issuer||p.audience!==audience||p.product_id!=='chatty'||p.relyingParty!=='chatty'||p.client_id!=='chatty-web-link')return fail();
 if(!Number.isSafeInteger(p.issuedAt)||!Number.isSafeInteger(p.expiresAt)||p.issuedAt>now||p.expiresAt<=now||p.expiresAt-p.issuedAt>60||p.expiresAt<=p.issuedAt)return fail();
 const identity=normalizeVerifiedProviderIdentity(p.provider_identity);
 if(!identity || !['google','email'].includes(identity.provider)||!identity.verifiedEmail||identity.verifiedEmail!==p.email||typeof p.name!=='string'||!p.name.trim()||p.name.length>512)return fail();
 if(!/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i.test(p.ownerId)||!['authorization_request','nonce','authoritySessionBinding'].every(k=>typeof p[k]==='string'&&p[k].length>=16&&p[k].length<=256))return fail();
 if(!['enrollment','session','device','policy'].every(k=>p.requirements?.[k]==='SATISFIED'))return fail();
 if(!Array.isArray(p.chattyConsents)||p.chattyConsents.length!==3)return fail();
 const keys=new Set();
 for(const d of p.chattyConsents){if(!['chatty:terms','chatty:privacy','chatty:eeccd'].includes(d?.key)||keys.has(d.key)||typeof d.version!=='string'||!d.version||!/^[a-f0-9]{64}$/.test(d.sha256)||typeof d.acceptedAt!=='string'||!Number.isFinite(Date.parse(d.acceptedAt))||Date.parse(d.acceptedAt)>now*1000)return fail();keys.add(d.key);}
 return {...p,provider_identity:identity};
}

export async function verifyChattyConsentManifest(receipts:any[], clientUiUrl:string, fetchImpl=fetch) {
 const origin=new URL(clientUiUrl).origin;
 const response=await fetchImpl(new URL('/api/auth/enrollment/documents',origin),{redirect:'error',signal:AbortSignal.timeout(5000),headers:{accept:'application/json'}});
 if(!response.ok)return false;
 const body=await response.json() as any;
 if(body.authority!=='chatty'||!Array.isArray(body.documents)||body.documents.length!==3)return false;
 const keys=new Set();
 return body.documents.every((d:any)=>{if(!['chatty:terms','chatty:privacy','chatty:eeccd'].includes(d.key)||keys.has(d.key)||!/^[a-f0-9]{64}$/.test(d.sha256))return false;keys.add(d.key);return receipts.some(r=>r.key===d.key&&r.version===d.version&&r.sha256===d.sha256);});
}
