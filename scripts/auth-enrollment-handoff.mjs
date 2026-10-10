import { createHash, randomUUID, sign, verify } from 'node:crypto';

export const ENROLLMENT_CONTRACT_VERSION = 'auth.enrollment.v1';
const fail = code => { throw Object.assign(new Error(code), { code }); };
const text = v => typeof v === 'string' && v.length > 0 && v.length <= 512;
const uuid = v => typeof v === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(v);
const digest = v => createHash('sha256').update(JSON.stringify(v)).digest('hex');
const identity = value => {
  if (!value || !text(value.subject) || !text(value.provider) || !text(value.providerSubject) || !text(value.providerIssuer)) fail('AUTHENTICATED_IDENTITY_REQUIRED');
  return { subject:value.subject, provider:value.provider, providerSubject:value.providerSubject, providerIssuer:value.providerIssuer };
};
function consentProof(value, now) {
  if(value===undefined)return undefined;
  if(value?.authority!=='vvault'||!Number.isSafeInteger(value.acceptedAt)||value.acceptedAt>now||value.acceptedAt<now-300||!Array.isArray(value.documents)||!value.documents.length||value.documents.length!==3)fail('INVALID_CANONICAL_CONSENT');
  const keys=new Set();
  const documents=value.documents.map(d=>{if(!['vvault:terms','vvault:privacy','vvault:eeccd'].includes(d?.key)||!text(d?.version)||!/^[a-f0-9]{64}$/.test(d?.sha256)||keys.has(d.key))fail('INVALID_CANONICAL_CONSENT');keys.add(d.key);return {key:d.key,version:d.version,sha256:d.sha256};});
  return {authority:'vvault',acceptedAt:value.acceptedAt,documents};
}
function encode(payload, key) {
  if (key?.asymmetricKeyType !== 'ed25519') fail('ED25519_KEY_REQUIRED');
  const body=Buffer.from(JSON.stringify(payload)).toString('base64url');
  return `${body}.${sign(null,Buffer.from(body),key).toString('base64url')}`;
}
function decode(token,key,{issuer,audience,kind,now}) {
  if (key?.asymmetricKeyType !== 'ed25519') fail('ED25519_KEY_REQUIRED');
  if(typeof token!=='string'||token.length>16384)fail('INVALID_PROOF');
  const pieces=token.split('.');
  if(pieces.length!==2||pieces.some(p=>!/^[A-Za-z0-9_-]+$/.test(p)))fail('INVALID_PROOF');
  if(!verify(null,Buffer.from(pieces[0]),key,Buffer.from(pieces[1],'base64url')))fail('INVALID_SIGNATURE');
  let p;try{p=JSON.parse(Buffer.from(pieces[0],'base64url'));}catch{fail('INVALID_PROOF');}
  if(!p||p.version!==ENROLLMENT_CONTRACT_VERSION||p.kind!==kind||p.issuer!==issuer||p.audience!==audience)fail('PROVENANCE_MISMATCH');
  if(!Number.isSafeInteger(p.issuedAt)||!Number.isSafeInteger(p.expiresAt)||p.issuedAt>now||p.expiresAt<=now||p.expiresAt<=p.issuedAt||p.expiresAt-p.issuedAt>(kind==='COMPLETION'?60:300))fail('EXPIRED_OR_INVALID_TIME');
  return p;
}

/** Server-only coordinator. resolveSession authenticates a host session handle and returns
 * {sessionBinding, identity, ownerId?}. sessionBinding is a non-secret opaque session ID,
 * never a cookie/token. authorizeRelyingParty checks a server-owned registered client policy.
 * store.put is insert-only; consume(id, expected, notAfter) atomically checks its trusted clock < notAfter,
 * compares and deletes a
 * transaction across ALL workers/restarts. Production must supply a durable store.
 */
export function createEnrollmentCoordinator({issuer,authorityIssuer,signingKey,authorityPublicKey,store,resolveSession,authorizeRelyingParty,now=()=>Math.floor(Date.now()/1000)}) {
  if(!text(issuer)||!text(authorityIssuer)||!store||!['put','get','consume'].every(k=>typeof store[k]==='function')||typeof resolveSession!=='function'||typeof authorizeRelyingParty!=='function')fail('CONFIGURATION_REQUIRED');
  async function session(handle) {
    const s=await resolveSession(handle);
    if(!s||!text(s.sessionBinding))fail('AUTHENTICATION_REQUIRED');
    const contact=s.contact;
    if(contact!==undefined && (!['google','email'].includes(s.identity?.provider)||!text(contact.email)||contact.email.length>320||!/^[^\s@]+@[^\s@]+$/.test(contact.email)||contact.emailVerified!==true))fail('INVALID_VERIFIED_CONTACT');
    const canonicalConsents=consentProof(s.canonicalConsents,now());
    return {...(canonicalConsents?{canonicalConsents}:{}),sessionBinding:s.sessionBinding,identity:identity(s.identity),ownerId:s.ownerId??null,...(contact?{contact:{email:contact.email,emailVerified:true}}:{})};
  }
  return {
    async start(handle,{intent,relyingParty}) {
      if(!['SIGN_IN','SIGN_UP'].includes(intent)||!text(relyingParty))fail('INVALID_REQUEST');
      const s=await session(handle);
      if(s.canonicalConsents && intent!=='SIGN_UP')fail('INVALID_CANONICAL_CONSENT');
      if(await authorizeRelyingParty(s,relyingParty)!==true)fail('RELYING_PARTY_NOT_AUTHORIZED');
      if(s.ownerId!==null&&!uuid(s.ownerId))fail('INVALID_OWNER');
      const issuedAt=now();
      const p={version:ENROLLMENT_CONTRACT_VERSION,kind:'HANDOFF',issuer,audience:authorityIssuer,issuedAt,expiresAt:issuedAt+300,transaction:randomUUID(),relyingParty,intent,...s};
      const token=encode(p,signingKey);
      await store.put(p.transaction,p);
      return {handoff:token,transaction:p.transaction,expiresAt:p.expiresAt,disposition:s.ownerId?'ENROLLMENT_CHECK_REQUIRED':'ENROLLMENT_REQUIRED'};
    },
    async complete(handle,token) {
      const s=await session(handle);
      const p=decode(token,authorityPublicKey,{issuer:authorityIssuer,audience:issuer,kind:'COMPLETION',now:now()});
      const expected=await store.get(p.transaction);
      if(!expected)fail('UNKNOWN_OR_REPLAYED_TRANSACTION');
      if(expected.expiresAt<=now())fail('EXPIRED_TRANSACTION');
      if(await authorizeRelyingParty(s,expected.relyingParty)!==true)fail('RELYING_PARTY_NOT_AUTHORIZED');
      if(p.handoffDigest!==digest(expected)||p.relyingParty!==expected.relyingParty||p.sessionBinding!==expected.sessionBinding||s.sessionBinding!==expected.sessionBinding||digest(identity(p.identity))!==digest(expected.identity)||digest(s.identity)!==digest(expected.identity))fail('TRANSACTION_OR_IDENTITY_MISMATCH');
      if(!uuid(p.ownerId)||(expected.ownerId!==null&&p.ownerId!==expected.ownerId)||(s.ownerId!==null&&s.ownerId!==p.ownerId))fail('OWNER_MISMATCH');
      if(p.enrollment!=='COMPLETED'||!text(p.policyVersion)||!text(p.authoritySessionBinding)||!['session','device','policy'].every(k=>p.requirements?.[k]==='SATISFIED'))fail('ADMISSION_NOT_AUTHORIZED');
      if(p.expiresAt<=now())fail('EXPIRED_OR_INVALID_TIME');
      if(await store.consume(p.transaction,expected,Math.min(p.expiresAt,expected.expiresAt))!==true)fail('UNKNOWN_OR_REPLAYED_TRANSACTION');
      if(p.expiresAt<=now())fail('EXPIRED_OR_INVALID_TIME');
      return {version:ENROLLMENT_CONTRACT_VERSION,admission:'AUTHORIZED',identity:s.identity,ownerId:p.ownerId,relyingParty:p.relyingParty,sessionBinding:s.sessionBinding,transaction:p.transaction,expiresAt:p.expiresAt,policyVersion:p.policyVersion};
    }
  };
}

/** VVAULT-side integration primitive, NOT an implemented VVAULT route. attest must
 * authenticate/bind the existing VVAULT workflow to this verified identity+transaction,
 * resolve the canonical owner using authoritative provider linkage, and read current
 * stored activation/session/device/legal policy state. It must never trust browser
 * booleans. It must not regenerate recovery codes or mutate saved checkpoints.
 * A pending result creates no completion token; redirect/status alone grants nothing.
 */
export async function createAuthorityCompletion({handoff,authPublicKey,authIssuer,authorityIssuer,authoritySigningKey,attest,now=()=>Math.floor(Date.now()/1000)}) {
  const h=decode(handoff,authPublicKey,{issuer:authIssuer,audience:authorityIssuer,kind:'HANDOFF',now:now()});
  identity(h.identity);
  if(h.canonicalConsents!==undefined){if(h.intent!=='SIGN_UP')fail('INVALID_CANONICAL_CONSENT');consentProof(h.canonicalConsents,h.issuedAt);}
  if(h.contact!==undefined && (!['google','email'].includes(h.identity.provider)||!text(h.contact?.email)||h.contact.email.length>320||!/^[^\s@]+@[^\s@]+$/.test(h.contact.email)||h.contact.emailVerified!==true))fail('INVALID_VERIFIED_CONTACT');
  if(!uuid(h.transaction)||!text(h.sessionBinding)||!text(h.relyingParty)||!['SIGN_IN','SIGN_UP'].includes(h.intent)||(h.ownerId!==null&&!uuid(h.ownerId)))fail('INVALID_HANDOFF');
  if(typeof attest!=='function')fail('AUTHORITATIVE_ATTESTER_REQUIRED');
  const a=await attest(Object.freeze({...h,identity:Object.freeze({...h.identity})}));
  if(!a||a.enrollment!=='COMPLETED')return {disposition:'ENROLLMENT_REQUIRED',checkpoint:['DEVICE','CONSENT','PASSKEY','RECOVERY_CODES','ACTIVATION'].includes(a?.checkpoint)?a.checkpoint:'AUTHORITY_STATUS_REQUIRED'};
  if(!uuid(a.ownerId)||(h.ownerId!==null&&h.ownerId!==a.ownerId)||digest(identity(a.identity))!==digest(h.identity))fail('OWNER_OR_IDENTITY_CONFLICT');
  if(!text(a.policyVersion)||!text(a.authoritySessionBinding)||!['session','device','policy'].every(k=>a.requirements?.[k]==='SATISFIED'))fail('ADMISSION_NOT_AUTHORIZED');
  const issuedAt=now();
  if(h.expiresAt<=issuedAt)fail('EXPIRED_TRANSACTION');
  const p={version:ENROLLMENT_CONTRACT_VERSION,kind:'COMPLETION',issuer:authorityIssuer,audience:authIssuer,issuedAt,expiresAt:Math.min(issuedAt+60,h.expiresAt),transaction:h.transaction,relyingParty:h.relyingParty,sessionBinding:h.sessionBinding,identity:h.identity,ownerId:a.ownerId,handoffDigest:digest(h),enrollment:'COMPLETED',requirements:{session:'SATISFIED',device:'SATISFIED',policy:'SATISFIED'},policyVersion:a.policyVersion,authoritySessionBinding:a.authoritySessionBinding};
  return {completion:encode(p,authoritySigningKey),expiresAt:p.expiresAt};
}
