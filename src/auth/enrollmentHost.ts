import {pairedWelcomeEvent,submitPairedWelcome} from './pairedWelcomeEvent.js';
import {canonicalConsentManifest,acceptedCanonicalConsent} from './enrollmentCanonicalConsent.js';
import crypto from 'node:crypto';
import { EnrollmentStore } from './enrollmentStore.js';
import { resolveVvaultAccessAssertionConfig } from './vvaultAccessAssertion.js';
import { normalizeVerifiedProviderIdentity } from './canonicalOwner.js';

export function mountEnrollmentHost(app: any, readSession: (req: any) => Promise<any>, productConsent: (session:any,input:any,record:boolean)=>Promise<any>, readCanonicalDocuments=canonicalConsentManifest) {
  let store: EnrollmentStore | undefined;
  async function handle(req: any, res: any, operation: string) {
    res.set('Cache-Control','no-store');
    // Browser cookies are not accepted: only the authenticated product backchannel.
    if (req.get('X-Chatty-Auth-Bridge') !== 'auth.enrollment.v1' || !/^Bearer\s+\S+$/i.test(req.get('authorization') || '') || req.headers.cookie) {
      return res.status(403).json({ok:false,errorCode:'ENROLLMENT_BACKCHANNEL_REQUIRED'});
    }
    try {
    const authenticated = await readSession(req);
    if ('error' in authenticated) return res.status(authenticated.status).json({ok:false,errorCode:'AUTH_SESSION_REQUIRED'});
    const s=authenticated.session;
    const provider=normalizeVerifiedProviderIdentity(s.providerIdentity);
    if (!provider || !s.sub || !['chatty','chatty-cli'].includes(s.relyingPartyId)) return res.status(409).json({ok:false,errorCode:'AUTHENTICATED_IDENTITY_REQUIRED'});
    const readiness=s.accountContextReadiness;
    const canonicalOwner=readiness?.ready===true && readiness.reason==='canonical_owner_verified' && readiness.subject===s.sub && readiness.vvaultOwnerId===s.vvaultUserId && s.actorAttestation?.subject===s.sub && s.actorAttestation?.vvaultOwnerId===s.vvaultUserId ? s.vvaultUserId : null;
    let canonicalDocuments:any[]=operation==='start' && req.body?.intent==='SIGN_UP' ? await readCanonicalDocuments() : [];
    const canonicalConsents=operation==='start' && req.body?.intent==='SIGN_UP' ? acceptedCanonicalConsent(req.body,canonicalDocuments) : null;
    if(operation==='start' && req.body?.intent==='SIGN_UP' && !canonicalConsents)return res.status(409).json({ok:false,errorCode:'CANONICAL_CONSENT_REQUIRED'});
    const consent=await productConsent(s,req.body,operation==='start' && req.body?.intent==='SIGN_UP');
    if(consent.required && operation!=='admission')return res.status(409).json({ok:false,errorCode:'PRODUCT_CONSENT_REQUIRED',productConsentRequired:true,consentDocuments:consent.docs,canonicalConsentDocuments:canonicalDocuments});
    const identity={subject:s.sub,provider:provider.provider,providerSubject:provider.subject,providerIssuer:provider.issuer};
      const path=process.env.AUTH_ENROLLMENT_STORE_PATH;
      const authorityPem=process.env.AUTH_ENROLLMENT_AUTHORITY_PUBLIC_KEY_PEM?.replace(/\\n/g,'\n');
      const signing=resolveVvaultAccessAssertionConfig();
      if (!path || !authorityPem || !signing) return res.status(503).json({ok:false,errorCode:'ENROLLMENT_HOST_NOT_CONFIGURED'});
      store ||= new EnrollmentStore(path);
      if(operation==='admission') {
        const admission=await store.admission(authenticated.sessionId);
        const matches=!consent.required && admission && admission.expiresAt>Math.floor(Date.now()/1000) && JSON.stringify(admission.identity)===JSON.stringify(identity) && admission.relyingParty===s.relyingPartyId && (!canonicalOwner || canonicalOwner===admission.ownerId);
        if(!matches && (consent.required || !canonicalOwner)) canonicalDocuments=await readCanonicalDocuments();
        return res.json({ok:true,...(matches ? admission : {admission:'ENROLLMENT_REQUIRED',identity,ownerId:canonicalOwner,ownerResolved:Boolean(canonicalOwner),productConsentRequired:consent.required,consentDocuments:consent.docs,canonicalConsentDocuments:canonicalDocuments})});
      }
      const moduleUrl=new URL('../../scripts/auth-enrollment-handoff.mjs',import.meta.url).href;
      // dist/auth -> repository scripts; same path when running src/auth during tests.
      const {createEnrollmentCoordinator}=await import(moduleUrl);
      const coordinator=createEnrollmentCoordinator({
        issuer:signing.issuer, authorityIssuer:process.env.AUTH_ENROLLMENT_AUTHORITY_ISSUER || 'vvault',
        signingKey:crypto.createPrivateKey(signing.privateKeyPem), authorityPublicKey:crypto.createPublicKey(authorityPem),store,
        resolveSession:async()=>({sessionBinding:authenticated.sessionId,identity,ownerId:canonicalOwner,...(canonicalConsents?{canonicalConsents}:{}),...(provider.verifiedEmail?{contact:{email:provider.verifiedEmail,emailVerified:true}}:{})}),
        authorizeRelyingParty:async(_context: any,party: string)=>party===s.relyingPartyId,
      });
      if(operation==='start') return res.json({ok:true,...await coordinator.start(null,{intent:req.body?.intent,relyingParty:s.relyingPartyId})});
      const admission=await coordinator.complete(null,req.body?.completion);
      await store.saveAdmission(admission);
      let welcomeDelivery='NOT_CONFIGURED';
      if(process.env.AUTH_PAIRED_WELCOME_ENABLED==='true' && admission.relyingParty==='chatty') {
        try { welcomeDelivery=await submitPairedWelcome(pairedWelcomeEvent(admission,signing.privateKeyPem,signing.issuer),process.env.AUTH_ENROLLMENT_AUTHORITY_ORIGIN || ''); }
        catch { welcomeDelivery='NOT_QUEUED'; }
      }
      return res.json({ok:true,...admission,welcomeDelivery});
    } catch(error: any) {
      const known=new Set(['AUTHENTICATION_REQUIRED','AUTHENTICATED_IDENTITY_REQUIRED','RELYING_PARTY_NOT_AUTHORIZED','INVALID_REQUEST','INVALID_OWNER','INVALID_PROOF','INVALID_SIGNATURE','PROVENANCE_MISMATCH','EXPIRED_OR_INVALID_TIME','UNKNOWN_OR_REPLAYED_TRANSACTION','EXPIRED_TRANSACTION','TRANSACTION_OR_IDENTITY_MISMATCH','OWNER_MISMATCH','ADMISSION_NOT_AUTHORIZED','PRODUCT_CONSENT_POLICY_UNAVAILABLE','CANONICAL_CONSENT_POLICY_UNAVAILABLE']);
      const code=known.has(error?.code)?error.code:'ENROLLMENT_HOST_UNAVAILABLE';
      return res.status(code==='ENROLLMENT_HOST_UNAVAILABLE'?503:409).json({ok:false,errorCode:code});
    }
  }
  app.post('/api/auth/enrollment/start',(req: any,res: any)=>handle(req,res,'start'));
  app.post('/api/auth/enrollment/complete',(req: any,res: any)=>handle(req,res,'complete'));
  app.get('/api/auth/enrollment/admission',(req: any,res: any)=>handle(req,res,'admission'));
}
