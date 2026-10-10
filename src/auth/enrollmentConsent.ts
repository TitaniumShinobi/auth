import type { StorageAdapter, AuthAppConfig } from '../types.js';
export function createEnrollmentConsent(storage: StorageAdapter, configStore: {getConfig:(request:any)=>Promise<AuthAppConfig>}) {
 return async (session:any, input:any, record:boolean) => {
  const appId=session.relyingPartyId==='chatty-cli'?'chatty':session.relyingPartyId;
  const config=await configStore.getConfig({query:{app:appId},headers:{}});
  const docs=config.docs.filter(doc=>doc.required).map(doc=>({...doc,version:process.env[`LEGAL_VERSION_CHATTY_${doc.key.split(':')[1]?.toUpperCase()}`] || doc.version}));
  if(config.app.id!==appId || !docs.length || !storage.hasAcceptedConsentDocs) throw Object.assign(new Error('PRODUCT_CONSENT_POLICY_UNAVAILABLE'),{code:'PRODUCT_CONSENT_POLICY_UNAVAILABLE'});
  const user=await storage.findUserByLifeUserId?.(session.sub);
  if(!user)throw Object.assign(new Error('AUTHENTICATION_REQUIRED'),{code:'AUTHENTICATION_REQUIRED'});
  if(record){
    if(!docs.every(doc=>input?.consent?.[doc.key]===true && input?.consentVersions?.[doc.key]===doc.version)) return {required:true,docs};
    await storage.replaceConsentAcceptances(user.id,appId,docs.map(doc=>({key:doc.key,version:doc.version,label:doc.label,url:doc.url,acceptedAt:new Date().toISOString()})));
  }
  return {required:!await storage.hasAcceptedConsentDocs(user.id,appId,docs),docs};
 };
}
