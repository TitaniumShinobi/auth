/** User-safe terminal errors; no reflected exception, token, URL or SQL text. */
import {randomUUID} from 'node:crypto';
export function recoverableFailure(reason: string, correlation: unknown) {
 const requestId=typeof correlation==='string'&&/^[a-f0-9-]{16,64}$/.test(correlation)?correlation:randomUUID();
 const allowed=new Set(['temporarily_unavailable','access_denied','invalid_state','missing_code','missing_session','unsupported_provider','AUTHENTICATION_FAILED','DESKTOP_HANDOFF_REQUIRED']);
 const error=allowed.has(reason)?reason:'temporarily_unavailable';
 const message='Sign-in could not complete. Return to the application and try again. If this continues, provide the reference below to support.';
 const body={ok:false,state:'RECOVERABLE_ERROR',error,message,requestId};
 const html=`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Sign-in could not complete</title></head><body><main><h1>Sign-in could not complete</h1><p>${message}</p><p>Reference: <code>${requestId}</code></p><p>You can close this tab and retry Sign In or Sign Up in the application.</p></main></body></html>`;
 return {body,html,requestId};
}
export function sendRecoverableFailure(req:any,res:any,status:number,reason:string){
 const failure=recoverableFailure(reason,req._rid);
 res.setHeader('Cache-Control','no-store');res.setHeader('Referrer-Policy','no-referrer');
 res.setHeader('X-Request-ID',failure.requestId);res.setHeader('X-Content-Type-Options','nosniff');
 res.setHeader('Content-Security-Policy',"default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'");
 return String(req.headers?.accept||'').includes('text/html')?res.status(status).type('html').send(failure.html):res.status(status).json(failure.body);
}
