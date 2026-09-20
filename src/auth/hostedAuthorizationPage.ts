import type { AuthAppConfig, AuthProviderConfig } from '../types.js';

function escapeHtml(value: string) {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export function renderHostedAuthorizationPage(input: {
  config: AuthAppConfig;
  providers: AuthProviderConfig[];
  authorizationRequest: string;
  authorizationReturn: string;
  consentRequired: boolean;
}) {
  const boot = JSON.stringify({
    app: input.config.app,
    providers: input.providers.filter((provider) => provider.enabled && provider.available),
    docs: input.config.docs.filter((doc) => doc.required),
    authorizationRequest: input.authorizationRequest,
    authorizationReturn: input.authorizationReturn,
    consentRequired: input.consentRequired,
  }).replace(/</g, '\\u003c');

  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${escapeHtml(input.config.app.name)} authorization</title><style>body{font:16px system-ui;margin:0;background:#10131a;color:#f5f7fb;display:grid;min-height:100vh;place-items:center}.card{max-width:420px;padding:28px;border:1px solid #394050;border-radius:14px;background:#191e29}button{width:100%;padding:12px;margin:8px 0}label{display:block;margin:12px 0}a{color:#a9d5ff}.error{color:#ffb4b4}</style></head><body><main class="card"><h1 id="title"></h1><p id="message"></p><section id="providers"></section><form id="consent" hidden><div id="documents"></div><button type="submit">Accept and continue</button></form><p id="error" class="error" role="alert"></p></main><script>(()=>{const boot=${boot};const q=id=>document.getElementById(id);q('title').textContent=boot.app.name;q('message').textContent=boot.consentRequired?'Review and accept the required documents to continue.':'Choose a sign-in provider to continue.';const error=m=>q('error').textContent=m||'';if(boot.consentRequired){q('consent').hidden=false;q('documents').replaceChildren(...boot.docs.map(doc=>{const label=document.createElement('label');const box=document.createElement('input');box.type='checkbox';box.dataset.key=doc.key;const link=document.createElement('a');link.href=doc.url;link.target='_blank';link.rel='noopener noreferrer';link.textContent=doc.label;label.append(box,' I agree to ',link);return label;}));q('consent').addEventListener('submit',async event=>{event.preventDefault();const consent={};for(const box of q('documents').querySelectorAll('input[data-key]'))consent[box.dataset.key]=box.checked;const response=await fetch('/api/auth/consent',{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'},body:JSON.stringify({consent})});const body=await response.json().catch(()=>({}));if(!response.ok){error(body.error||'Consent could not be recorded.');return;}location.assign(boot.authorizationReturn+'?authorization_request='+encodeURIComponent(boot.authorizationRequest));});return;}if(!boot.providers.length){error('No sign-in provider is available.');return;}for(const provider of boot.providers){const button=document.createElement('button');button.type='button';button.textContent=provider.label;button.addEventListener('click',()=>{const target=new URL('/api/auth/'+encodeURIComponent(provider.provider),location.origin);target.searchParams.set('authorization_request',boot.authorizationRequest);target.searchParams.set('authorization_return',boot.authorizationReturn);location.assign(target);});q('providers').append(button);}})();</script></body></html>`;
}
