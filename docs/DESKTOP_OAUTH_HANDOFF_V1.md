# Desktop OAuth handoff v1

Contract: `life.auth.desktop-handoff/v1`. Source: `src/auth/desktopHandoff.ts`.

AUTH supplies a reusable host-side coordinator and callback-page renderer. It does not host a product login page or manage OS windows. The consuming desktop host integrates this module (or implements this versioned interface in its native language) with its existing OAuth/session adapter. No new token format, identity authority, or runtime service is introduced.

## Integration

1. Register the native public client using existing `AuthPublicClient` policy plus its server-registered `appId` in `DesktopClientRegistration`. The coordinator includes AUTH’s existing `app` selector so multi-product authorities do not default to another product. The exchange adapter must select that same app configuration. Prefer an exclusive loopback listener on an OS-assigned port; bind before browser launch. Explicitly registered deep links use the same callback validation. Pin one HTTPS issuer and token endpoint. Never follow token-exchange redirects.
2. Implement `DesktopHost` in the primary application process. Secondary activation processes forward callbacks through authenticated, user-scoped IPC and exit without opening a window. Serialize all coordinator calls on that primary instance. Do not log callback URLs, authorization codes, tokens, PKCE verifiers or pending records.
3. Before `begin(callbackUri, resumeReference)`, persist the opaque local resume reference independently of pending secrets. Keep account ownership on saved workspace state. Begin saves an OS-protected transaction before opening the system browser; never use an embedded webview. Registration passed to the coordinator must come from trusted application configuration.
4. Deliver browser callbacks to `callback(url)`. The coordinator validates callback/state/PKCE/client/issuer binding and expiry, marks the transaction exchanging before asynchronous work, then delegates token exchange to the existing OAuth client. `exchange` must verify issuer, audience/client, token validity, user identity, and all existing consent/enrollment/admission requirements. Validate OIDC nonce where the provider flow uses one. Returned issuer/client metadata must derive from verified results, never from browser claims. No local account or owner ID is proof of admission.
5. `commitSession` must atomically verify current generation and pending transaction, securely persist the validated session, and erase pending secrets. Never switch accounts implicitly; apply the product's explicit account-switch policy. Restore only the matching authorized account's workspace, then activate the existing instance. Each asynchronous host operation must observe its AbortSignal and generation immediately before side effects. Timeouts are bounded to 30 seconds; failure never means successful focus or admission.
6. On authenticated completion, the loopback callback host serves `desktopCompletionPage(appName, activationUri)` with all returned headers. For direct deep links, the browser return surface may show the page only after a separate host-confirmed completion signal; otherwise show a neutral return state, not authenticated success. This signal is a host integration requirement, not a new authorization credential.

The activation URI is trusted registration metadata of the shape `<registered-scheme>://auth-complete`, with no path, query, fragment or credentials. It carries no authority. Activation only raises the existing instance; it must never sign in, consume a code, select an account, or create a window. The renderer attempts activation automatically and retains an explicit **Open <App>** link. Custom protocol registration must target the single-instance dispatcher. Browser/OS policies may require a click; report `user-action-required` rather than claiming foreground success.

## Lifecycle and recovery

States: pending, exchanging, authenticated, cancelled, denied, timed-out, recoverable-error. Expired callbacks are rejected; the host also schedules `expire()` at the persisted request deadline (ten minutes, matching existing AUTH requests). Authorization codes retain the existing server-side two-minute lifetime and single-use semantics.

`cancel()` invalidates pending requests without deleting workspace state. `signOut()` invalidates pending requests and clears local credentials; the host also invokes its existing remote logout/revocation flow and reports remote failure. Account switching must invalidate the current generation before composing the next account. Never allow stale restore/exchange results to write sessions or restore the prior account.

After crash/reboot, call `recover(callbackUri, savedResumeReference)`: abandon any possibly consumed exchange, validate/refresh existing secure session state, and restore the workspace; otherwise initiate a fresh transaction. Secure storage uses DPAPI/Keychain/platform equivalent. `restoreSession` must never persist late results after cancellation and must enforce existing current admission rules. A restoration network error is explicit and retryable; it does not erase user state or claim authentication success.

## Verification and limits

Run `bin/node20 --test src/test/desktop-handoff.test.mjs`; it is also included in `npm test` through `test:wizard`. Synthetic hosts prove coordinator ordering, cancellation, binding, replay, expiry, recovery, page secrecy and fallback. They do not prove an OS adapter, provider deployment, or automatic focus.

Product acceptance requires a real host run: originating workspace → Sign in → foreground system browser → provider → secure callback → same desktop process/window foreground → original authorized workspace. Repeat denial, timeout, interrupted exchange, restart, sign-out and account switch. Confirm no duplicate windows, pasted codes, manual refresh, cross-account restoration, or secrets in browser page/logs. Contract development is complete separately from this product acceptance.

See [Desktop handoff repair 1.0.1](DESKTOP_HANDOFF_REPAIR_V1_0_1.md) for sanitized callback failure continuation, the recovery-page renderer, and deployment evidence requirements.
