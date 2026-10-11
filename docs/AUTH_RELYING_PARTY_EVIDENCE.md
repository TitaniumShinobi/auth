# Relying-party evidence

A relying party consumes an identity authority; it does not become that authority. Its observation declares `authenticationRole: "RELYING_PARTY"` and identifies the authority and deployment revision it actually exercised.

Product evidence covers its own state binding, PKCE generation, callback handling, session persistence, logout cleanup, and user-visible failure behavior. Authority evidence separately covers code/token validation, rotation, replay prevention, revocation, expiry, and redirect registration. Shared cryptographic and logging guarantees require evidence from both sides. Health alone proves none of these.

Reviewed authority evidence may be supplied to `auth wizard` with `--authority-evidence <json> --authority-sha256 <independently trusted digest>`. The digest pins the reviewed bytes but is not a signature or proof of origin. Evidence must contain no credentials, bearer tokens, authorization codes, cookies, private keys, or user records. Wrong authority/revision, stale evidence, conflicts, missing references, or absent owner proof fail closed.

AUTH no longer ships a local product-specific conformance collector. Each authority must publish its own controlled, secret-free test evidence. Missing authority proof is `EXTERNAL_ACTION_REQUIRED`; missing reusable AUTH validation logic is `AUTH_DEVELOPMENT_REQUIRED`; product-side observation seams are `AGENT_INTEGRATION_REQUIRED`. Any authorized change is followed by fresh observation and VERIFY.
