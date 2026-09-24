export type AuthProviderId = string;

export type AuthLegalDoc = {
  product: string;
  docType: string;
  key: string;
  version: string;
  label: string;
  url: string;
  required: boolean;
};

export type AuthTurnstileConfig = {
  required: boolean;
  enabled: boolean;
  siteKey?: string;
};

export type AuthProviderDefinition = {
  provider: AuthProviderId;
  label: string;
  enabled: boolean;
  /** Optional provider callback pinned to this product's allowed origin. */
  callbackUrl?: string;
};

export type AuthProviderConfig = AuthProviderDefinition & {
  available: boolean;
  reason?: string;
};

export type AuthAppConfig = {
  app: {
    id: string;
    name: string;
    brandTagline?: string;
  };
  oauth?: {
    envPrefix?: string;
  };
  allowedOrigins: string[];
  redirects: {
    postLoginPath: string;
    postLogoutPath?: string;
  };
  credentials: {
    enabled: boolean;
  };
  docs: AuthLegalDoc[];
  turnstile: AuthTurnstileConfig;
  providers: AuthProviderDefinition[];
  publicClients?: AuthPublicClient[];
  sessionFederation?: {
    enabled: boolean;
    assertionSecretEnv: string;
  };
};

export type AuthPublicClient = {
  clientId: string;
  authorizationUiUrl: string;
  redirectUris?: string[];
  loopback?: {
    hosts: string[];
    path: string;
    allowDynamicPorts: boolean;
  };
  scopes?: string[];
};

export type NativeClientBinding = {
  clientId: string;
  applicationId: string;
};

export type SessionUser = {
  /** Signed native-client identity; current registration must still be checked. */
  nativeClient?: NativeClientBinding;
  providerIdentity?: import('./auth/canonicalOwner.js').VerifiedProviderIdentity;
  id: string;
  sub: string;
  uid: string;
  lifeUserId?: string;
  vvaultUserId?: string;
  supabaseUserId?: string;
  email: string;
  name: string;
  picture?: string;
  auth_provider: string;
  /** Derived by AUTH from the registered browser app or OAuth client. */
  relyingPartyId?: 'chatty' | 'chatty-cli' | 'vvault';
  /** Signed inside the access token. Contains identity binding only, never DOB. */
  actorAttestation?: ActorAttestationV1;
  /** Additive, signed readiness evidence for VVAULT account-context projection. */
  accountContextReadiness?: AccountContextReadinessV1;
};

export type AgeAssurance = 'adult' | 'minor' | 'unknown';

export type ActorAttestationV1 = {
  version: 'life-auth-actor-attestation/v1';
  subject: string;
  vvaultOwnerId: string;
  issuer: 'quantum-auth';
  ageAssurance?: AgeAssurance;
};

export type CanonicalOwnerEvidenceSource =
  | 'ovvaults_user'
  | 'cache'
  | 'supabase_found'
  | 'supabase_upserted'
  | 'local_registry';

export type AccountContextReadinessV1 = {
  version: 'life-auth-account-context-readiness/v1';
  ready: boolean;
  subject: string;
  reason: 'canonical_owner_verified' | 'canonical_owner_unverified';
  vvaultOwnerId?: string;
  evidenceSource?: CanonicalOwnerEvidenceSource;
};

export type AccountContextProfileV1 = {
  displayName: string;
  ageAssurance?: Exclude<AgeAssurance, 'unknown'>;
};

export type AccountContextAssertionV1 = {
  version: 'life-auth-account-context-assertion/v1';
  subject: string;
  vvaultOwnerId: string;
  issuer: string;
  audience: 'vvault';
  sessionId: string;
  assertionId: string;
  keyId: string;
  issuedAt: number;
  expiresAt: number;
  accountContext: AccountContextProfileV1;
};

export type VvaultAccessScope =
  | 'constructs:read'
  | 'identity:read'
  | 'knowledge:read'
  | 'memory:read'
  | 'transcripts:read'
  | 'transcripts:append'
  | 'work:read';

export type VvaultAccessAssertionV2 = {
  version: 'life-auth-vvault-access-assertion/v2';
  subject: string;
  vvaultOwnerId: string;
  issuer: string;
  audience: 'vvault';
  sessionId: string;
  assertionId: string;
  keyId: string;
  issuedAt: number;
  expiresAt: number;
  scopes: VvaultAccessScope[];
  relyingPartyId: 'chatty' | 'chatty-cli';
};

export type SessionPayload = SessionUser & {
  exp: number;
  iat: number;
};

export type StoredUser = {
  id: string;
  email: string;
  displayName: string;
  passwordHash: string | null;
  avatarUrl: string | null;
  authProvider: string;
  createdAt: string;
  updatedAt: string;
  lastLoginAt: string | null;
  /** LIFE-format id (Chatty `user_id`), cached after first resolution */
  lifeUserId?: string | null;
  /** Supabase `public.users.id` UUID string */
  supabaseUserId?: string | null;
  /** Optional coarse assurance imported from an authorized verifier; never a birth date. */
  ageAssurance?: AgeAssurance;
};

export type ProviderAccount = {
  id: string;
  userId: string;
  provider: string;
  providerUserId: string;
  email: string | null;
  displayName: string | null;
  avatarUrl: string | null;
  profileJson: string;
  accessTokenEncrypted: string | null;
  accessTokenScope: string | null;
  connectedAt: string | null;
  connectionUpdatedAt: string | null;
  createdAt: string;
  updatedAt: string;
};

export type ConsentAcceptance = {
  key: string;
  version: string;
  label: string;
  url: string;
  acceptedAt: string;
};

export type CreateCredentialUserInput = {
  email: string;
  displayName: string;
  passwordHash: string;
};

export type UpsertOAuthUserInput = {
  provider: string;
  providerUserId: string;
  email: string;
  displayName: string;
  avatarUrl?: string | null;
  profile: Record<string, unknown>;
};

export type UpsertProviderAccountConnectionInput = {
  userId: string;
  provider: string;
  providerUserId: string;
  email?: string | null;
  displayName?: string | null;
  avatarUrl?: string | null;
  profile: Record<string, unknown>;
  accessTokenEncrypted: string;
  accessTokenScope?: string | null;
  connectedAt?: string | null;
};

export type ProviderProfile = {
  providerUserId: string;
  email: string;
  displayName: string;
  avatarUrl?: string;
  raw: Record<string, unknown>;
};

export type OAuthStartContext = {
  origin: string;
  callbackUrl: string;
  state: string;
};

export type OAuthExchangeContext = {
  code: string;
  callbackUrl: string;
};

export type OAuthProviderClient = {
  provider: string;
  label: string;
  isConfigured: () => boolean;
  buildAuthorizationUrl: (context: OAuthStartContext) => string;
  exchangeCodeForProfile: (context: OAuthExchangeContext) => Promise<ProviderProfile>;
};

export type StorageAdapter = {
  initialize: () => Promise<void>;
  findUserByEmail: (email: string) => Promise<StoredUser | null>;
  findUserByLifeUserId?: (subject:string) => Promise<StoredUser | null>;
  findUserById: (id: string) => Promise<StoredUser | null>;
  findProviderAccount: (userId: string, provider: string) => Promise<ProviderAccount | null>;
  createCredentialUser: (input: CreateCredentialUserInput) => Promise<StoredUser>;
  updateUserLogin: (userId: string) => Promise<void>;
  upsertOAuthUser: (input: UpsertOAuthUserInput) => Promise<StoredUser>;
  upsertProviderAccountConnection: (input: UpsertProviderAccountConnectionInput) => Promise<ProviderAccount>;
  clearProviderAccountConnection: (userId: string, provider: string) => Promise<void>;
  replaceConsentAcceptances: (userId: string, appId: string, docs: ConsentAcceptance[]) => Promise<void>;
  hasAcceptedConsentDocs?: (userId: string, appId: string, docs: {key:string;version:string}[]) => Promise<boolean>;
  hasAcceptedConsentKeys: (userId: string, appId: string, requiredKeys: string[]) => Promise<boolean>;
  updateUserLifeAnchors: (
    userId: string,
    lifeUserId: string,
    supabaseUserId: string | null,
  ) => Promise<void>;
};

export type AppConfigStore = {
  getConfig: (req?: any) => Promise<AuthAppConfig>;
};

export type TurnstileVerifier = (token: string, remoteIp: string | null) => Promise<boolean>;
