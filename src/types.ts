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
};

export type SessionUser = {
  id: string;
  sub: string;
  uid: string;
  email: string;
  name: string;
  picture?: string;
  auth_provider: string;
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
  findUserById: (id: string) => Promise<StoredUser | null>;
  createCredentialUser: (input: CreateCredentialUserInput) => Promise<StoredUser>;
  updateUserLogin: (userId: string) => Promise<void>;
  upsertOAuthUser: (input: UpsertOAuthUserInput) => Promise<StoredUser>;
  replaceConsentAcceptances: (userId: string, appId: string, docs: ConsentAcceptance[]) => Promise<void>;
  hasAcceptedConsentKeys: (userId: string, appId: string, requiredKeys: string[]) => Promise<boolean>;
  updateUserLifeAnchors: (
    userId: string,
    lifeUserId: string,
    supabaseUserId: string | null,
  ) => Promise<void>;
};

export type AppConfigStore = {
  getConfig: () => Promise<AuthAppConfig>;
};

export type TurnstileVerifier = (token: string, remoteIp: string | null) => Promise<boolean>;
