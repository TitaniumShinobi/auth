import crypto from 'node:crypto';

import type {
  ConsentAcceptance,
  CreateCredentialUserInput,
  ProviderAccount,
  StoredUser,
  StorageAdapter,
  UpsertOAuthUserInput,
  UpsertProviderAccountConnectionInput,
} from '../types.js';

function createId(prefix: string) {
  return `${prefix}_${crypto.randomUUID()}`;
}

function providerUserKey(provider: string, providerUserId: string) {
  return `${provider}:${providerUserId}`;
}

function userProviderKey(userId: string, provider: string) {
  return `${userId}:${provider}`;
}

export class MemoryStorageAdapter implements StorageAdapter {
  private readonly users = new Map<string, StoredUser>();
  private readonly usersByEmail = new Map<string, string>();
  private readonly providerLinks = new Map<string, string>();
  private readonly providerAccounts = new Map<string, ProviderAccount>();
  private readonly consentMap = new Map<string, ConsentAcceptance[]>();

  async initialize() {}

  async findUserByEmail(email: string) {
    const id = this.usersByEmail.get(email.toLowerCase());
    return id ? this.users.get(id) ?? null : null;
  }

  async findUserById(id: string) {
    return this.users.get(id) ?? null;
  }

  async findProviderAccount(userId: string, provider: string) {
    return this.providerAccounts.get(userProviderKey(userId, provider)) ?? null;
  }

  async createCredentialUser(input: CreateCredentialUserInput) {
    const now = new Date().toISOString();
    const user: StoredUser = {
      id: createId('user'),
      email: input.email.toLowerCase(),
      displayName: input.displayName,
      passwordHash: input.passwordHash,
      avatarUrl: null,
      authProvider: 'credentials',
      createdAt: now,
      updatedAt: now,
      lastLoginAt: null,
    };
    this.users.set(user.id, user);
    this.usersByEmail.set(user.email, user.id);
    return user;
  }

  async updateUserLogin(userId: string) {
    const current = this.users.get(userId);
    if (!current) return;
    this.users.set(userId, { ...current, lastLoginAt: new Date().toISOString(), updatedAt: new Date().toISOString() });
  }

  async upsertOAuthUser(input: UpsertOAuthUserInput) {
    const linkKey = providerUserKey(input.provider, input.providerUserId);
    const linkedId = this.providerLinks.get(linkKey);
    const now = new Date().toISOString();
    if (linkedId) {
      const current = this.users.get(linkedId);
      if (!current) throw new Error('Linked OAuth user missing');
      const updated = {
        ...current,
        displayName: input.displayName || current.displayName,
        avatarUrl: input.avatarUrl || current.avatarUrl,
        authProvider: input.provider,
        updatedAt: now,
      };
      this.users.set(current.id, updated);
      await this.writeProviderAccount({
        userId: current.id,
        provider: input.provider,
        providerUserId: input.providerUserId,
        email: input.email.toLowerCase(),
        displayName: input.displayName,
        avatarUrl: input.avatarUrl || null,
        profile: input.profile,
      });
      return updated;
    }

    const existingByEmail = await this.findUserByEmail(input.email);
    if (existingByEmail) {
      const updated = {
        ...existingByEmail,
        displayName: input.displayName || existingByEmail.displayName,
        avatarUrl: input.avatarUrl || existingByEmail.avatarUrl,
        authProvider: input.provider,
        updatedAt: now,
      };
      this.users.set(existingByEmail.id, updated);
      this.providerLinks.set(linkKey, existingByEmail.id);
      await this.writeProviderAccount({
        userId: existingByEmail.id,
        provider: input.provider,
        providerUserId: input.providerUserId,
        email: input.email.toLowerCase(),
        displayName: input.displayName,
        avatarUrl: input.avatarUrl || null,
        profile: input.profile,
      });
      return updated;
    }

    const user: StoredUser = {
      id: createId('user'),
      email: input.email.toLowerCase(),
      displayName: input.displayName,
      passwordHash: null,
      avatarUrl: input.avatarUrl || null,
      authProvider: input.provider,
      createdAt: now,
      updatedAt: now,
      lastLoginAt: null,
    };
    this.users.set(user.id, user);
    this.usersByEmail.set(user.email, user.id);
    this.providerLinks.set(linkKey, user.id);
    await this.writeProviderAccount({
      userId: user.id,
      provider: input.provider,
      providerUserId: input.providerUserId,
      email: input.email.toLowerCase(),
      displayName: input.displayName,
      avatarUrl: input.avatarUrl || null,
      profile: input.profile,
    });
    return user;
  }

  async upsertProviderAccountConnection(input: UpsertProviderAccountConnectionInput) {
    const now = new Date().toISOString();
    return this.writeProviderAccount({
      userId: input.userId,
      provider: input.provider,
      providerUserId: input.providerUserId,
      email: input.email ?? null,
      displayName: input.displayName ?? null,
      avatarUrl: input.avatarUrl ?? null,
      profile: input.profile,
      accessTokenEncrypted: input.accessTokenEncrypted,
      accessTokenScope: input.accessTokenScope ?? null,
      connectedAt: input.connectedAt ?? now,
      connectionUpdatedAt: now,
    });
  }

  async clearProviderAccountConnection(userId: string, provider: string) {
    const account = this.providerAccounts.get(userProviderKey(userId, provider));
    if (!account) return;
    this.providerAccounts.set(userProviderKey(userId, provider), {
      ...account,
      accessTokenEncrypted: null,
      accessTokenScope: null,
      connectedAt: null,
      connectionUpdatedAt: null,
      updatedAt: new Date().toISOString(),
    });
  }

  async replaceConsentAcceptances(userId: string, appId: string, docs: ConsentAcceptance[]) {
    this.consentMap.set(`${userId}:${appId}`, docs);
  }

  async hasAcceptedConsentKeys(userId: string, appId: string, requiredKeys: string[]) {
    if (requiredKeys.length === 0) return true;
    const accepted = this.consentMap.get(`${userId}:${appId}`) || [];
    const acceptedKeys = new Set(accepted.map((doc) => doc.key));
    return requiredKeys.every((key) => acceptedKeys.has(key));
  }

  async updateUserLifeAnchors(userId: string, lifeUserId: string, supabaseUserId: string | null) {
    const current = this.users.get(userId);
    if (!current) return;
    const now = new Date().toISOString();
    this.users.set(userId, {
      ...current,
      lifeUserId,
      supabaseUserId,
      updatedAt: now,
    });
  }

  private async writeProviderAccount(input: {
    userId: string;
    provider: string;
    providerUserId: string;
    email: string | null;
    displayName: string | null;
    avatarUrl: string | null;
    profile: Record<string, unknown>;
    accessTokenEncrypted?: string | null;
    accessTokenScope?: string | null;
    connectedAt?: string | null;
    connectionUpdatedAt?: string | null;
  }): Promise<ProviderAccount> {
    const now = new Date().toISOString();
    const key = userProviderKey(input.userId, input.provider);
    const existing = this.providerAccounts.get(key);
    const linkedUserId = this.providerLinks.get(providerUserKey(input.provider, input.providerUserId));
    const linkedKey = linkedUserId ? userProviderKey(linkedUserId, input.provider) : null;
    const linkedAccount = linkedKey ? this.providerAccounts.get(linkedKey) ?? null : null;

    if (linkedAccount && linkedUserId && linkedUserId !== input.userId) {
      this.providerAccounts.delete(linkedKey as string);
    }

    if (existing && existing.providerUserId !== input.providerUserId) {
      this.providerLinks.delete(providerUserKey(existing.provider, existing.providerUserId));
    }

    const source = existing ?? linkedAccount ?? null;
    const account: ProviderAccount = {
      id: source?.id || createId('acct'),
      userId: input.userId,
      provider: input.provider,
      providerUserId: input.providerUserId,
      email: input.email ?? source?.email ?? null,
      displayName: input.displayName ?? source?.displayName ?? null,
      avatarUrl: input.avatarUrl ?? source?.avatarUrl ?? null,
      profileJson: JSON.stringify(input.profile),
      accessTokenEncrypted: input.accessTokenEncrypted ?? source?.accessTokenEncrypted ?? null,
      accessTokenScope: input.accessTokenScope ?? source?.accessTokenScope ?? null,
      connectedAt: input.connectedAt ?? source?.connectedAt ?? null,
      connectionUpdatedAt: input.connectionUpdatedAt ?? source?.connectionUpdatedAt ?? null,
      createdAt: source?.createdAt || now,
      updatedAt: now,
    };

    this.providerAccounts.set(key, account);
    this.providerLinks.set(providerUserKey(input.provider, input.providerUserId), input.userId);
    return account;
  }
}
