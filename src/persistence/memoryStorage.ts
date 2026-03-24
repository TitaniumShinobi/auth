import crypto from 'node:crypto';

import type {
  ConsentAcceptance,
  CreateCredentialUserInput,
  StoredUser,
  StorageAdapter,
  UpsertOAuthUserInput,
} from '../types.js';

function createId(prefix: string) {
  return `${prefix}_${crypto.randomUUID()}`;
}

export class MemoryStorageAdapter implements StorageAdapter {
  private readonly users = new Map<string, StoredUser>();
  private readonly usersByEmail = new Map<string, string>();
  private readonly providerLinks = new Map<string, string>();
  private readonly consentMap = new Map<string, ConsentAcceptance[]>();

  async initialize() {}

  async findUserByEmail(email: string) {
    const id = this.usersByEmail.get(email.toLowerCase());
    return id ? this.users.get(id) ?? null : null;
  }

  async findUserById(id: string) {
    return this.users.get(id) ?? null;
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
    const linkKey = `${input.provider}:${input.providerUserId}`;
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
    return user;
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
}
