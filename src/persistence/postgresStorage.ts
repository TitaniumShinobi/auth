import crypto from 'node:crypto';
import type { PrismaClient } from '@prisma/client';

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

type PgUserRow = {
  id: string;
  email: string;
  display_name: string;
  password_hash: string | null;
  avatar_url: string | null;
  auth_provider: string;
  life_user_id: string | null;
  supabase_user_id: string | null;
  created_at: Date;
  updated_at: Date;
  last_login_at: Date | null;
};

type PgProviderAccountRow = {
  id: string;
  user_id: string;
  provider: string;
  provider_user_id: string;
  email: string | null;
  display_name: string | null;
  avatar_url: string | null;
  profile_json: unknown;
  access_token_encrypted: string | null;
  access_token_scope: string | null;
  connected_at: Date | null;
  connection_updated_at: Date | null;
  created_at: Date;
  updated_at: Date;
};

function iso(value: Date | string | null | undefined) {
  if (!value) return null;
  return value instanceof Date ? value.toISOString() : value;
}

function mapUser(row: PgUserRow): StoredUser {
  return {
    id: row.id,
    email: row.email,
    displayName: row.display_name,
    passwordHash: row.password_hash,
    avatarUrl: row.avatar_url,
    authProvider: row.auth_provider,
    createdAt: iso(row.created_at) as string,
    updatedAt: iso(row.updated_at) as string,
    lastLoginAt: iso(row.last_login_at),
    lifeUserId: row.life_user_id ?? undefined,
    supabaseUserId: row.supabase_user_id ?? undefined,
  };
}

function mapProviderAccount(row: PgProviderAccountRow): ProviderAccount {
  return {
    id: row.id,
    userId: row.user_id,
    provider: row.provider,
    providerUserId: row.provider_user_id,
    email: row.email,
    displayName: row.display_name,
    avatarUrl: row.avatar_url,
    profileJson: JSON.stringify(row.profile_json ?? {}),
    accessTokenEncrypted: row.access_token_encrypted,
    accessTokenScope: row.access_token_scope,
    connectedAt: iso(row.connected_at),
    connectionUpdatedAt: iso(row.connection_updated_at),
    createdAt: iso(row.created_at) as string,
    updatedAt: iso(row.updated_at) as string,
  };
}

export class PostgresStorageAdapter implements StorageAdapter {
  constructor(private readonly prisma: PrismaClient) {}

  async initialize() {
    const [contract] = await this.prisma.$queryRawUnsafe<Array<{
      users: string | null;
      provider_accounts: string | null;
      consent_acceptances: string | null;
      auth_sessions: string | null;
      refresh_tokens: string | null;
      auth_session_events: string | null;
    }>>(`
      SELECT
        to_regclass('auth.users')::text AS users,
        to_regclass('auth.provider_accounts')::text AS provider_accounts,
        to_regclass('auth.consent_acceptances')::text AS consent_acceptances,
        to_regclass('auth.auth_sessions')::text AS auth_sessions,
        to_regclass('auth.refresh_tokens')::text AS refresh_tokens,
        to_regclass('auth.auth_session_events')::text AS auth_session_events;
    `);
    const missing = Object.entries(contract || {})
      .filter(([, relation]) => !relation)
      .map(([relation]) => relation);
    if (!contract || missing.length > 0) {
      throw Object.assign(
        new Error(`Canonical Auth schema is incomplete: ${missing.join(', ') || 'contract query returned no row'}`),
        { code: 'AUTH_SCHEMA_UNAVAILABLE' },
      );
    }
  }

  async findUserByEmail(email: string) {
    const rows = await this.prisma.$queryRawUnsafe<PgUserRow[]>(
      `
      SELECT *
      FROM auth.users
      WHERE email = $1
      LIMIT 1;
      `,
      email.toLowerCase(),
    );
    return rows[0] ? mapUser(rows[0]) : null;
  }

  async findUserByLifeUserId(subject:string) { const rows=await this.prisma.$queryRawUnsafe<{id:string}[]>('SELECT id FROM auth.users WHERE life_user_id=$1 LIMIT 2',subject); return rows.length===1?this.findUserById(rows[0].id):null; }

  async findUserById(id: string) {
    const rows = await this.prisma.$queryRawUnsafe<PgUserRow[]>(
      `
      SELECT *
      FROM auth.users
      WHERE id = $1
      LIMIT 1;
      `,
      id,
    );
    return rows[0] ? mapUser(rows[0]) : null;
  }

  async findProviderAccount(userId: string, provider: string) {
    const rows = await this.prisma.$queryRawUnsafe<PgProviderAccountRow[]>(
      `
      SELECT *
      FROM auth.provider_accounts
      WHERE user_id = $1
        AND provider = $2
      ORDER BY updated_at DESC
      LIMIT 1;
      `,
      userId,
      provider,
    );
    return rows[0] ? mapProviderAccount(rows[0]) : null;
  }

  async createCredentialUser(input: CreateCredentialUserInput) {
    const now = new Date();
    const user: StoredUser = {
      id: createId('user'),
      email: input.email.toLowerCase(),
      displayName: input.displayName,
      passwordHash: input.passwordHash,
      avatarUrl: null,
      authProvider: 'credentials',
      createdAt: now.toISOString(),
      updatedAt: now.toISOString(),
      lastLoginAt: null,
    };
    await this.prisma.$executeRawUnsafe(
      `
      INSERT INTO auth.users (
        id, email, display_name, password_hash, avatar_url, auth_provider,
        created_at, updated_at, last_login_at
      ) VALUES (
        $1, $2, $3, $4, NULL, $5,
        $6, $6, NULL
      );
      `,
      user.id,
      user.email,
      user.displayName,
      user.passwordHash,
      user.authProvider,
      now,
    );
    return user;
  }

  async updateUserLogin(userId: string) {
    const now = new Date();
    await this.prisma.$executeRawUnsafe(
      `
      UPDATE auth.users
      SET last_login_at = $2,
          updated_at = $2
      WHERE id = $1;
      `,
      userId,
      now,
    );
  }

  async upsertOAuthUser(input: UpsertOAuthUserInput) {
    const now = new Date();
    const providerRows = await this.prisma.$queryRawUnsafe<{ user_id: string }[]>(
      `
      SELECT user_id
      FROM auth.provider_accounts
      WHERE provider = $1
        AND provider_user_id = $2
      LIMIT 1;
      `,
      input.provider,
      input.providerUserId,
    );
    const existingUser =
      (providerRows[0]?.user_id ? await this.findUserById(providerRows[0].user_id) : null)
      || await this.findUserByEmail(input.email);
    const user = existingUser ?? {
      id: createId('user'),
      email: input.email.toLowerCase(),
      displayName: input.displayName,
      passwordHash: null,
      avatarUrl: input.avatarUrl || null,
      authProvider: input.provider,
      createdAt: now.toISOString(),
      updatedAt: now.toISOString(),
      lastLoginAt: null,
    };

    await this.prisma.$transaction(async (tx) => {
      if (existingUser) {
        await tx.$executeRawUnsafe(
          `
          UPDATE auth.users
          SET display_name = $2,
              avatar_url = $3,
              auth_provider = $4,
              updated_at = $5
          WHERE id = $1;
          `,
          existingUser.id,
          input.displayName || existingUser.displayName,
          input.avatarUrl || existingUser.avatarUrl,
          input.provider,
          now,
        );
      } else {
        await tx.$executeRawUnsafe(
          `
          INSERT INTO auth.users (
            id, email, display_name, password_hash, avatar_url, auth_provider,
            created_at, updated_at, last_login_at
          ) VALUES (
            $1, $2, $3, NULL, $4, $5,
            $6, $6, NULL
          );
          `,
          user.id,
          user.email,
          user.displayName,
          user.avatarUrl,
          user.authProvider,
          now,
        );
      }

      await tx.$executeRawUnsafe(
        `
        INSERT INTO auth.provider_accounts (
          id, user_id, provider, provider_user_id, email, display_name, avatar_url,
          profile_json, access_token_encrypted, access_token_scope, connected_at,
          connection_updated_at, created_at, updated_at
        ) VALUES (
          $1, $2, $3, $4, $5, $6, $7,
          $8::jsonb, NULL, NULL, NULL,
          NULL, $9, $9
        )
        ON CONFLICT(provider, provider_user_id) DO UPDATE SET
          user_id = excluded.user_id,
          email = excluded.email,
          display_name = excluded.display_name,
          avatar_url = excluded.avatar_url,
          profile_json = excluded.profile_json,
          updated_at = excluded.updated_at;
        `,
        createId('acct'),
        user.id,
        input.provider,
        input.providerUserId,
        input.email.toLowerCase(),
        input.displayName,
        input.avatarUrl || null,
        JSON.stringify(input.profile),
        now,
      );
    });

    return (await this.findUserById(user.id)) as StoredUser;
  }

  async upsertProviderAccountConnection(input: UpsertProviderAccountConnectionInput) {
    const now = new Date();
    const connectedAt = input.connectedAt ? new Date(input.connectedAt) : now;
    const existingByUser = await this.findProviderAccount(input.userId, input.provider);
    const existingByProviderUser = (await this.prisma.$queryRawUnsafe<PgProviderAccountRow[]>(
      `
      SELECT *
      FROM auth.provider_accounts
      WHERE provider = $1
        AND provider_user_id = $2
      ORDER BY updated_at DESC
      LIMIT 1;
      `,
      input.provider,
      input.providerUserId,
    ))[0];

    if (existingByUser && existingByProviderUser && existingByUser.id !== existingByProviderUser.id) {
      await this.prisma.$executeRawUnsafe(
        `DELETE FROM auth.provider_accounts WHERE id = $1;`,
        existingByProviderUser.id,
      );
    }

    const source = existingByUser ?? (existingByProviderUser ? mapProviderAccount(existingByProviderUser) : null);
    const targetId = existingByUser?.id || existingByProviderUser?.id || createId('acct');
    await this.prisma.$executeRawUnsafe(
      `
      INSERT INTO auth.provider_accounts (
        id, user_id, provider, provider_user_id, email, display_name, avatar_url,
        profile_json, access_token_encrypted, access_token_scope, connected_at,
        connection_updated_at, created_at, updated_at
      ) VALUES (
        $1, $2, $3, $4, $5, $6, $7,
        $8::jsonb, $9, $10, $11,
        $12, $13, $12
      )
      ON CONFLICT(id) DO UPDATE SET
        user_id = excluded.user_id,
        provider = excluded.provider,
        provider_user_id = excluded.provider_user_id,
        email = excluded.email,
        display_name = excluded.display_name,
        avatar_url = excluded.avatar_url,
        profile_json = excluded.profile_json,
        access_token_encrypted = excluded.access_token_encrypted,
        access_token_scope = excluded.access_token_scope,
        connected_at = excluded.connected_at,
        connection_updated_at = excluded.connection_updated_at,
        updated_at = excluded.updated_at;
      `,
      targetId,
      input.userId,
      input.provider,
      input.providerUserId,
      input.email ?? source?.email ?? null,
      input.displayName ?? source?.displayName ?? null,
      input.avatarUrl ?? source?.avatarUrl ?? null,
      JSON.stringify(input.profile),
      input.accessTokenEncrypted,
      input.accessTokenScope ?? null,
      connectedAt,
      now,
      source?.createdAt ? new Date(source.createdAt) : now,
    );
    return (await this.findProviderAccount(input.userId, input.provider)) as ProviderAccount;
  }

  async clearProviderAccountConnection(userId: string, provider: string) {
    await this.prisma.$executeRawUnsafe(
      `
      UPDATE auth.provider_accounts
      SET access_token_encrypted = NULL,
          access_token_scope = NULL,
          connected_at = NULL,
          connection_updated_at = NULL,
          updated_at = $3
      WHERE user_id = $1
        AND provider = $2;
      `,
      userId,
      provider,
      new Date(),
    );
  }

  async replaceConsentAcceptances(userId: string, appId: string, docs: ConsentAcceptance[]) {
    await this.prisma.$transaction(async (tx) => {
      await tx.$executeRawUnsafe(
        `
        DELETE FROM auth.consent_acceptances
        WHERE user_id = $1
          AND app_id = $2;
        `,
        userId,
        appId,
      );
      for (const doc of docs) {
        await tx.$executeRawUnsafe(
          `
          INSERT INTO auth.consent_acceptances (
            id, user_id, app_id, consent_key, doc_version, label, url, accepted_at
          ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8
          );
          `,
          createId('consent'),
          userId,
          appId,
          doc.key,
          doc.version,
          doc.label,
          doc.url,
          new Date(doc.acceptedAt),
        );
      }
    });
  }

  async hasAcceptedConsentDocs(userId: string, appId: string, docs: {key:string;version:string}[]) {
    const rows=await this.prisma.$queryRawUnsafe<{consent_key:string;doc_version:string}[]>('SELECT consent_key, doc_version FROM auth.consent_acceptances WHERE user_id=$1 AND app_id=$2',userId,appId);
    return docs.length>0 && docs.every(doc=>rows.some(row=>row.consent_key===doc.key && row.doc_version===doc.version));
  }

  async hasAcceptedConsentKeys(userId: string, appId: string, requiredKeys: string[]) {
    if (requiredKeys.length === 0) return true;
    const rows = await this.prisma.$queryRawUnsafe<{ consent_key: string }[]>(
      `
      SELECT consent_key
      FROM auth.consent_acceptances
      WHERE user_id = $1
        AND app_id = $2;
      `,
      userId,
      appId,
    );
    const acceptedKeys = new Set(rows.map((row) => row.consent_key));
    return requiredKeys.every((key) => acceptedKeys.has(key));
  }

  async updateUserLifeAnchors(userId: string, lifeUserId: string, supabaseUserId: string | null) {
    await this.prisma.$executeRawUnsafe(
      `
      UPDATE auth.users
      SET life_user_id = $2,
          supabase_user_id = $3,
          updated_at = $4
      WHERE id = $1;
      `,
      userId,
      lifeUserId,
      supabaseUserId,
      new Date(),
    );
  }
}
