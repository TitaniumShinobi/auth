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
import { execSql, querySql, sqlString } from './sqliteCli.js';

function createId(prefix: string) {
  return `${prefix}_${crypto.randomUUID()}`;
}

type SqlUserRow = {
  id: string;
  email: string;
  display_name: string;
  password_hash: string | null;
  avatar_url: string | null;
  auth_provider: string;
  created_at: string;
  updated_at: string;
  last_login_at: string | null;
  life_user_id?: string | null;
  supabase_user_id?: string | null;
};

type SqlProviderAccountRow = {
  id: string;
  user_id: string;
  provider: string;
  provider_user_id: string;
  email: string | null;
  display_name: string | null;
  avatar_url: string | null;
  profile_json: string;
  access_token_encrypted?: string | null;
  access_token_scope?: string | null;
  connected_at?: string | null;
  connection_updated_at?: string | null;
  created_at: string;
  updated_at: string;
};

function mapUser(row: SqlUserRow): StoredUser {
  return {
    id: row.id,
    email: row.email,
    displayName: row.display_name,
    passwordHash: row.password_hash,
    avatarUrl: row.avatar_url,
    authProvider: row.auth_provider,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    lastLoginAt: row.last_login_at,
    lifeUserId: row.life_user_id ?? undefined,
    supabaseUserId: row.supabase_user_id ?? undefined,
  };
}

function mapProviderAccount(row: SqlProviderAccountRow): ProviderAccount {
  return {
    id: row.id,
    userId: row.user_id,
    provider: row.provider,
    providerUserId: row.provider_user_id,
    email: row.email,
    displayName: row.display_name,
    avatarUrl: row.avatar_url,
    profileJson: row.profile_json,
    accessTokenEncrypted: row.access_token_encrypted ?? null,
    accessTokenScope: row.access_token_scope ?? null,
    connectedAt: row.connected_at ?? null,
    connectionUpdatedAt: row.connection_updated_at ?? null,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

function ensureUserLifeColumns(dbPath: string) {
  try {
    const cols = querySql<{ name: string }>(dbPath, 'PRAGMA table_info(users);');
    const names = new Set(cols.map((row) => row.name));
    if (!names.has('life_user_id')) {
      execSql(dbPath, 'ALTER TABLE users ADD COLUMN life_user_id TEXT;');
    }
    if (!names.has('supabase_user_id')) {
      execSql(dbPath, 'ALTER TABLE users ADD COLUMN supabase_user_id TEXT;');
    }
  } catch {
    // ignore
  }
}

function ensureProviderAccountConnectionColumns(dbPath: string) {
  try {
    const cols = querySql<{ name: string }>(dbPath, 'PRAGMA table_info(provider_accounts);');
    const names = new Set(cols.map((row) => row.name));
    if (!names.has('access_token_encrypted')) {
      execSql(dbPath, 'ALTER TABLE provider_accounts ADD COLUMN access_token_encrypted TEXT;');
    }
    if (!names.has('access_token_scope')) {
      execSql(dbPath, 'ALTER TABLE provider_accounts ADD COLUMN access_token_scope TEXT;');
    }
    if (!names.has('connected_at')) {
      execSql(dbPath, 'ALTER TABLE provider_accounts ADD COLUMN connected_at TEXT;');
    }
    if (!names.has('connection_updated_at')) {
      execSql(dbPath, 'ALTER TABLE provider_accounts ADD COLUMN connection_updated_at TEXT;');
    }
  } catch {
    // ignore
  }
}

export class SqliteStorageAdapter implements StorageAdapter {
  constructor(private readonly dbPath: string) {}

  async initialize() {
    execSql(
      this.dbPath,
      `
      PRAGMA journal_mode = WAL;
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        email TEXT NOT NULL UNIQUE,
        display_name TEXT NOT NULL,
        password_hash TEXT,
        avatar_url TEXT,
        auth_provider TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        last_login_at TEXT
      );
      CREATE TABLE IF NOT EXISTS provider_accounts (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        provider TEXT NOT NULL,
        provider_user_id TEXT NOT NULL,
        email TEXT,
        display_name TEXT,
        avatar_url TEXT,
        profile_json TEXT NOT NULL,
        access_token_encrypted TEXT,
        access_token_scope TEXT,
        connected_at TEXT,
        connection_updated_at TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        UNIQUE(provider, provider_user_id)
      );
      CREATE TABLE IF NOT EXISTS consent_acceptances (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        app_id TEXT NOT NULL,
        consent_key TEXT NOT NULL,
        doc_version TEXT NOT NULL,
        label TEXT NOT NULL,
        url TEXT NOT NULL,
        accepted_at TEXT NOT NULL
      );
      `,
    );
    ensureUserLifeColumns(this.dbPath);
    ensureProviderAccountConnectionColumns(this.dbPath);
  }

  async findUserByEmail(email: string) {
    const rows = querySql<SqlUserRow>(
      this.dbPath,
      `SELECT * FROM users WHERE email = ${sqlString(email.toLowerCase())} LIMIT 1;`,
    );
    return rows[0] ? mapUser(rows[0]) : null;
  }

  async findUserById(id: string) {
    const rows = querySql<SqlUserRow>(
      this.dbPath,
      `SELECT * FROM users WHERE id = ${sqlString(id)} LIMIT 1;`,
    );
    return rows[0] ? mapUser(rows[0]) : null;
  }

  async findProviderAccount(userId: string, provider: string) {
    const rows = querySql<SqlProviderAccountRow>(
      this.dbPath,
      `
      SELECT *
      FROM provider_accounts
      WHERE user_id = ${sqlString(userId)}
        AND provider = ${sqlString(provider)}
      ORDER BY updated_at DESC
      LIMIT 1;
      `,
    );
    return rows[0] ? mapProviderAccount(rows[0]) : null;
  }

  async createCredentialUser(input: CreateCredentialUserInput) {
    const user: StoredUser = {
      id: createId('user'),
      email: input.email.toLowerCase(),
      displayName: input.displayName,
      passwordHash: input.passwordHash,
      avatarUrl: null,
      authProvider: 'credentials',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      lastLoginAt: null,
    };
    execSql(
      this.dbPath,
      `
      INSERT INTO users (
        id, email, display_name, password_hash, avatar_url, auth_provider, created_at, updated_at, last_login_at
      ) VALUES (
        ${sqlString(user.id)},
        ${sqlString(user.email)},
        ${sqlString(user.displayName)},
        ${sqlString(user.passwordHash)},
        ${sqlString(user.avatarUrl)},
        ${sqlString(user.authProvider)},
        ${sqlString(user.createdAt)},
        ${sqlString(user.updatedAt)},
        NULL
      );
      `,
    );
    return user;
  }

  async updateUserLogin(userId: string) {
    const now = new Date().toISOString();
    execSql(
      this.dbPath,
      `
      UPDATE users
      SET last_login_at = ${sqlString(now)}, updated_at = ${sqlString(now)}
      WHERE id = ${sqlString(userId)};
      `,
    );
  }

  async upsertOAuthUser(input: UpsertOAuthUserInput) {
    const now = new Date().toISOString();
    const existingLink = querySql<{ user_id: string }>(
      this.dbPath,
      `
      SELECT user_id
      FROM provider_accounts
      WHERE provider = ${sqlString(input.provider)}
        AND provider_user_id = ${sqlString(input.providerUserId)}
      LIMIT 1;
      `,
    )[0];

    const existingUser =
      (existingLink ? await this.findUserById(existingLink.user_id) : null)
      || await this.findUserByEmail(input.email);

    const user = existingUser ?? {
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

    if (!existingUser) {
      execSql(
        this.dbPath,
        `
        INSERT INTO users (
          id, email, display_name, password_hash, avatar_url, auth_provider, created_at, updated_at, last_login_at
        ) VALUES (
          ${sqlString(user.id)},
          ${sqlString(user.email)},
          ${sqlString(user.displayName)},
          NULL,
          ${sqlString(user.avatarUrl)},
          ${sqlString(user.authProvider)},
          ${sqlString(user.createdAt)},
          ${sqlString(user.updatedAt)},
          NULL
        );
        `,
      );
    } else {
      execSql(
        this.dbPath,
        `
        UPDATE users
        SET display_name = ${sqlString(input.displayName || existingUser.displayName)},
            avatar_url = ${sqlString(input.avatarUrl || existingUser.avatarUrl)},
            auth_provider = ${sqlString(input.provider)},
            updated_at = ${sqlString(now)}
        WHERE id = ${sqlString(existingUser.id)};
        `,
      );
    }

    execSql(
      this.dbPath,
      `
      INSERT INTO provider_accounts (
        id, user_id, provider, provider_user_id, email, display_name, avatar_url, profile_json,
        access_token_encrypted, access_token_scope, connected_at, connection_updated_at, created_at, updated_at
      ) VALUES (
        ${sqlString(createId('acct'))},
        ${sqlString(user.id)},
        ${sqlString(input.provider)},
        ${sqlString(input.providerUserId)},
        ${sqlString(input.email.toLowerCase())},
        ${sqlString(input.displayName)},
        ${sqlString(input.avatarUrl || null)},
        ${sqlString(JSON.stringify(input.profile))},
        NULL,
        NULL,
        NULL,
        NULL,
        ${sqlString(now)},
        ${sqlString(now)}
      )
      ON CONFLICT(provider, provider_user_id) DO UPDATE SET
        user_id = excluded.user_id,
        email = excluded.email,
        display_name = excluded.display_name,
        avatar_url = excluded.avatar_url,
        profile_json = excluded.profile_json,
        updated_at = excluded.updated_at;
      `,
    );

    return (await this.findUserById(user.id)) as StoredUser;
  }

  async upsertProviderAccountConnection(input: UpsertProviderAccountConnectionInput) {
    const now = new Date().toISOString();
    const connectedAt = input.connectedAt ?? now;
    const existingByUser = await this.findProviderAccount(input.userId, input.provider);
    const existingByProviderUser = querySql<SqlProviderAccountRow>(
      this.dbPath,
      `
      SELECT *
      FROM provider_accounts
      WHERE provider = ${sqlString(input.provider)}
        AND provider_user_id = ${sqlString(input.providerUserId)}
      ORDER BY updated_at DESC
      LIMIT 1;
      `,
    )[0];

    if (existingByUser && existingByProviderUser && existingByUser.id !== existingByProviderUser.id) {
      execSql(
        this.dbPath,
        `DELETE FROM provider_accounts WHERE id = ${sqlString(existingByProviderUser.id)};`,
      );
    }

    const targetId = existingByUser?.id || existingByProviderUser?.id || createId('acct');
    const source = existingByUser ?? (existingByProviderUser ? mapProviderAccount(existingByProviderUser) : null);
    execSql(
      this.dbPath,
      `
      INSERT INTO provider_accounts (
        id, user_id, provider, provider_user_id, email, display_name, avatar_url, profile_json,
        access_token_encrypted, access_token_scope, connected_at, connection_updated_at, created_at, updated_at
      ) VALUES (
        ${sqlString(targetId)},
        ${sqlString(input.userId)},
        ${sqlString(input.provider)},
        ${sqlString(input.providerUserId)},
        ${sqlString(input.email ?? source?.email ?? null)},
        ${sqlString(input.displayName ?? source?.displayName ?? null)},
        ${sqlString(input.avatarUrl ?? source?.avatarUrl ?? null)},
        ${sqlString(JSON.stringify(input.profile))},
        ${sqlString(input.accessTokenEncrypted)},
        ${sqlString(input.accessTokenScope ?? null)},
        ${sqlString(connectedAt)},
        ${sqlString(now)},
        ${sqlString(source?.createdAt ?? now)},
        ${sqlString(now)}
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
    );
    return (await this.findProviderAccount(input.userId, input.provider)) as ProviderAccount;
  }

  async clearProviderAccountConnection(userId: string, provider: string) {
    execSql(
      this.dbPath,
      `
      UPDATE provider_accounts
      SET access_token_encrypted = NULL,
          access_token_scope = NULL,
          connected_at = NULL,
          connection_updated_at = NULL,
          updated_at = ${sqlString(new Date().toISOString())}
      WHERE user_id = ${sqlString(userId)}
        AND provider = ${sqlString(provider)};
      `,
    );
  }

  async replaceConsentAcceptances(userId: string, appId: string, docs: ConsentAcceptance[]) {
    execSql(
      this.dbPath,
      `
      DELETE FROM consent_acceptances
      WHERE user_id = ${sqlString(userId)}
        AND app_id = ${sqlString(appId)};
      `,
    );
    for (const doc of docs) {
      execSql(
        this.dbPath,
        `
        INSERT INTO consent_acceptances (
          id, user_id, app_id, consent_key, doc_version, label, url, accepted_at
        ) VALUES (
          ${sqlString(createId('consent'))},
          ${sqlString(userId)},
          ${sqlString(appId)},
          ${sqlString(doc.key)},
          ${sqlString(doc.version)},
          ${sqlString(doc.label)},
          ${sqlString(doc.url)},
          ${sqlString(doc.acceptedAt)}
        );
        `,
      );
    }
  }

  async hasAcceptedConsentKeys(userId: string, appId: string, requiredKeys: string[]) {
    if (requiredKeys.length === 0) return true;
    const rows = querySql<{ consent_key: string }>(
      this.dbPath,
      `
      SELECT consent_key
      FROM consent_acceptances
      WHERE user_id = ${sqlString(userId)}
        AND app_id = ${sqlString(appId)};
      `,
    );
    const acceptedKeys = new Set(rows.map((row) => row.consent_key));
    return requiredKeys.every((key) => acceptedKeys.has(key));
  }

  async updateUserLifeAnchors(userId: string, lifeUserId: string, supabaseUserId: string | null) {
    const now = new Date().toISOString();
    execSql(
      this.dbPath,
      `
      UPDATE users
      SET life_user_id = ${sqlString(lifeUserId)},
          supabase_user_id = ${sqlString(supabaseUserId)},
          updated_at = ${sqlString(now)}
      WHERE id = ${sqlString(userId)};
      `,
    );
  }
}
