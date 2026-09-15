import crypto from 'node:crypto';
import type { PrismaClient } from '@prisma/client';

export type RefreshSessionStatus = 'active' | 'revoked' | 'missing';

export type CreateRefreshSessionInput = {
  sessionId: string;
  userId: string;
  appId: string;
  refreshTokenId: string;
  refreshTokenJti: string;
  refreshTokenHash: string;
  refreshExpiresAt: Date;
  ipHash?: string | null;
  userAgentHash?: string | null;
  requestId?: string | null;
};

export type RotateRefreshTokenInput = {
  sessionId: string;
  userId: string;
  presentedTokenJti: string;
  presentedTokenHash: string;
  newRefreshTokenId: string;
  newRefreshTokenJti: string;
  newRefreshTokenHash: string;
  newRefreshExpiresAt: Date;
  ipHash?: string | null;
  userAgentHash?: string | null;
  requestId?: string | null;
};

export type RotateRefreshTokenResult =
  | { ok: true }
  | { ok: false; status: number; reason: string; replay: boolean; sessionId?: string };

export interface RefreshTokenStore {
  initialize(): Promise<void>;
  createSession(input: CreateRefreshSessionInput): Promise<void>;
  rotateRefreshToken(input: RotateRefreshTokenInput): Promise<RotateRefreshTokenResult>;
  revokeSession(sessionId: string, reason: string, requestId?: string | null): Promise<void>;
  getSessionStatus(sessionId: string): Promise<RefreshSessionStatus>;
  revokeUserSessions?(userId: string, appId: string, reason: string): Promise<number>;
}

type MemorySession = {
  id: string;
  userId: string;
  appId: string;
  currentRefreshTokenId: string;
  rotationCounter: number;
  expiresAt: Date;
  revokedAt: Date | null;
  revokedReason: string | null;
};

type MemoryRefreshToken = {
  id: string;
  sessionId: string;
  userId: string;
  tokenJti: string;
  tokenHash: string;
  parentTokenId: string | null;
  replacedByTokenId: string | null;
  generation: number;
  status: 'active' | 'used' | 'revoked' | 'reused';
  expiresAt: Date;
  usedAt: Date | null;
  revokedAt: Date | null;
  reuseDetectedAt: Date | null;
};

export class MemoryRefreshTokenStore implements RefreshTokenStore {
  private readonly sessions = new Map<string, MemorySession>();
  private readonly tokensByHash = new Map<string, MemoryRefreshToken>();
  private readonly tokensById = new Map<string, MemoryRefreshToken>();

  async initialize() {}

  async createSession(input: CreateRefreshSessionInput) {
    const now = new Date();
    const token: MemoryRefreshToken = {
      id: input.refreshTokenId,
      sessionId: input.sessionId,
      userId: input.userId,
      tokenJti: input.refreshTokenJti,
      tokenHash: input.refreshTokenHash,
      parentTokenId: null,
      replacedByTokenId: null,
      generation: 0,
      status: 'active',
      expiresAt: input.refreshExpiresAt,
      usedAt: null,
      revokedAt: null,
      reuseDetectedAt: null,
    };
    this.sessions.set(input.sessionId, {
      id: input.sessionId,
      userId: input.userId,
      appId: input.appId,
      currentRefreshTokenId: input.refreshTokenId,
      rotationCounter: 0,
      expiresAt: input.refreshExpiresAt,
      revokedAt: null,
      revokedReason: null,
    });
    this.writeToken(token);
    void now;
  }

  async rotateRefreshToken(input: RotateRefreshTokenInput): Promise<RotateRefreshTokenResult> {
    const now = new Date();
    const token = this.tokensByHash.get(input.presentedTokenHash);
    const session = this.sessions.get(input.sessionId);
    if (!token || !session) {
      if (session) this.revokeMemorySession(session, 'unknown_refresh_token', now);
      return { ok: false, status: 401, reason: 'invalid_refresh_token', replay: false, sessionId: input.sessionId };
    }
    if (
      token.sessionId !== input.sessionId
      || token.userId !== input.userId
      || token.tokenJti !== input.presentedTokenJti
    ) {
      this.revokeMemorySession(session, 'refresh_token_claim_mismatch', now);
      return { ok: false, status: 401, reason: 'refresh_token_claim_mismatch', replay: true, sessionId: session.id };
    }
    if (session.revokedAt) {
      return { ok: false, status: 401, reason: 'session_revoked', replay: false, sessionId: session.id };
    }
    if (token.expiresAt <= now || session.expiresAt <= now) {
      this.revokeMemorySession(session, 'refresh_token_expired', now);
      return { ok: false, status: 401, reason: 'refresh_token_expired', replay: false, sessionId: session.id };
    }
    if (token.status !== 'active' || session.currentRefreshTokenId !== token.id) {
      token.status = 'reused';
      token.reuseDetectedAt = now;
      this.revokeMemorySession(session, 'refresh_token_replay', now);
      return { ok: false, status: 401, reason: 'refresh_token_replay', replay: true, sessionId: session.id };
    }

    token.status = 'used';
    token.usedAt = now;
    token.replacedByTokenId = input.newRefreshTokenId;
    const nextToken: MemoryRefreshToken = {
      id: input.newRefreshTokenId,
      sessionId: session.id,
      userId: input.userId,
      tokenJti: input.newRefreshTokenJti,
      tokenHash: input.newRefreshTokenHash,
      parentTokenId: token.id,
      replacedByTokenId: null,
      generation: token.generation + 1,
      status: 'active',
      expiresAt: input.newRefreshExpiresAt,
      usedAt: null,
      revokedAt: null,
      reuseDetectedAt: null,
    };
    this.writeToken(nextToken);
    session.currentRefreshTokenId = nextToken.id;
    session.rotationCounter += 1;
    session.expiresAt = input.newRefreshExpiresAt;
    return { ok: true };
  }

  async revokeSession(sessionId: string, reason: string) {
    const session = this.sessions.get(sessionId);
    if (!session) return;
    this.revokeMemorySession(session, reason, new Date());
  }

  async revokeUserSessions(userId: string, appId: string, reason: string) {
    let count=0;
    for (const session of this.sessions.values()) if(session.userId===userId && session.appId===appId && !session.revokedAt) {
      await this.revokeSession(session.id, reason); count++;
    }
    return count;
  }

  async getSessionStatus(sessionId: string): Promise<RefreshSessionStatus> {
    const session = this.sessions.get(sessionId);
    if (!session) return 'missing';
    if (session.revokedAt || session.expiresAt <= new Date()) return 'revoked';
    return 'active';
  }

  private writeToken(token: MemoryRefreshToken) {
    this.tokensById.set(token.id, token);
    this.tokensByHash.set(token.tokenHash, token);
  }

  private revokeMemorySession(session: MemorySession, reason: string, now: Date) {
    session.revokedAt = session.revokedAt || now;
    session.revokedReason = session.revokedReason || reason;
    for (const token of this.tokensById.values()) {
      if (token.sessionId !== session.id || token.status !== 'active') continue;
      token.status = 'revoked';
      token.revokedAt = token.revokedAt || now;
    }
  }
}

type TokenRow = {
  id: string;
  session_id: string;
  user_id: string;
  token_jti: string;
  status: 'active' | 'used' | 'revoked' | 'reused';
  generation: number;
  expires_at: Date;
};

type SessionRow = {
  id: string;
  user_id: string;
  current_refresh_token_id: string | null;
  revoked_at: Date | null;
  expires_at: Date;
};

export class PostgresRefreshTokenStore implements RefreshTokenStore {
  constructor(private readonly prisma: PrismaClient) {}

  async initialize() {
    await this.prisma.$queryRawUnsafe('SELECT 1;');
  }

  async createSession(input: CreateRefreshSessionInput) {
    const now = new Date();
    await this.prisma.$transaction(async (tx) => {
      await tx.$executeRawUnsafe(
        `
        INSERT INTO auth.auth_sessions (
          id, user_id, app_id, current_refresh_token_id, rotation_counter,
          created_at, authenticated_at, last_seen_at, expires_at,
          ip_hash, user_agent_hash, metadata
        ) VALUES (
          $1::uuid, $2, $3, NULL, 0,
          $4, $4, $4, $5,
          $6, $7, '{}'::jsonb
        );
        `,
        input.sessionId,
        input.userId,
        input.appId,
        now,
        input.refreshExpiresAt,
        input.ipHash ?? null,
        input.userAgentHash ?? null,
      );
      await tx.$executeRawUnsafe(
        `
        INSERT INTO auth.refresh_tokens (
          id, session_id, user_id, token_jti, token_hash, generation, status,
          issued_at, expires_at, ip_hash, user_agent_hash
        ) VALUES (
          $1::uuid, $2::uuid, $3, $4, $5, 0, 'active',
          $6, $7, $8, $9
        );
        `,
        input.refreshTokenId,
        input.sessionId,
        input.userId,
        input.refreshTokenJti,
        input.refreshTokenHash,
        now,
        input.refreshExpiresAt,
        input.ipHash ?? null,
        input.userAgentHash ?? null,
      );
      await tx.$executeRawUnsafe(
        `
        UPDATE auth.auth_sessions
        SET current_refresh_token_id = $1::uuid
        WHERE id = $2::uuid;
        `,
        input.refreshTokenId,
        input.sessionId,
      );
      await this.insertEvent(tx, {
        eventType: 'login',
        sessionId: input.sessionId,
        refreshTokenId: input.refreshTokenId,
        userId: input.userId,
        requestId: input.requestId,
        ipHash: input.ipHash,
        userAgentHash: input.userAgentHash,
      });
    });
  }

  async rotateRefreshToken(input: RotateRefreshTokenInput): Promise<RotateRefreshTokenResult> {
    const now = new Date();
    return this.prisma.$transaction(async (tx) => {
      const sessions = await tx.$queryRawUnsafe<SessionRow[]>(
        `
        SELECT id, user_id, current_refresh_token_id, revoked_at, expires_at
        FROM auth.auth_sessions
        WHERE id = $1::uuid
        FOR UPDATE;
        `,
        input.sessionId,
      );
      const session = sessions[0] ?? null;
      const tokens = await tx.$queryRawUnsafe<TokenRow[]>(
        `
        SELECT id, session_id, user_id, token_jti, status, generation, expires_at
        FROM auth.refresh_tokens
        WHERE token_hash = $1
        FOR UPDATE;
        `,
        input.presentedTokenHash,
      );
      const token = tokens[0] ?? null;
      if (!session || !token) {
        if (session) {
          await this.revokeSessionInTransaction(tx, session.id, 'unknown_refresh_token', now);
        }
        return { ok: false, status: 401, reason: 'invalid_refresh_token', replay: false, sessionId: input.sessionId };
      }
      if (
        token.session_id !== input.sessionId
        || token.user_id !== input.userId
        || token.token_jti !== input.presentedTokenJti
      ) {
        await this.revokeSessionInTransaction(tx, session.id, 'refresh_token_claim_mismatch', now);
        return { ok: false, status: 401, reason: 'refresh_token_claim_mismatch', replay: true, sessionId: session.id };
      }
      if (session.revoked_at) {
        return { ok: false, status: 401, reason: 'session_revoked', replay: false, sessionId: session.id };
      }
      if (token.expires_at <= now || session.expires_at <= now) {
        await this.revokeSessionInTransaction(tx, session.id, 'refresh_token_expired', now);
        return { ok: false, status: 401, reason: 'refresh_token_expired', replay: false, sessionId: session.id };
      }
      if (token.status !== 'active' || session.current_refresh_token_id !== token.id) {
        await tx.$executeRawUnsafe(
          `
          UPDATE auth.refresh_tokens
          SET status = 'reused', reuse_detected_at = COALESCE(reuse_detected_at, $2)
          WHERE id = $1::uuid;
          `,
          token.id,
          now,
        );
        await this.revokeSessionInTransaction(tx, session.id, 'refresh_token_replay', now);
        await this.insertEvent(tx, {
          eventType: 'refresh_replay',
          sessionId: session.id,
          refreshTokenId: token.id,
          userId: token.user_id,
          requestId: input.requestId,
          ipHash: input.ipHash,
          userAgentHash: input.userAgentHash,
        });
        return { ok: false, status: 401, reason: 'refresh_token_replay', replay: true, sessionId: session.id };
      }

      await tx.$executeRawUnsafe(
        `
        UPDATE auth.refresh_tokens
        SET status = 'used', used_at = $2
        WHERE id = $1::uuid;
        `,
        token.id,
        now,
      );
      await tx.$executeRawUnsafe(
        `
        INSERT INTO auth.refresh_tokens (
          id, session_id, user_id, token_jti, token_hash, parent_token_id,
          generation, status, issued_at, expires_at, ip_hash, user_agent_hash
        ) VALUES (
          $1::uuid, $2::uuid, $3, $4, $5, $6::uuid,
          $7, 'active', $8, $9, $10, $11
        );
        `,
        input.newRefreshTokenId,
        session.id,
        input.userId,
        input.newRefreshTokenJti,
        input.newRefreshTokenHash,
        token.id,
        token.generation + 1,
        now,
        input.newRefreshExpiresAt,
        input.ipHash ?? null,
        input.userAgentHash ?? null,
      );
      // The replacement row must exist before the old row references it. The
      // FK is intentionally immediate (unlike the session's deferred current
      // token FK), so setting replaced_by_token_id before INSERT makes every
      // real Postgres rotation fail even though in-memory tests pass.
      await tx.$executeRawUnsafe(
        `
        UPDATE auth.refresh_tokens
        SET replaced_by_token_id = $2::uuid
        WHERE id = $1::uuid;
        `,
        token.id,
        input.newRefreshTokenId,
      );
      await tx.$executeRawUnsafe(
        `
        UPDATE auth.auth_sessions
        SET current_refresh_token_id = $1::uuid,
            rotation_counter = rotation_counter + 1,
            last_seen_at = $2,
            expires_at = $3
        WHERE id = $4::uuid;
        `,
        input.newRefreshTokenId,
        now,
        input.newRefreshExpiresAt,
        session.id,
      );
      await this.insertEvent(tx, {
        eventType: 'refresh_rotate',
        sessionId: session.id,
        refreshTokenId: input.newRefreshTokenId,
        userId: input.userId,
        requestId: input.requestId,
        ipHash: input.ipHash,
        userAgentHash: input.userAgentHash,
      });
      return { ok: true };
    });
  }

  async revokeSession(sessionId: string, reason: string, requestId?: string | null) {
    const now = new Date();
    await this.prisma.$transaction(async (tx) => {
      await this.revokeSessionInTransaction(tx, sessionId, reason, now);
      await this.insertEvent(tx, {
        eventType: 'session_revoke',
        sessionId,
        requestId,
      });
    });
  }

  async revokeUserSessions(userId: string, appId: string, reason: string) {
    return this.prisma.$transaction(async (tx) => {
      const rows=await tx.$queryRawUnsafe<Array<{id:string}>>(
        `SELECT id FROM auth.auth_sessions WHERE user_id=$1::uuid AND app_id=$2 AND revoked_at IS NULL FOR UPDATE`,userId,appId);
      const now=new Date();
      for(const row of rows) {
        await this.revokeSessionInTransaction(tx,row.id,reason,now);
        await this.insertEvent(tx,{eventType:'session_revoke',sessionId:row.id});
      }
      return rows.length;
    });
  }

  async getSessionStatus(sessionId: string): Promise<RefreshSessionStatus> {
    const rows = await this.prisma.$queryRawUnsafe<SessionRow[]>(
      `
      SELECT id, user_id, current_refresh_token_id, revoked_at, expires_at
      FROM auth.auth_sessions
      WHERE id = $1::uuid
      LIMIT 1;
      `,
      sessionId,
    );
    const session = rows[0] ?? null;
    if (!session) return 'missing';
    if (session.revoked_at || session.expires_at <= new Date()) return 'revoked';
    return 'active';
  }

  private async revokeSessionInTransaction(tx: any, sessionId: string, reason: string, now: Date) {
    await tx.$executeRawUnsafe(
      `
      UPDATE auth.auth_sessions
      SET revoked_at = COALESCE(revoked_at, $2),
          revoked_reason = COALESCE(revoked_reason, $3)
      WHERE id = $1::uuid;
      `,
      sessionId,
      now,
      reason,
    );
    await tx.$executeRawUnsafe(
      `
      UPDATE auth.refresh_tokens
      SET status = 'revoked',
          revoked_at = COALESCE(revoked_at, $2)
      WHERE session_id = $1::uuid
        AND status = 'active';
      `,
      sessionId,
      now,
    );
  }

  private async insertEvent(
    tx: any,
    input: {
      eventType: string;
      sessionId?: string | null;
      refreshTokenId?: string | null;
      userId?: string | null;
      requestId?: string | null;
      ipHash?: string | null;
      userAgentHash?: string | null;
    },
  ) {
    await tx.$executeRawUnsafe(
      `
      INSERT INTO auth.auth_session_events (
        id, session_id, refresh_token_id, user_id, event_type,
        occurred_at, request_id, ip_hash, user_agent_hash, metadata
      ) VALUES (
        $1::uuid, $2::uuid, $3::uuid, $4, $5,
        $6, $7, $8, $9, '{}'::jsonb
      );
      `,
      crypto.randomUUID(),
      input.sessionId ?? null,
      input.refreshTokenId ?? null,
      input.userId ?? null,
      input.eventType,
      new Date(),
      input.requestId ?? null,
      input.ipHash ?? null,
      input.userAgentHash ?? null,
    );
  }
}
