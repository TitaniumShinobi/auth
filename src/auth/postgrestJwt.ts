import { SignJWT } from 'jose';

export type PostgrestJwtClaims = {
  sub: string;
  role: string;
  email?: string;
  iat: number;
  exp: number;
};

function secretBytes(secret: string) {
  return new TextEncoder().encode(secret);
}

export async function createPostgrestJwt(input: {
  sub: string;
  email?: string;
  role?: string;
  secret: string;
  ttlSeconds: number;
  nowSeconds?: number;
}) {
  const iat = input.nowSeconds ?? Math.floor(Date.now() / 1000);
  const claims: PostgrestJwtClaims = {
    sub: input.sub,
    role: input.role || 'authenticated',
    ...(input.email ? { email: input.email } : {}),
    iat,
    exp: iat + input.ttlSeconds,
  };
  const token = await new SignJWT({
    role: claims.role,
    ...(claims.email ? { email: claims.email } : {}),
  })
    .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
    .setSubject(claims.sub)
    .setIssuedAt(claims.iat)
    .setExpirationTime(claims.exp)
    .sign(secretBytes(input.secret));
  return {
    token,
    claims,
  };
}
