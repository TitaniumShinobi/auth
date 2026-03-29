import crypto from 'node:crypto';

const TOKEN_VERSION = 'v1';
const IV_LENGTH_BYTES = 12;

function deriveKey(secret: string) {
  return crypto.createHash('sha256').update(secret).digest();
}

export function encryptProviderToken(token: string, secret: string) {
  const iv = crypto.randomBytes(IV_LENGTH_BYTES);
  const cipher = crypto.createCipheriv('aes-256-gcm', deriveKey(secret), iv);
  const ciphertext = Buffer.concat([cipher.update(token, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return [
    TOKEN_VERSION,
    iv.toString('base64url'),
    ciphertext.toString('base64url'),
    authTag.toString('base64url'),
  ].join('.');
}

export function decryptProviderToken(payload: string, secret: string) {
  const [version, encodedIv, encodedCiphertext, encodedAuthTag] = payload.split('.');
  if (version !== TOKEN_VERSION || !encodedIv || !encodedCiphertext || !encodedAuthTag) {
    throw new Error('Invalid provider token payload');
  }

  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    deriveKey(secret),
    Buffer.from(encodedIv, 'base64url'),
  );
  decipher.setAuthTag(Buffer.from(encodedAuthTag, 'base64url'));
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(encodedCiphertext, 'base64url')),
    decipher.final(),
  ]);
  return plaintext.toString('utf8');
}
