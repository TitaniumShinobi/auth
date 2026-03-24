import crypto from 'node:crypto';

const SCRYPT_KEY_LENGTH = 64;

export async function hashPassword(password: string): Promise<string> {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = await new Promise<string>((resolve, reject) => {
    crypto.scrypt(password, salt, SCRYPT_KEY_LENGTH, (error, derivedKey) => {
      if (error) {
        reject(error);
        return;
      }
      resolve(Buffer.from(derivedKey).toString('hex'));
    });
  });
  return `scrypt$${salt}$${hash}`;
}

export async function verifyPassword(password: string, serializedHash: string): Promise<boolean> {
  const [scheme, salt, storedHash] = serializedHash.split('$');
  if (scheme !== 'scrypt' || !salt || !storedHash) return false;
  const derivedHash = await new Promise<string>((resolve, reject) => {
    crypto.scrypt(password, salt, SCRYPT_KEY_LENGTH, (error, derivedKey) => {
      if (error) {
        reject(error);
        return;
      }
      resolve(Buffer.from(derivedKey).toString('hex'));
    });
  });
  return crypto.timingSafeEqual(Buffer.from(derivedHash, 'hex'), Buffer.from(storedHash, 'hex'));
}

export function validatePasswordStrength(password: string) {
  if (password.length < 8) {
    return 'Password must be at least 8 characters';
  }
  return null;
}
