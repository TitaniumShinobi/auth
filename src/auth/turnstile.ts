import { getTurnstileSecret } from '../config.js';
import type { TurnstileVerifier } from '../types.js';

export const verifyTurnstileToken: TurnstileVerifier = async (token, remoteIp) => {
  const secret = getTurnstileSecret();
  if (!secret) return false;

  const body = new URLSearchParams({
    secret,
    response: token,
  });
  if (remoteIp) body.set('remoteip', remoteIp);

  const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body,
  });
  if (!response.ok) return false;
  const payload = await response.json() as { success?: boolean };
  return payload.success === true;
};
