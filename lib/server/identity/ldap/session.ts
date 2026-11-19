/**
 * LDAP session cookies: minting, verification and renewal (Node only).
 *
 * `v1.<base64url(payload)>.<hex HMAC-SHA256>` signed with
 * `LDAP_SESSION_SECRET`. The token carries only the owner id, an optional
 * display name and the lifetime — never a password, and never anything the
 * directory can change under the user's feet.
 */
import { createHmac, timingSafeEqual } from 'node:crypto';

import { cookiesAreSecure } from '@/lib/server/cookie-secure';

import {
  decodeLdapSessionPayload,
  LDAP_SESSION_COOKIE,
  LDAP_SESSION_DEFAULT_TTL_SECONDS,
  LDAP_SESSION_VERSION,
  readCookieValue,
  type LdapSessionPayload,
} from './session-shared';

export {
  LDAP_SESSION_COOKIE,
  LDAP_SESSION_DEFAULT_TTL_SECONDS,
  type LdapSessionPayload,
} from './session-shared';

export interface LdapSessionOptions {
  secret: string;
  ttlSeconds?: number;
  now?: number;
}

export interface MintedLdapSession {
  token: string;
  payload: LdapSessionPayload;
}

const SIGNATURE = /^[0-9a-f]{64}$/;

export function createLdapSession(
  input: { ownerId: string; name?: string },
  options: LdapSessionOptions,
): MintedLdapSession {
  const now = options.now ?? Date.now();
  const ttlSeconds = options.ttlSeconds ?? LDAP_SESSION_DEFAULT_TTL_SECONDS;
  const payload: LdapSessionPayload = {
    sub: input.ownerId,
    ...(input.name ? { name: input.name } : {}),
    iat: now,
    exp: now + ttlSeconds * 1000,
  };
  const encoded = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  const signed = `${LDAP_SESSION_VERSION}.${encoded}`;
  const signature = createHmac('sha256', options.secret).update(signed).digest('hex');
  return { token: `${signed}.${signature}`, payload };
}

/** Verify the signature and the lifetime. Returns `null` for anything unusable. */
export function verifyLdapSession(
  token: string,
  options: { secret: string; now?: number },
): LdapSessionPayload | null {
  const parts = token.split('.');
  if (parts.length !== 3 || parts[0] !== LDAP_SESSION_VERSION) return null;
  const signature = parts[2]!;
  if (!SIGNATURE.test(signature)) return null;

  const signed = `${parts[0]}.${parts[1]}`;
  const expected = createHmac('sha256', options.secret).update(signed).digest('hex');
  const given = Buffer.from(signature, 'hex');
  const wanted = Buffer.from(expected, 'hex');
  if (given.length !== wanted.length || !timingSafeEqual(given, wanted)) return null;

  return decodeLdapSessionPayload(token, options.now);
}

export function readLdapSessionToken(headers: Headers): string | undefined {
  return readCookieValue(headers, LDAP_SESSION_COOKIE);
}

/** Refresh once less than half the lifetime remains. */
export function shouldRenewLdapSession(
  session: LdapSessionPayload,
  now: number = Date.now(),
): boolean {
  const lifetime = session.exp - session.iat;
  return session.exp - now <= lifetime / 2;
}

function secureAttribute(): string {
  return cookiesAreSecure() ? '; Secure' : '';
}

export function ldapSessionSetCookie(token: string, maxAgeSeconds: number): string {
  return (
    `${LDAP_SESSION_COOKIE}=${token}; Path=/; HttpOnly; SameSite=Lax; ` +
    `Max-Age=${Math.max(0, Math.floor(maxAgeSeconds))}${secureAttribute()}`
  );
}

export function clearLdapSessionCookie(): string {
  return `${LDAP_SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${secureAttribute()}`;
}
