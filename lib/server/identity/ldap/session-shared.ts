/**
 * Edge-safe LDAP session-token constants and payload reader.
 *
 * Both sides of the identity seam need this module: the Node route handlers
 * verify the signature (`./session.ts`), while `middleware.ts` only needs to
 * tell an expired or malformed page cookie from a live one — and it may run in
 * the Edge runtime, where `node:crypto` is unavailable. Keeping the format and
 * the expiry policy here means the two readers cannot drift apart.
 *
 * Signature verification is deliberately absent: the middleware is a routing
 * convenience, not a security boundary. Every owner-scoped API route verifies
 * the signature before trusting the payload (see `./auth-method.ts`).
 */

/** The cookie this deployment's LDAP session lives in. */
export const LDAP_SESSION_COOKIE = 'openmaic_ldap';

/** Token format version, the first dot-separated part. */
export const LDAP_SESSION_VERSION = 'v1';

/** Default session lifetime: 7 days, renewed while in use. */
export const LDAP_SESSION_DEFAULT_TTL_SECONDS = 60 * 60 * 24 * 7;

/** Shortest session lifetime a deployment may configure: 5 minutes. */
export const LDAP_SESSION_MIN_TTL_SECONDS = 5 * 60;

/** Longest session lifetime a deployment may configure: 30 days. */
export const LDAP_SESSION_MAX_TTL_SECONDS = 60 * 60 * 24 * 30;

export interface LdapSessionPayload {
  /** The owner id this session belongs to, always `ldap:<id>`. */
  readonly sub: string;
  /** Display name for the account menu, when the directory provided one. */
  readonly name?: string;
  /** Issued-at, epoch milliseconds. */
  readonly iat: number;
  /** Expires-at, epoch milliseconds. */
  readonly exp: number;
}

const PRINTABLE_OWNER = /^[\x21-\x7e]{1,256}$/;

function base64UrlDecode(input: string): string | null {
  if (!/^[A-Za-z0-9_-]+$/.test(input)) return null;
  const base64 = input.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
  try {
    const binary = atob(padded);
    const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
    return new TextDecoder().decode(bytes);
  } catch {
    return null;
  }
}

function isPayload(value: unknown): value is LdapSessionPayload {
  if (typeof value !== 'object' || value === null) return false;
  const payload = value as Record<string, unknown>;
  return (
    typeof payload.sub === 'string' &&
    payload.sub.startsWith('ldap:') &&
    PRINTABLE_OWNER.test(payload.sub) &&
    typeof payload.iat === 'number' &&
    Number.isFinite(payload.iat) &&
    typeof payload.exp === 'number' &&
    Number.isFinite(payload.exp) &&
    payload.exp > payload.iat &&
    (payload.name === undefined || typeof payload.name === 'string')
  );
}

/**
 * Read the payload of a token without checking its signature. Returns `null`
 * for a malformed, expired or future-dated token.
 */
export function decodeLdapSessionPayload(
  token: string,
  now: number = Date.now(),
): LdapSessionPayload | null {
  const parts = token.split('.');
  if (parts.length !== 3 || parts[0] !== LDAP_SESSION_VERSION) return null;
  const json = base64UrlDecode(parts[1]!);
  if (json === null) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    return null;
  }
  if (!isPayload(parsed)) return null;
  if (parsed.exp <= now) return null;
  // A token minted in the future is a clock problem or a forgery; either way
  // it is not something this deployment issued.
  if (parsed.iat > now + 5 * 60 * 1000) return null;
  return parsed;
}

/** Find a cookie value in a request's `Cookie` header. */
export function readCookieValue(headers: Headers, name: string): string | undefined {
  const header = headers.get('cookie');
  if (!header) return undefined;
  for (const part of header.split(';')) {
    const separator = part.indexOf('=');
    if (separator === -1) continue;
    if (part.slice(0, separator).trim() !== name) continue;
    const value = part.slice(separator + 1).trim();
    return value === '' ? undefined : value;
  }
  return undefined;
}
