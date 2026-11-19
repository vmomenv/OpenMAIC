import { describe, expect, it } from 'vitest';

import {
  clearLdapSessionCookie,
  createLdapSession,
  ldapSessionSetCookie,
  readLdapSessionToken,
  shouldRenewLdapSession,
  verifyLdapSession,
  LDAP_SESSION_COOKIE,
} from '@/lib/server/identity/ldap/session';
import { decodeLdapSessionPayload } from '@/lib/server/identity/ldap/session-shared';

const SECRET = 's'.repeat(48);
const NOW = 1_800_000_000_000;
const TTL = 3600;

function mint(now = NOW) {
  return createLdapSession(
    { ownerId: 'ldap:alice', name: 'Alice' },
    { secret: SECRET, ttlSeconds: TTL, now },
  );
}

describe('LDAP session tokens', () => {
  it('round-trips the owner id and expiry', () => {
    const { token } = mint();
    expect(verifyLdapSession(token, { secret: SECRET, now: NOW + 1000 })).toEqual({
      sub: 'ldap:alice',
      name: 'Alice',
      iat: NOW,
      exp: NOW + TTL * 1000,
    });
  });

  it('rejects a token signed with another secret', () => {
    const { token } = mint();
    expect(verifyLdapSession(token, { secret: 'x'.repeat(48), now: NOW })).toBeNull();
  });

  it('rejects a tampered payload', () => {
    const { token } = mint();
    const [version, payload, signature] = token.split('.');
    const flipped = payload.slice(0, -1) + (payload.endsWith('A') ? 'B' : 'A');
    expect(
      verifyLdapSession(`${version}.${flipped}.${signature}`, { secret: SECRET, now: NOW }),
    ).toBeNull();
  });

  it('rejects an expired token', () => {
    const { token } = mint();
    expect(verifyLdapSession(token, { secret: SECRET, now: NOW + TTL * 1000 + 1 })).toBeNull();
  });

  it('renews once less than half the lifetime remains', () => {
    const { token } = mint();
    const session = verifyLdapSession(token, { secret: SECRET, now: NOW })!;
    expect(shouldRenewLdapSession(session, NOW + 1000)).toBe(false);
    expect(shouldRenewLdapSession(session, NOW + TTL * 1000 - 1000)).toBe(true);
  });

  it('writes an HttpOnly, SameSite=Lax cookie and clears it by expiry', () => {
    const { token } = mint();
    const cookie = ldapSessionSetCookie(token, TTL);
    expect(cookie).toContain(`${LDAP_SESSION_COOKIE}=`);
    expect(cookie).toContain('Path=/');
    expect(cookie).toContain('HttpOnly');
    expect(cookie).toContain('SameSite=Lax');
    expect(cookie).toContain(`Max-Age=${TTL}`);
    expect(cookie).not.toContain('Secure');

    const cleared = clearLdapSessionCookie();
    expect(cleared).toContain(`${LDAP_SESSION_COOKIE}=`);
    expect(cleared).toContain('Max-Age=0');
  });

  it('finds its cookie among others', () => {
    const headers = new Headers({ cookie: 'theme=dark; openmaic_ldap=abc.def.ghi; locale=zh-CN' });
    expect(readLdapSessionToken(headers)).toBe('abc.def.ghi');
    expect(readLdapSessionToken(new Headers({ cookie: 'theme=dark' }))).toBeUndefined();
  });
});

describe('Edge-safe payload decoding', () => {
  it('reads an unexpired payload without verifying the signature', () => {
    const { token } = mint();
    expect(decodeLdapSessionPayload(token, NOW + 1000)).toEqual({
      sub: 'ldap:alice',
      name: 'Alice',
      iat: NOW,
      exp: NOW + TTL * 1000,
    });
  });

  it('refuses an expired or malformed payload', () => {
    const { token } = mint();
    expect(decodeLdapSessionPayload(token, NOW + TTL * 1000 + 1)).toBeNull();
    expect(decodeLdapSessionPayload('not-a-token', NOW)).toBeNull();
  });
});
