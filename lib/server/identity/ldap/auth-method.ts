/**
 * The `ldap` built-in: one owner per signed-in directory user.
 *
 * Registered by `instrumentation.ts` when `NEXT_PUBLIC_LDAP_ENABLED=true`,
 * with `anonymousFallback: false`, so every owner-scoped surface either sees a
 * valid LDAP session or answers 401. Each user's library, folders, materials,
 * agent sessions, skills, model settings and asset quota are partitioned by
 * the `ldap:<stable id>` owner id the login route minted.
 */
import type { OwnerAuthMethod, OwnerPrincipal } from '../types';

import type { LdapConfig } from './config';
import {
  createLdapSession,
  ldapSessionSetCookie,
  readLdapSessionToken,
  shouldRenewLdapSession,
  verifyLdapSession,
} from './session';

/** Everyone with a directory account owns their courses and may publish them. */
const LDAP_ROLES: ReadonlySet<string> = new Set(['course:publish']);

export interface LdapAuthMethodOptions {
  config: LdapConfig;
  /** Injectable clock, for tests. */
  now?: () => number;
}

export function createLdapAuthMethod(options: LdapAuthMethodOptions): OwnerAuthMethod {
  const now = options.now ?? (() => Date.now());

  return {
    name: 'ldap',
    async authenticate(req) {
      const token = readLdapSessionToken(req.headers);
      if (token === undefined) return { status: 'not-applicable' };

      const current = now();
      const session = verifyLdapSession(token, {
        secret: options.config.sessionSecret,
        now: current,
      });
      if (session === null) {
        return { status: 'invalid', reason: 'invalid or expired LDAP session' };
      }

      // Slide the expiry while the user keeps using the deployment. The
      // response headers every owner-scoped route forwards carry the refresh.
      const setCookies = shouldRenewLdapSession(session, current)
        ? [
            ldapSessionSetCookie(
              createLdapSession(
                {
                  ownerId: session.sub,
                  ...(session.name ? { name: session.name } : {}),
                },
                {
                  secret: options.config.sessionSecret,
                  ttlSeconds: options.config.sessionTtlSeconds,
                  now: current,
                },
              ).token,
              options.config.sessionTtlSeconds,
            ),
          ]
        : undefined;

      const principal: OwnerPrincipal = {
        ownerId: session.sub,
        kind: 'user',
        roles: LDAP_ROLES,
        assurance: 'verified',
      };
      return {
        status: 'authenticated',
        principal,
        ...(setCookies ? { setCookies } : {}),
      };
    },
    describeStoredOwner(ownerId) {
      return ownerId.startsWith('ldap:') ? { kind: 'user', roles: LDAP_ROLES } : undefined;
    },
  };
}
