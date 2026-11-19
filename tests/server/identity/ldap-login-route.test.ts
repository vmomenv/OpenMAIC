import { afterEach, describe, expect, it, vi } from 'vitest';

const BIND_PASSWORD = 'correct';

vi.mock('ldapts', () => {
  class Client {
    async bind(_dn: string, password: string) {
      if (password !== BIND_PASSWORD) {
        throw Object.assign(new Error('invalid credentials'), { code: 49 });
      }
    }
    async search() {
      return {
        searchEntries: [
          {
            dn: 'uid=alice,ou=people,dc=example,dc=com',
            entryUUID: 'uuid-alice',
            displayName: 'Alice',
          },
        ],
      };
    }
    async unbind() {}
    async startTLS() {}
  }
  return { Client };
});

const LDAP_ENV = {
  NEXT_PUBLIC_LDAP_ENABLED: 'true',
  LDAP_URL: 'ldaps://ldap.example.com:636',
  LDAP_SEARCH_BASE: 'ou=people,dc=example,dc=com',
  LDAP_USER_FILTER: '(uid={username})',
  LDAP_SESSION_SECRET: 's'.repeat(48),
  LDAP_SESSION_TTL_SECONDS: '3600',
};

function stubLdapEnv(overrides: Record<string, string> = {}) {
  for (const [key, value] of Object.entries({ ...LDAP_ENV, ...overrides })) {
    vi.stubEnv(key, value);
  }
}

function loginRequest(
  body: unknown,
  headers: Record<string, string> = {
    'content-type': 'application/json',
    'sec-fetch-site': 'same-origin',
  },
) {
  return new Request('http://localhost/api/auth/login', {
    method: 'POST',
    headers,
    body: JSON.stringify(body),
  });
}

afterEach(() => {
  vi.unstubAllEnvs();
  vi.resetModules();
});

describe('POST /api/auth/login', () => {
  it('sets a session cookie for a valid directory login', async () => {
    stubLdapEnv();
    const { POST } = await import('@/app/api/auth/login/route');

    const response = await POST(loginRequest({ username: 'alice', password: BIND_PASSWORD }));

    expect(response.status).toBe(200);
    const cookie = response.headers.get('set-cookie') ?? '';
    expect(cookie).toContain('openmaic_ldap=');
    expect(cookie).toContain('HttpOnly');
    expect(cookie).toContain('Max-Age=3600');
    const body = (await response.json()) as Record<string, unknown>;
    expect(body).toMatchObject({ ok: true, user: { name: 'Alice' } });
    expect(JSON.stringify(body)).not.toContain(BIND_PASSWORD);
  });

  it('answers a generic 401 for a wrong password', async () => {
    stubLdapEnv();
    const { POST } = await import('@/app/api/auth/login/route');

    const response = await POST(loginRequest({ username: 'alice', password: 'wrong' }));

    expect(response.status).toBe(401);
    expect(response.headers.get('set-cookie')).toBeNull();
    expect(JSON.stringify(await response.json())).not.toMatch(
      /invalid credentials|user.*not found/i,
    );
  });

  it('refuses a cross-origin login', async () => {
    stubLdapEnv();
    const { POST } = await import('@/app/api/auth/login/route');

    const response = await POST(
      loginRequest(
        { username: 'alice', password: BIND_PASSWORD },
        {
          'content-type': 'application/json',
          'sec-fetch-site': 'cross-site',
        },
      ),
    );

    expect(response.status).toBe(403);
  });

  it('is not found while LDAP is not enabled', async () => {
    stubLdapEnv({ NEXT_PUBLIC_LDAP_ENABLED: 'false' });
    const { POST } = await import('@/app/api/auth/login/route');

    const response = await POST(loginRequest({ username: 'alice', password: BIND_PASSWORD }));
    expect(response.status).toBe(404);
  });

  it('refuses a body without both fields', async () => {
    stubLdapEnv();
    const { POST } = await import('@/app/api/auth/login/route');

    const response = await POST(loginRequest({ username: 'alice' }));
    expect(response.status).toBe(400);
  });
});
