import { describe, expect, it } from 'vitest';

import { escapeLdapFilterValue } from '@/lib/server/identity/ldap/filter';

describe('escapeLdapFilterValue', () => {
  it('escapes every RFC 4515 special character', () => {
    expect(escapeLdapFilterValue('a*b(c)d\\e\u0000f')).toBe('a\\2ab\\28c\\29d\\5ce\\00f');
  });

  it('leaves ordinary usernames unchanged', () => {
    expect(escapeLdapFilterValue('alice.smith@example.com')).toBe('alice.smith@example.com');
  });
});
