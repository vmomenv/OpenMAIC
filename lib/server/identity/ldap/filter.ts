/**
 * RFC 4515 escaping for values interpolated into an LDAP filter.
 *
 * The username comes from a login form and is spliced into
 * `LDAP_USER_FILTER`. Without escaping, `*` turns the search into a wildcard
 * and `)(|(objectClass=*)` widens it into an injection. Escape the five special
 * characters; everything else is literal.
 */
export function escapeLdapFilterValue(value: string): string {
  let escaped = '';
  for (const character of value) {
    switch (character) {
      case '\\':
        escaped += '\\5c';
        break;
      case '*':
        escaped += '\\2a';
        break;
      case '(':
        escaped += '\\28';
        break;
      case ')':
        escaped += '\\29';
        break;
      case '\u0000':
        escaped += '\\00';
        break;
      default:
        escaped += character;
    }
  }
  return escaped;
}
