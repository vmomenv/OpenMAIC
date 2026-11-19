import { NextRequest, NextResponse } from 'next/server';

import { isAgentRuntimeConfigured, isWorkbenchEnabled } from '@/lib/config/feature-flags';
import { verifyAccessTokenEdge } from '@/lib/server/access-token-edge';
import { ldapEnabled } from '@/lib/server/identity/ldap/config';
import {
  decodeLdapSessionPayload,
  LDAP_SESSION_COOKIE,
} from '@/lib/server/identity/ldap/session-shared';
import {
  anonymousOwnerForNavigation,
  isDocumentNavigation,
  type NavigationIdentity,
} from '@/lib/server/identity/navigation';

/**
 * Let the request through, carrying the anonymous owner a page request
 * establishes: the cookie is set on the page response, and the forwarded
 * request carries it too, so the page and every request it sends resolve one
 * owner (see `lib/server/identity/navigation.ts`).
 */
function next(request: NextRequest, identity: NavigationIdentity | undefined): NextResponse {
  if (!identity) return NextResponse.next();
  const headers = new Headers(request.headers);
  headers.set('cookie', identity.requestCookie);
  const response = NextResponse.next({ request: { headers } });
  response.headers.append('set-cookie', identity.setCookie);
  return response;
}

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;

  // This machine-only route verifies its own signed gateway request in Node.
  if (pathname === '/api/sandbox/preview/resolve') return NextResponse.next();

  // Return an actual server-side 404 when either half of the workbench is off.
  // Edge middleware cannot reliably inspect server-only deployment variables,
  // so it enforces the public gate and leaves the complete runtime/database
  // check to Node. A Node-hosted middleware uses the same gate as startup.
  const canInspectServerRuntime = process.env.NEXT_RUNTIME !== 'edge';
  const workbenchEnabled =
    isWorkbenchEnabled() && (!canInspectServerRuntime || isAgentRuntimeConfigured());
  if (!workbenchEnabled && (pathname === '/workbench' || pathname.startsWith('/workbench/'))) {
    return new NextResponse('Not found', { status: 404 });
  }

  // One anonymous owner per browser, established on the page response before
  // any API request can mint its own.
  const identity = anonymousOwnerForNavigation({
    method: request.method,
    headers: request.headers,
    pathname,
  });

  const accessCode = process.env.ACCESS_CODE;
  if (accessCode) {
    // Whitelist: access-code endpoints, health check
    if (!pathname.startsWith('/api/access-code/') && pathname !== '/api/health') {
      // Check cookie — validate HMAC signature, not just existence
      const cookie = request.cookies.get('openmaic_access');
      if (!(cookie?.value && (await verifyAccessTokenEdge(cookie.value, accessCode)))) {
        // API requests without valid cookie → 401
        if (pathname.startsWith('/api/')) {
          return NextResponse.json(
            { success: false, errorCode: 'INVALID_REQUEST', error: 'Access code required' },
            { status: 401 },
          );
        }
        // Page requests → let through, frontend shows modal
      }
    }
  }

  // LDAP accounts: page navigations without a live session go to /login, and
  // every other request that is not the login/logout surface is refused. The
  // signature is checked by the owner auth method in Node; here only the
  // payload and expiry are read, because middleware may run in the Edge
  // runtime where the signing secret is not available.
  const ldapResponse = ldapGate(request);
  if (ldapResponse) return ldapResponse;

  return next(request, identity);
}

const LDAP_PUBLIC_PATHS = ['/login', '/api/auth/login', '/api/auth/logout', '/api/health'];

function ldapGate(request: NextRequest): NextResponse | undefined {
  if (!ldapEnabled()) return undefined;
  const { pathname } = request.nextUrl;
  if (LDAP_PUBLIC_PATHS.includes(pathname) || pathname.startsWith('/api/access-code/')) {
    return undefined;
  }

  const token = request.cookies.get(LDAP_SESSION_COOKIE)?.value;
  if (token && decodeLdapSessionPayload(token)) return undefined;

  if (pathname.startsWith('/api/')) {
    return NextResponse.json(
      { success: false, errorCode: 'INVALID_CREDENTIAL', error: 'authentication required' },
      { status: 401 },
    );
  }

  // An expired session in an open tab should land on the login form; an RSC
  // fetch or Server Action gets a plain refusal instead of an HTML redirect.
  if (
    !isDocumentNavigation({
      method: request.method,
      headers: request.headers,
      pathname,
    })
  ) {
    return new NextResponse('Authentication required', { status: 401 });
  }

  const login = new URL('/login', request.url);
  login.searchParams.set('next', `${pathname}${request.nextUrl.search}`);
  return NextResponse.redirect(login);
}

export const config = {
  // The duplex machine route authenticates its signed descriptor itself. Middleware
  // forwarding buffers POST bodies and would deadlock a bidirectional stream.
  matcher: ['/((?!_next/static|_next/image|favicon.ico|logos/|api/sandbox/preview/tunnel$).*)'],
};
