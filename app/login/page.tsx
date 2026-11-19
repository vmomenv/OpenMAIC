import { cookies, headers } from 'next/headers';
import { redirect } from 'next/navigation';

import { LOCALE_COOKIE, resolveRequestLocale } from '@/lib/i18n/resolve-locale';
import { ldapEnabled } from '@/lib/server/identity/ldap/config';
import {
  decodeLdapSessionPayload,
  LDAP_SESSION_COOKIE,
} from '@/lib/server/identity/ldap/session-shared';

import { LoginForm, type LoginLabels } from './login-form';

export const dynamic = 'force-dynamic';

/**
 * The only page reachable without an owner session.
 *
 * It lives outside the workspace shell on purpose: the shell reads owner-scoped
 * APIs, and with `anonymousFallback: false` those answer 401 until this page
 * has minted a session. Static assets and the root layout still load, so the
 * form has the app's theme and locale.
 */
export default async function LoginPage({
  searchParams,
}: {
  readonly searchParams: Promise<{ next?: string | string[] }>;
}) {
  const params = await searchParams;
  const nextPath = safeNextPath(params.next);

  if (!ldapEnabled()) redirect('/');

  const [cookieStore, headerStore] = await Promise.all([cookies(), headers()]);
  const token = cookieStore.get(LDAP_SESSION_COOKIE)?.value;
  if (token && decodeLdapSessionPayload(token)) redirect(nextPath);

  const locale = resolveRequestLocale({
    cookie: cookieStore.get(LOCALE_COOKIE)?.value,
    acceptLanguage: headerStore.get('accept-language'),
  });
  const labels = loginLabels(locale.startsWith('zh'));

  return (
    <main className="flex min-h-dvh items-center justify-center bg-background px-4 py-10 text-foreground">
      <div className="w-full max-w-sm">
        <div className="mb-7 flex flex-col items-center gap-2 text-center">
          <span className="text-2xl font-semibold tracking-tight">OpenMAIC</span>
          <h1 className="text-lg font-medium">{labels.title}</h1>
          <p className="text-sm text-muted-foreground">{labels.subtitle}</p>
        </div>
        <LoginForm nextPath={nextPath} labels={labels} />
        <p className="mt-6 text-center text-xs text-muted-foreground">{labels.footer}</p>
      </div>
    </main>
  );
}

/** Only a path on this site; a protocol-relative or absolute URL is ignored. */
function safeNextPath(value: string | string[] | undefined): string {
  const raw = Array.isArray(value) ? value[0] : value;
  if (!raw || !raw.startsWith('/') || raw.startsWith('//') || raw.includes('\\')) return '/';
  return raw;
}

function loginLabels(zh: boolean): LoginLabels {
  return zh
    ? {
        title: '使用 LDAP 账号登录',
        subtitle: '登录后，每个人的课程库相互独立。',
        username: '用户名',
        password: '密码',
        submit: '登录',
        pending: '正在登录…',
        invalid: '用户名或密码错误',
        unavailable: '目录服务暂时不可用，请稍后重试。',
        rateLimited: '尝试次数过多，请稍后再试。',
        empty: '请输入用户名和密码。',
        footer: '账号由你所在组织的 LDAP 目录管理。',
      }
    : {
        title: 'Sign in with your LDAP account',
        subtitle: 'Each account gets its own course library.',
        username: 'Username',
        password: 'Password',
        submit: 'Sign in',
        pending: 'Signing in…',
        invalid: 'Incorrect username or password',
        unavailable: 'The directory is unavailable. Try again shortly.',
        rateLimited: 'Too many attempts. Try again later.',
        empty: 'Enter your username and password.',
        footer: 'Accounts are managed by your organization’s LDAP directory.',
      };
}
