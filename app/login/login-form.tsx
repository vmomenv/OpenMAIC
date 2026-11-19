'use client';

import { useState, type FormEvent } from 'react';

export interface LoginLabels {
  title: string;
  subtitle: string;
  username: string;
  password: string;
  submit: string;
  pending: string;
  invalid: string;
  unavailable: string;
  rateLimited: string;
  empty: string;
  footer: string;
}

export function LoginForm({
  nextPath,
  labels,
}: {
  readonly nextPath: string;
  readonly labels: LoginLabels;
}) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (pending) return;
    if (username.trim() === '' || password === '') {
      setError(labels.empty);
      return;
    }
    setPending(true);
    setError(null);

    try {
      const response = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ username: username.trim(), password }),
        cache: 'no-store',
      });
      if (response.ok) {
        // A full navigation, not a client transition: every owner-scoped store
        // and fetch on the next page must start from the new session.
        window.location.assign(nextPath);
        return;
      }
      setPassword('');
      if (response.status === 429) setError(labels.rateLimited);
      else if (response.status === 503) setError(labels.unavailable);
      else setError(labels.invalid);
    } catch {
      setError(labels.unavailable);
    } finally {
      setPending(false);
    }
  }

  return (
    <form
      onSubmit={onSubmit}
      className="flex flex-col gap-4 rounded-2xl border border-border bg-card p-6 shadow-sm"
      noValidate
    >
      <label className="flex flex-col gap-1.5 text-sm">
        <span className="font-medium">{labels.username}</span>
        <input
          name="username"
          type="text"
          autoComplete="username"
          autoCapitalize="none"
          autoCorrect="off"
          spellCheck={false}
          required
          autoFocus
          disabled={pending}
          value={username}
          onChange={(event) => setUsername(event.target.value)}
          className="h-10 rounded-lg border border-input bg-background px-3 text-sm outline-none ring-offset-background focus-visible:ring-2 focus-visible:ring-ring disabled:opacity-60"
        />
      </label>

      <label className="flex flex-col gap-1.5 text-sm">
        <span className="font-medium">{labels.password}</span>
        <input
          name="password"
          type="password"
          autoComplete="current-password"
          required
          disabled={pending}
          value={password}
          onChange={(event) => setPassword(event.target.value)}
          className="h-10 rounded-lg border border-input bg-background px-3 text-sm outline-none ring-offset-background focus-visible:ring-2 focus-visible:ring-ring disabled:opacity-60"
        />
      </label>

      <p
        role="alert"
        aria-live="polite"
        className={error === null ? 'sr-only' : 'text-sm text-destructive'}
      >
        {error ?? ''}
      </p>

      <button
        type="submit"
        disabled={pending}
        className="mt-1 inline-flex h-10 items-center justify-center rounded-lg bg-primary px-4 text-sm font-medium text-primary-foreground transition-opacity hover:opacity-90 disabled:opacity-60"
      >
        {pending ? labels.pending : labels.submit}
      </button>
    </form>
  );
}
