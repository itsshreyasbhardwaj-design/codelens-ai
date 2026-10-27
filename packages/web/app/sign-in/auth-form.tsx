'use client';
import { useState } from 'react';
import { useRouter } from 'next/navigation';

type Mode = 'signin' | 'register';

const field: React.CSSProperties = {
  width: '100%', padding: '0.45rem 0.6rem', borderRadius: 6,
  border: '1px solid var(--border)', background: 'var(--surface-2)',
  color: 'var(--ink)', font: 'inherit', fontSize: '0.9rem',
};

export function AuthForm({ next }: { next?: string }) {
  const router = useRouter();
  const [mode, setMode] = useState<Mode>('signin');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | undefined>();

  async function submit(event: React.FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    setBusy(true);
    setError(undefined);
    try {
      const res = await fetch(`/api/auth/${mode === 'signin' ? 'login' : 'register'}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          email: String(form.get('email') ?? ''),
          password: String(form.get('password') ?? ''),
          ...(mode === 'register' ? { displayName: String(form.get('displayName') ?? '') || undefined } : {}),
        }),
      });
      if (!res.ok) {
        const body = (await res.json().catch(() => ({}))) as { error?: string };
        setError(body.error ?? `request failed (${res.status})`);
        return;
      }
      router.push(next && next.startsWith('/') ? next : '/dashboard');
      router.refresh();
    } catch {
      setError('could not reach the server');
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} style={{ display: 'grid', gap: '0.75rem' }}>
      <div role="group" aria-label="Account action" style={{ display: 'flex', gap: '0.3rem' }}>
        {(['signin', 'register'] as Mode[]).map((m) => (
          <button
            key={m}
            type="button"
            onClick={() => { setMode(m); setError(undefined); }}
            aria-pressed={mode === m}
            style={{
              flex: 1, padding: '0.35rem', borderRadius: 6, cursor: 'pointer',
              border: '1px solid var(--border)',
              background: mode === m ? 'var(--surface-3)' : 'transparent',
              color: mode === m ? 'var(--ink)' : 'var(--ink-3)',
              font: 'inherit', fontSize: '0.86rem', fontWeight: mode === m ? 600 : 500,
            }}
          >
            {m === 'signin' ? 'Sign in' : 'Create account'}
          </button>
        ))}
      </div>

      {mode === 'register' ? (
        <label style={{ display: 'grid', gap: '0.25rem', fontSize: '0.84rem' }}>
          Name <span style={{ color: 'var(--ink-3)' }}>(optional)</span>
          <input name="displayName" type="text" autoComplete="name" style={field} />
        </label>
      ) : null}

      <label style={{ display: 'grid', gap: '0.25rem', fontSize: '0.84rem' }}>
        Email
        <input name="email" type="email" required autoComplete="email" style={field} />
      </label>

      <label style={{ display: 'grid', gap: '0.25rem', fontSize: '0.84rem' }}>
        Password
        <input
          name="password"
          type="password"
          required
          minLength={10}
          autoComplete={mode === 'signin' ? 'current-password' : 'new-password'}
          aria-describedby={mode === 'register' ? 'pw-hint' : undefined}
          style={field}
        />
      </label>
      {mode === 'register' ? (
        <p id="pw-hint" style={{ margin: 0, fontSize: '0.78rem', color: 'var(--ink-3)' }}>
          At least 10 characters.
        </p>
      ) : null}

      {error ? (
        <p role="alert" style={{ margin: 0, fontSize: '0.84rem', color: 'var(--critical)' }}>
          {error}
        </p>
      ) : null}

      <button
        type="submit"
        disabled={busy}
        style={{
          padding: '0.5rem', borderRadius: 6, border: '1px solid var(--accent)',
          background: 'var(--accent)', color: 'var(--accent-ink)',
          cursor: busy ? 'progress' : 'pointer', font: 'inherit', fontSize: '0.9rem', fontWeight: 600,
          opacity: busy ? 0.7 : 1,
        }}
      >
        {busy ? 'Working…' : mode === 'signin' ? 'Sign in' : 'Create account'}
      </button>
    </form>
  );
}
