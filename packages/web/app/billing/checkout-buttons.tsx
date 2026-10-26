'use client';

import { useState } from 'react';

/**
 * Checkout buttons.
 *
 * A client component because it posts and then navigates. It imports nothing
 * server-side: every price, label and code arrives as a plain prop from the
 * page that read them from the database, so no billing module and no database
 * handle is pulled into the browser bundle.
 *
 * The failure behaviour is the point of this file. A checkout that does not
 * start must look like a checkout that did not start: the error the route
 * returned is shown verbatim — 402 when a payment is outstanding, 409 when the
 * plan is not purchasable, 503 when billing is not configured on this
 * installation — and there is no success state to reach without a provider URL
 * in hand. The browser is only sent away once a URL has actually come back.
 */

export interface CheckoutOption {
  /** A plan code or a product code. Validated again on the server. */
  code: string;
  kind: 'subscription' | 'one_time';
  label: string;
  /** Rendered under the label. Already formatted by the server. */
  detail?: string;
  /** The visually prominent option, if any. */
  primary?: boolean;
}

interface Pending {
  code: string;
}

function buttonStyle(primary: boolean, busy: boolean) {
  return {
    display: 'grid',
    gap: '0.15rem',
    textAlign: 'left' as const,
    padding: '0.55rem 0.8rem',
    borderRadius: 8,
    font: 'inherit',
    fontSize: '0.9rem',
    cursor: busy ? 'progress' : 'pointer',
    border: `1px solid ${primary ? 'var(--accent)' : 'var(--border-strong)'}`,
    background: primary ? 'var(--accent)' : 'var(--surface)',
    color: primary ? 'var(--accent-ink)' : 'var(--ink)',
    opacity: busy ? 0.7 : 1,
  };
}

export function CheckoutButtons({ options, label }: { options: CheckoutOption[]; label: string }) {
  const [pending, setPending] = useState<Pending | undefined>();
  const [error, setError] = useState<string | undefined>();

  async function start(option: CheckoutOption): Promise<void> {
    setPending({ code: option.code });
    setError(undefined);
    try {
      const res = await fetch('/api/billing/checkout', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ code: option.code, kind: option.kind }),
      });
      const body = (await res.json().catch(() => ({}))) as { url?: unknown; error?: unknown };

      if (!res.ok) {
        const message = typeof body.error === 'string' && body.error.length > 0
          ? body.error
          : `Checkout could not be started (HTTP ${res.status}).`;
        setError(message);
        return;
      }
      // A 200 with no usable URL is still a failure. Saying otherwise would
      // leave someone waiting for a payment page that is never coming.
      if (typeof body.url !== 'string' || !/^https?:\/\//.test(body.url)) {
        setError('The server accepted the request but returned no checkout URL. Nothing has been charged.');
        return;
      }
      // A full navigation, not a router push: the destination is the provider's
      // own domain.
      window.location.assign(body.url);
    } catch {
      setError('Could not reach the server, so no checkout was started.');
    } finally {
      // Left pending on the success path too — the navigation is already under
      // way, and re-enabling the button would invite a second checkout.
      setPending((current) => (current?.code === option.code ? undefined : current));
    }
  }

  const busy = pending !== undefined;

  return (
    <div style={{ display: 'grid', gap: '0.6rem' }}>
      <div
        role="group"
        aria-label={label}
        style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}
      >
        {options.map((option) => {
          const thisBusy = pending?.code === option.code;
          return (
            <button
              key={`${option.kind}:${option.code}`}
              type="button"
              onClick={() => { void start(option); }}
              disabled={busy}
              aria-busy={thisBusy || undefined}
              style={buttonStyle(option.primary === true, thisBusy)}
            >
              <span style={{ fontWeight: 650 }}>
                {thisBusy ? 'Opening checkout…' : option.label}
              </span>
              {option.detail ? (
                <span
                  style={{
                    fontSize: '0.8rem',
                    opacity: 0.85,
                    fontWeight: 500,
                  }}
                >
                  {option.detail}
                </span>
              ) : null}
            </button>
          );
        })}
      </div>

      {error ? (
        <p
          role="alert"
          style={{
            margin: 0,
            padding: '0.5rem 0.7rem',
            borderRadius: 6,
            border: '1px solid var(--critical)',
            background: 'var(--critical-soft)',
            color: 'var(--critical)',
            fontSize: '0.84rem',
            lineHeight: 1.5,
          }}
        >
          <strong style={{ fontWeight: 650 }}>Checkout did not start.</strong> {error}
        </p>
      ) : null}
    </div>
  );
}
