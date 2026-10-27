import Link from 'next/link';
import { ThemeToggle } from './theme-toggle.tsx';

export interface NavTab { href: string; label: string }

const MAIN_LINKS: NavTab[] = [
  { href: '/dashboard', label: 'Dashboard' },
  { href: '/billing', label: 'Billing' },
  { href: '/pricing', label: 'Pricing' },
];

export function TopBar({ tabs, current, context }: { tabs?: NavTab[]; current?: string; context?: string }) {
  return (
    <header
      style={{
        borderBottom: '1px solid var(--border)', background: 'var(--surface)',
        position: 'sticky', top: 0, zIndex: 10,
      }}
    >
      <div
        style={{
          maxWidth: '78rem', margin: '0 auto', padding: '0 1rem',
          display: 'flex', alignItems: 'center', gap: '1rem', minHeight: 52, flexWrap: 'wrap',
        }}
      >
        <Link
          href="/"
          style={{
            display: 'flex', alignItems: 'baseline', gap: '0.4rem',
            textDecoration: 'none', color: 'var(--ink)', fontWeight: 650, letterSpacing: '-0.01em',
          }}
        >
          <span aria-hidden="true" style={{ color: 'var(--accent)' }}>◎</span>
          <span>CodeLens</span>
          <span style={{ color: 'var(--ink-3)', fontWeight: 500, fontSize: '0.85rem' }}>AI</span>
        </Link>

        {context ? (
          <>
            <span aria-hidden="true" style={{ color: 'var(--border-strong)' }}>/</span>
            <span style={{ color: 'var(--ink-2)', fontSize: '0.9rem', fontWeight: 550 }}>{context}</span>
          </>
        ) : null}

        <div style={{ flex: 1 }} />

        {tabs && tabs.length > 0 ? (
          <nav aria-label="Project sections" style={{ display: 'flex', gap: '0.15rem', flexWrap: 'wrap' }}>
            {tabs.map((t) => {
              const active = current === t.href;
              return (
                <Link
                  key={t.href}
                  href={t.href}
                  aria-current={active ? 'page' : undefined}
                  style={{
                    padding: '0.3rem 0.6rem', borderRadius: 6, fontSize: '0.86rem',
                    textDecoration: 'none',
                    color: active ? 'var(--ink)' : 'var(--ink-3)',
                    background: active ? 'var(--surface-3)' : 'transparent',
                    fontWeight: active ? 600 : 500,
                  }}
                >
                  {t.label}
                </Link>
              );
            })}
          </nav>
        ) : (
          <nav aria-label="Main" style={{ display: 'flex', gap: '0.15rem' }}>
            {MAIN_LINKS.map((l) => (
              <Link
                key={l.href}
                href={l.href}
                style={{ padding: '0.3rem 0.6rem', borderRadius: 6, fontSize: '0.86rem', textDecoration: 'none', color: 'var(--ink-3)' }}
              >
                {l.label}
              </Link>
            ))}
          </nav>
        )}

        <ThemeToggle />
      </div>
    </header>
  );
}

export function projectTabs(projectId: string): NavTab[] {
  const base = `/projects/${encodeURIComponent(projectId)}`;
  return [
    { href: base, label: 'Overview' },
    { href: `${base}/architecture`, label: 'Architecture' },
    { href: `${base}/findings`, label: 'Findings' },
    { href: `${base}/fix-studio`, label: 'Fix Studio' },
    { href: `${base}/chat`, label: 'Ask' },
    { href: `${base}/reports`, label: 'Reports' },
  ];
}

export function Shell({ children }: { children: React.ReactNode }) {
  return (
    <main
      id="main"
      style={{
        maxWidth: '78rem', margin: '0 auto', padding: '1.5rem 1rem 4rem',
        display: 'grid', gap: '1.25rem',
        // `minmax(0, 1fr)` rather than the implicit `1fr`.
        //
        // A grid item's default `min-width: auto` refuses to shrink below its
        // content's minimum width. `Table` already wraps itself in
        // `overflow-x: auto` so a wide table scrolls inside its card — but that
        // wrapper can never engage while the card above it is a grid item that
        // will not narrow. The card widens instead and takes the page with it.
        //
        // Measured on /billing at 375px, where the credit ledger is the widest
        // table in the application: `document.body.scrollWidth` was 558px
        // without this declaration and 375px with it. Use `body.scrollWidth`,
        // or whether the page actually scrolls, to check this —
        // `documentElement.scrollWidth` reports the unclipped width of content
        // inside a scroll container and reads as overflow on pages that are
        // perfectly fine.
        gridTemplateColumns: 'minmax(0, 1fr)',
      }}
    >
      {children}
    </main>
  );
}
