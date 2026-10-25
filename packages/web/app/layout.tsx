import type { Metadata, Viewport } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'CodeLens AI — understand any codebase',
  description:
    'Turn any accessible codebase into a technical blueprint, an evidence-backed diagnostic report, and a small set of actionable coding-agent prompts.',
};

export const viewport: Viewport = {
  width: 'device-width',
  initialScale: 1,
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        {/*
          Apply the stored theme before first paint so a user who chose a theme
          does not see a flash of the other one. Wrapped in try/catch because
          storage access throws in a private window.
        */}
        <script
          dangerouslySetInnerHTML={{
            __html:
              "try{var t=localStorage.getItem('codelens-theme');if(t==='light'||t==='dark'){document.documentElement.setAttribute('data-theme',t)}}catch(e){}",
          }}
        />
      </head>
      <body>
        <a
          href="#main"
          style={{
            position: 'absolute', left: '-9999px', top: 0, zIndex: 100,
            background: 'var(--surface)', color: 'var(--ink)', padding: '0.5rem 0.8rem',
            border: '1px solid var(--border)', borderRadius: 6,
          }}
          onFocus={undefined}
          className="skip-link"
        >
          Skip to content
        </a>
        {children}
      </body>
    </html>
  );
}
