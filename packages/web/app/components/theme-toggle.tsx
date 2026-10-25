'use client';
import { useEffect, useState } from 'react';

type Theme = 'system' | 'light' | 'dark';

/**
 * Theme control.
 *
 * Defaults to the operating-system preference and only overrides it when the
 * user asks. The chosen value is written to localStorage inside try/catch,
 * because storage throws in a private window and the control must keep working.
 */
export function ThemeToggle() {
  const [theme, setTheme] = useState<Theme>('system');

  useEffect(() => {
    try {
      const stored = localStorage.getItem('codelens-theme');
      if (stored === 'light' || stored === 'dark') setTheme(stored);
    } catch { /* storage unavailable: keep the system default */ }
  }, []);

  useEffect(() => {
    const root = document.documentElement;
    if (theme === 'system') root.removeAttribute('data-theme');
    else root.setAttribute('data-theme', theme);
    try {
      if (theme === 'system') localStorage.removeItem('codelens-theme');
      else localStorage.setItem('codelens-theme', theme);
    } catch { /* ignore */ }
  }, [theme]);

  const next: Record<Theme, Theme> = { system: 'light', light: 'dark', dark: 'system' };
  const label: Record<Theme, string> = { system: 'System theme', light: 'Light theme', dark: 'Dark theme' };
  const icon: Record<Theme, string> = { system: '◐', light: '☀', dark: '☾' };

  return (
    <button
      type="button"
      onClick={() => setTheme(next[theme])}
      aria-label={`${label[theme]}. Activate to switch to ${label[next[theme]].toLowerCase()}.`}
      title={label[theme]}
      style={{
        background: 'transparent', border: '1px solid var(--border)', color: 'var(--ink-2)',
        borderRadius: 6, width: 30, height: 30, cursor: 'pointer', fontSize: '0.9rem', lineHeight: 1,
      }}
    >
      <span aria-hidden="true">{icon[theme]}</span>
    </button>
  );
}
