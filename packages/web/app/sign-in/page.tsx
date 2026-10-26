import { redirect } from 'next/navigation';
import { TopBar, Shell } from '../components/nav.tsx';
import { Card, Caveat, SectionHeading } from '../components/ui.tsx';
import { currentSession } from '../lib/session.ts';
import { AuthForm } from './auth-form.tsx';

export const metadata = { title: 'Sign in — CodeLens AI' };

export default async function SignInPage({
  searchParams,
}: {
  searchParams: Promise<{ next?: string }>;
}) {
  // Already signed in: there is nothing to do here.
  if (await currentSession()) redirect('/dashboard');
  const { next } = await searchParams;

  return (
    <>
      <TopBar />
      <Shell>
        <div style={{ maxWidth: '26rem', margin: '2rem auto 0', width: '100%' }}>
          <Card>
            <SectionHeading hint="Projects, scans and findings belong to the account that created them.">
              Sign in to CodeLens
            </SectionHeading>
            <AuthForm next={typeof next === 'string' ? next : undefined} />
          </Card>

          <div style={{ marginTop: '1rem' }}>
            <Caveat tone="neutral">
              This installation stores accounts in its own database. Passwords are kept as scrypt
              verifiers, never in plain text, and the session cookie is signed. Set a
              <code style={{ fontFamily: 'var(--font-mono)' }}> CODELENS_SECRET_KEY</code> of 32
              characters or more before using this on anything but your own machine.
            </Caveat>
          </div>
        </div>
      </Shell>
    </>
  );
}
