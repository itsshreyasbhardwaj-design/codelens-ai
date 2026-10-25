import Link from 'next/link';
import { Shell, TopBar } from '../../components/nav.tsx';
import { Card } from '../../components/ui.tsx';

/**
 * Shown when `getProject()` returns nothing.
 *
 * The store answers a request for another organisation's project exactly as it
 * answers a request for one that was never created, so this page must not
 * distinguish the two. It says the project is not available to this account and
 * stops there — guessing identifiers must not be a way to learn what exists.
 */
export default function ProjectNotFound() {
  return (
    <>
      <TopBar />
      <Shell>
        <Card>
          <h1 style={{ margin: 0, fontSize: '1.4rem', fontWeight: 680, letterSpacing: '-0.02em' }}>
            Project not available
          </h1>
          <p style={{ margin: '0.6rem 0 0', color: 'var(--ink-2)', lineHeight: 1.65, maxWidth: '44rem' }}>
            No project is available at this address. Either the identifier does not exist or it belongs to
            another account; this page will not say which, because answering that question would let anyone
            map out projects by guessing identifiers.
          </p>
          <p style={{ margin: '0.6rem 0 0', color: 'var(--ink-2)', lineHeight: 1.65, maxWidth: '44rem' }}>
            If you typed or pasted the address, check it for a missing character. Otherwise, open the
            dashboard, which lists every project this account can see.
          </p>
          <p style={{ margin: '1rem 0 0' }}>
            <Link href="/dashboard">Back to the dashboard</Link>
          </p>
        </Card>
      </Shell>
    </>
  );
}
