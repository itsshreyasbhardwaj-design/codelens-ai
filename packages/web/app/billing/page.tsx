import Link from 'next/link';
import { grantMonthlyAllowance, ledger, type LedgerEntry } from '@codelens/engine/billing/credits.ts';
import { usageSummary, type UsageSummary } from '@codelens/engine/billing/entitlements.ts';
import { loadPaymentProvider } from '@codelens/engine/billing/payments.ts';
import { DEFAULT_PRODUCTS, listPlans, type PlanRow } from '@codelens/engine/billing/plans.ts';
import { Shell, TopBar } from '../components/nav.tsx';
import { Card, Caveat, EmptyState, SectionHeading, Stat, Table, Tag, Td } from '../components/ui.tsx';
import { requireSession } from '../lib/session.ts';
import { db } from '../lib/store.ts';
import { CheckoutButtons, type CheckoutOption } from './checkout-buttons.tsx';

/**
 * Billing and usage.
 *
 * Every number comes from the billing engine: the plan and its limits from
 * `usageSummary`, the balance and its history from the credit ledger. Nothing
 * is estimated and nothing is rounded into a nicer figure — this is the page
 * someone opens to check a charge, so the ledger is shown in full, in order,
 * with the balance after each entry, exactly as recorded.
 *
 * Where billing is not configured the page says so and renders no checkout
 * control, because an upgrade button that cannot work is a lie with a hover
 * state.
 */

export const dynamic = 'force-dynamic';

export const metadata = {
  title: 'Billing — CodeLens AI',
  description: 'The current plan, usage against its limits, the credit balance and the credit ledger.',
};

// -------------------------------------------------------------- formatting --

const CURRENCY_SYMBOL: Record<string, string> = { usd: '$', eur: '€', gbp: '£', inr: '₹' };

/** Minor units to a readable amount: 1900 becomes "$19", 1950 becomes "$19.50". */
function money(minorUnits: number, currency: string): string {
  const major = Math.trunc(minorUnits / 100);
  const minor = Math.abs(minorUnits % 100);
  const amount = minor === 0
    ? major.toLocaleString('en-GB')
    : `${major.toLocaleString('en-GB')}.${String(minor).padStart(2, '0')}`;
  const symbol = CURRENCY_SYMBOL[currency.toLowerCase()];
  return symbol ? `${symbol}${amount}` : `${amount} ${currency.toUpperCase()}`;
}

const INTERVAL_SUFFIX: Record<PlanRow['interval'], string> = {
  month: 'a month', year: 'a year', once: 'once', none: '',
};

function num(value: number): string {
  return value.toLocaleString('en-GB');
}

/**
 * An ISO timestamp to the second, in UTC.
 *
 * Deliberately not localised: a ledger line is evidence, and it should read the
 * same for the customer and for whoever they quote it to. Seconds are kept
 * because several movements of one scan — the reservation, then its settlement
 * and refund — land in the same minute, and an audit trail that cannot
 * distinguish them is harder to check than one that can.
 */
function timestamp(iso: string): string {
  return /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(iso)
    ? `${iso.slice(0, 10)} ${iso.slice(11, 19)} UTC`
    : iso;
}

/** A plain date, for an allowance reset. */
function dateOnly(iso: string): string {
  return /^\d{4}-\d{2}-\d{2}/.test(iso) ? iso.slice(0, 10) : iso;
}

// -------------------------------------------------------------- components --

/**
 * Usage against one limit.
 *
 * A null limit is unbounded and renders as words, never as a full bar — a bar
 * at 100% would read as "exhausted", the opposite of what it means. A limit of
 * zero is a figure the contract sets rather than a quota, so it is worded too.
 * The percentage is shown as text as well as width, so the bar is never the
 * only way to read the value.
 */
function UsageMeter({
  label, used, limit, unit, note, limitIsBlocking = true,
}: {
  label: string; used: number; limit: number | null; unit: string; note?: string;
  /**
   * Whether reaching this limit actually stops the customer doing something.
   *
   * Default true: a project or scan allowance that is used up does block the
   * next scan, and saying so in the alarm colour is correct. Seats are the
   * exception — a one-seat plan sitting at 1 of 1 is the plan working as sold,
   * not a problem, and this release has no invite flow to be blocked from. A
   * warning that fires permanently for every free account is a warning people
   * learn to ignore, which costs us the ones that matter.
   */
  limitIsBlocking?: boolean;
}) {
  const headingStyle = { fontSize: '0.8rem', color: 'var(--ink-3)', textTransform: 'uppercase' as const, letterSpacing: '0.05em', fontWeight: 600 };

  if (limit === null || limit === 0) {
    return (
      <div style={{ display: 'grid', gap: '0.25rem' }}>
        <div style={headingStyle}>{label}</div>
        <div style={{ fontSize: '0.95rem', fontWeight: 600, fontVariantNumeric: 'tabular-nums' }}>
          {num(used)} {unit}
          <span style={{ color: 'var(--ink-3)', fontWeight: 500 }}>
            {limit === null ? ' · unlimited on this plan' : ' · agreed with your contract'}
          </span>
        </div>
        {note ? <div style={{ fontSize: '0.8rem', color: 'var(--ink-3)' }}>{note}</div> : null}
      </div>
    );
  }

  const percent = Math.min(100, Math.round((used / limit) * 100));
  const full = used >= limit;
  const atLimit = full && limitIsBlocking;
  const colour = atLimit ? 'var(--critical)' : percent >= 80 ? 'var(--medium)' : 'var(--accent)';

  return (
    <div style={{ display: 'grid', gap: '0.3rem' }}>
      <div style={headingStyle}>{label}</div>
      <div
        role="meter"
        aria-valuenow={used}
        aria-valuemin={0}
        aria-valuemax={limit}
        aria-label={`${label}: ${used} of ${limit} ${unit} used`}
        style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}
      >
        <div style={{ flex: 1, height: 7, background: 'var(--surface-3)', borderRadius: 999, overflow: 'hidden', minWidth: 60 }}>
          <div style={{ width: `${percent}%`, height: '100%', background: colour }} />
        </div>
        <span style={{ fontVariantNumeric: 'tabular-nums', fontWeight: 650, fontSize: '0.88rem', whiteSpace: 'nowrap' }}>
          {num(used)} / {num(limit)}
        </span>
      </div>
      <div style={{ fontSize: '0.8rem', color: atLimit ? 'var(--critical)' : 'var(--ink-3)' }}>
        {atLimit
          ? `At the limit for ${unit}.`
          : full
            ? `Using all ${num(limit)} ${limit === 1 ? unit.replace(/s$/, '') : unit} on this plan.`
            : `${percent}% of the ${unit} on this plan.`}
        {note ? ` ${note}` : ''}
      </div>
    </div>
  );
}

function LedgerTable({ entries }: { entries: LedgerEntry[] }) {
  if (entries.length === 0) {
    return (
      <EmptyState title="No credit movements yet">
        Grants, reservations, settlements and refunds appear here as they happen, each with the
        balance it left behind.
      </EmptyState>
    );
  }
  return (
    <Table
      caption="Credit ledger: date, reason, change and resulting balance for each movement"
      head={['When', 'Reason', 'Change', 'Balance after', 'Scan']}
    >
      {entries.map((e, i) => {
        const positive = e.delta > 0;
        const sign = positive ? '+' : e.delta < 0 ? '-' : '';
        return (
          <tr key={`${e.createdAt}-${i}`}>
            <Td nowrap>
              <time dateTime={e.createdAt} style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem' }}>
                {timestamp(e.createdAt)}
              </time>
            </Td>
            <Td>{e.reason}</Td>
            <Td nowrap>
              <span
                style={{
                  color: e.delta === 0 ? 'var(--ink-3)' : positive ? 'var(--good)' : 'var(--critical)',
                  fontWeight: 650,
                  fontVariantNumeric: 'tabular-nums',
                }}
              >
                {sign}{num(Math.abs(e.delta))}
              </span>
            </Td>
            <Td nowrap>
              <span style={{ fontVariantNumeric: 'tabular-nums' }}>{num(e.balanceAfter)}</span>
            </Td>
            <Td mono nowrap>{e.scanId ?? '—'}</Td>
          </tr>
        );
      })}
    </Table>
  );
}

function PlanPanel({ summary }: { summary: UsageSummary }) {
  const plan = summary.plan;
  const suffix = INTERVAL_SUFFIX[plan.interval];
  return (
    <Card>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem 1rem', alignItems: 'baseline' }}>
        <div>
          <div style={{ fontSize: '0.8rem', color: 'var(--ink-3)', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 600 }}>
            Current plan
          </div>
          <h2 style={{ margin: '0.1rem 0 0', fontSize: '1.35rem', fontWeight: 680, letterSpacing: '-0.02em' }}>
            {plan.name}
          </h2>
        </div>
        <div style={{ fontSize: '0.95rem', color: 'var(--ink-2)', fontVariantNumeric: 'tabular-nums' }}>
          {plan.priceCents === null
            ? 'Priced by agreement'
            : `${money(plan.priceCents, plan.currency)}${suffix ? ` ${suffix}` : ''}`}
        </div>
        {plan.priceCents === 0 ? <Tag tone="good">Free plan</Tag> : null}
        <div style={{ flex: 1 }} />
        <Link href="/pricing" style={{ fontSize: '0.88rem' }}>Compare plans</Link>
      </div>

      {plan.features.length > 0 ? (
        <ul style={{ margin: '0.8rem 0 0', paddingLeft: '1.05rem', fontSize: '0.86rem', color: 'var(--ink-2)' }}>
          {plan.features.map((f) => <li key={f}>{f}</li>)}
        </ul>
      ) : null}
    </Card>
  );
}

// ------------------------------------------------------------------- page --

export default async function BillingPage({
  searchParams,
}: {
  searchParams: Promise<{ checkout?: string }>;
}) {
  const { organizationId } = await requireSession();
  const { checkout } = await searchParams;

  const unavailable = loadPaymentProvider().unavailableReason();
  const billingOff = unavailable !== undefined;

  /*
   * `usageSummary` resolves the organisation's plan, which needs the plan
   * catalogue to exist. On an installation whose `subscription_plans` table has
   * never been seeded it cannot, and the honest answer is to say which piece of
   * setup is missing rather than render a page of zeroes that look like real
   * usage.
   */
  let summary: UsageSummary;
  try {
    const atIso = new Date().toISOString();
    /*
     * Take the month's allowance before reading anything.
     *
     * The grant paths are registration, starting a scan, and the subscription
     * webhook — opening this page is none of them. So an account that spent
     * October's credits and opened Billing on the 1st of November saw a zero
     * balance and "the AI layer is unavailable until this is topped up" next to
     * the purchase buttons, while submitting a scan would have granted the
     * credits immediately. That prompts someone to buy what they already have.
     *
     * Idempotent on (organisation, plan, month), so a refresh cannot grant
     * twice, and it returns early for a plan with no monthly allowance. It sits
     * INSIDE this try because it resolves the plan too: on an unseeded
     * catalogue it raises the same error, and that must still render the
     * explanation below rather than failing the page.
     */
    grantMonthlyAllowance(db(), organizationId, atIso);
    summary = usageSummary(db(), organizationId, atIso);
  } catch (e) {
    return (
      <>
        <TopBar context="Billing" />
        <Shell>
          <h1 style={{ fontSize: '1.45rem', fontWeight: 680, letterSpacing: '-0.02em', margin: 0 }}>Billing</h1>
          <Caveat>
            <strong style={{ fontWeight: 650 }}>Usage cannot be read on this installation.</strong>{' '}
            Resolving the plan for this organisation failed, which happens when the plan catalogue
            has not been seeded into the database — the{' '}
            <code style={{ fontFamily: 'var(--font-mono)' }}>subscription_plans</code> table needs{' '}
            <code style={{ fontFamily: 'var(--font-mono)' }}>seedPlans(db())</code> to have run. No
            figures are shown here because none can be read. The server reported:{' '}
            {e instanceof Error ? e.message : String(e)}
          </Caveat>
        </Shell>
      </>
    );
  }

  const entries = ledger(db(), organizationId, 50);
  const plans = listPlans(db());

  // Only plans with a real price can be bought here. The one directly above the
  // current plan is the prominent option; the rest, including cheaper ones, are
  // offered plainly rather than hidden, since a downgrade is a legitimate thing
  // to want from a billing page.
  const purchasable = plans.filter((p) => p.priceCents !== null && p.priceCents > 0);
  const nextUp = purchasable
    .filter((p) => p.sortOrder > summary.plan.sortOrder)
    .sort((a, b) => a.sortOrder - b.sortOrder)[0];

  const upgradeOptions: CheckoutOption[] = billingOff ? [] : purchasable
    .filter((p) => p.code !== summary.plan.code)
    .map((p) => ({
      code: p.code,
      kind: 'subscription' as const,
      label: `Choose ${p.name}`,
      detail: `${money(p.priceCents as number, p.currency)}${INTERVAL_SUFFIX[p.interval] ? ` ${INTERVAL_SUFFIX[p.interval]}` : ''}`,
      primary: p.code === nextUp?.code,
    }));

  const topUpOptions: CheckoutOption[] = billingOff ? [] : DEFAULT_PRODUCTS.map((p) => ({
    code: p.code,
    kind: 'one_time' as const,
    label: p.name,
    detail: money(p.priceCents, p.currency),
  }));

  return (
    <>
      <TopBar context="Billing" />
      <Shell>
        <h1 style={{ fontSize: '1.45rem', fontWeight: 680, letterSpacing: '-0.02em', margin: 0 }}>
          Billing and usage
        </h1>

        {checkout === 'returned' || checkout === 'cancelled' ? (
          <Caveat tone="neutral">
            {checkout === 'cancelled'
              ? 'The checkout was cancelled. Nothing has been charged and your plan is unchanged.'
              : 'You have returned from the payment page. That by itself changes nothing here: a plan or a credit grant is applied only when the payment provider’s signed webhook arrives and is verified. If the figures below have not moved yet, reload in a moment.'}
          </Caveat>
        ) : null}

        {billingOff ? (
          <Caveat>
            <strong style={{ fontWeight: 650 }}>Billing is not enabled on this installation.</strong>{' '}
            No payment can be taken, nothing can be upgraded or topped up from here, and every
            account stays on the free plan. Your usage below is real and current. The reason given
            by the server is: {unavailable}
          </Caveat>
        ) : null}

        <PlanPanel summary={summary} />

        <Card>
          <SectionHeading hint={`Counted for this organisation. Scan allowances run by calendar month and reset on ${dateOnly(summary.scans.resetsOn)}.`}>
            Usage against this plan
          </SectionHeading>
          <div
            style={{
              display: 'grid',
              gap: '1rem',
              gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 15rem), 1fr))',
            }}
          >
            <UsageMeter label="Projects" used={summary.projects.used} limit={summary.projects.limit} unit="projects" />
            <UsageMeter
              label="Scans this month"
              used={summary.scans.used}
              limit={summary.scans.limit}
              unit="scans"
              note={`Resets on ${dateOnly(summary.scans.resetsOn)}.`}
            />
            <UsageMeter
              label="Seats"
              used={summary.seats.used}
              limit={summary.seats.limit}
              unit="seats"
              limitIsBlocking={false}
              note="Team invitations are not implemented in this release, so a full seat count blocks nothing today."
            />
          </div>
        </Card>

        <Card>
          <SectionHeading hint="Credits pay for the optional AI semantic layer. At zero, scans still run in full: every deterministic analyzer runs and nothing is withheld.">
            AI credits
          </SectionHeading>
          <div
            style={{
              display: 'grid',
              gap: '1rem',
              gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 12rem), 1fr))',
            }}
          >
            <Stat
              label="Balance"
              value={num(summary.credits.balance)}
              hint={summary.credits.balance === 0 ? 'The AI layer is unavailable until this is topped up; deterministic analysis is not affected.' : 'Available to spend now.'}
            />
            <Stat
              label="Monthly allowance"
              value={summary.credits.monthlyAllowance > 0 ? num(summary.credits.monthlyAllowance) : 'None'}
              hint={
                summary.credits.monthlyAllowance > 0
                  ? `Granted once per calendar month on the ${summary.plan.name} plan.`
                  : 'This plan includes no monthly credit allowance.'
              }
            />
          </div>

          {topUpOptions.length > 0 ? (
            <div style={{ marginTop: '1rem' }}>
              <CheckoutButtons label="Buy more credits" options={topUpOptions} />
            </div>
          ) : null}
        </Card>

        <Card>
          <SectionHeading hint="Every movement, newest first, up to the last 50. The balance after each entry is the one recorded at the time, so a charge can be checked line by line.">
            Credit ledger
          </SectionHeading>
          <LedgerTable entries={entries} />
        </Card>

        <Card>
          <SectionHeading hint="A plan change takes effect when the payment provider confirms it, not when the browser comes back.">
            Change plan
          </SectionHeading>
          {billingOff ? (
            <p style={{ margin: 0, fontSize: '0.88rem', color: 'var(--ink-2)' }}>
              There is nothing to choose while billing is disabled on this installation. The{' '}
              <Link href="/pricing">pricing page</Link> lists the catalogue this installation would
              charge if a payment provider were configured.
            </p>
          ) : upgradeOptions.length > 0 ? (
            <CheckoutButtons label="Change plan" options={upgradeOptions} />
          ) : (
            <p style={{ margin: 0, fontSize: '0.88rem', color: 'var(--ink-2)' }}>
              No other purchasable plan is published by this installation. See the{' '}
              <Link href="/pricing">pricing page</Link> for plans agreed rather than bought.
            </p>
          )}
        </Card>
      </Shell>
    </>
  );
}
