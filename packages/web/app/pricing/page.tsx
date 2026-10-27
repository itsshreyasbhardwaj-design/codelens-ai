import Link from 'next/link';
import { DEFAULT_PRODUCTS, listPlans, type PlanRow } from '@codelens/engine/billing/plans.ts';
import { loadPaymentProvider } from '@codelens/engine/billing/payments.ts';
import { Shell, TopBar } from '../components/nav.tsx';
import { Card, Caveat, EmptyState, SectionHeading, Tag } from '../components/ui.tsx';
import { currentSession } from '../lib/session.ts';
import { db } from '../lib/store.ts';
import { CheckoutButtons, type CheckoutOption } from '../billing/checkout-buttons.tsx';

/**
 * Pricing.
 *
 * Public: no session is required to read it, and the middleware allows it
 * through. A visitor who is not signed in is shown the same prices and the same
 * limits as a customer; what changes is the call to action, because a checkout
 * needs an account to attribute the payment to.
 *
 * Every figure on this page is read from `subscription_plans` at request time.
 * Nothing is hardcoded here, which is the point of seeding the catalogue into
 * the database: a price change is a row update, not a deploy. When the table is
 * empty this page says so rather than falling back to figures that might not be
 * the ones this installation charges.
 *
 * When no payment provider is configured the page says plainly that billing is
 * off and everyone stays on the free plan. It does not render a dead upgrade
 * button — a control that cannot work is worse than no control at all.
 */

export const dynamic = 'force-dynamic';

export const metadata = {
  title: 'Pricing — CodeLens AI',
  description:
    'Plans, limits and credit top-ups, read from this installation’s own plan catalogue. The deterministic analysis is complete on the free plan.',
};

// -------------------------------------------------------------- formatting --

const CURRENCY_SYMBOL: Record<string, string> = { usd: '$', eur: '€', gbp: '£', inr: '₹' };

/**
 * Minor units to a readable amount: 1900 becomes "$19", 1950 becomes "$19.50".
 *
 * Integer arithmetic throughout. The division is exact because the operands are
 * whole cents and the result is only ever displayed, never stored or compared.
 */
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
  month: 'a month',
  year: 'a year',
  once: 'once',
  none: '',
};

/** A limit of null is unbounded, and says so. Never rendered as a number. */
function limitText(value: number | null, unit?: string): string {
  if (value === null) return 'Unlimited';
  return unit ? `${value.toLocaleString('en-GB')} ${unit}` : value.toLocaleString('en-GB');
}

/**
 * Zero on a contact-us plan means the figure is part of the agreement, not that
 * the plan includes none. The two cases are worded differently rather than both
 * rendered as "0".
 */
function allowanceText(value: number, negotiated: boolean, unit: string): string {
  if (value > 0) return `${value.toLocaleString('en-GB')} ${unit}`;
  return negotiated ? 'Agreed with your contract' : `No ${unit} included`;
}

/** "1 seat", not "1 seats". */
function seatText(value: number, negotiated: boolean): string {
  if (value > 0) return `${value.toLocaleString('en-GB')} ${value === 1 ? 'seat' : 'seats'}`;
  return negotiated ? 'Agreed with your contract' : 'No seats included';
}

// ------------------------------------------------------------- components --

function PlanLimits({ plan }: { plan: PlanRow }) {
  const negotiated = plan.priceCents === null;
  const rows: Array<[string, string]> = [
    ['Projects', limitText(plan.projectsLimit)],
    ['Scans', limitText(plan.scansPerMonth, 'a month')],
    ['AI credits', allowanceText(plan.monthlyCredits, negotiated, 'a month')],
    ['Seats', seatText(plan.seats, negotiated)],
    ['Repository size', plan.maxRepoMb === null ? 'Unlimited' : `Up to ${plan.maxRepoMb.toLocaleString('en-GB')} MB`],
  ];
  return (
    <dl
      style={{
        margin: 0,
        display: 'grid',
        gridTemplateColumns: 'auto 1fr',
        columnGap: '0.75rem',
        rowGap: '0.2rem',
        fontSize: '0.84rem',
      }}
    >
      {rows.map(([label, value]) => (
        <div key={label} style={{ display: 'contents' }}>
          <dt style={{ color: 'var(--ink-3)' }}>{label}</dt>
          <dd style={{ margin: 0, color: 'var(--ink)', fontVariantNumeric: 'tabular-nums' }}>{value}</dd>
        </div>
      ))}
    </dl>
  );
}

function PlanCard({
  plan,
  billingOff,
  signedIn,
}: {
  plan: PlanRow;
  billingOff: boolean;
  signedIn: boolean;
}) {
  const free = plan.priceCents === 0;
  const contact = plan.priceCents === null;
  const purchasable = !free && !contact;
  const suffix = INTERVAL_SUFFIX[plan.interval];

  return (
    <Card as="li">
      <div style={{ display: 'grid', gap: '0.7rem' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: '0.5rem', flexWrap: 'wrap' }}>
            <h3 style={{ margin: 0, fontSize: '1.05rem', fontWeight: 650 }}>{plan.name}</h3>
            {free ? <Tag tone="good">Included with every account</Tag> : null}
          </div>
          <p
            style={{
              margin: '0.3rem 0 0',
              fontSize: '1.6rem',
              fontWeight: 680,
              letterSpacing: '-0.02em',
              lineHeight: 1.15,
              fontVariantNumeric: 'tabular-nums',
            }}
          >
            {contact ? 'Contact us' : money(plan.priceCents as number, plan.currency)}
            {!contact && suffix ? (
              <span style={{ fontSize: '0.84rem', fontWeight: 500, color: 'var(--ink-3)' }}> {suffix}</span>
            ) : null}
          </p>
        </div>

        <PlanLimits plan={plan} />

        {plan.features.length > 0 ? (
          <ul style={{ margin: 0, paddingLeft: '1.05rem', fontSize: '0.86rem', color: 'var(--ink-2)', display: 'grid', gap: '0.15rem' }}>
            {plan.features.map((f) => <li key={f}>{f}</li>)}
          </ul>
        ) : null}

        {purchasable && !billingOff ? (
          signedIn ? (
            <CheckoutButtons
              label={`Subscribe to ${plan.name}`}
              options={[{
                code: plan.code,
                kind: 'subscription',
                label: `Choose ${plan.name}`,
                detail: `${money(plan.priceCents as number, plan.currency)}${suffix ? ` ${suffix}` : ''}`,
                primary: true,
              }]}
            />
          ) : (
            <Link
              href={`/sign-in?next=${encodeURIComponent('/pricing')}`}
              style={{
                display: 'inline-block',
                padding: '0.45rem 0.8rem',
                borderRadius: 8,
                border: '1px solid var(--accent)',
                background: 'var(--accent)',
                color: 'var(--accent-ink)',
                textDecoration: 'none',
                fontWeight: 650,
                fontSize: '0.88rem',
                justifySelf: 'start',
              }}
            >
              Sign in to choose {plan.name}
            </Link>
          )
        ) : null}

        {contact ? (
          <p style={{ margin: 0, fontSize: '0.84rem', color: 'var(--ink-3)' }}>
            This plan is agreed rather than bought: limits, seats and deployment are set in the
            contract, so there is no checkout for it.
          </p>
        ) : null}
      </div>
    </Card>
  );
}

function TopUps({ billingOff, signedIn }: { billingOff: boolean; signedIn: boolean }) {
  const options: CheckoutOption[] = DEFAULT_PRODUCTS.map((p) => ({
    code: p.code,
    kind: 'one_time' as const,
    label: p.name,
    detail: money(p.priceCents, p.currency),
  }));

  return (
    <Card>
      <SectionHeading hint="One-time purchases. Buying credits does not start a subscription and does not change your plan limits.">
        Credit top-ups
      </SectionHeading>
      <ul style={{ listStyle: 'none', margin: '0 0 0.9rem', padding: 0, display: 'grid', gap: '0.55rem' }}>
        {DEFAULT_PRODUCTS.map((p) => (
          <li
            key={p.code}
            style={{
              display: 'flex',
              flexWrap: 'wrap',
              gap: '0.3rem 0.75rem',
              alignItems: 'baseline',
              borderBottom: '1px solid var(--border)',
              paddingBottom: '0.5rem',
            }}
          >
            <span style={{ fontWeight: 650, fontSize: '0.92rem' }}>{p.name}</span>
            <span style={{ fontVariantNumeric: 'tabular-nums', color: 'var(--ink-2)' }}>
              {money(p.priceCents, p.currency)}
            </span>
            <span style={{ fontSize: '0.84rem', color: 'var(--ink-3)', flexBasis: '100%' }}>
              {p.description}
            </span>
          </li>
        ))}
      </ul>
      {billingOff ? null : signedIn ? (
        <CheckoutButtons label="Buy credits" options={options} />
      ) : (
        <p style={{ margin: 0, fontSize: '0.86rem' }}>
          <Link href={`/sign-in?next=${encodeURIComponent('/pricing')}`}>Sign in</Link> to buy
          credits — a purchase is credited to an account.
        </p>
      )}
    </Card>
  );
}

// ------------------------------------------------------------------- page --

export default async function PricingPage() {
  const plans = listPlans(db());
  const unavailable = loadPaymentProvider().unavailableReason();
  const billingOff = unavailable !== undefined;
  const signedIn = (await currentSession()) !== undefined;

  return (
    <>
      <TopBar context="Pricing" />
      <Shell>
        <header style={{ display: 'grid', gap: '0.5rem', maxWidth: '44rem' }}>
          <h1 style={{ fontSize: 'clamp(1.5rem, 1.1rem + 1.6vw, 2.1rem)', fontWeight: 700, letterSpacing: '-0.025em', margin: 0, lineHeight: 1.15 }}>
            Pricing
          </h1>
          <p style={{ margin: 0, color: 'var(--ink-2)' }}>
            Plans differ in how much you can scan, not in how well it is analysed. The
            deterministic analysis — every analyzer, the architecture map, the feature inventory,
            the findings with their evidence and the Fix Packs — is the same on every plan,
            including the free one.
          </p>
        </header>

        {billingOff ? (
          <Caveat>
            <strong style={{ fontWeight: 650 }}>Billing is not enabled on this installation.</strong>{' '}
            No payment can be taken and every account stays on the free plan, so the prices below
            are the catalogue rather than something you can buy here. The reason given by the
            server is: {unavailable}
          </Caveat>
        ) : null}

        {plans.length === 0 ? (
          <EmptyState title="This installation has no plan catalogue">
            <p style={{ margin: 0 }}>
              The <code style={{ fontFamily: 'var(--font-mono)' }}>subscription_plans</code> table is
              empty, so there are no prices or limits to show. Rather than display figures that might
              not be the ones this installation charges, the page shows nothing. Seeding the
              catalogue — <code style={{ fontFamily: 'var(--font-mono)' }}>seedPlans(db())</code> from
              the billing engine — populates it with the launch defaults.
            </p>
          </EmptyState>
        ) : (
          <section aria-labelledby="plans-heading" style={{ display: 'grid', gap: '0.85rem' }}>
            <h2 id="plans-heading" style={{ fontSize: '1.02rem', fontWeight: 650, margin: 0 }}>
              Plans
            </h2>
            <ul
              style={{
                listStyle: 'none',
                margin: 0,
                padding: 0,
                display: 'grid',
                gap: '0.85rem',
                gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 16rem), 1fr))',
                alignItems: 'start',
              }}
            >
              {plans.map((plan) => (
                <PlanCard key={plan.code} plan={plan} billingOff={billingOff} signedIn={signedIn} />
              ))}
            </ul>
          </section>
        )}

        <Card>
          <SectionHeading hint="The part of the pricing most likely to be misread, so it is stated rather than implied.">
            What AI credits do, and what they do not do
          </SectionHeading>
          <div style={{ display: 'grid', gap: '0.6rem', fontSize: '0.88rem', color: 'var(--ink-2)', lineHeight: 1.6 }}>
            <p style={{ margin: 0 }}>
              Credits pay for the <strong style={{ color: 'var(--ink)' }}>optional AI semantic
              layer</strong> only — the pass that investigates selected areas with a language model.
              That layer is off unless a provider is configured for it.
            </p>
            <p style={{ margin: 0 }}>
              At a balance of zero, <strong style={{ color: 'var(--ink)' }}>scans still run in
              full</strong>. Every deterministic analyzer runs, the architecture and feature
              inventories are built, findings are reported with their evidence, and Fix Packs are
              generated. Nothing is withheld and nothing is degraded; the AI layer is simply skipped,
              and the scan says so in its coverage panel.
            </p>
            <p style={{ margin: 0 }}>
              So the free plan is a working tool rather than a trial. Its limit is throughput — how
              many projects and how many scans a month — not depth.
            </p>
          </div>
        </Card>

        <TopUps billingOff={billingOff} signedIn={signedIn} />

        <Caveat tone="neutral">
          Prices and limits on this page are read from this installation&rsquo;s own plan catalogue
          at the moment you load it. Paid entitlements are applied from the payment provider&rsquo;s
          verified webhook, never from a browser returning from a checkout page, so a plan change
          appears on your {' '}
          <Link href="/billing">billing page</Link> once the provider has confirmed the payment.
        </Caveat>
      </Shell>
    </>
  );
}
