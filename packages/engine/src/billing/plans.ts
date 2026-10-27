import { randomUUID } from 'node:crypto';
import { Db, now } from '../db/index.ts';

/**
 * Plan catalogue.
 *
 * Seeded into the database so prices and limits are configurable at runtime
 * rather than compiled in, which is what the brief asks for and what lets a
 * price change without a deploy. These are the launch defaults.
 *
 * `null` on a limit means unbounded. Credits are whole units; prices are minor
 * units (cents) because money never touches a float.
 */

export interface PlanSpec {
  code: string;
  name: string;
  /** Minor units. null means "contact us". */
  priceCents: number | null;
  currency: string;
  interval: 'month' | 'year' | 'once' | 'none';
  projectsLimit: number | null;
  scansPerMonth: number | null;
  monthlyCredits: number;
  seats: number;
  maxRepoMb: number | null;
  features: string[];
  sortOrder: number;
}

export const DEFAULT_PLANS: PlanSpec[] = [
  {
    code: 'free', name: 'Free', priceCents: 0, currency: 'usd', interval: 'none',
    projectsLimit: 1, scansPerMonth: 2, monthlyCredits: 40, seats: 1, maxRepoMb: 50,
    sortOrder: 0,
    features: [
      'Full deterministic analysis — all ten analyzers',
      'Architecture explorer and feature inventory',
      'Fix Packs for every finding',
      'Reports in Markdown, JSON and printable HTML',
    ],
  },
  {
    code: 'solo', name: 'Solo', priceCents: 1900, currency: 'usd', interval: 'month',
    projectsLimit: 3, scansPerMonth: 30, monthlyCredits: 350, seats: 1, maxRepoMb: 250,
    sortOrder: 1,
    features: [
      'Everything in Free',
      '3 projects, 30 scans a month',
      '350 AI credits a month',
      'Scan comparison and improvement tracking',
    ],
  },
  {
    code: 'pro', name: 'Pro', priceCents: 4900, currency: 'usd', interval: 'month',
    projectsLimit: 10, scansPerMonth: 100, monthlyCredits: 1200, seats: 1, maxRepoMb: 1000,
    sortOrder: 2,
    features: [
      'Everything in Solo',
      '10 projects, 100 scans a month',
      '1,200 AI credits a month',
      'Private repositories',
    ],
  },
  {
    code: 'team', name: 'Team', priceCents: 14900, currency: 'usd', interval: 'month',
    projectsLimit: 30, scansPerMonth: 500, monthlyCredits: 3800, seats: 5, maxRepoMb: 2000,
    sortOrder: 3,
    features: [
      'Everything in Pro',
      '30 projects, 500 scans a month',
      '3,800 shared AI credits a month',
      '5 seats, shared findings and credit pool',
    ],
  },
  {
    code: 'enterprise', name: 'Enterprise', priceCents: null, currency: 'usd', interval: 'none',
    projectsLimit: null, scansPerMonth: null, monthlyCredits: 0, seats: 0, maxRepoMb: null,
    sortOrder: 4,
    features: [
      'Everything in Team',
      'Custom limits, seats and support terms',
      'Self-hosted or private deployment',
      'Bring your own model provider',
    ],
  },
];

/** One-time products. A purchase grants credits; it does not start a subscription. */
export interface ProductSpec {
  code: string;
  name: string;
  priceCents: number;
  currency: string;
  credits: number;
  description: string;
}

export const DEFAULT_PRODUCTS: ProductSpec[] = [
  {
    code: 'credits_10', name: '1,000 credits', priceCents: 1000, currency: 'usd', credits: 1000,
    description: 'Top-up credits. They do not expire while your account is active.',
  },
  {
    code: 'credits_30', name: '3,250 credits', priceCents: 3000, currency: 'usd', credits: 3250,
    description: 'Top-up credits, about 8% better value than the smallest pack.',
  },
  {
    code: 'credits_80', name: '9,000 credits', priceCents: 8000, currency: 'usd', credits: 9000,
    description: 'Top-up credits, about 12% better value than the smallest pack.',
  },
];

export interface PlanRow extends PlanSpec {
  id: string;
  active: boolean;
}

/** Insert any plan the database does not have. Existing rows are left alone, so
 *  a price edited in the database is not overwritten by a deploy. */
export function seedPlans(db: Db, plans: PlanSpec[] = DEFAULT_PLANS): void {
  for (const p of plans) {
    if (db.get('SELECT id FROM subscription_plans WHERE code = ?', p.code)) continue;
    db.run(
      `INSERT INTO subscription_plans
         (id, code, name, price_cents, currency, interval, projects_limit, scans_per_month,
          monthly_credits, seats, max_repo_mb, features_json, sort_order, active, created_at)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,1,?)`,
      randomUUID(), p.code, p.name, p.priceCents, p.currency, p.interval,
      p.projectsLimit, p.scansPerMonth, p.monthlyCredits, p.seats, p.maxRepoMb,
      JSON.stringify(p.features), p.sortOrder, now(),
    );
  }
}

function toPlan(r: Record<string, unknown>): PlanRow {
  return {
    id: String(r.id),
    code: String(r.code),
    name: String(r.name),
    priceCents: r.price_cents === null ? null : Number(r.price_cents),
    currency: String(r.currency),
    interval: String(r.interval) as PlanSpec['interval'],
    projectsLimit: r.projects_limit === null ? null : Number(r.projects_limit),
    scansPerMonth: r.scans_per_month === null ? null : Number(r.scans_per_month),
    monthlyCredits: Number(r.monthly_credits),
    seats: Number(r.seats),
    maxRepoMb: r.max_repo_mb === null ? null : Number(r.max_repo_mb),
    features: JSON.parse(String(r.features_json ?? '[]')) as string[],
    sortOrder: Number(r.sort_order),
    active: Number(r.active) === 1,
  };
}

export function listPlans(db: Db): PlanRow[] {
  return db.all<Record<string, unknown>>(
    'SELECT * FROM subscription_plans WHERE active = 1 ORDER BY sort_order',
  ).map(toPlan);
}

export function planByCode(db: Db, code: string): PlanRow | undefined {
  const r = db.get<Record<string, unknown>>('SELECT * FROM subscription_plans WHERE code = ?', code);
  return r ? toPlan(r) : undefined;
}

/**
 * The plan an organisation is actually on.
 *
 * An active subscription wins; otherwise the organisation's `plan_code`, which
 * defaults to free. A past-due subscription deliberately still counts as its
 * plan — access is reduced through the payment flow, not by silently dropping a
 * paying customer to the free tier mid-period.
 */
export function planForOrganization(db: Db, organizationId: string): PlanRow {
  const sub = db.get<{ plan_id: string }>(
    `SELECT plan_id FROM subscriptions
      WHERE organization_id = ? AND status IN ('active','trialing','past_due')
      ORDER BY created_at DESC LIMIT 1`,
    organizationId,
  );
  if (sub) {
    const r = db.get<Record<string, unknown>>('SELECT * FROM subscription_plans WHERE id = ?', sub.plan_id);
    if (r) return toPlan(r);
  }
  const org = db.get<{ plan_code: string }>('SELECT plan_code FROM organizations WHERE id = ?', organizationId);
  const plan = planByCode(db, org?.plan_code ?? 'free') ?? planByCode(db, 'free');
  if (plan) return plan;

  // No catalogue at all. This is a deployment that was migrated but never
  // seeded, and the honest response is to say so rather than to invent limits:
  // guessing generous ones gives work away, and guessing strict ones locks a
  // paying customer out. `seedPlans` is the fix, and the message names it.
  throw new PlanCatalogueMissing();
}

export class PlanCatalogueMissing extends Error {
  constructor() {
    super(
      'the subscription_plans table has no free plan, so no entitlement can be resolved. ' +
      'Run seedPlans(db) once after migrating; see docs/DEPLOYMENT.md.',
    );
    this.name = 'PlanCatalogueMissing';
  }
}
