import { Db } from '../db/index.ts';
import { balance } from './credits.ts';
import { planForOrganization, type PlanRow } from './plans.ts';

/**
 * Plan limits, enforced on the server.
 *
 * Every check returns a reason the user can act on rather than a bare boolean,
 * because "you have reached a limit" without saying which one is the kind of
 * dead end that makes people leave. The frontend may mirror these numbers, but
 * it never decides them.
 */

export interface LimitCheck {
  allowed: boolean;
  /** Present when allowed is false. Written for the user, not the log. */
  reason?: string;
  /** What they would need to do about it. */
  remedy?: 'upgrade' | 'buy_credits' | 'delete_project' | 'wait_for_reset' | 'contact';
  limit?: number | null;
  current?: number;
}

const ALLOWED: LimitCheck = { allowed: true };

/** Scans this organisation started in the current calendar month. */
export function scansThisMonth(db: Db, organizationId: string, atIso: string): number {
  const period = atIso.slice(0, 7);
  const row = db.get<{ n: number }>(
    `SELECT COUNT(*) AS n FROM scan_jobs s
       JOIN projects p ON p.id = s.project_id
      WHERE p.organization_id = ? AND substr(s.queued_at, 1, 7) = ?`,
    organizationId, period,
  );
  return Number(row?.n ?? 0);
}

export function projectCount(db: Db, organizationId: string): number {
  const row = db.get<{ n: number }>(
    'SELECT COUNT(*) AS n FROM projects WHERE organization_id = ? AND deleted_at IS NULL',
    organizationId,
  );
  return Number(row?.n ?? 0);
}

export function seatCount(db: Db, organizationId: string): number {
  const row = db.get<{ n: number }>(
    'SELECT COUNT(*) AS n FROM organization_members WHERE organization_id = ?',
    organizationId,
  );
  return Number(row?.n ?? 0);
}

function startOfNextMonth(atIso: string): string {
  const d = new Date(atIso);
  return new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + 1, 1)).toISOString().slice(0, 10);
}

export function canCreateProject(db: Db, organizationId: string): LimitCheck {
  const plan = planForOrganization(db, organizationId);
  if (plan.projectsLimit === null) return ALLOWED;
  const current = projectCount(db, organizationId);
  if (current < plan.projectsLimit) return ALLOWED;
  return {
    allowed: false,
    reason: `The ${plan.name} plan includes ${plan.projectsLimit} project${plan.projectsLimit === 1 ? '' : 's'}, and you have ${current}.`,
    remedy: current > 0 ? 'upgrade' : 'contact',
    limit: plan.projectsLimit,
    current,
  };
}

export function canStartScan(
  db: Db,
  organizationId: string,
  opts: { atIso: string; repoSizeMb?: number } = { atIso: new Date().toISOString() },
): LimitCheck {
  const plan = planForOrganization(db, organizationId);

  if (plan.scansPerMonth !== null) {
    const used = scansThisMonth(db, organizationId, opts.atIso);
    if (used >= plan.scansPerMonth) {
      return {
        allowed: false,
        reason: `The ${plan.name} plan includes ${plan.scansPerMonth} scans a month and you have used ${used}. The allowance resets on ${startOfNextMonth(opts.atIso)}.`,
        remedy: 'upgrade',
        limit: plan.scansPerMonth,
        current: used,
      };
    }
  }

  if (plan.maxRepoMb !== null && opts.repoSizeMb !== undefined && opts.repoSizeMb > plan.maxRepoMb) {
    return {
      allowed: false,
      reason: `That repository is about ${Math.round(opts.repoSizeMb)} MB and the ${plan.name} plan analyses up to ${plan.maxRepoMb} MB.`,
      remedy: 'upgrade',
      limit: plan.maxRepoMb,
      current: Math.round(opts.repoSizeMb),
    };
  }

  return ALLOWED;
}

export function canAddSeat(db: Db, organizationId: string): LimitCheck {
  const plan = planForOrganization(db, organizationId);
  if (plan.seats === 0) return ALLOWED; // enterprise: negotiated separately
  const current = seatCount(db, organizationId);
  if (current < plan.seats) return ALLOWED;
  return {
    allowed: false,
    reason: `The ${plan.name} plan includes ${plan.seats} seat${plan.seats === 1 ? '' : 's'} and ${current} are in use.`,
    remedy: 'upgrade',
    limit: plan.seats,
    current,
  };
}

/**
 * Whether an AI-backed operation may start, and what it may spend.
 *
 * Deterministic analysis is never gated on credits: it costs nothing to run and
 * is the product's floor. Only the optional AI layer draws on the balance, so
 * an organisation at zero credits still gets a complete, useful scan.
 */
export function canUseAi(db: Db, organizationId: string, estimatedCredits: number): LimitCheck {
  const available = balance(db, organizationId);
  if (available >= estimatedCredits) return ALLOWED;
  return {
    allowed: false,
    reason: `This would use up to ${estimatedCredits} credits and ${available} are available. Deterministic analysis still runs in full and costs nothing.`,
    remedy: 'buy_credits',
    limit: estimatedCredits,
    current: available,
  };
}

/**
 * Credit ceiling for an AI-backed scan.
 *
 * One credit is budgeted at roughly one US cent of variable cost. This is a
 * pricing abstraction, not a token count: the figure is the ceiling the job may
 * not exceed, and settlement charges metered usage, so an over-estimate costs
 * the customer nothing.
 */
export const CREDITS_PER_1K_TOKENS = 2;

export function estimateScanCredits(
  opts: { files: number; targets?: number; aiEnabled: boolean },
): number {
  if (!opts.aiEnabled) return 0;
  // `selectTargets` picks targets from routes and features, NOT from file
  // count: a ten-file service with eight unvalidated POST handlers yields the
  // full eight. Estimating from files alone under-counted by 4x on exactly
  // those repositories, and because `settle` clamps the charge to the
  // reservation, the overspend was absorbed silently instead of billed.
  //
  // `targets` is the real count where the caller knows it. The fallback assumes
  // the maximum rather than guessing low, because guessing low is cost the
  // clamp hides.
  const targets = Math.min(8, Math.max(1, opts.targets ?? 8));
  // 6,000 tokens of context, line-numbered (~+21%), plus prompt scaffolding and
  // the 2,000-token output ceiling. Measured at ~7,800 with empty replies and
  // ~9,850 with a full one.
  const tokens = targets * 9900;
  return Math.ceil((tokens / 1000) * CREDITS_PER_1K_TOKENS);
}

/** Tokens that `credits` actually funds, at this module's pricing. */
export function tokensForCredits(credits: number): number {
  return (credits / CREDITS_PER_1K_TOKENS) * 1000;
}

/** Convert metered token usage into credits actually charged. */
export function creditsForUsage(tokensIn: number, tokensOut: number): number {
  return Math.ceil(((tokensIn + tokensOut) / 1000) * CREDITS_PER_1K_TOKENS);
}

export interface UsageSummary {
  plan: PlanRow;
  projects: { used: number; limit: number | null };
  scans: { used: number; limit: number | null; resetsOn: string };
  seats: { used: number; limit: number };
  credits: { balance: number; monthlyAllowance: number };
}

export function usageSummary(db: Db, organizationId: string, atIso: string): UsageSummary {
  const plan = planForOrganization(db, organizationId);
  return {
    plan,
    projects: { used: projectCount(db, organizationId), limit: plan.projectsLimit },
    scans: {
      used: scansThisMonth(db, organizationId, atIso),
      limit: plan.scansPerMonth,
      resetsOn: startOfNextMonth(atIso),
    },
    seats: { used: seatCount(db, organizationId), limit: plan.seats },
    credits: { balance: balance(db, organizationId), monthlyAllowance: plan.monthlyCredits },
  };
}
