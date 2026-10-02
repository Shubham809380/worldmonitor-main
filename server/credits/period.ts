/**
 * Credit and quota engine — billing period resolution.
 *
 * ## Why the provider owns the boundary
 *
 * The requirement is a credit allowance that resets on the billing cycle, with
 * correct handling of timezone, renewal, cancellation, upgrade, downgrade,
 * refunds and expiry. Implementing that as a local calendar computation means
 * reimplementing a payment provider's proration, trial and dunning rules, and
 * getting the difference wrong in a way that silently grants or steals money.
 *
 * So the provider's period is authoritative when a subscription exists: Dodo
 * has already decided what "this customer's month" means, including the
 * timezone and the proration caused by an upgrade mid-cycle. This module
 * validates that period rather than recomputing it.
 *
 * The UTC calendar fallback exists only for the free tier, which has no
 * subscription and therefore no provider boundary. It is anchored to UTC
 * deliberately: a period boundary that depends on a user's local timezone would
 * let a caller shift which cycle they are billed into by moving.
 *
 * ## Why reset is a new row, not a mutation
 *
 * A wallet is keyed by (caller, periodStart). Rollover is therefore the
 * creation of a new row rather than a counter being topped back up. That makes
 * the reset atomic without a transaction, leaves the previous period's spend
 * intact for invoicing and dispute review, and means a rolled-back reset cannot
 * restore credits that were already spent.
 */

import {
  ACTIVE_SUBSCRIPTION_STATUSES,
  type ActiveSubscriptionStatus,
  type BillingPeriod,
  type PeriodSource,
} from "./types";

/**
 * Named period sources. Declared as constants rather than read out of the
 * `PERIOD_SOURCES` tuple by index: positional access means reordering that
 * array for readability silently re-points every caller at the wrong source,
 * and a wallet that records `CALENDAR_UTC` for a provider period is a billing
 * dispute nobody can reconstruct.
 */
export const PERIOD_SOURCE_PROVIDER: PeriodSource = "PROVIDER";
export const PERIOD_SOURCE_CALENDAR_UTC: PeriodSource = "CALENDAR_UTC";
export const PERIOD_SOURCE_OPERATOR: PeriodSource = "OPERATOR";

/**
 * Longest period the engine will honour from a provider.
 *
 * A monthly credit grant against a multi-year period would be re-granted every
 * month against a boundary that never arrives, so an unbounded period is an
 * unbounded liability. Contracts longer than this must be modelled as
 * `PERIOD_SOURCES.OPERATOR` with an explicit monthly grant, which puts the
 * duration in a field a human set on purpose.
 */
export const MAX_PROVIDER_PERIOD_MS = 400 * 24 * 60 * 60 * 1000;

export class BillingPeriodError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "BillingPeriodError";
    this.code = code;
  }
}

export type SubscriptionPeriodInput = {
  /** Provider-reported period start, epoch ms. */
  periodStart: number;
  /** Provider-reported period end, epoch ms. */
  periodEnd: number;
  /**
   * Subscription status. A non-active subscription still yields a period — the
   * engine reports it so the caller can distinguish "lapsed" from "exhausted",
   * which is a different remediation for the customer.
   */
  status: string;
};

function assertFinite(value: number, field: string): void {
  if (!Number.isFinite(value)) {
    throw new BillingPeriodError(
      "PERIOD_NOT_FINITE",
      `Billing period ${field} is not a finite timestamp: ${String(value)}`,
    );
  }
}

/**
 * Validates a provider-reported period and returns it unchanged.
 *
 * A malformed provider period is a hard error, never a fallback to the
 * calendar. Falling back would hand a live subscriber a free calendar month
 * because of a provider formatting bug — the failure mode is over-granting,
 * which is the expensive direction, and it would be invisible until the
 * provider fixed its own data.
 */
export function providerPeriod(
  input: SubscriptionPeriodInput,
): BillingPeriod {
  assertFinite(input.periodStart, "periodStart");
  assertFinite(input.periodEnd, "periodEnd");

  if (input.periodStart <= 0) {
    throw new BillingPeriodError(
      "PERIOD_START_NOT_POSITIVE",
      `Billing period start must be a positive epoch timestamp, received ${input.periodStart}`,
    );
  }
  if (input.periodEnd <= input.periodStart) {
    throw new BillingPeriodError(
      "PERIOD_NOT_ORDERED",
      `Billing period end ${input.periodEnd} must be after start ${input.periodStart}`,
    );
  }
  if (input.periodEnd - input.periodStart > MAX_PROVIDER_PERIOD_MS) {
    throw new BillingPeriodError(
      "PERIOD_TOO_LONG",
      `Billing period spans ${input.periodEnd - input.periodStart}ms, which exceeds the ${MAX_PROVIDER_PERIOD_MS}ms maximum. Model a longer contract as an operator period.`,
    );
  }

  return {
    start: input.periodStart,
    end: input.periodEnd,
    source: PERIOD_SOURCE_PROVIDER,
  };
}

/**
 * UTC calendar month containing `at`. Used only when no subscription exists.
 *
 * `Date.UTC` normalises month and year overflow, so December rolls into the
 * following January without a special case, and leap years are handled by the
 * platform rather than by hand-written day arithmetic.
 */
export function calendarPeriodUtc(at: number): BillingPeriod {
  assertFinite(at, "at");

  const d = new Date(at);
  const year = d.getUTCFullYear();
  const month = d.getUTCMonth();

  return {
    start: Date.UTC(year, month, 1),
    // Month 12 overflows into the next year, which is the rollover we want.
    end: Date.UTC(year, month + 1, 1),
    source: PERIOD_SOURCE_CALENDAR_UTC,
  };
}

/** An operator-pinned period, for contracts that outlive `MAX_PROVIDER_PERIOD_MS`. */
export function operatorPeriod(
  periodStart: number,
  periodEnd: number,
): BillingPeriod {
  assertFinite(periodStart, "periodStart");
  assertFinite(periodEnd, "periodEnd");
  if (periodEnd <= periodStart) {
    throw new BillingPeriodError(
      "PERIOD_NOT_ORDERED",
      `Operator period end ${periodEnd} must be after start ${periodStart}`,
    );
  }
  return {
    start: periodStart,
    end: periodEnd,
    source: PERIOD_SOURCE_OPERATOR,
  };
}

/**
 * Resolves the period a caller belongs to.
 *
 * A subscription is used when one exists AND it carries a usable period. A
 * subscription row with no period is treated as no subscription: an absent
 * boundary must not silently become the calendar, because a subscriber whose
 * provider payload failed to land would then be served on a free-tier period
 * while being charged. It is surfaced as `NO_ACTIVE_PLAN` upstream.
 */
export function resolveBillingPeriod(args: {
  at: number;
  subscription: SubscriptionPeriodInput | null;
}): BillingPeriod {
  const { at, subscription } = args;
  assertFinite(at, "at");

  if (subscription) return providerPeriod(subscription);
  return calendarPeriodUtc(at);
}

export function isActiveSubscriptionStatus(
  status: string,
): status is ActiveSubscriptionStatus {
  return (ACTIVE_SUBSCRIPTION_STATUSES as readonly string[]).includes(status);
}

/**
 * Whether `at` falls inside `period`. Half-open `[start, end)` so consecutive
 * periods tile the timeline without overlapping: an instant exactly on a
 * boundary belongs to the later period, which is what makes rollover total
 * rather than leaving an unattributed instant.
 */
export function containsInstant(period: BillingPeriod, at: number): boolean {
  return at >= period.start && at < period.end;
}

export type PeriodSourceName = PeriodSource;
