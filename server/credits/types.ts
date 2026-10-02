/**
 * Credit and quota engine — types.
 *
 * This module is pure: no I/O, no clock, no network. Every time- and
 * environment-dependent value arrives through the caller's arguments, for the
 * same reason `server/securescan/` is pure — a billing decision that cannot be
 * replayed against a fixed clock cannot be tested at the boundaries where it
 * actually breaks (period rollover, concurrent spend, expiry).
 *
 * The engine answers three questions and refuses to answer a fourth:
 *   1. Which billing period does this caller belong to?  (`period.ts`)
 *   2. What does this operation cost?                   (`costs.ts`)
 *   3. May this wallet spend that cost, and by how much? (`wallet.ts`)
 *   4. — never "is this finding real". Verification is an analyst decision.
 */

/**
 * Operations the platform meters. Cost is NOT encoded here: an operation's
 * price is an operator decision that must be changeable without a deploy, so
 * it lives in the `operationCosts` table and this list only fixes the set of
 * names that may be priced.
 *
 * `list_plans` and `get_usage` exist so a client can discover its own quota
 * without spending any — a customer who cannot see their balance cannot
 * predict when they will be cut off, and a 429 with no way to anticipate it
 * is indistinguishable from an outage.
 */
export const CREDIT_OPERATIONS = [
  "list_plans",
  "get_usage",
  "security_headers_scan",
  "dependency_scan",
  "secret_scan",
  "api_scan",
  "authentication_assessment",
  "authorization_assessment",
  "full_security_assessment",
  "report_generation",
  "retest",
] as const;

export type CreditOperation = (typeof CREDIT_OPERATIONS)[number];

/**
 * Why a spend was refused. A closed set, because the HTTP layer maps each
 * value to a status code and an unrecognised reason must not silently become a
 * 500 — "you are out of credits" and "we could not price this operation" are
 * different problems with different fixes, and a customer who is told the
 * first when it is the second will buy a plan they did not need.
 */
export const SPEND_REFUSALS = [
  /** No priced cost for this operation. Fails closed: never assume free. */
  "COST_NOT_CONFIGURED",
  /** Wallet holds fewer credits than the operation costs. */
  "INSUFFICIENT_CREDITS",
  /** The plan does not permit this operation at all. */
  "OPERATION_NOT_IN_PLAN",
  /** No active plan resolved for the caller. */
  "NO_ACTIVE_PLAN",
  /**
   * The subscription exists but is not in a state that grants service
   * (`PAST_DUE`, `SUSPENDED`, `EXPIRED`, `CANCELLED`). Distinct from
   * INSUFFICIENT_CREDITS: buying credits will not fix a lapsed subscription.
   */
  "SUBSCRIPTION_NOT_ACTIVE",
  /** The grant itself is capped and the cap is reached. Enterprise contracts. */
  "GRANT_CAP_REACHED",
] as const;

export type SpendRefusal = (typeof SPEND_REFUSALS)[number];

/**
 * Subscription states that grant service. A locally-held value, not an import
 * from the Dodo mapping, so the engine can be tested without a payment
 * provider — `convex/credits/validators.ts` restates it for persistence and a
 * parity test fails if the two drift.
 */
export const ACTIVE_SUBSCRIPTION_STATUSES = [
  "active",
  "trialing",
] as const;

export type ActiveSubscriptionStatus =
  (typeof ACTIVE_SUBSCRIPTION_STATUSES)[number];

export type BillingPeriod = {
  /** Epoch ms, inclusive. */
  start: number;
  /** Epoch ms, exclusive. */
  end: number;
  /**
   * How this period was established. Recorded on the wallet so a later reader
   * can tell a provider-authoritative period from a locally derived one, and
   * so a disputed charge can be traced back to the source of the boundary.
   */
  source: PeriodSource;
};

export const PERIOD_SOURCES = [
  /** Taken verbatim from the payment provider's subscription period. */
  "PROVIDER",
  /** Derived from the UTC calendar because no subscription exists (free tier). */
  "CALENDAR_UTC",
  /** Pinned by an operator, e.g. a contractual enterprise period. */
  "OPERATOR",
] as const;

export type PeriodSource = (typeof PERIOD_SOURCES)[number];

/**
 * A plan row as the engine reads it. Deliberately a narrow projection rather
 * than the Convex document so the engine can be exercised with literals and
 * so a storage refactor cannot silently change billing behaviour.
 */
export type PlanPricing = {
  planId: string;
  /** Credits granted per billing period. `-1` means unlimited. */
  monthlyCredits: number;
  /**
   * Optional hard ceiling on a single period's spend, independent of the
   * grant. `null` means no ceiling. This exists because "unlimited credits"
   * still needs a runaway guard: `monthlyCredits: -1` with no cap lets one
   * mispriced operation drain an enterprise contract in a single request.
   */
  periodSpendCap: number | null;
  /** Operations this plan may run at all. Empty means "not configured yet". */
  allowedOperations: readonly CreditOperation[];
  status: PlanStatus;
};

export const PLAN_STATUSES = ["active", "disabled", "archived"] as const;
export type PlanStatus = (typeof PLAN_STATUSES)[number];

/** The persisted unit of quota. One row per (caller, billing period). */
export type Wallet = {
  /** Credits granted for this period, from the plan or an operator grant. */
  granted: number;
  /** Credits already spent in this period. Never negative. */
  consumed: number;
};

/**
 * A priced operation. `cost` is credits per invocation.
 */
export type OperationCost = {
  operation: CreditOperation;
  cost: number;
  /**
   * Whether the cost was seeded from code or set by an operator. A seeded cost
   * is a default; an operator cost has been deliberately chosen. A plan that
   * relies on seeded pricing is not a pricing decision.
   */
  source: "seed" | "operator";
};

export type SpendDecision =
  | { allowed: true; cost: number; remainingAfter: number }
  | { allowed: false; reason: SpendRefusal; shortfall: number };
