/**
 * Credit and quota engine — spend decisions.
 *
 * A spend decision is the one function in this system that must never be wrong
 * in the customer's favour, so it is stated as a total function over an
 * explicit ordered check list rather than a chain of `if`s whose precedence is
 * an accident of where somebody typed them.
 *
 * ## Check order, and why
 *
 * The order below is chosen so the refusal names the problem the caller can
 * actually act on:
 *
 *   1. plan resolvable      → NO_ACTIVE_PLAN
 *   2. subscription live    → SUBSCRIPTION_NOT_ACTIVE
 *   3. plan permits it      → OPERATION_NOT_IN_PLAN
 *   4. price known          → COST_NOT_CONFIGURED
 *   5. guard cap not hit    → GRANT_CAP_REACHED
 *   6. wallet can afford it → INSUFFICIENT_CREDITS
 *
 * Plan permission is checked before pricing deliberately. "Your plan does not
 * include this operation" is actionable and needs no price; "this operation has
 * no price" is our bug. Returning the internal one to a customer who simply
 * bought the wrong plan leaks configuration state and sends them to support for
 * a problem a plan upgrade would have solved.
 *
 * The consequence is that `COST_NOT_CONFIGURED` can be masked by a plan that
 * omits the operation. That is the right trade for the caller-facing reason and
 * the wrong one for monitoring, so the caller is expected to alert on
 * `COST_NOT_CONFIGURED` wherever it appears — see `isInternalMisconfiguration`.
 */

import {
  isActiveSubscriptionStatus,
} from "./period";
import { resolveOperationCost, validateOperationCost } from "./costs";
import type {
  BillingPeriod,
  CreditOperation,
  OperationCost,
  PlanPricing,
  SpendDecision,
  SpendRefusal,
  Wallet,
} from "./types";

/** Sentinel for "unlimited", matching the catalog's existing convention. */
export const UNLIMITED = -1;

export class WalletError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "WalletError";
    this.code = code;
  }
}

/**
 * Validates a wallet before any arithmetic trusts it.
 *
 * Storage is not trusted because it was stored. A negative `consumed` would
 * mint credits on the next balance computation; a non-integer would make the
 * ledger inexact and "did this fit" ambiguous. A `consumed` above `granted` is
 * tolerated rather than rejected, because that is the expected shape after a
 * downgrade mid-period — the customer spent under the old grant — and
 * hard-failing it would strand them with no path to recovery.
 */
export function validateWallet(wallet: Wallet): Wallet {
  const { granted, consumed } = wallet;

  if (!Number.isInteger(granted)) {
    throw new WalletError(
      "GRANT_NOT_INTEGER",
      `Wallet grant must be a whole number of credits, received ${granted}`,
    );
  }
  if (!Number.isInteger(consumed)) {
    throw new WalletError(
      "CONSUMED_NOT_INTEGER",
      `Wallet consumption must be a whole number of credits, received ${consumed}`,
    );
  }
  if (consumed < 0) {
    throw new WalletError(
      "CONSUMED_NEGATIVE",
      `Wallet consumption must not be negative, received ${consumed}. A negative value would mint credits on the next balance computation.`,
    );
  }
  if (granted !== UNLIMITED && granted < 0) {
    throw new WalletError(
      "GRANT_NEGATIVE",
      `Wallet grant must be non-negative or ${UNLIMITED} for unlimited, received ${granted}`,
    );
  }

  return { granted, consumed };
}

export function isUnlimitedGrant(granted: number): boolean {
  return granted === UNLIMITED;
}

/**
 * Credits still available in this period. Floored at zero so a
 * downgrade-over-consumption reads as "no credits left" rather than as a
 * negative balance that downstream arithmetic would propagate.
 */
export function remainingCredits(wallet: Wallet): number {
  const { granted, consumed } = validateWallet(wallet);
  if (isUnlimitedGrant(granted)) return UNLIMITED;
  return Math.max(0, granted - consumed);
}

/**
 * A refusal caused by our own configuration rather than the caller's situation.
 * Alerting on these is how an unpriced operation is noticed before a customer
 * is billed wrong or, worse, served for free.
 */
export function isInternalMisconfiguration(decision: SpendDecision): boolean {
  return !decision.allowed && decision.reason === "COST_NOT_CONFIGURED";
}

export type SpendContext = {
  /** The plan as the caller resolved it, or null when none applies. */
  plan: PlanPricing | null;
  /** Raw cost table rows. */
  costs: readonly OperationCost[];
  /** The wallet for the current billing period. */
  wallet: Wallet;
  /**
   * Subscription status when a subscription exists. `null` means no
   * subscription, which for a plan with a grant is the free tier.
   */
  subscriptionStatus: string | null;
  operation: string;
  /** Period the decision is made in. Recorded on the spend, never inferred. */
  period: BillingPeriod;
};

/**
 * Decides whether a spend is permitted, and what it leaves behind.
 *
 * Pure: the caller has already established (via an OCC-serialized read) that
 * this wallet is the current one. The engine does not and cannot protect
 * against a concurrent write on its own — see `convex/credits/spend.ts`, which
 * re-runs this decision inside the transaction that performs the write.
 */
export function decideSpend(context: SpendContext): SpendDecision {
  const { plan, costs, wallet, subscriptionStatus, operation, period } = context;
  const safeWallet = validateWallet(wallet);

  if (!period || !Number.isFinite(period.start) || !Number.isFinite(period.end)) {
    throw new WalletError(
      "PERIOD_MISSING",
      "A spend decision requires a resolved billing period",
    );
  }

  // 1. A plan must resolve at all.
  if (!plan) return refuse("NO_ACTIVE_PLAN");
  if (plan.status !== "active") return refuse("NO_ACTIVE_PLAN");

  // 2. A subscription that exists must be in a state that grants service.
  //    A null status is the free tier, which is not a lapse.
  if (subscriptionStatus !== null && !isActiveSubscriptionStatus(subscriptionStatus)) {
    return refuse("SUBSCRIPTION_NOT_ACTIVE");
  }

  // 3. Plan policy. Checked before pricing so the caller is told the actionable
  //    reason; see the module comment on check order.
  if (!plan.allowedOperations.includes(operation as CreditOperation)) {
    return refuse("OPERATION_NOT_IN_PLAN");
  }

  // 4. Price. Resolved through the shared resolver so the seed fallback, the
  //    stored-row re-validation, and the unknown-operation check all apply.
  //    Doing a bare `costs.find()` here instead would silently ignore the
  //    seeded defaults, so a fresh deployment with no cost rows would refuse
  //    every operation — the product would look broken rather than unconfigured.
  const resolution = resolveOperationCost({ operation, rows: costs });
  if (!resolution.priced) return refuse(resolution.reason, 0);
  const cost = resolution.cost.cost;

  // 5. Runaway guard. Independent of the grant so an unlimited contract still
  //    has a ceiling: one mispriced operation must not be able to drain it.
  //
  //    The test is `consumed + cost > cap`, not `consumed >= cap`. The latter
  //    only refuses *after* the ceiling is reached, so a cap of 50 with 49
  //    consumed admits a 5-credit operation and lands at 54 — the guard leaks
  //    exactly the overspend it exists to prevent. `>` still permits a spend
  //    that lands precisely on the cap.
  //
  //    Zero-cost operations are exempt: they move no credits, so they cannot
  //    overrun anything, and refusing them would let a lowered cap break
  //    read-only endpoints like `list_plans`.
  if (plan.periodSpendCap !== null && cost > 0) {
    if (safeWallet.consumed + cost > plan.periodSpendCap) {
      return refuse("GRANT_CAP_REACHED", safeWallet.consumed + cost - plan.periodSpendCap);
    }
  }

  // 6. Affordability.
  const remaining = remainingCredits(safeWallet);
  if (isUnlimitedGrant(safeWallet.granted)) {
    // An unlimited grant's "remaining" is its cap, not `cap - cost`. Dropping
    // the already-consumed term overstates headroom by exactly what has
    // already been spent, which is the number a runaway guard depends on.
    return {
      allowed: true,
      cost,
      remainingAfter:
        plan.periodSpendCap === null
          ? UNLIMITED
          : plan.periodSpendCap - safeWallet.consumed - cost,
    };
  }
  if (remaining < cost) {
    return refuse("INSUFFICIENT_CREDITS", cost - remaining);
  }

  return {
    allowed: true,
    cost,
    remainingAfter: remaining - cost,
  };
}

function refuse(reason: SpendRefusal, shortfall = 0): SpendDecision {
  return { allowed: false, reason, shortfall };
}

/**
 * Applies an approved spend to a wallet. Refuses a decision that was not
 * allowed, so a caller cannot bypass `decideSpend` by constructing its own
 * decision object.
 */
export function applySpend(wallet: Wallet, cost: number): Wallet {
  const safe = validateWallet(wallet);
  const safeCost = validateOperationCost(cost);
  return { granted: safe.granted, consumed: safe.consumed + safeCost };
}

/**
 * Returns credits to a wallet after a failed operation.
 *
 * Clamped at the original consumption: a refund above what was actually spent
 * would mint credits, so a double-refund of the same operation is a no-op
 * rather than a payout.
 */
export function refundSpend(wallet: Wallet, amount: number): Wallet {
  const safe = validateWallet(wallet);
  if (!Number.isInteger(amount) || amount < 0) {
    throw new WalletError(
      "REFUND_AMOUNT_INVALID",
      `Refund amount must be a non-negative whole number, received ${String(amount)}`,
    );
  }
  return {
    granted: safe.granted,
    consumed: Math.max(0, safe.consumed - amount),
  };
}
