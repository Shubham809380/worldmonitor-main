// @vitest-environment node

/**
 * Credit and quota engine — cost resolution and spend decisions.
 *
 * The properties that matter here are the ones a naive implementation gets
 * wrong in the customer's favour:
 *
 *  - **Unpriced means refused, not free.** An operation with no cost row is an
 *    unmetered operation, and unmetered means unlimited.
 *  - **A stored cost is re-validated on read.** Storage is not trusted because
 *    it was stored: a negative cost is a faucet that pays the caller for
 *    consuming credits.
 *  - **Check order is part of the contract.** Plan permission is evaluated
 *    before pricing, so a customer who bought the wrong plan is told that
 *    rather than told about our missing configuration.
 *  - **An unlimited grant still has a cap.** One mispriced operation must not
 *    be able to drain an enterprise contract in a single request.
 *  - **A refund above the original spend is a no-op**, so a double refund
 *    cannot pay out.
 */

import { describe, expect, test } from 'vitest';
import {
  OperationCostError,
  UNLIMITED,
  WalletError,
  applySpend,
  calendarPeriodUtc,
  decideSpend,
  isCreditOperation,
  isInternalMisconfiguration,
  isUnlimitedGrant,
  refundSpend,
  remainingCredits,
  resolveOperationCost,
  validateOperationCost,
  validateWallet,
  type OperationCost,
  type PlanPricing,
  type SpendContext,
} from '../credits';

const PERIOD = calendarPeriodUtc(Date.UTC(2026, 9, 15));

function plan(overrides: Partial<PlanPricing> = {}): PlanPricing {
  return {
    planId: 'developer',
    monthlyCredits: 5_000,
    periodSpendCap: null,
    allowedOperations: [
      'list_plans',
      'get_usage',
      'security_headers_scan',
      'dependency_scan',
      'api_scan',
      'full_security_assessment',
      'retest',
    ],
    status: 'active',
    ...overrides,
  };
}

const COSTS: OperationCost[] = [
  { operation: 'list_plans', cost: 0, source: 'operator' },
  { operation: 'get_usage', cost: 0, source: 'operator' },
  { operation: 'security_headers_scan', cost: 1, source: 'operator' },
  { operation: 'dependency_scan', cost: 2, source: 'operator' },
  { operation: 'api_scan', cost: 5, source: 'operator' },
  { operation: 'retest', cost: 5, source: 'operator' },
  { operation: 'full_security_assessment', cost: 20, source: 'operator' },
];

function context(overrides: Partial<SpendContext> = {}): SpendContext {
  return {
    plan: plan(),
    costs: COSTS,
    wallet: { granted: 100, consumed: 0 },
    subscriptionStatus: 'active',
    operation: 'security_headers_scan',
    period: PERIOD,
    ...overrides,
  };
}

describe('validateOperationCost', () => {
  test('accepts zero, because a deliberate free operation is a decision', () => {
    expect(validateOperationCost(0)).toBe(0);
  });

  test('rejects a negative cost, which would pay the caller for spending', () => {
    expect(() => validateOperationCost(-1)).toThrow(OperationCostError);
  });

  test('rejects a fractional cost, which would make "did this fit" ambiguous', () => {
    expect(() => validateOperationCost(1.5)).toThrow(/whole number/);
  });

  test('rejects a non-finite cost', () => {
    expect(() => validateOperationCost(Number.NaN)).toThrow(OperationCostError);
    expect(() => validateOperationCost(Number.POSITIVE_INFINITY)).toThrow(OperationCostError);
  });

  test('rejects an implausibly large cost, which would be a typo', () => {
    expect(() => validateOperationCost(1_000_000)).toThrow(/exceeds the maximum/);
  });
});

describe('resolveOperationCost', () => {
  test('prefers a stored row', () => {
    const result = resolveOperationCost({
      operation: 'api_scan',
      rows: [{ operation: 'api_scan', cost: 7, source: 'operator' }],
    });
    expect(result).toEqual({
      priced: true,
      cost: { operation: 'api_scan', cost: 7, source: 'operator' },
    });
  });

  test('falls back to the seeded default when no row exists', () => {
    const result = resolveOperationCost({ operation: 'api_scan', rows: [] });
    expect(result.priced).toBe(true);
  });

  test('refuses an unpriced operation rather than treating it as free', () => {
    // An unmetered operation is an unlimited one.
    const result = resolveOperationCost({
      operation: 'api_scan',
      rows: [],
      seeded: {},
    });
    expect(result).toEqual({ priced: false, reason: 'COST_NOT_CONFIGURED' });
  });

  test('refuses an operation outside the engine vocabulary', () => {
    const result = resolveOperationCost({ operation: 'rm -rf', rows: [] });
    expect(result).toEqual({ priced: false, reason: 'COST_NOT_CONFIGURED' });
  });

  test('re-validates a stored cost on read, so a bad row cannot become a live faucet', () => {
    // A row written before validation existed must not mint credits at read
    // time. Resolution throws eagerly rather than returning a poisoned object,
    // so a caller cannot forget to check.
    expect(() =>
      resolveOperationCost({
        operation: 'api_scan',
        rows: [{ operation: 'api_scan', cost: -100, source: 'operator' }],
      }),
    ).toThrow(OperationCostError);
  });

  test('re-validates a stored fractional cost on read', () => {
    expect(() =>
      resolveOperationCost({
        operation: 'api_scan',
        rows: [{ operation: 'api_scan', cost: 2.5, source: 'operator' }],
      }),
    ).toThrow(/whole number/);
  });
});

describe('isCreditOperation', () => {
  test('recognises every seeded operation', () => {
    expect(isCreditOperation('full_security_assessment')).toBe(true);
    expect(isCreditOperation('list_plans')).toBe(true);
  });

  test('rejects an unknown name', () => {
    expect(isCreditOperation('delete_everything')).toBe(false);
  });
});

describe('validateWallet', () => {
  test('accepts a sane wallet', () => {
    expect(validateWallet({ granted: 100, consumed: 40 })).toEqual({
      granted: 100,
      consumed: 40,
    });
  });

  test('rejects negative consumption, which would mint credits on the next read', () => {
    expect(() => validateWallet({ granted: 100, consumed: -1 })).toThrow(WalletError);
  });

  test('rejects a non-integer grant or consumption', () => {
    expect(() => validateWallet({ granted: 10.5, consumed: 0 })).toThrow(/whole number/);
    expect(() => validateWallet({ granted: 10, consumed: 0.5 })).toThrow(/whole number/);
  });

  test('tolerates consumption above the grant, which is expected after a downgrade', () => {
    // Hard-failing this would strand a customer with no path to recovery.
    expect(() => validateWallet({ granted: 10, consumed: 25 })).not.toThrow();
  });

  test('treats the unlimited sentinel as a valid grant', () => {
    expect(() => validateWallet({ granted: UNLIMITED, consumed: 999_999 })).not.toThrow();
  });

  test('rejects any other negative grant', () => {
    expect(() => validateWallet({ granted: -5, consumed: 0 })).toThrow(/non-negative/);
  });
});

describe('remainingCredits', () => {
  test('subtracts consumption from the grant', () => {
    expect(remainingCredits({ granted: 100, consumed: 30 })).toBe(70);
  });

  test('floors at zero so an over-consumed wallet does not propagate a negative', () => {
    expect(remainingCredits({ granted: 10, consumed: 25 })).toBe(0);
  });

  test('reports the sentinel for an unlimited grant', () => {
    expect(remainingCredits({ granted: UNLIMITED, consumed: 500 })).toBe(UNLIMITED);
    expect(isUnlimitedGrant(UNLIMITED)).toBe(true);
  });
});

describe('decideSpend — cost resolution', () => {
  test('prices from the seeded defaults when no cost rows exist', () => {
    // A fresh deployment has an empty creditOperationCosts table. If the
    // decision consulted only the rows, every operation would refuse with
    // COST_NOT_CONFIGURED and the product would look broken rather than
    // unconfigured.
    const decision = decideSpend(
      context({
        costs: [],
        wallet: { granted: 100, consumed: 0 },
        operation: 'full_security_assessment',
      }),
    );
    expect(decision).toEqual({ allowed: true, cost: 20, remainingAfter: 80 });
  });

  test('an explicit row overrides the seeded default', () => {
    const decision = decideSpend(
      context({
        costs: [
          {
            operation: 'full_security_assessment',
            cost: 50,
            source: 'operator',
          },
        ],
        wallet: { granted: 100, consumed: 0 },
        operation: 'full_security_assessment',
      }),
    );
    expect(decision).toEqual({ allowed: true, cost: 50, remainingAfter: 50 });
  });

  test('refuses an operation that is in neither the rows nor the seeds', () => {
    const decision = decideSpend(
      context({
        costs: COSTS,
        wallet: { granted: 100, consumed: 0 },
        operation: 'not_a_real_operation',
      }),
    );
    expect(decision).toEqual({
      allowed: false,
      reason: 'OPERATION_NOT_IN_PLAN',
      shortfall: 0,
    });
  });

  test('a plan naming an operation the engine does not know is refused', () => {
    // The reachable COST_NOT_CONFIGURED path: the plan check passes because the
    // operation is listed, then pricing fails because no human ever defined it.
    // This is what an admin typo in `allowedOperations` looks like at runtime,
    // and it must stop rather than serve the request unmetered.
    const decision = decideSpend(
      context({
        plan: plan({
          allowedOperations: ['typoed_operation'] as unknown as never,
        }),
        wallet: { granted: 100, consumed: 0 },
        operation: 'typoed_operation',
      }),
    );
    expect(decision).toEqual({
      allowed: false,
      reason: 'COST_NOT_CONFIGURED',
      shortfall: 0,
    });
  });

  test('COST_NOT_CONFIGURED is flagged as internal misconfiguration', () => {
    // The distinction that makes this alertable: a caller cannot cause this,
    // so it must not be counted as ordinary quota exhaustion.
    const decision = decideSpend(
      context({
        plan: plan({
          allowedOperations: ['typoed_operation'] as unknown as never,
        }),
        wallet: { granted: 100, consumed: 0 },
        operation: 'typoed_operation',
      }),
    );
    expect(isInternalMisconfiguration(decision)).toBe(true);
  });
});
describe('decideSpend — refusals', () => {
  test('refuses when no plan resolves', () => {
    const decision = decideSpend(context({ plan: null }));
    expect(decision).toEqual({ allowed: false, reason: 'NO_ACTIVE_PLAN', shortfall: 0 });
  });

  test('refuses a disabled or archived plan', () => {
    for (const status of ['disabled', 'archived'] as const) {
      const decision = decideSpend(context({ plan: plan({ status }) }));
      expect(decision.allowed).toBe(false);
      if (!decision.allowed) expect(decision.reason).toBe('NO_ACTIVE_PLAN');
    }
  });

  test('refuses a lapsed subscription, which is distinct from exhaustion', () => {
    // Buying credits does not fix a lapsed subscription, so the reason must
    // not be INSUFFICIENT_CREDITS.
    const decision = decideSpend(context({ subscriptionStatus: 'past_due' }));
    expect(decision.allowed).toBe(false);
    if (!decision.allowed) expect(decision.reason).toBe('SUBSCRIPTION_NOT_ACTIVE');
  });

  test('serves a free-tier caller with no subscription at all', () => {
    const decision = decideSpend(context({ subscriptionStatus: null }));
    expect(decision.allowed).toBe(true);
  });

  test('refuses an operation the plan does not include', () => {
    const decision = decideSpend(
      context({
        operation: 'authentication_assessment',
        plan: plan({ allowedOperations: ['security_headers_scan'] }),
      }),
    );
    expect(decision.allowed).toBe(false);
    if (!decision.allowed) expect(decision.reason).toBe('OPERATION_NOT_IN_PLAN');
  });

  test('prices a seeded operation even when the cost table is empty', () => {
    // The seed fallback is what makes a fresh deployment serve requests
    // instead of refusing everything. `secret_scan` is seeded at 2 credits.
    const decision = decideSpend(
      context({
        operation: 'secret_scan',
        costs: [],
        plan: plan({ allowedOperations: ['secret_scan'] }),
      }),
    );
    expect(decision).toEqual({ allowed: true, cost: 2, remainingAfter: 98 });
  });

  test('reports the shortfall when the wallet cannot afford the operation', () => {
    const decision = decideSpend(
      context({ operation: 'full_security_assessment', wallet: { granted: 100, consumed: 95 } }),
    );
    expect(decision).toEqual({
      allowed: false,
      reason: 'INSUFFICIENT_CREDITS',
      shortfall: 15,
    });
  });

  test('allows a spend that exactly empties the wallet', () => {
    // Off-by-one here is the difference between "you may run this scan" and
    // "429 for a customer who paid for it".
    const decision = decideSpend(
      context({ operation: 'full_security_assessment', wallet: { granted: 20, consumed: 0 } }),
    );
    expect(decision).toEqual({ allowed: true, cost: 20, remainingAfter: 0 });
  });

  test('refuses one credit short of affording it', () => {
    const decision = decideSpend(
      context({ operation: 'full_security_assessment', wallet: { granted: 19, consumed: 0 } }),
    );
    expect(decision.allowed).toBe(false);
    if (!decision.allowed) expect(decision.reason).toBe('INSUFFICIENT_CREDITS');
  });
});

describe('decideSpend — check order', () => {
  test('plan permission is reported ahead of a missing price', () => {
    // A customer who bought the wrong plan must be told that, not told that we
    // forgot to price the operation.
    const decision = decideSpend(
      context({
        operation: 'authentication_assessment',
        costs: [],
        plan: plan({ allowedOperations: ['security_headers_scan'] }),
      }),
    );
    expect(decision.allowed).toBe(false);
    if (!decision.allowed) expect(decision.reason).toBe('OPERATION_NOT_IN_PLAN');
  });

  test('a lapsed subscription is reported ahead of an empty wallet', () => {
    const decision = decideSpend(
      context({ subscriptionStatus: 'expired', wallet: { granted: 0, consumed: 0 } }),
    );
    expect(decision.allowed).toBe(false);
    if (!decision.allowed) expect(decision.reason).toBe('SUBSCRIPTION_NOT_ACTIVE');
  });

  test('a disabled plan is reported ahead of a lapsed subscription', () => {
    const decision = decideSpend(
      context({ plan: plan({ status: 'disabled' }), subscriptionStatus: 'cancelled' }),
    );
    expect(decision.allowed).toBe(false);
    if (!decision.allowed) expect(decision.reason).toBe('NO_ACTIVE_PLAN');
  });
});

describe('decideSpend — unlimited and capped grants', () => {
  test('an unlimited grant always affords a positive-cost operation', () => {
    const decision = decideSpend(
      context({ wallet: { granted: UNLIMITED, consumed: 10_000_000 } }),
    );
    expect(decision).toEqual({
      allowed: true,
      cost: 1,
      remainingAfter: UNLIMITED,
    });
  });

  test('an unlimited grant still respects the period spend cap', () => {
    // One mispriced operation must not be able to drain an enterprise contract.
    const decision = decideSpend(
      context({
        plan: plan({ monthlyCredits: UNLIMITED, periodSpendCap: 50 }),
        wallet: { granted: UNLIMITED, consumed: 50 },
        operation: 'full_security_assessment',
      }),
    );
    expect(decision.allowed).toBe(false);
    if (!decision.allowed) expect(decision.reason).toBe('GRANT_CAP_REACHED');
  });

  test('a zero-cost operation is allowed once the cap is reached', () => {
    // Otherwise a caller that has hit its cap could not read its own balance,
    // which is the one request that must always work.
    const decision = decideSpend(
      context({
        plan: plan({ periodSpendCap: 0 }),
        wallet: { granted: 100, consumed: 0 },
        operation: 'get_usage',
      }),
    );
    expect(decision.allowed).toBe(true);
  });

  test('reports the remaining cap for an unlimited grant with a cap', () => {
    // The remaining cap accounts for what is already spent. Reporting
    // `cap - cost` alone overstates headroom by exactly the consumed amount.
    const decision = decideSpend(
      context({
        plan: plan({ monthlyCredits: UNLIMITED, periodSpendCap: 50 }),
        wallet: { granted: UNLIMITED, consumed: 10 },
        operation: 'api_scan',
      }),
    );
    expect(decision).toEqual({ allowed: true, cost: 5, remainingAfter: 35 });
  });

  test('a cap remaining of zero is reported as zero, not as unlimited', () => {
    const decision = decideSpend(
      context({
        plan: plan({ monthlyCredits: UNLIMITED, periodSpendCap: 15 }),
        wallet: { granted: UNLIMITED, consumed: 10 },
        operation: 'api_scan',
      }),
    );
    expect(decision).toEqual({ allowed: true, cost: 5, remainingAfter: 0 });
  });

  test('refuses a spend that would cross the cap, not only one past it', () => {
    // 49 of 50 consumed, then a 5-credit operation. The old `consumed >= cap`
    // test admitted this and landed at 54, so the guard leaked the overspend
    // it was written to prevent.
    const decision = decideSpend(
      context({
        plan: plan({ monthlyCredits: UNLIMITED, periodSpendCap: 50 }),
        wallet: { granted: UNLIMITED, consumed: 49 },
        operation: 'api_scan',
      }),
    );
    expect(decision).toEqual({
      allowed: false,
      reason: 'GRANT_CAP_REACHED',
      shortfall: 4,
    });
  });

  test('a spend landing exactly on the cap is still allowed', () => {
    const decision = decideSpend(
      context({
        plan: plan({ monthlyCredits: UNLIMITED, periodSpendCap: 50 }),
        wallet: { granted: UNLIMITED, consumed: 45 },
        operation: 'api_scan',
      }),
    );
    expect(decision).toEqual({ allowed: true, cost: 5, remainingAfter: 0 });
  });

  test('the cap also holds for a metered grant, not just unlimited', () => {
    const decision = decideSpend(
      context({
        plan: plan({ monthlyCredits: 100, periodSpendCap: 10 }),
        wallet: { granted: 100, consumed: 8 },
        operation: 'api_scan',
      }),
    );
    expect(decision).toEqual({
      allowed: false,
      reason: 'GRANT_CAP_REACHED',
      shortfall: 3,
    });
  });

  test('a lowered cap below current consumption refuses further spend', () => {
    // A downgrade mid-period can put `consumed` above the new cap. Refusing is
    // the point: the cap is a ceiling on the period, not a target.
    const decision = decideSpend(
      context({
        plan: plan({ monthlyCredits: 100, periodSpendCap: 5 }),
        wallet: { granted: 100, consumed: 20 },
        operation: 'api_scan',
      }),
    );
    expect(decision).toEqual({
      allowed: false,
      reason: 'GRANT_CAP_REACHED',
      shortfall: 20,
    });
  });

  test('a zero-cost operation is exempt from the cap', () => {
    // A lowered cap must not break read-only endpoints. Zero credits cannot
    // overrun anything, so the runaway guard has nothing to do here.
    const decision = decideSpend(
      context({
        plan: plan({ monthlyCredits: 0, periodSpendCap: 0 }),
        wallet: { granted: 0, consumed: 0 },
        operation: 'list_plans',
      }),
    );
    expect(decision).toEqual({ allowed: true, cost: 0, remainingAfter: 0 });
  });
});

describe('applySpend', () => {
  test('adds the cost to consumption and leaves the grant alone', () => {
    expect(applySpend({ granted: 100, consumed: 10 }, 5)).toEqual({
      granted: 100,
      consumed: 15,
    });
  });

  test('rejects a negative cost rather than crediting the wallet', () => {
    expect(() => applySpend({ granted: 100, consumed: 10 }, -5)).toThrow(OperationCostError);
  });
});

describe('refundSpend', () => {
  test('returns credits after a failed operation', () => {
    expect(refundSpend({ granted: 100, consumed: 30 }, 5)).toEqual({
      granted: 100,
      consumed: 25,
    });
  });

  test('is a no-op when the refund exceeds the original spend', () => {
    // A double refund of the same operation must not pay out.
    expect(refundSpend({ granted: 100, consumed: 10 }, 25)).toEqual({
      granted: 100,
      consumed: 0,
    });
  });

  test('rejects a negative or fractional refund amount', () => {
    expect(() => refundSpend({ granted: 100, consumed: 10 }, -1)).toThrow(WalletError);
    expect(() => refundSpend({ granted: 100, consumed: 10 }, 1.5)).toThrow(WalletError);
  });

  test('round-trips: spend then refund restores the original balance', () => {
    const start = { granted: 100, consumed: 40 };
    const afterSpend = applySpend(start, 20);
    expect(refundSpend(afterSpend, 20)).toEqual(start);
  });
});
