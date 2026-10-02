import { convexTest } from "convex-test";
import { beforeEach, describe, expect, test } from "vitest";
import schema from "../schema";
import { chargeCredits, refundCredits } from "../credits/spend";
import { ensureCreditLock } from "../credits/lock";
import { clerkPrincipal } from "../credits/principal";

/**
 * Credit spend and refund against real storage.
 *
 * ## What these tests do and do not prove
 *
 * CONCURRENCY-SIMULATION CAVEAT (convex-test 0.0.43):
 *   `convex-test`'s TransactionManager takes a single `_waitOnCurrentFunction`
 *   lock at the start of each top-level mutation, so `Promise.all([t.mutation(),
 *   t.mutation()])` runs strictly sequentially even when the test author writes
 *   it as parallel. There is no OCC retry in the mock; the second mutation
 *   begins after the first commits.
 *
 *   So these tests CANNOT prove "the loser retries and re-reads". What they CAN
 *   prove is the FINAL-STATE INVARIANT: when the second call runs back-to-back
 *   against the post-winner state, the grant is never exceeded and the balance
 *   never goes negative. In production, Convex's real OCC layer turns that same
 *   final-state invariant into the no-overgrant guarantee, because the per-user
 *   lock in `creditUserLocks` forces the loser to retry against the winner's
 *   commit. See `convex/credits/lock.ts` and the equivalent caveat in
 *   `followed-countries-mutations.test.ts:934`.
 *
 * ## Why the lock is required rather than created on demand
 *
 * A lazily created lock is the racy step: two first-ever charges would each
 * create one and serialize against different documents. `chargeCredits`
 * therefore fails closed with `CREDIT_LOCK_NOT_SEEDED`, and the first test below
 * pins that. Provisioning lives in `users.ensureRecord` and in
 * `ensureCreditLock`.
 */

const modules = import.meta.glob("../**/*.ts");

const NOW = Date.parse("2026-09-15T00:00:00.000Z");
const USER = "user_credits_1";
const PRINCIPAL = clerkPrincipal(USER);
const PLAN = "developer";

/** September 2026, the free-tier UTC calendar period for NOW. */
const PERIOD_START = Date.UTC(2026, 8, 1);
const PERIOD_END = Date.UTC(2026, 9, 1);

type SetupOpts = {
  granted?: number;
  cap?: number | null;
  operations?: string[];
  withLock?: boolean;
};

function makeT() {
  return convexTest(schema, modules);
}

async function setup(t: ReturnType<typeof makeT>, opts: SetupOpts = {}) {
  const {
    granted = 100,
    cap = null,
    operations = [
      "list_plans",
      "get_usage",
      "security_headers_scan",
      "dependency_scan",
      "api_scan",
      "full_security_assessment",
      "retest",
    ],
    withLock = true,
  } = opts;

  await t.run(async (ctx) => {
    await ctx.db.insert("creditPlans", {
      planId: PLAN,
      displayName: "Developer",
      monthlyCredits: granted,
      periodSpendCap: cap,
      allowedOperations: operations,
      status: "active",
      createdAt: NOW,
      updatedAt: NOW,
    });
    if (withLock) {
      await ctx.db.insert("creditUserLocks", {
        principalId: PRINCIPAL,
        createdAt: NOW,
        lastTouchedAt: NOW,
      });
    }
  });
  return t;
}

function chargeArgs(overrides: Record<string, unknown> = {}) {
  return {
    principalId: PRINCIPAL,
    operation: "api_scan",
    planId: PLAN,
    now: NOW,
    ...overrides,
  } as Parameters<typeof chargeCredits>[0];
}

async function walletFor(t: ReturnType<typeof makeT>, periodStart = PERIOD_START) {
  return t.run(async (ctx) => {
    const rows = await ctx.db
      .query("creditWallets")
      .withIndex("by_principal_period", (q) =>
        q.eq("principalId", PRINCIPAL).eq("periodStart", periodStart),
      )
      .collect();
    return rows[0] ?? null;
  });
}

async function ledgerFor(t: ReturnType<typeof makeT>) {
  return t.run(async (ctx) => ctx.db.query("creditLedger").collect());
}

beforeEach(() => {
  // Nothing global to reset; the harness is constructed per test so a document
  // left in a bad state by one case cannot leak into the next.
});

describe("chargeCredits - fail closed", () => {
  test("refuses when the account has no credit lock, and writes nothing", async () => {
    const t = await setup(makeT(), { withLock: false });

    await expect(t.mutation(chargeCredits, chargeArgs())).rejects.toThrow(
      /CREDIT_LOCK_NOT_SEEDED|credit lock/i,
    );

    // Fail closed means no partial state: a refusal here must not create a
    // wallet, because a wallet created without the lock is the overgrant.
    expect(await walletFor(t)).toBeNull();
    expect(await ledgerFor(t)).toEqual([]);
  });

  test("refuses a plan that does not exist", async () => {
    const t = await setup(makeT());
    await expect(
      t.mutation(chargeCredits, chargeArgs({ planId: "nonexistent" })),
    ).rejects.toThrow(/PLAN_NOT_FOUND|nonexistent/);
    expect(await walletFor(t)).toBeNull();
  });

  test("refuses a malformed provider period instead of falling back to the calendar", async () => {
    // Falling back would hand a live subscriber a free month because of a
    // provider formatting bug, and it would also put their wallet in the wrong
    // period so renewal would not find it.
    const t = await setup(makeT());
    await expect(
      t.mutation(
        chargeCredits,
        chargeArgs({
          subscription: { periodStart: PERIOD_END, periodEnd: PERIOD_START, status: "active" },
        }),
      ),
    ).rejects.toThrow(/BILLING_PERIOD|period/i);
    expect(await walletFor(t)).toBeNull();
  });

  test("refuses a lapsed subscription even when the wallet has credits", async () => {
    // Buying credits does not fix a past-due subscription, so the reason has to
    // be distinguishable from INSUFFICIENT_CREDITS.
    const t = await setup(makeT(), { granted: 1000 });
    const refused = await t.mutation(
      chargeCredits,
      chargeArgs({
        subscription: {
          periodStart: PERIOD_START,
          periodEnd: PERIOD_END,
          status: "past_due",
        },
      }),
    );

    expect(refused).toMatchObject({ charged: false, reason: "SUBSCRIPTION_NOT_ACTIVE" });
    // The wallet exists and is untouched: the subscription check comes before
    // the grant is ever consulted, so the customer can see the credits are
    // sitting there waiting for the payment to clear.
    const wallet = await walletFor(t);
    expect(wallet).toMatchObject({ granted: 1000, consumed: 0 });
    expect(wallet?.periodSource).toBe("PROVIDER");
  });
});

describe("chargeCredits - accumulation", () => {
  test("creates the wallet on first spend and records one ledger entry", async () => {
    const t = await setup(makeT());

    const result = await t.mutation(chargeCredits, chargeArgs());

    expect(result).toMatchObject({ charged: true, replayed: false, cost: 5, remaining: 95 });
    const wallet = await walletFor(t);
    expect(wallet).toMatchObject({ granted: 100, consumed: 5, planId: PLAN });
    expect(wallet?.periodSource).toBe("CALENDAR_UTC");

    const ledger = await ledgerFor(t);
    expect(ledger).toHaveLength(1);
    expect(ledger[0]).toMatchObject({ kind: "SPEND", credits: -5, balanceAfter: 95 });
  });

  test("repeated charges accumulate and never exceed the grant", async () => {
    const t = await setup(makeT(), { granted: 20 });

    await t.mutation(chargeCredits, chargeArgs());
    await t.mutation(chargeCredits, chargeArgs());
    await t.mutation(chargeCredits, chargeArgs());
    await t.mutation(chargeCredits, chargeArgs());

    const wallet = await walletFor(t);
    expect(wallet?.consumed).toBe(20);
    expect(wallet?.consumed).toBeLessThanOrEqual(wallet?.granted ?? 0);
  });

  test("uses the seeded price when the cost table is empty", async () => {
    // A fresh deployment has no cost rows. Pricing from the seeds is what keeps
    // the product serving instead of refusing every scan.
    const t = await setup(makeT());
    const result = await t.mutation(chargeCredits, chargeArgs());
    expect(result).toMatchObject({ charged: true, cost: 5 });
  });

  test("an operator price overrides the seeded price", async () => {
    const t = await setup(makeT());
    await t.run(async (ctx) => {
      await ctx.db.insert("creditOperationCosts", {
        operation: "api_scan",
        cost: 12,
        source: "operator",
        updatedAt: NOW,
      });
    });
    const result = await t.mutation(chargeCredits, chargeArgs());
    expect(result).toMatchObject({ charged: true, cost: 12, remaining: 88 });
  });
});

describe("chargeCredits - no overgrant", () => {
  test("a burst of charges for more than the grant allows only the affordable ones", async () => {
    // 10 credits granted, 5 per api_scan, 4 requests. Exactly 2 may succeed.
    // This is the final-state invariant: the third and fourth must observe the
    // committed consumption of the first two, not a stale snapshot.
    const t = await setup(makeT(), { granted: 10 });

    const results = await Promise.allSettled([
      t.mutation(chargeCredits, chargeArgs({ idempotencyKey: "k1" })),
      t.mutation(chargeCredits, chargeArgs({ idempotencyKey: "k2" })),
      t.mutation(chargeCredits, chargeArgs({ idempotencyKey: "k3" })),
      t.mutation(chargeCredits, chargeArgs({ idempotencyKey: "k4" })),
    ]);

    const outcomes = results.map((r) =>
      r.status === "fulfilled" ? r.value : { charged: false, reason: "threw" },
    );
    const charged = outcomes.filter((o) => o.charged);
    const refusedOutcomes = outcomes.filter((o) => !o.charged);
    expect(charged).toHaveLength(2);
    expect(refusedOutcomes).toHaveLength(2);
    for (const o of refusedOutcomes) {
      expect(o).toMatchObject({ charged: false, reason: "INSUFFICIENT_CREDITS" });
    }

    const wallet = await walletFor(t);
    expect(wallet?.consumed).toBe(10);
    expect(wallet?.consumed).toBeLessThanOrEqual(wallet?.granted ?? 0);
  });

  test("a refused charge leaves the balance untouched and is recorded with its reason", async () => {
    const t = await setup(makeT(), { granted: 5 });

    await t.mutation(chargeCredits, chargeArgs());
    const before = await walletFor(t);

    const refused = await t.mutation(chargeCredits, chargeArgs());
    expect(refused).toMatchObject({ charged: false, reason: "INSUFFICIENT_CREDITS" });

    const after = await walletFor(t);
    expect(after?.consumed).toBe(before?.consumed);
    expect(after?.granted).toBe(5);

    const ledger = await ledgerFor(t);
    const refusalRow = ledger.find(
      (entry) => entry.refusalReason === "INSUFFICIENT_CREDITS",
    );
    expect(refusalRow).toMatchObject({ kind: "SPEND", credits: 0 });
  });

  test("the runaway cap stops spending below the grant level", async () => {
    // 100 granted but a cap of 20: the cap is the ceiling, not the balance.
    const t = await setup(makeT(), { granted: 100, cap: 20 });

    for (let i = 0; i < 4; i += 1) {
      await t.mutation(chargeCredits, chargeArgs({ idempotencyKey: `c${i}` }));
    }
    const wallet = await walletFor(t);
    expect(wallet?.consumed).toBe(20);

    const capped = await t.mutation(chargeCredits, chargeArgs({ idempotencyKey: "c5" }));
    expect(capped).toMatchObject({ charged: false, reason: "GRANT_CAP_REACHED" });
  });

  test("an operation the plan does not include is refused", async () => {
    const t = await setup(makeT(), { operations: ["list_plans"] });
    const refused = await t.mutation(chargeCredits, chargeArgs());
    expect(refused).toMatchObject({ charged: false, reason: "OPERATION_NOT_IN_PLAN" });
  });
});

describe("chargeCredits - idempotency", () => {
  test("a replayed key is not charged twice", async () => {
    const t = await setup(makeT());
    const first = await t.mutation(chargeCredits, chargeArgs({ idempotencyKey: "same" }));
    const second = await t.mutation(chargeCredits, chargeArgs({ idempotencyKey: "same" }));

    expect(first).toMatchObject({ charged: true, replayed: false, remaining: 95 });
    expect(second).toMatchObject({ charged: false, replayed: true });
    expect((await walletFor(t))?.consumed).toBe(5);
    expect(await ledgerFor(t)).toHaveLength(1);
  });

  test("distinct keys on the same operation each charge", async () => {
    // The opposite failure: deduping on (user, operation) would refuse the
    // second genuine purchase and let it through unmetered.
    const t = await setup(makeT());
    await t.mutation(chargeCredits, chargeArgs({ idempotencyKey: "a" }));
    await t.mutation(chargeCredits, chargeArgs({ idempotencyKey: "b" }));
    expect((await walletFor(t))?.consumed).toBe(10);
  });

  test("a refusal does not consume the key, so a retry after top-up is charged", async () => {
    // The revenue bug this guards: if a refused attempt burned the key, a
    // customer refused for INSUFFICIENT_CREDITS who buys credits and retries
    // would get the scan free.
    const t = await setup(makeT(), { granted: 2 });

    const firstAttempt = await t.mutation(chargeCredits, chargeArgs({ idempotencyKey: "retry" }));
    expect(firstAttempt).toMatchObject({ charged: false, reason: "INSUFFICIENT_CREDITS" });

    // Top up by moving the wallet, simulating the grant path.
    await t.run(async (ctx) => {
      const wallet = await ctx.db
        .query("creditWallets")
        .withIndex("by_principal_period", (q) =>
          q.eq("principalId", PRINCIPAL).eq("periodStart", PERIOD_START),
        )
        .first();
      if (wallet) await ctx.db.patch(wallet._id, { granted: 50 });
    });

    const retried = await t.mutation(chargeCredits, chargeArgs({ idempotencyKey: "retry" }));
    expect(retried).toMatchObject({ charged: true, replayed: false, cost: 5 });
  });
});

describe("chargeCredits - period rollover", () => {
  test("a new period gets a new wallet row and leaves the old one intact", async () => {
    const t = await setup(makeT(), { granted: 20 });

    await t.mutation(chargeCredits, chargeArgs());
    const september = await walletFor(t, PERIOD_START);
    expect(september?.consumed).toBe(5);

    const october = Date.parse("2026-10-02T00:00:00.000Z");
    await t.mutation(chargeCredits, chargeArgs({ now: october, idempotencyKey: "oct" }));

    const octStart = Date.UTC(2026, 9, 1);
    const octEnd = Date.UTC(2026, 10, 1);
    const octoberWallet = await walletFor(t, octStart);
    expect(octoberWallet).toMatchObject({ granted: 20, consumed: 5, periodSource: "CALENDAR_UTC" });
    expect(octoberWallet?.periodEnd).toBe(octEnd);

    // The previous period is a historical fact and must not be rewritten.
    const stillSeptember = await walletFor(t, PERIOD_START);
    expect(stillSeptember?.consumed).toBe(5);
    expect(stillSeptember?.periodEnd).toBe(PERIOD_END);
  });

  test("a provider period wins over the calendar and is recorded as the source", async () => {
    const t = await setup(makeT());
    const providerStart = Date.UTC(2026, 8, 10);
    const providerEnd = Date.UTC(2026, 9, 10);

    await t.mutation(
      chargeCredits,
      chargeArgs({
        subscription: { periodStart: providerStart, periodEnd: providerEnd, status: "active" },
      }),
    );

    const wallet = await walletFor(t, providerStart);
    expect(wallet).toMatchObject({
      periodSource: "PROVIDER",
      periodStart: providerStart,
      periodEnd: providerEnd,
    });
    // No calendar wallet was created for the same month.
    expect(await walletFor(t, PERIOD_START)).toBeNull();
  });
});

describe("refundCredits", () => {
  async function spendThenRefund(t: ReturnType<typeof makeT>, amount: number) {
    await t.mutation(chargeCredits, chargeArgs());
    const ledger = await ledgerFor(t);
    const spend = ledger.find((entry) => entry.kind === "SPEND");
    if (!spend) throw new Error("no spend recorded");
    return t.mutation(refundCredits, {
      principalId: PRINCIPAL,
      operation: "api_scan",
      amount,
      refLedgerId: spend._id,
      periodStart: PERIOD_START,
      now: NOW + 1_000,
    });
  }

  test("returns the credits and records a REFUND pointing at the spend", async () => {
    const t = await setup(makeT());
    const result = await spendThenRefund(t, 5);

    expect(result).toMatchObject({ refunded: true, duplicate: false, remaining: 100 });
    expect((await walletFor(t))?.consumed).toBe(0);

    const ledger = await ledgerFor(t);
    const refund = ledger.find((entry) => entry.kind === "REFUND");
    expect(refund).toMatchObject({ credits: 5, balanceAfter: 100 });
    expect(refund?.refLedgerId).toBeTruthy();
  });

  test("a second refund of the same spend is a no-op, not a payout", async () => {
    const t = await setup(makeT());
    await spendThenRefund(t, 5);

    const ledger = await ledgerFor(t);
    const spend = ledger.find((entry) => entry.kind === "SPEND");
    const duplicate = await t.mutation(refundCredits, {
      principalId: PRINCIPAL,
      operation: "api_scan",
      amount: 5,
      refLedgerId: spend!._id,
      periodStart: PERIOD_START,
      now: NOW + 2_000,
    });

    expect(duplicate).toMatchObject({ refunded: false, duplicate: true });
    // Consumed stays at 0; the duplicate refund did not mint credits.
    expect((await walletFor(t))?.consumed).toBe(0);
    expect((await ledgerFor(t)).filter((e) => e.kind === "REFUND")).toHaveLength(1);
  });

  test("refuses to refund another user's spend", async () => {
    const t = await setup(makeT());
    await t.mutation(chargeCredits, chargeArgs());
    const spend = (await ledgerFor(t)).find((entry) => entry.kind === "SPEND");

    await expect(
      t.mutation(refundCredits, {
        principalId: clerkPrincipal("someone_else"),
        operation: "api_scan",
        amount: 5,
        refLedgerId: spend!._id,
        periodStart: PERIOD_START,
        now: NOW + 1_000,
      }),
    ).rejects.toThrow(/CREDIT_LOCK_NOT_SEEDED|credit lock/i);
  });

  test("refuses to refund a refused attempt, which took no credits", async () => {
    const t = await setup(makeT(), { granted: 0 });
    const attempt = await t.mutation(chargeCredits, chargeArgs({ idempotencyKey: "x" }));
    expect(attempt).toMatchObject({ charged: false, reason: "INSUFFICIENT_CREDITS" });
    const refused = (await ledgerFor(t)).find((entry) => entry.refusalReason);

    await expect(
      t.mutation(refundCredits, {
        principalId: PRINCIPAL,
        operation: "api_scan",
        amount: 0,
        refLedgerId: refused!._id,
        periodStart: PERIOD_START,
        now: NOW + 1_000,
      }),
    ).rejects.toThrow(/REFUND_TARGET_REFUSED/);
  });

  test("refuses a refund larger than the spend it points at", async () => {
    const t = await setup(makeT());
    // The one-refund-per-spend guard stops a repeat payout but says nothing
    // about an oversized first one, so without an amount bound this mints 20
    // credits against a 5-credit spend.
    await t.mutation(chargeCredits, chargeArgs());
    const spend = (await ledgerFor(t)).find((entry) => entry.kind === "SPEND");

    await expect(
      t.mutation(refundCredits, {
        principalId: PRINCIPAL,
        operation: "api_scan",
        amount: 20,
        refLedgerId: spend!._id,
        periodStart: PERIOD_START,
        now: NOW + 1_000,
      }),
    ).rejects.toThrow(/REFUND_EXCEEDS_SPEND/);

    expect((await walletFor(t))?.consumed).toBe(5);
    expect((await ledgerFor(t)).filter((e) => e.kind === "REFUND")).toHaveLength(0);
  });

  test("refuses a refund aimed at a different period's wallet", async () => {
    const t = await setup(makeT());
    // October's period. The September spend below stays debited, so a refund
    // into October would mint credits the customer never paid for.
    await t.mutation(chargeCredits, chargeArgs());
    const spend = (await ledgerFor(t)).find((entry) => entry.kind === "SPEND");
    const octoberStart = Date.UTC(2026, 9, 1);
    await t.mutation(chargeCredits, chargeArgs({ now: NOW + 20 * 86_400_000, idempotencyKey: "oct" }));
    // October already holds that charge. A refused refund must leave the wallet
    // exactly as the charge left it, so capture it rather than hard-coding a
    // balance: the assertion is about the refund being inert, not about the
    // charge's amount.
    const octoberBefore = await walletFor(t, octoberStart);

    await expect(
      t.mutation(refundCredits, {
        principalId: PRINCIPAL,
        operation: "api_scan",
        amount: 5,
        refLedgerId: spend!._id,
        periodStart: octoberStart,
        now: NOW + 20 * 86_400_000,
      }),
    ).rejects.toThrow(/REFUND_PERIOD_MISMATCH/);

    expect(await walletFor(t, octoberStart)).toEqual(octoberBefore);
  });
});

describe("ensureCreditLock", () => {
  test("creates the lock once and is idempotent", async () => {
    const t = makeT();
    const first = await t.mutation(ensureCreditLock, { principalId: PRINCIPAL, now: NOW });
    const second = await t.mutation(ensureCreditLock, { principalId: PRINCIPAL, now: NOW });

    expect(first).toEqual({ created: true, principalId: PRINCIPAL });
    expect(second).toEqual({ created: false, principalId: PRINCIPAL });

    const locks = await t.run(async (ctx) => ctx.db.query("creditUserLocks").collect());
    expect(locks).toHaveLength(1);
  });
});
