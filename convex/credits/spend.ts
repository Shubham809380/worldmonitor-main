/**
 * WorldGuard credit spend and refund.
 *
 * ## The race this file exists to close
 *
 * A naive implementation reads the wallet, checks affordability, and writes the
 * decremented balance. Two parallel requests both read `{granted: 20,
 * consumed: 0}`, both see that a 20-credit assessment fits, and both write
 * `consumed: 20`. The customer is served two assessments for the price of one
 * and the ledger says they bought one. This is not a theoretical interleaving —
 * it is what happens the moment a customer runs two scans from two terminals,
 * which is the exact behaviour we are asking them to adopt.
 *
 * ## Why the engine alone cannot fix it
 *
 * `server/credits/` is pure, so it cannot see a concurrent write and cannot
 * serialize one. The fix is structural: the check and the write must happen in
 * the same Convex mutation, touching the same wallet document, so Convex's
 * per-document OCC serializes them. Convex retries the entire mutation body on
 * conflict, so the re-read observes fresh state and the loser recomputes
 * against a wallet the winner already decremented.
 *
 * This is the same mechanism `convex/payments/businessSeats.ts:54` uses to hold
 * the seat cap at 4, for the same reason.
 */

import { ConvexError, GenericId, v } from "convex/values";
import {
  internalMutation,
  type MutationCtx,
} from "../_generated/server";
import {
  applySpend,
  decideSpend,
  isCreditOperation,
  isInternalMisconfiguration,
  refundSpend,
  remainingCredits,
  resolveBillingPeriod,
  validateOperationCost,
  type BillingPeriod,
  type OperationCost,
  type PlanPricing,
  type Wallet,
} from "../../server/credits";
import { readCreditLockOrThrow } from "./lock";
import { assertPrincipal } from "./principal";
import { creditPrincipalValidator } from "./validators";

/**
 * Structured ConvexError. Deliberately not a subclass: Convex serializes
 * `error.data` across the function boundary by JSON-encoding it, and the HTTP
 * layer reads `data.code ?? data.kind` back out (`convex/http.ts`,
 * `extractConvexErrorCode`). A subclass with its own field would not survive
 * that trip, so the code travels in `data.code` the way the rest of this
 * codebase expects.
 */
function creditError(code: string, message: string): ConvexError<{
  code: string;
  message: string;
}> {
  return new ConvexError({ code, message });
}

type PlanRow = {
  planId: string;
  monthlyCredits: number;
  periodSpendCap?: number | null;
  allowedOperations: string[];
  status: string;
};

type WalletRow = {
  // Convex documents always carry an `_id`, and this row type is the return type
  // of `readOrCreateWallet`, which returns the stored document rather than a
  // synthesized object precisely so the `patch` that closes the spend race
  // addresses the row that was actually read. Omitting the field made that write
  // untypeable without a cast, which is how an OCC-critical write ends up
  // unverified by the compiler. Branded rather than `string` because `ctx.db.patch`
  // only accepts a document id, and that is the type checking it.
  _id: GenericId<"creditWallets">;
  principalId: string;
  periodStart: number;
  periodEnd: number;
  planId: string;
  granted: number;
  consumed: number;
};

function toPlanPricing(row: PlanRow): PlanPricing {
  return {
    planId: row.planId,
    monthlyCredits: row.monthlyCredits,
    periodSpendCap: row.periodSpendCap ?? null,
    allowedOperations: row.allowedOperations as PlanPricing["allowedOperations"],
    status: row.status as PlanPricing["status"],
  };
}

function toWallet(row: Pick<WalletRow, "granted" | "consumed">): Wallet {
  return { granted: row.granted, consumed: row.consumed };
}

/**
 * Reads the wallet for a period, creating it if absent.
 *
 * Creation is a grant, not a top-up: the row is written with the plan's
 * `granted` and `consumed: 0`, and it is keyed by periodStart so the next
 * period is a different row. This is what makes rollover atomic without a
 * transaction.
 *
 * Safe to create here only because the caller has already read the
 * per-principal lock in `creditUserLocks`. An index-range read that finds nothing
 * establishes no OCC conflict, so without that lock two first-ever charges would
 * each insert a wallet and the customer would get two grants. See
 * `convex/credits/lock.ts`.
 *
 * `.first()` rather than `.unique()`: if a duplicate wallet ever does appear
 * (a provisioning race, or a backfill run twice), the spend path must not
 * throw and deny service. It reads one wallet, and the duplicate is a data
 * hygiene issue for an operator to see, not a reason to stop charging.
 */
async function readOrCreateWallet(
  ctx: MutationCtx,
  args: {
    principalId: string;
    plan: PlanPricing;
    period: BillingPeriod;
    now: number;
  },
): Promise<WalletRow> {
  const existing = await ctx.db
    .query("creditWallets")
    .withIndex("by_principal_period", (q) =>
      q.eq("principalId", args.principalId).eq("periodStart", args.period.start),
    )
    .first();

  if (existing) return existing;

  await ctx.db.insert("creditWallets", {
    principalId: args.principalId,
    periodStart: args.period.start,
    periodEnd: args.period.end,
    periodSource: args.period.source,
    planId: args.plan.planId,
    granted: args.plan.monthlyCredits,
    consumed: 0,
    createdAt: args.now,
    updatedAt: args.now,
  });

  // Re-read rather than returning a synthesized object: the insert above
  // established the document this transaction now conflicts on, so re-reading
  // keeps the returned value identical to what a competing mutation would see.
  const created = await ctx.db
    .query("creditWallets")
    .withIndex("by_principal_period", (q) =>
      q.eq("principalId", args.principalId).eq("periodStart", args.period.start),
    )
    .first();

  if (!created) {
    // Only reachable if the insert above was rolled back mid-transaction, which
    // Convex does not do. Failing loudly beats spending against a wallet whose
    // granted amount was never actually written.
    throw creditError(
      "WALLET_CREATE_FAILED",
      `Credit wallet for period starting ${args.period.start} was not readable after insert`,
    );
  }
  return created;
}

async function loadCosts(ctx: MutationCtx): Promise<OperationCost[]> {
  const rows = await ctx.db.query("creditOperationCosts").collect();
  // `creditOperationValidator` is `union(CREDIT_OPERATIONS)`, so the stored value
  // is one of the engine's operations at rest. The generated table types lag the
  // schema, so it arrives typed as `string`; the engine's own guard narrows it
  // back to the union rather than casting past the check. The refusal is
  // unreachable through any write the app can make, and exists so a row that
  // somehow escaped the validator surfaces as a named internal error instead of
  // pricing a spend against an operation the engine cannot meter.
  return rows.map((row) => {
    if (!isCreditOperation(row.operation)) {
      throw creditError(
        "CREDIT_OPERATION_COST_INVALID",
        `Credit cost row names an operation the engine does not recognise: ${row.operation}`,
      );
    }
    return { operation: row.operation, cost: row.cost, source: row.source };
  });
}

/**
 * Charges credits for one operation.
 *
 * `internal` on purpose: this is the primitive the API layer and the runner
 * call, and the caller must be authorized before it gets here. Exposing it as
 * a public `mutation` would let any authenticated client name any user and
 * spend their credits.
 */
export const chargeCredits = internalMutation({
  args: {
    principalId: creditPrincipalValidator,
    operation: v.string(),
    /** Provider-reported subscription period, when one exists. */
    subscription: v.optional(
      v.object({
        periodStart: v.number(),
        periodEnd: v.number(),
        status: v.string(),
      }),
    ),
    /** Plan to bill against. A caller that cannot name a plan gets refused. */
    planId: v.string(),
    now: v.number(),
    actorUserAgent: v.optional(v.string()),
    actorIp: v.optional(v.string()),
    /** Idempotency key. A repeat with the same key is a no-op, not a second charge. */
    idempotencyKey: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    // The Convex validator is only .string(); the <kind>:<id> shape is
    // checked here, before any read, so a malformed principal is a caller error
    // rather than a confusing "no wallet for this user" further down.
    assertPrincipal(args.principalId);

    // Establish the serialization point before anything else. Reading the
    // per-principal lock is what makes this mutation conflict with any other
    // credit write for the same principal, including one that has not created a
    // wallet yet. Fails closed when the account predates credits.
    const lock = await readCreditLockOrThrow(ctx, args.principalId);
    await ctx.db.patch(lock._id, { lastTouchedAt: args.now });

    const planRow = await ctx.db
      .query("creditPlans")
      .withIndex("by_planId", (q) => q.eq("planId", args.planId))
      .first();

    if (!planRow) {
      throw creditError("PLAN_NOT_FOUND", `No credit plan "${args.planId}"`);
    }
    const plan = toPlanPricing(planRow);

    let period: BillingPeriod;
    try {
      period = resolveBillingPeriod({
        at: args.now,
        subscription: args.subscription ?? null,
      });
    } catch (err) {
      // A malformed provider period is a hard stop, not a fallback to the
      // calendar: falling back would hand a live subscriber a free month
      // because of a provider formatting bug.
      throw creditError(
        "BILLING_PERIOD_INVALID",
        err instanceof Error ? err.message : "Unresolvable billing period",
      );
    }

    // Idempotent replay: a retried request must not be charged twice. Checked
    // before the wallet write so a duplicate never reaches the decrement. The
    // lookup is by (principal, key), not by (operation, time window) — an
    // operation filter would collide a genuine repeat purchase with a retry, and
    // would silently refuse the retry while charging the new request.
    //
    // The principal is part of the index key rather than a post-filter. A global
    // index plus a `seen.principalId === args.principalId` check looks equivalent
    // and is not: two principals may legitimately pick the same key, so `.first()`
    // could return the *other* one's row, the identity check would discard it as
    // a miss, and a genuine replay would be charged a second time.
    if (args.idempotencyKey) {
      const seen = await ctx.db
        .query("creditLedger")
        .withIndex("by_principal_idempotencyKey", (q) =>
          q
            .eq("principalId", args.principalId)
            .eq("idempotencyKey", args.idempotencyKey),
        )
        .first();
      if (seen) {
        return {
          charged: false as const,
          replayed: true as const,
          remaining: seen.balanceAfter,
        };
      }
    }

    const wallet = await readOrCreateWallet(ctx, {
      principalId: args.principalId,
      plan,
      period,
      now: args.now,
    });

    const decision = decideSpend({
      plan,
      costs: await loadCosts(ctx),
      wallet: toWallet(wallet),
      subscriptionStatus: args.subscription?.status ?? null,
      operation: args.operation,
      period,
    });

    if (!decision.allowed) {
      // Our bug, not the caller's. Thrown rather than returned so it surfaces as
      // a 500 and alerts, instead of being counted as ordinary quota exhaustion.
      // No ledger row: a throw rolls the transaction back, and there is no
      // customer dispute to answer here anyway.
      if (isInternalMisconfiguration(decision)) {
        throw creditError(
          "COST_NOT_CONFIGURED",
          `Operation "${args.operation}" has no configured cost. Refusing rather than serving it for free.`,
        );
      }

      // A customer-facing refusal is an outcome, not an exception.
      //
      // Returning rather than throwing is what makes the audit row below
      // durable: Convex rolls back every write in a mutation that throws, so
      // recording the refusal and then throwing would discard the record and
      // leave a customer who disputes a 429 with nothing to show. The caller
      // maps `reason` to a status code.
      await ctx.db.insert("creditLedger", {
        principalId: args.principalId,
        kind: "SPEND",
        operation: args.operation as never,
        credits: 0,
        // The customer's remaining balance, same as a successful spend records.
        // `wallet.consumed` would be the *opposite* number: it would read as a
        // balance of 0 on a full wallet and as a positive balance on a spent one,
        // and `balanceAfter` is a signed running balance to anyone reconciling
        // the ledger.
        balanceAfter: remainingCredits(toWallet(wallet)),
        periodStart: period.start,
        refusalReason: decision.reason,
        actorUserAgent: args.actorUserAgent,
        actorIp: args.actorIp,
        // Deliberately no idempotencyKey. A refusal must not consume the key:
        // the customer who is refused for INSUFFICIENT_CREDITS, buys credits,
        // and retries with the same key has to be charged. Recording the key on
        // a refusal would hand that retry back for free.
        at: args.now,
      });

      return {
        charged: false as const,
        replayed: false as const,
        reason: decision.reason,
        shortfall: decision.shortfall,
        remaining: remainingCredits(toWallet(wallet)),
      };
    }

    const next = applySpend(toWallet(wallet), decision.cost);
    // The write that closes the race. Every competing charge for this wallet
    // conflicts on this document and is retried against the new value.
    await ctx.db.patch(wallet._id, {
      consumed: next.consumed,
      updatedAt: args.now,
    });

    await ctx.db.insert("creditLedger", {
      principalId: args.principalId,
      kind: "SPEND",
      operation: args.operation as never,
      credits: -decision.cost,
      balanceAfter: remainingCredits(next),
      periodStart: period.start,
      actorUserAgent: args.actorUserAgent,
      actorIp: args.actorIp,
      idempotencyKey: args.idempotencyKey,
      at: args.now,
    });

    return {
      charged: true as const,
      replayed: false as const,
      cost: decision.cost,
      remaining: decision.remainingAfter,
      periodStart: period.start,
    };
  },
});

/**
 * Returns credits after an operation failed downstream.
 *
 * Mirrors the rollback the daily meter performs in `server/gateway.ts`: credits
 * taken for work that did not happen are a charge for nothing, and "it failed
 * but still cost you" is how a customer decides the product charges them for
 * outages.
 *
 * `refLedgerId` is what makes this auditable: the refund points at the spend
 * that caused it, so a refund with no matching spend, or two refunds for one
 * spend, is detectable from the ledger rather than merely suspicious.
 */
export const refundCredits = internalMutation({
  args: {
    principalId: creditPrincipalValidator,
    operation: v.string(),
    amount: v.number(),
    /** The SPEND ledger row being compensated. */
    refLedgerId: v.id("creditLedger"),
    periodStart: v.number(),
    now: v.number(),
    actorUserAgent: v.optional(v.string()),
    actorIp: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    assertPrincipal(args.principalId);
    const amount = validateOperationCost(args.amount);

    // Same serialization point as the charge path, so a refund cannot interleave
    // with a spend for the same user and overwrite its balance.
    const lock = await readCreditLockOrThrow(ctx, args.principalId);
    await ctx.db.patch(lock._id, { lastTouchedAt: args.now });

    const spend = await ctx.db.get(args.refLedgerId);
    if (!spend || spend.kind !== "SPEND") {
      throw creditError("REFUND_TARGET_INVALID", "refLedgerId is not a spend entry");
    }
    if (spend.principalId !== args.principalId) {
      throw creditError("REFUND_TARGET_MISMATCH", "refLedgerId belongs to another principal");
    }
    if (spend.operation !== args.operation) {
      throw creditError("REFUND_OPERATION_MISMATCH", "refLedgerId is for a different operation");
    }
    if (spend.refusalReason) {
      // A refused spend never moved credits, so compensating it would be a
      // payout with no matching charge.
      throw creditError(
        "REFUND_TARGET_REFUSED",
        "refLedgerId is a refused attempt; no credits were taken to return",
      );
    }
    if (spend.periodStart !== args.periodStart) {
      // A refund lands in the wallet for `args.periodStart`, while the credits
      // came out of the wallet for `spend.periodStart`. If those differ the
      // returned credits would be minted into a period the customer never paid
      // for, and the original period would stay debited. Refusing is the only
      // outcome that leaves the two ledgers agreeing.
      throw creditError(
        "REFUND_PERIOD_MISMATCH",
        "refLedgerId belongs to a different billing period than the refund targets",
      );
    }
    const spendAmount = Math.abs(spend.credits);
    if (amount > spendAmount) {
      // Without this, a caller passing a larger `amount` than the spend returned
      // credits out of thin air: the one-refund-per-spend guard above stops a
      // *repeat* payout but has nothing to say about an oversized first one.
      throw creditError(
        "REFUND_EXCEEDS_SPEND",
        `refund of ${amount} exceeds the ${spendAmount} credits taken by refLedgerId`,
      );
    }

    // One refund per spend. A duplicate is a no-op rather than a payout, so a
    // retried compensation cannot drain a wallet.
    const alreadyRefunded = await ctx.db
      .query("creditLedger")
      .withIndex("by_ref", (q) => q.eq("refLedgerId", args.refLedgerId))
      .first();
    if (alreadyRefunded) {
      const wallet = await ctx.db
        .query("creditWallets")
        .withIndex("by_principal_period", (q) =>
          q.eq("principalId", args.principalId).eq("periodStart", args.periodStart),
        )
        .unique();
      return {
        refunded: false,
        duplicate: true,
        remaining: wallet ? remainingCredits(toWallet(wallet)) : 0,
      };
    }

    const wallet = await ctx.db
      .query("creditWallets")
      .withIndex("by_principal_period", (q) =>
        q.eq("principalId", args.principalId).eq("periodStart", args.periodStart),
      )
      .unique();
    if (!wallet) {
      throw creditError("WALLET_NOT_FOUND", "No wallet for that period to refund into");
    }

    const next = refundSpend(toWallet(wallet), amount);
    await ctx.db.patch(wallet._id, {
      consumed: next.consumed,
      updatedAt: args.now,
    });

    await ctx.db.insert("creditLedger", {
      principalId: args.principalId,
      kind: "REFUND",
      operation: args.operation as never,
      credits: amount,
      balanceAfter: remainingCredits(next),
      periodStart: args.periodStart,
      refLedgerId: args.refLedgerId,
      actorUserAgent: args.actorUserAgent,
      actorIp: args.actorIp,
      at: args.now,
    });

    return { refunded: true, duplicate: false, remaining: remainingCredits(next) };
  },
});
