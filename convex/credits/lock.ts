/**
 * Per-principal credit serialization lock.
 *
 * ## Why this is a table and not a wallet field
 *
 * Convex's OCC conflict tracking is per *document*, not per index range. A
 * mutation that asks "does a wallet exist for this (principal, period)?" and gets
 * nothing back has read no document, so it has established no conflict point.
 * Two first-ever charges for the same principal would both find no wallet, both
 * insert one, and the customer would receive two full grants.
 *
 * Touching one pre-existing document per principal before writing the wallet
 * fixes that: every credit write for a principal now conflicts on the same row,
 * so the loser is retried against the winner's commit. This is the same
 * mechanism `convex/intelHistory.ts:102` uses for its append lock, and the same
 * reason the repo keeps a `countryLocks` row per country rather than counting a
 * range.
 *
 * ## Why the lock is pre-provisioned rather than created on demand
 *
 * Creating the lock inside the spend path does not work, and the reason is worth
 * recording because the obvious fix is wrong.
 *
 * The obvious fix is to derive the lock's document id from the principal, so
 * racing creates contend on one document. Convex has no such API: `ctx.db.insert`
 * is `insert(table, value)` and allocates the id itself. There is no way to
 * choose a document id, so two transactions that both find no lock each insert
 * their own, and each serializes against a *different* document. The guarantee is
 * gone while the code still reads as though it were not. (`convex-test` does not
 * error on a third `insert` argument, it silently ignores it and hands back a
 * generated id, so this cannot be caught by a test that looks like it passes
 * either.)
 *
 * So the lock is created once, at a single-writer moment, and the spend path
 * fails closed when it is missing. That is the `intelHistoryAppendLocks`
 * precedent rather than an invention.
 *
 * ## What that costs, concretely
 *
 * A principal whose lock was never provisioned cannot spend, and says so with
 * `CREDIT_LOCK_NOT_SEEDED` rather than silently skipping the serialization. The
 * two provisioning points are:
 *
 * - Clerk: `convex/users.ts` `ensureRecord`, on the insert branch.
 * - WorldGuard: **not yet wired.** These accounts authenticate against Neon
 *   `worldguard_users`, and their sign-in path must not depend on Convex —
 *   `api/auth/google/callback.js:15` records that the Convex relay was removed
 *   from Google sign-in precisely because a second identity store "would split
 *   accounts and leave Google sign-in unusable wherever the Convex secret is
 *   absent". So there is no sign-up moment that can write a Convex row, and
 *   these accounts need a backfill driven from the Neon table. Until that
 *   exists, no WorldGuard customer can spend credits; the alternative is a
 *   broken first scan, which is worse.
 *
 * `ensureCreditLock` is the idempotent provisioning primitive that backfill will
 * call. It is idempotent for sequential calls, not for concurrent ones: a race
 * can leave two rows for one principal, and the `.unique()` reads below then
 * throw rather than picking a winner. That is the safe direction to fail — a
 * customer sees an error and the backfill repairs it, instead of being charged
 * twice or served two free grants.
 */

import { ConvexError, v } from "convex/values";
import type { Doc } from "../_generated/dataModel";
import { internalMutation, type MutationCtx } from "../_generated/server";
import { assertPrincipal } from "./principal";
import { creditPrincipalValidator } from "./validators";

/**
 * Reads a principal's credit lock or fails closed.
 *
 * Returning a `Doc` rather than a boolean keeps the read inside the caller's
 * transaction, so the conflict registers against the lock document the caller is
 * about to write — which is the entire purpose of the read.
 *
 * `.unique()` on purpose: two rows for one principal means provisioning raced,
 * and picking either one would leave the other as a second serialization point
 * that spends no longer contend on. Throwing keeps the ambiguity visible.
 */
export async function readCreditLockOrThrow(
  ctx: MutationCtx,
  principalId: string,
): Promise<Doc<"creditUserLocks">> {
  assertPrincipal(principalId);

  const lock = await ctx.db
    .query("creditUserLocks")
    .withIndex("by_principalId", (q) => q.eq("principalId", principalId))
    .unique();

  if (!lock) {
    throw new ConvexError({
      code: "CREDIT_LOCK_NOT_SEEDED",
      principalId,
      message:
        `No credit lock for principal "${principalId}". The account predates WorldGuard ` +
        `credits, or its account-creation path did not provision one. Run the credit ` +
        `lock backfill for this principal.`,
    });
  }
  return lock;
}

/**
 * Idempotently provisions the credit lock for a principal.
 *
 * Safe to call repeatedly for one caller at a time: a principal that already has
 * a lock gets `created: false` and no write. Concurrent first calls can both
 * insert — see the module comment for why that is safe to surface rather than to
 * paper over.
 */
export const ensureCreditLock = internalMutation({
  args: { principalId: creditPrincipalValidator, now: v.optional(v.number()) },
  handler: async (ctx, args) => {
    assertPrincipal(args.principalId);
    const now = args.now ?? Date.now();
    const existing = await ctx.db
      .query("creditUserLocks")
      .withIndex("by_principalId", (q) => q.eq("principalId", args.principalId))
      .unique();

    if (existing) {
      return { created: false, principalId: args.principalId };
    }

    await ctx.db.insert("creditUserLocks", {
      principalId: args.principalId,
      createdAt: now,
      lastTouchedAt: now,
    });
    return { created: true, principalId: args.principalId };
  },
});
