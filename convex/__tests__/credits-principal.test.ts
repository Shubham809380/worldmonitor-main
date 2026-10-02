import { describe, expect, test } from "vitest";
import { convexTest } from "convex-test";
import { internalQuery } from "../_generated/server";
import schema from "../schema";
import { ensureCreditLock } from "../credits/lock";
import {
  assertPrincipal,
  clerkPrincipal,
  isPrincipal,
  parsePrincipal,
  PRINCIPAL_KINDS,
  requirePrincipalOfKind,
  worldguardPrincipal,
} from "../credits/principal";

const countLocks = internalQuery({
  args: {},
  handler: async (ctx) => {
    const rows = await ctx.db.query("creditUserLocks").collect();
    return rows.length;
  },
});

function lockCount(t: ReturnType<typeof convexTest>): Promise<number> {
  return t.query(countLocks, {});
}

/**
 * The lock's correctness rests on one property: every credit write for a
 * principal contends on the same document, so a second first-ever charge for
 * that principal is forced to retry. The `by_principalId` index is what makes
 * that document reachable from a principal, so these tests pin the index as the
 * thing that must not be renamed or dropped — a missing lock row and a
 * missing index look identical from `chargeCredits`, which is exactly the
 * failure the `CREDIT_LOCK_NOT_SEEDED` message has to explain.
 */
describe("credit lock provisioning", () => {
  test("provisions once and is idempotent for a single caller", async () => {
    const t = convexTest(schema);
    const principalId = worldguardPrincipal("3f1c9a2e-0000-4000-8000-000000000001");

    const first = await t.mutation(ensureCreditLock, { principalId });
    const second = await t.mutation(ensureCreditLock, { principalId });

    expect(first).toEqual({ created: true, principalId });
    expect(second).toEqual({ created: false, principalId });
    // The idempotence is the point: provisioning runs on account creation and
    // again from backfill, so a second call must not add a second serialization
    // point for the same principal.
    expect(await lockCount(t)).toBe(1);
  });

  test("keeps one lock per principal, so two principals do not share a conflict point", async () => {
    const t = convexTest(schema);
    await t.mutation(ensureCreditLock, { principalId: worldguardPrincipal("wg-a") });
    await t.mutation(ensureCreditLock, { principalId: worldguardPrincipal("wg-b") });
    await t.mutation(ensureCreditLock, { principalId: clerkPrincipal("user_same") });

    expect(await lockCount(t)).toBe(3);
  });

  test("does not merge principals that differ only after a colon", async () => {
    const t = convexTest(schema);
    // Guards against a lookup that truncated or matched loosely: "wg:a" and
    // "wg:a:b" are different accounts and must not contend on one lock.
    await t.mutation(ensureCreditLock, { principalId: worldguardPrincipal("a") });
    await t.mutation(ensureCreditLock, { principalId: worldguardPrincipal("a:b") });
    expect(await lockCount(t)).toBe(2);
  });

  test("never lets a Clerk and a WorldGuard principal share a lock", async () => {
    const t = convexTest(schema);
    // The whole reason for namespacing: two unrelated identity systems must not
    // contend on, or worse read, the same wallet.
    await t.mutation(ensureCreditLock, { principalId: clerkPrincipal("shared-id") });
    await t.mutation(ensureCreditLock, {
      principalId: worldguardPrincipal("shared-id"),
    });
    expect(await lockCount(t)).toBe(2);
  });

  test("rejects a malformed principal rather than provisioning an unreachable lock", async () => {
    const t = convexTest(schema);
    for (const bad of ["", "nocolon", ":missing-kind", "unknown:kind", "clerk:"]) {
      await expect(
        t.mutation(ensureCreditLock, { principalId: bad }),
      ).rejects.toThrow();
    }
    // A lock under a principal no spend could ever build is dead weight that
    // still shows up in the table, so it must not be written at all.
    expect(await lockCount(t)).toBe(0);
  });
});

describe("principal format", () => {
  test("round-trips both identity domains", () => {
    expect(parsePrincipal(clerkPrincipal("user_2abc"))).toEqual({
      kind: "clerk",
      id: "user_2abc",
    });
    expect(parsePrincipal(worldguardPrincipal("3f1c-uuid"))).toEqual({
      kind: "worldguard",
      id: "3f1c-uuid",
    });
  });

  test("splits on the first colon so an id containing one is preserved", () => {
    // A naive `split(":")` that dropped the remainder, or rejected ids with a
    // colon, would make some real ids unusable depending on the parser.
    expect(parsePrincipal("worldguard:a:b:c")).toEqual({
      kind: "worldguard",
      id: "a:b:c",
    });
  });

  test("rejects the shapes that would create a principal nothing can match", () => {
    for (const bad of [
      "",
      "nocolon",
      ":leading",
      "clerk:",
      "unknown:id",
      "Clerk:id", // case-sensitive: a kind typo must not resolve to another domain
      "clerk:with space",
      "clerk:with\ttab",
      " clerk:id", // leading space
      "clerk: id",
    ]) {
      expect(isPrincipal(bad), `expected ${JSON.stringify(bad)} to be rejected`).toBe(
        false,
      );
    }
  });

  test("rejects an over-long id", () => {
    expect(isPrincipal(`clerk:${"a".repeat(257)}`)).toBe(false);
    expect(isPrincipal(`clerk:${"a".repeat(256)}`)).toBe(true);
  });

  test("refuses to build a principal from an unusable id", () => {
    expect(() => clerkPrincipal("   ")).toThrow();
    expect(() => worldguardPrincipal("")).toThrow();
    expect(() => clerkPrincipal("has space")).toThrow();
  });

  test("requirePrincipalOfKind rejects a cross-domain principal", () => {
    const wg = worldguardPrincipal("abc");
    expect(requirePrincipalOfKind(wg, "worldguard")).toBe(wg);
    // The relay-route case: a caller that must write a WorldGuard principal
    // cannot smuggle a Clerk one through the body.
    expect(() => requirePrincipalOfKind(wg, "clerk")).toThrow(/kind mismatch/);
  });

  test("assertPrincipal returns the parsed kind for a caller that routes on it", () => {
    expect(assertPrincipal(clerkPrincipal("user_x")).kind).toBe("clerk");
    expect(() => assertPrincipal("garbage")).toThrow(/Malformed credit principal/);
  });

  test("every declared kind is constructible", () => {
    for (const kind of PRINCIPAL_KINDS) {
      expect(isPrincipal(`${kind}:some-id`)).toBe(true);
    }
  });
});
