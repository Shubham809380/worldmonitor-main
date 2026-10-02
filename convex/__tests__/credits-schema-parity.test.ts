import { describe, expect, test } from "vitest";
import {
  ACTIVE_SUBSCRIPTION_STATUSES,
  CREDIT_OPERATIONS,
  PERIOD_SOURCES,
  PLAN_STATUSES,
  SPEND_REFUSALS,
  type CreditOperation,
  type PlanStatus,
  type SpendRefusal,
} from "../../server/credits/types";
import { SEEDED_OPERATION_COSTS } from "../../server/credits/costs";
import {
  CREDIT_LEDGER_KINDS,
  creditActiveSubscriptionStatusValidator,
  creditLedgerKindValidator,
  creditOperationValidator,
  creditPeriodSourceValidator,
  creditPlanStatusValidator,
  creditSpendRefusalValidator,
} from "../credits/validators";

/**
 * Extracts the string literals a `v.union` accepts.
 *
 * Convex validators are opaque at runtime, so the union members are read back
 * off the `.json` schema the validator carries. This is what lets a drift
 * between the engine's TypeScript unions and the stored column types be caught
 * by a test instead of by a failed insert in production.
 */
function unionMembers(validator: unknown): string[] {
  const json = (validator as { json?: { type?: string; value?: unknown } }).json;
  if (json?.type !== "union" || !Array.isArray(json.value)) {
    throw new Error("validator is not a union; the parity helper needs updating");
  }
  return json.value.map((value) => {
    const literal = value as { type?: string; value?: unknown };
    if (literal.type !== "literal" || typeof literal.value !== "string") {
      throw new Error("union member is not a string literal");
    }
    return literal.value;
  });
}

function expectParity(
  name: string,
  validator: unknown,
  engineUnion: readonly string[],
): void {
  const stored = unionMembers(validator).sort();
  const engine = [...engineUnion].sort();
  // A value present in the engine but absent from the column would fail the
  // write at runtime; a value present in the column but not the engine would
  // mean the ledger accepts a reason the engine never produces.
  expect(stored, `${name} stored/allowed mismatch`).toEqual(engine);
}

describe("credit schema parity with the engine", () => {
  test("operations", () => {
    expectParity("operation", creditOperationValidator, CREDIT_OPERATIONS);
  });

  test("plan statuses", () => {
    expectParity("plan status", creditPlanStatusValidator, PLAN_STATUSES);
  });

  test("period sources", () => {
    expectParity("period source", creditPeriodSourceValidator, PERIOD_SOURCES);
  });

  test("spend refusals", () => {
    expectParity("spend refusal", creditSpendRefusalValidator, SPEND_REFUSALS);
  });

  test("active subscription statuses", () => {
    expectParity(
      "active subscription status",
      creditActiveSubscriptionStatusValidator,
      ACTIVE_SUBSCRIPTION_STATUSES,
    );
  });
});

describe("seeded cost table integrity", () => {
  /**
   * Every seeded operation is a `source: "seed"` row, which the admin surface
   * reads as "this is a default, change me". A row that claimed `operator`
   * while still living in the seed table would make a deploy look like a
   * deliberate repricing and hide the fact that nobody chose the number.
   */
  test("every seeded row is marked source seed", () => {
    for (const [operation, row] of Object.entries(SEEDED_OPERATION_COSTS)) {
      expect(row.source, `${operation} is not a seed row`).toBe("seed");
    }
  });

  test("every seeded operation is in the engine vocabulary", () => {
    // A seed for an operation the engine does not know is dead configuration
    // that looks like coverage in an admin UI.
    for (const operation of Object.keys(SEEDED_OPERATION_COSTS)) {
      expect(CREDIT_OPERATIONS, `${operation} is seeded but unknown`).toContain(
        operation,
      );
    }
  });

  test("every seeded cost passes validation", () => {
    // Validated here rather than only on read, so a bad seed fails a test
    // instead of refusing a customer's first scan in production.
    for (const [operation, row] of Object.entries(SEEDED_OPERATION_COSTS)) {
      expect(Number.isInteger(row.cost), `${operation} cost is not an integer`).toBe(true);
      expect(row.cost, `${operation} cost is negative`).toBeGreaterThanOrEqual(0);
    }
  });

  test("only the read operations are free", () => {
    // `list_plans` and `get_usage` cost 0 so a customer can always see what
    // they have. Any other free operation is revenue given away, so this pins
    // the two that are allowed to be zero.
    const free = Object.entries(SEEDED_OPERATION_COSTS)
      .filter(([, row]) => row.cost === 0)
      .map(([operation]) => operation)
      .sort();
    expect(free).toEqual(["get_usage", "list_plans"]);
  });

  test("the read operations a plan needs are all seeded", () => {
    // A plan whose `allowedOperations` names an unpriced operation refuses at
    // request time, which reads to a customer as a broken product.
    for (const operation of ["list_plans", "get_usage"] as const) {
      expect(SEEDED_OPERATION_COSTS[operation], `${operation} unpriced`).toBeDefined();
    }
  });
});

describe("typed unions restate the stored vocabulary", () => {
  test("plan status type covers exactly the stored statuses", () => {
    // The hand-typed `PlanStatus` union is what a plan row is cast to inside the
    // mutation. If it drifts from the column, the cast in `toPlanPricing`
    // becomes an unchecked lie.
    const typed: readonly PlanStatus[] = ["active", "disabled", "archived"];
    expect([...typed].sort()).toEqual([...PLAN_STATUSES].sort());
  });

  test("spend refusal type covers exactly the stored refusals", () => {
    // `refusalReason` is written from `decision.reason`. A refusal the type
    // excludes would not compile at the insert, which is the point: the
    // compiler and the column have to agree.
    const typed: readonly SpendRefusal[] = [
      "COST_NOT_CONFIGURED",
      "INSUFFICIENT_CREDITS",
      "OPERATION_NOT_IN_PLAN",
      "NO_ACTIVE_PLAN",
      "SUBSCRIPTION_NOT_ACTIVE",
      "GRANT_CAP_REACHED",
    ];
    expect([...typed].sort()).toEqual([...SPEND_REFUSALS].sort());
  });

  test("operation type covers exactly the seeded vocabulary", () => {
    const typed: readonly CreditOperation[] = [
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
    ];
    expect([...typed].sort()).toEqual([...CREDIT_OPERATIONS].sort());
  });
});

describe("ledger kinds", () => {
  test("the ledger has a kind for every direction a balance can move", () => {
    // A balance is a sum over the ledger, so a movement with no kind is a
    // movement nobody can explain. GRANT covers `granted`, SPEND and REFUND
    // cover `consumed`.
    expect([...CREDIT_LEDGER_KINDS].sort()).toEqual(["GRANT", "REFUND", "SPEND"]);
  });

  test("ledger kinds are a stored union of string literals", () => {
    expect(unionMembers(creditLedgerKindValidator).sort()).toEqual(
      [...CREDIT_LEDGER_KINDS].sort(),
    );
  });
});
