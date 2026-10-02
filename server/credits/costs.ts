/**
 * Credit and quota engine — operation cost resolution.
 *
 * ## Why an unpriced operation is refused
 *
 * Every spend needs a price, and the price is an operator decision that must be
 * changeable without a deploy. So costs live in storage, not in code. That
 * creates one dangerous case: an operation that exists in the engine's
 * vocabulary but has no row in the cost table.
 *
 * The tempting default is "treat it as free" so a newly added operation still
 * works. That default is a revenue hole and a security hole at once — an
 * unpriced operation is an unmetered one, and unmetered means unlimited. So an
 * unpriced operation is refused with `COST_NOT_CONFIGURED`.
 *
 * Operations that genuinely should be free (`list_plans`, `get_usage`) are
 * priced at 0 by an explicit seeded row. The distinction matters: a deliberate
 * zero is a pricing decision with an author, whereas an absent row is an
 * oversight. The engine treats them differently on purpose.
 */

import {
  type CreditOperation,
  CREDIT_OPERATIONS,
  type OperationCost,
  type SpendRefusal,
} from "./types";

/**
 * Seeded defaults. These are a starting position for a fresh deployment, not a
 * pricing decision: every row is `source: "seed"`, which the admin surface
 * treats as "change me". An operator-set row always wins over a seeded one.
 */
export const SEEDED_OPERATION_COSTS: Readonly<Record<string, OperationCost>> =
  Object.freeze({
    // Deliberately free. A customer who cannot read their own balance cannot
    // predict when they will be cut off, and a 429 with no way to anticipate it
    // is indistinguishable from an outage.
    list_plans: { operation: "list_plans", cost: 0, source: "seed" },
    get_usage: { operation: "get_usage", cost: 0, source: "seed" },

    security_headers_scan: {
      operation: "security_headers_scan",
      cost: 1,
      source: "seed",
    },
    secret_scan: { operation: "secret_scan", cost: 2, source: "seed" },
    dependency_scan: {
      operation: "dependency_scan",
      cost: 2,
      source: "seed",
    },
    api_scan: { operation: "api_scan", cost: 5, source: "seed" },
    retest: { operation: "retest", cost: 5, source: "seed" },
    authentication_assessment: {
      operation: "authentication_assessment",
      cost: 10,
      source: "seed",
    },
    authorization_assessment: {
      operation: "authorization_assessment",
      cost: 10,
      source: "seed",
    },
    report_generation: {
      operation: "report_generation",
      cost: 2,
      source: "seed",
    },
    full_security_assessment: {
      operation: "full_security_assessment",
      cost: 20,
      source: "seed",
    },
  });

/** Largest price the engine will accept, as a runaway guard. */
export const MAX_OPERATION_COST = 10_000;

export class OperationCostError extends Error {
  readonly code: string;

  constructor(code: string, message: string) {
    super(message);
    this.name = "OperationCostError";
    this.code = code;
  }
}

export function isCreditOperation(value: string): value is CreditOperation {
  return (CREDIT_OPERATIONS as readonly string[]).includes(value);
}

/**
 * Validates an operator-supplied cost.
 *
 * Rejects negatives (a negative cost is a faucet that pays the attacker for
 * consuming the platform), non-integers (balances must stay exact, and a
 * fractional cost makes "did this fit in the wallet" ambiguous), and
 * implausibly large values (a typo of `1000000` would silently price a scan
 * out of every plan's reach).
 */
export function validateOperationCost(cost: number): number {
  if (!Number.isFinite(cost)) {
    throw new OperationCostError(
      "COST_NOT_FINITE",
      `Operation cost is not a finite number: ${String(cost)}`,
    );
  }
  if (!Number.isInteger(cost)) {
    throw new OperationCostError(
      "COST_NOT_INTEGER",
      `Operation cost must be a whole number of credits, received ${cost}`,
    );
  }
  if (cost < 0) {
    throw new OperationCostError(
      "COST_NEGATIVE",
      `Operation cost must not be negative, received ${cost}. A negative cost would credit the caller for consuming credits.`,
    );
  }
  if (cost > MAX_OPERATION_COST) {
    throw new OperationCostError(
      "COST_TOO_LARGE",
      `Operation cost ${cost} exceeds the maximum of ${MAX_OPERATION_COST}`,
    );
  }
  return cost;
}

export type CostResolution =
  | { priced: true; cost: OperationCost }
  | { priced: false; reason: SpendRefusal };

/**
 * Resolves the price for an operation.
 *
 * Operator-set costs take precedence over seeded ones: a deployment that has
 * deliberately repriced an operation must not be silently overridden by a
 * deploy that only changed the seed table.
 */
export function resolveOperationCost(args: {
  operation: string;
  rows: readonly OperationCost[];
  seeded?: Readonly<Record<string, OperationCost>>;
}): CostResolution {
  const { operation, rows, seeded = SEEDED_OPERATION_COSTS } = args;

  if (!isCreditOperation(operation)) {
    return { priced: false, reason: "COST_NOT_CONFIGURED" };
  }

  const row = rows.find((r) => r.operation === operation);
  if (row) {
    // A stored cost is re-validated on read. Storage is not trusted because it
    // was stored: a row written before this rule existed, or by a migration
    // that did not check, must not become a live faucet.
    return { priced: true, cost: { ...row, cost: validateOperationCost(row.cost) } };
  }

  const fallback = seeded[operation];
  if (fallback) {
    return { priced: true, cost: fallback };
  }

  return { priced: false, reason: "COST_NOT_CONFIGURED" };
}
