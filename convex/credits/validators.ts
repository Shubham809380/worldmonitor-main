import { v } from "convex/values";

/**
 * Persistence validators for the WorldGuard credit and quota engine.
 *
 * These restate the engine's unions rather than importing them, because a Convex
 * validator must be a statically analysable literal and a TypeScript type alias
 * erases at build time. `convex/__tests__/credits-schema-parity.test.ts` fails if
 * a union here drifts from the one in `server/credits/types.ts`.
 *
 * The same reasoning as `convex/securescan/validators.ts` applies: each union is
 * built from an exported `as const` array so one hand-typed copy cannot diverge
 * from the list the read models bucket by. A third copy is how a console ends up
 * reporting a refusal bucket that can never be non-zero, and a cast hides that
 * from `tsc`.
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

export const PLAN_STATUSES = ["active", "disabled", "archived"] as const;

export const PERIOD_SOURCES = ["PROVIDER", "CALENDAR_UTC", "OPERATOR"] as const;

export const SPEND_REFUSALS = [
  "COST_NOT_CONFIGURED",
  "INSUFFICIENT_CREDITS",
  "OPERATION_NOT_IN_PLAN",
  "NO_ACTIVE_PLAN",
  "SUBSCRIPTION_NOT_ACTIVE",
  "GRANT_CAP_REACHED",
] as const;

export const ACTIVE_SUBSCRIPTION_STATUSES = ["active", "trialing"] as const;

/**
 * Ledger entry kinds. `SPEND` and `REFUND` are the only two that move
 * `consumed`; `GRANT` records an operator adjustment that moves `granted`.
 * Recording the direction of every balance change is what makes a disputed
 * charge reconstructible from the ledger alone rather than by inference.
 */
export const CREDIT_LEDGER_KINDS = ["GRANT", "SPEND", "REFUND"] as const;

function union<const T extends readonly string[]>(values: T) {
  return v.union(...values.map((value) => v.literal(value)));
}

/**
 * A namespaced credit principal, `clerk:<sub>` or `worldguard:<id>`.
 *
 * `v.string()`, not a pattern: Convex's validator language is a closed set of
 * structural combinators with no regex, and the `custom` validator that would
 * express this lives in `convex-helpers`, which this repo does not depend on.
 * Adding a dependency for one column would cost more than it buys, so the shape
 * is enforced instead by `assertPrincipal` (see `convex/credits/principal.ts`),
 * which every handler accepting a principal calls before touching the database.
 *
 * The column staying a plain string also keeps `principalId` usable as an index
 * field, which a custom validator would complicate.
 */
export const creditPrincipalValidator = v.string();

export const creditOperationValidator = union(CREDIT_OPERATIONS);
export const creditPlanStatusValidator = union(PLAN_STATUSES);
export const creditPeriodSourceValidator = union(PERIOD_SOURCES);
export const creditSpendRefusalValidator = union(SPEND_REFUSALS);
export const creditActiveSubscriptionStatusValidator = union(
  ACTIVE_SUBSCRIPTION_STATUSES,
);
export const creditLedgerKindValidator = union(CREDIT_LEDGER_KINDS);
