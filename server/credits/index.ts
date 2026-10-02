/**
 * Credit and quota engine — public surface.
 *
 * Pure by construction: no I/O, no clock, no network, no Convex import. The
 * persistence layer in `convex/credits/` imports from here; the reverse does
 * not hold, which is what lets the engine be tested against a fixed clock.
 */

export {
  ACTIVE_SUBSCRIPTION_STATUSES,
  CREDIT_OPERATIONS,
  PERIOD_SOURCES,
  PLAN_STATUSES,
  SPEND_REFUSALS,
  type ActiveSubscriptionStatus,
  type BillingPeriod,
  type CreditOperation,
  type OperationCost,
  type PeriodSource,
  type PlanPricing,
  type PlanStatus,
  type SpendDecision,
  type SpendRefusal,
  type Wallet,
} from "./types";

export {
  BillingPeriodError,
  containsInstant,
  calendarPeriodUtc,
  isActiveSubscriptionStatus,
  MAX_PROVIDER_PERIOD_MS,
  operatorPeriod,
  PERIOD_SOURCE_CALENDAR_UTC,
  PERIOD_SOURCE_OPERATOR,
  PERIOD_SOURCE_PROVIDER,
  providerPeriod,
  resolveBillingPeriod,
  type SubscriptionPeriodInput,
} from "./period";

export {
  isCreditOperation,
  MAX_OPERATION_COST,
  OperationCostError,
  resolveOperationCost,
  SEEDED_OPERATION_COSTS,
  validateOperationCost,
} from "./costs";

export {
  applySpend,
  decideSpend,
  isInternalMisconfiguration,
  isUnlimitedGrant,
  refundSpend,
  remainingCredits,
  UNLIMITED,
  validateWallet,
  WalletError,
  type SpendContext,
} from "./wallet";
