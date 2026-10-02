import { v } from "convex/values";

/**
 * Persistence validators for WM SecureScan.
 *
 * These restate the engine's unions rather than importing them, because a Convex
 * validator must be a statically analysable literal and a TypeScript type alias
 * erases at build time. `convex/__tests__/securescan-schema-parity.test.ts`
 * fails if a union here drifts from the one in `server/securescan/types.ts`.
 *
 * Each union is built from an exported `as const` array so the same list can also
 * drive read models. A third hand-typed copy of a state list is how a console
 * ends up reporting a `QUEUED` bucket that can never be non-zero, and a cast
 * hides that from `tsc`; deriving the buckets from these arrays means the parity
 * test protects every consumer, not just the validators.
 */

export const ROLES = ["ADMIN", "SECURITY_ANALYST", "VIEWER"] as const;

export const FINDING_STATES = [
  "CANDIDATE",
  "VALIDATING",
  "VALIDATED",
  "REMEDIATION",
  "RETEST_REQUIRED",
  "VERIFIED",
  "FALSE_POSITIVE",
  "ACCEPTED_RISK",
  "INCONCLUSIVE",
  "REGRESSION",
  "INFORMATIONAL",
  "FIXED",
] as const;

export const SEVERITIES = ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"] as const;

export const ASSESSMENT_STATES = [
  "DRAFT",
  "READY",
  "RUNNING",
  "PAUSED",
  "COMPLETED",
  "FAILED",
  "CANCELLED",
] as const;

export const RUN_STATES = ["RUNNING", "COMPLETED", "FAILED", "CANCELLED"] as const;

function union<const T extends readonly string[]>(values: T) {
  return v.union(...values.map((value) => v.literal(value)));
}

export const securescanRoleValidator = union(ROLES);

export const securescanFindingStateValidator = union(FINDING_STATES);

/**
 * `SKIPPED_OUT_OF_SCOPE` is stored as its own status rather than dropped, so a
 * report can state what was deliberately not attempted and why.
 */
export const securescanTestStatusValidator = v.union(
  v.literal("PASS"),
  v.literal("FAIL"),
  v.literal("INCONCLUSIVE"),
  v.literal("NOT_TESTED"),
  v.literal("SKIPPED_OUT_OF_SCOPE"),
);

export const securescanConfidenceValidator = v.union(
  v.literal("LOW"),
  v.literal("MEDIUM"),
  v.literal("HIGH"),
);

export const securescanSeverityValidator = union(SEVERITIES);

export const securescanAssessmentStateValidator = union(ASSESSMENT_STATES);

export const securescanRunStateValidator = union(RUN_STATES);

export const securescanTargetStateValidator = v.union(
  v.literal("ACTIVE"),
  v.literal("PAUSED"),
  v.literal("ARCHIVED"),
);

export const securescanTargetKindValidator = v.union(
  v.literal("REPOSITORY"),
  v.literal("DEPLOYED_APPLICATION"),
  v.literal("API"),
);

export const securescanEnvironmentValidator = v.union(
  v.literal("LOCAL"),
  v.literal("SELF_HOSTED"),
  v.literal("STAGING"),
  v.literal("PRODUCTION"),
);

export const securescanEvidenceTypeValidator = v.union(
  v.literal("CONFIGURATION"),
  v.literal("SOURCE_EXTRACTION"),
  v.literal("HTTP_REQUEST"),
  v.literal("HTTP_RESPONSE"),
  v.literal("DEPENDENCY_ADVISORY"),
  v.literal("CONTRACT_DECLARATION"),
  v.literal("ATTACK_SURFACE"),
  v.literal("CALCULATION"),
  v.literal("ARTIFACT_HASH"),
);

export const securescanAuditOutcomeValidator = v.union(
  v.literal("ALLOWED"),
  v.literal("DENIED"),
);

export const securescanFindingEventKindValidator = v.union(
  v.literal("CREATED"),
  v.literal("RE_OBSERVED"),
  v.literal("VALIDATION_STARTED"),
  v.literal("VALIDATED"),
  v.literal("REMEDIATION_STARTED"),
  v.literal("REMEDIATION_RECORDED"),
  v.literal("RETEST_STARTED"),
  v.literal("RETEST_PASSED"),
  v.literal("RETEST_FAILED"),
  v.literal("ACCEPTED_RISK"),
  v.literal("FALSE_POSITIVE"),
  v.literal("INFORMATIONAL"),
  v.literal("SCORED"),
  v.literal("REGRESSION"),
);
