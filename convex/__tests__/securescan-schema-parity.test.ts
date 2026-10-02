import { describe, expect, test } from "vitest";
import {
  FindingState,
  Severity,
  Confidence,
  TestStatus,
  EvidenceType,
  AssessmentState,
} from "../../server/securescan/types";
import {
  ROLES as ENGINE_ROLES,
  ACTIONS,
  can,
} from "../../server/securescan/identity";
import {
  securescanRoleValidator,
  securescanFindingStateValidator,
  securescanTestStatusValidator,
  securescanSeverityValidator,
  securescanConfidenceValidator,
  securescanEvidenceTypeValidator,
  securescanEnvironmentValidator,
  securescanTargetKindValidator,
  securescanAssessmentStateValidator,
  ROLES,
  FINDING_STATES,
  SEVERITIES,
  ASSESSMENT_STATES,
  RUN_STATES,
} from "../securescan/validators";

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
    const literal = (value as { type?: string; value?: unknown });
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
  // mean the API accepts a state the engine has no rules for.
  expect(stored, `${name} stored/allowed mismatch`).toEqual(engine);
}

describe("SecureScan schema parity with the engine", () => {
  test("roles", () => {
    expectParity("role", securescanRoleValidator, ENGINE_ROLES);
  });

  test("finding states", () => {
    // The engine's union is restated explicitly rather than derived, which is
    // exactly the drift this test exists to catch.
    const engineStates: readonly FindingState[] = [
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
    ];
    expectParity("finding state", securescanFindingStateValidator, engineStates);
  });

  test("test statuses", () => {
    const engineStatuses: readonly TestStatus[] = [
      "PASS",
      "FAIL",
      "INCONCLUSIVE",
      "NOT_TESTED",
      "SKIPPED_OUT_OF_SCOPE",
    ];
    expectParity("test status", securescanTestStatusValidator, engineStatuses);
  });

  test("severities", () => {
    const engineSeverities: readonly Severity[] = [
      "NONE",
      "LOW",
      "MEDIUM",
      "HIGH",
      "CRITICAL",
    ];
    expectParity("severity", securescanSeverityValidator, engineSeverities);
  });

  test("confidences", () => {
    const engineConfidences: readonly Confidence[] = ["LOW", "MEDIUM", "HIGH"];
    expectParity("confidence", securescanConfidenceValidator, engineConfidences);
  });

  test("evidence types", () => {
    const engineEvidence: readonly EvidenceType[] = [
      "CONFIGURATION",
      "SOURCE_EXTRACTION",
      "HTTP_REQUEST",
      "HTTP_RESPONSE",
      "DEPENDENCY_ADVISORY",
      "CONTRACT_DECLARATION",
      "ATTACK_SURFACE",
      "CALCULATION",
      "ARTIFACT_HASH",
    ];
    expectParity("evidence type", securescanEvidenceTypeValidator, engineEvidence);
  });

  test("environments", () => {
    expectParity("environment", securescanEnvironmentValidator, [
      "LOCAL",
      "SELF_HOSTED",
      "STAGING",
      "PRODUCTION",
    ]);
  });

  test("target kinds", () => {
    expectParity("target kind", securescanTargetKindValidator, [
      "REPOSITORY",
      "DEPLOYED_APPLICATION",
      "API",
    ]);
  });

  test("assessment states", () => {
    expectParity("assessment state", securescanAssessmentStateValidator, [
      "DRAFT",
      "READY",
      "RUNNING",
      "PAUSED",
      "COMPLETED",
      "FAILED",
      "CANCELLED",
    ]);
  });
});

describe("read-model state arrays", () => {
  /**
   * The console's severity and state buckets are built from the exported arrays
   * rather than from a hand-typed list, which is what stops a bucket existing for
   * a state the engine can never produce. This asserts the arrays themselves
   * still match the engine, so a read model cannot drift by adding a state here
   * and nothing noticing.
   */
  const engineFindingStates: readonly FindingState[] = [
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
  ];
  const engineSeverities: readonly Severity[] = ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
  const engineAssessmentStates: readonly AssessmentState[] = [
    "DRAFT",
    "READY",
    "RUNNING",
    "PAUSED",
    "COMPLETED",
    "FAILED",
    "CANCELLED",
  ];

  test("finding states match the engine", () => {
    expect([...FINDING_STATES].sort()).toEqual([...engineFindingStates].sort());
  });

  test("severities match the engine", () => {
    expect([...SEVERITIES].sort()).toEqual([...engineSeverities].sort());
  });

  test("assessment states match the engine", () => {
    expect([...ASSESSMENT_STATES].sort()).toEqual([...engineAssessmentStates].sort());
  });

  test("run states are a subset of nothing, and match the run validator", () => {
    // A run cannot be READY or PAUSED even though an assessment can, so this
    // pins the distinction rather than assuming the two lists align.
    expect([...RUN_STATES].sort()).toEqual(["CANCELLED", "COMPLETED", "FAILED", "RUNNING"]);
    for (const state of RUN_STATES) {
      expect(ASSESSMENT_STATES).toContain(state);
    }
  });

  test("roles match the engine", () => {
    expect([...ROLES].sort()).toEqual([...ENGINE_ROLES].sort());
  });
});

describe("permission matrix sanity", () => {
  test("only the admin role has the full matrix", () => {
    // An admin having every permission is the intended design, so this asserts
    // the other two do not. If a new action is added to ADMIN, the analyst and
    // viewer rows below are what must be reconsidered.
    const full = ACTIONS.filter((action) => can("ADMIN", action));
    expect(full.length).toBe(ACTIONS.length);

    for (const role of ["SECURITY_ANALYST", "VIEWER"] as const) {
      const allowed = ACTIONS.filter((action) => can(role, action));
      expect(allowed.length, `${role} can perform everything`).toBeLessThan(
        ACTIONS.length,
      );
    }
  });

  test("a viewer cannot mutate anything", () => {
    for (const action of ACTIONS) {
      const mutating = !action.endsWith(":read") && action !== "user:session";
      if (mutating) {
        expect(can("VIEWER", action), `VIEWER can ${action}`).toBe(false);
      }
    }
  });
});
