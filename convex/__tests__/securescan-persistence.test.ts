import { convexTest } from "convex-test";
import { describe, expect, test } from "vitest";
import schema from "../schema";
import { api, internal } from "../_generated/api";
import type { AssessmentResult } from "../../server/securescan/types";
import type * as findingsModule from "../securescan/findings";
import type * as assessmentsModule from "../securescan/assessments";

/**
 * The functions a browser client can reach.
 *
 * `api` is filtered to public functions, so a name that appears here is callable
 * by anyone signed in. A name that does not appear here is not reachable from the
 * product, which is how `setRole` and `recordRun` are kept internal.
 */
function publicSecurescanFunctions(): string[] {
  const namespaces: Record<string, object> = (api as unknown as {
    securescan: Record<string, object>;
  }).securescan;
  return Object.entries(namespaces).flatMap(([moduleName, namespace]) =>
    Object.keys(namespace as Record<string, unknown>).map(
      (fn) => `securescan.${moduleName}.${fn}`,
    ),
  );
}

// Compile-time proof that the public modules export nothing privileged.
type _PublicSurface = keyof typeof findingsModule | keyof typeof assessmentsModule;

const modules = import.meta.glob("../**/*.ts");

const ANALYST = { subject: "user-analyst", tokenIdentifier: "clerk|user-analyst" };
const VIEWER = { subject: "user-viewer", tokenIdentifier: "clerk|user-viewer" };
const OTHER_ANALYST = { subject: "user-other", tokenIdentifier: "clerk|user-other" };
const ADMIN = { subject: "user-admin", tokenIdentifier: "clerk|user-admin" };
const NOBODY = { subject: "user-nobody", tokenIdentifier: "clerk|user-nobody" };

const NOW = Date.parse("2026-09-01T00:00:00.000Z");

function t() {
  return convexTest(schema, modules);
}

async function as(t: ReturnType<typeof convexTest>, identity: { subject: string; tokenIdentifier: string }) {
  return t.withIdentity(identity);
}

async function grantRole(
  t: ReturnType<typeof convexTest>,
  userId: string,
  role: "ADMIN" | "SECURITY_ANALYST" | "VIEWER",
) {
  await t.mutation(internal.securescan.findings.setRole, { userId, role });
}

const CREATE_ARGS = {
  name: "Baseline assessment",
  targetName: "worldmonitor",
  targetKind: "REPOSITORY" as const,
  repositoryUrl: "https://github.com/koala73/worldmonitor",
  allowlistedPaths: ["api/"],
  maxRuntimeRequests: 0,
};

async function createAssessment(
  t: ReturnType<typeof convexTest>,
  identity: { subject: string; tokenIdentifier: string },
  args = CREATE_ARGS,
) {
  const client = await as(t, identity);
  return client.mutation(internal.securescan.assessments.create, args);
}

describe("assessment creation authorization", () => {
  test("an unauthenticated caller cannot create an assessment", async () => {
    const t0 = t();
    await expect(
      t0.mutation(internal.securescan.assessments.create, CREATE_ARGS),
    ).rejects.toThrow(/AUTH_REQUIRED/);
  });

  test("a user with no role row is refused at the door", async () => {
    // An existing World Monitor account that has never been granted SecureScan
    // access cannot create a scan, and cannot read one either.
    const t0 = t();
    const client = await as(t0, NOBODY);
    await expect(
      client.mutation(internal.securescan.assessments.create, CREATE_ARGS),
    ).rejects.toThrow(/SECURESCAN_NO_MEMBERSHIP/);
  });

  test("a viewer cannot create an assessment", async () => {
    const t0 = t();
    await grantRole(t0, VIEWER.subject, "VIEWER");
    await expect(createAssessment(t0, VIEWER)).rejects.toThrow(/ROLE_FORBIDDEN/);
  });

  test("an analyst can create an assessment", async () => {
    const t0 = t();
    await grantRole(t0, ANALYST.subject, "SECURITY_ANALYST");
    const created = await createAssessment(t0, ANALYST);
    expect(created.assessmentId).toMatch(/^ss_assessment_/);
    expect(created.targetId).toMatch(/^ss_target_/);
  });

  test("creation requires a locator appropriate to the target kind", async () => {
    const t0 = t();
    await grantRole(t0, ANALYST.subject, "SECURITY_ANALYST");
    await expect(
      createAssessment(t0, ANALYST, {
        ...CREATE_ARGS,
        repositoryUrl: undefined,
      }),
    ).rejects.toThrow(/SECURESCAN_TARGET_REQUIRES_REPOSITORY_URL/);

    await expect(
      createAssessment(t0, ANALYST, {
        ...CREATE_ARGS,
        targetKind: "API",
        repositoryUrl: undefined,
        baseUrl: undefined,
      }),
    ).rejects.toThrow(/SECURESCAN_TARGET_REQUIRES_BASE_URL/);
  });

  test("a negative request budget is rejected", async () => {
    const t0 = t();
    await grantRole(t0, ANALYST.subject, "SECURITY_ANALYST");
    await expect(
      createAssessment(t0, ANALYST, { ...CREATE_ARGS, maxRuntimeRequests: -1 }),
    ).rejects.toThrow(/SECURESCAN_INVALID_REQUEST_BUDGET/);
  });
});

describe("assessment reads are scoped and role-gated", () => {
  test("a viewer can read but sees no assessments it does not own", async () => {
    const t0 = t();
    await grantRole(t0, ANALYST.subject, "SECURITY_ANALYST");
    await grantRole(t0, VIEWER.subject, "VIEWER");
    const { assessmentId } = await createAssessment(t0, ANALYST);

    const client = await as(t0, VIEWER);
    const detail = await client.query(internal.securescan.assessments.get, {
      assessmentId,
    });
    // Reads are workspace-wide by design so an analyst can review a
    // colleague's work; the list view is what is owner-scoped.
    expect(detail.assessment.assessmentId).toBe(assessmentId);
    expect(detail.role).toBe("VIEWER");

    const list = await client.query(internal.securescan.assessments.list, {});
    expect(list.assessments).toEqual([]);
  });

  test("an account with no grant cannot read an assessment at all", async () => {
    // SecureScan access is granted, not inherited from having a World Monitor
    // account. The previous default of VIEWER meant any authenticated user who
    // had never been authorized could read every assessment, target, evidence
    // record and finding in the deployment. Reads are workspace-wide within the
    // team, so the membership row is the only thing that distinguishes a
    // colleague from a stranger, and a missing row has to mean no access.
    const t0 = t();
    await grantRole(t0, ANALYST.subject, "SECURITY_ANALYST");
    const { assessmentId } = await createAssessment(t0, ANALYST);
    const client = await as(t0, NOBODY);

    await expect(
      client.query(internal.securescan.assessments.get, { assessmentId }),
    ).rejects.toThrow(/SECURESCAN_NO_MEMBERSHIP/);
    await expect(
      client.query(internal.securescan.assessments.list, {}),
    ).rejects.toThrow(/SECURESCAN_NO_MEMBERSHIP/);
    await expect(
      client.query(internal.securescan.findings.listByAssessment, { assessmentId }),
    ).rejects.toThrow(/SECURESCAN_NO_MEMBERSHIP/);
    // The error code is the signal a UI turns into a request-access prompt, so
    // it must be stable rather than a generic forbidden.
    await expect(
      client.query(internal.securescan.audit.list, { assessmentId }),
    ).rejects.toThrow(/SECURESCAN_NO_MEMBERSHIP/);
  });

  test("a granted viewer can read a colleague's assessment", async () => {
    // Membership is what opens the door; the read is still workspace-wide.
    const t0 = t();
    await grantRole(t0, ANALYST.subject, "SECURITY_ANALYST");
    await grantRole(t0, VIEWER.subject, "VIEWER");
    const { assessmentId } = await createAssessment(t0, ANALYST);
    const client = await as(t0, VIEWER);
    const detail = await client.query(internal.securescan.assessments.get, { assessmentId });
    expect(detail.assessment.ownerUserId).toBe(ANALYST.subject);
  });

  test("an unknown assessment is a not-found, not an empty result", async () => {
    const t0 = t();
    await grantRole(t0, ANALYST.subject, "SECURITY_ANALYST");
    const client = await as(t0, ANALYST);
    await expect(
      client.query(internal.securescan.assessments.get, { assessmentId: "ss_assessment_nope" }),
    ).rejects.toThrow(/SECURESCAN_ASSESSMENT_NOT_FOUND/);
  });
});

/** A minimal but structurally valid engine result. */
/**
 * An assessment whose single finding arrives unscored, exactly as the engine
 * produces it: a failing static check becomes a CANDIDATE with `NONE` severity
 * and a "not yet scored" rationale. This is the state every real finding starts
 * in, so the scoring and validation rules are tested against it rather than
 * against a fixture that already has a severity.
 */
async function seedWithUnscoredFinding() {
  const t0 = t();
  await grantRole(t0, ANALYST.subject, "SECURITY_ANALYST");
  await grantRole(t0, VIEWER.subject, "VIEWER");
  const { assessmentId } = await createAssessment(t0, ANALYST);
  const base = engineResult(assessmentId, ANALYST.subject);
  const result: AssessmentResult = {
    ...base,
    findings: [
      {
        ...base.findings[0]!,
        id: "FND-UNSCORED",
        severity: "NONE",
        confidence: "HIGH",
        state: "CANDIDATE",
        risk: {
          ...base.findings[0]!.risk,
          technicalSeverity: "NONE",
          severityRationale: ["Not yet scored."],
        },
      },
    ],
  };
  await t0.mutation(internal.securescan.assessments.recordRun, {
    ownerUserId: ANALYST.subject,
    result: JSON.stringify(result),
  });
  return { t0, assessmentId };
}

async function auditEntries(t0: ReturnType<typeof convexTest>, assessmentId: string) {
  return t0.run(async (ctx) =>
    ctx.db
      .query("securescanAuditLog")
      .withIndex("by_assessment_seq", (q) => q.eq("assessmentId", assessmentId))
      .collect(),
  );
}

function engineResult(assessmentId: string, ownerUserId: string): AssessmentResult {
  return {
    assessment: {
      id: assessmentId,
      name: "Baseline assessment",
      state: "COMPLETED",
      scope: {
        targetId: "ss_target_x",
        targetKind: "REPOSITORY",
        allowedHosts: [],
        allowedPaths: ["api/"],
        maxRequests: 0,
        intensity: "PASSIVE",
        reason: "Baseline",
      },
      moduleNames: ["security-headers"],
      createdBy: ownerUserId,
      createdAt: new Date(NOW).toISOString(),
      startedAt: new Date(NOW).toISOString(),
      finishedAt: new Date(NOW + 1000).toISOString(),
      authorizationNote: "Baseline",
    },
    run: {
      id: "RUN-1",
      assessmentId,
      startedAt: new Date(NOW).toISOString(),
      finishedAt: new Date(NOW + 1000).toISOString(),
      progress: [
        {
          module: "security-headers",
          status: "COMPLETE",
          testsRun: 1,
          startedAt: new Date(NOW).toISOString(),
          finishedAt: new Date(NOW + 500).toISOString(),
          error: null,
        },
      ],
      requestsIssued: 0,
      errorCount: 0,
      warningCount: 0,
      durationMs: 1000,
    },
    architecture: { nodes: [], edges: [], boundaries: [] },
    surface: [],
    tests: [
      {
        testId: "TEST-1",
        assessmentId,
        runId: "RUN-1",
        module: "security-headers",
        category: "SECURITY_HEADERS",
        component: "Edge",
        control: "CSP",
        target: "vercel.json",
        boundary: null,
        expected: "CSP present",
        observed: "CSP missing",
        status: "FAIL",
        confidence: "HIGH",
        evidenceIds: ["EV-1"],
        notes: [],
        requiresCapability: "NONE",
      },
      {
        testId: "TEST-2",
        assessmentId,
        runId: "RUN-1",
        module: "cors",
        category: "CORS",
        component: "Edge",
        control: "CORS",
        target: "api/_cors.js",
        boundary: null,
        expected: "no wildcard with credentials",
        observed: "ok",
        status: "PASS",
        confidence: "HIGH",
        evidenceIds: [],
        notes: [],
        requiresCapability: "NONE",
      },
    ],
    controls: [],
    findings: [
      {
        id: "FND-1",
        title: "CSP absent on OAuth callback",
        category: "SECURITY_HEADERS",
        component: "Edge",
        node: "vercel-edge",
        boundary: null,
        control: "CSP",
        affectedEndpoints: ["/api/slack/oauth/callback"],
        description: "d",
        rootCause: "rc",
        rootCauseId: "RC-1",
        severity: "MEDIUM",
        confidence: "HIGH",
        risk: {
          technicalSeverity: "MEDIUM",
          businessImpact: "n/a",
          cvss: {
            version: null,
            vector: null,
            baseScore: null,
            severity: null,
            impact: null,
            exploitability: null,
            metricRationale: {},
            confidence: 0,
            environmentalContext: null,
          },
          confidence: "HIGH",
          severityRationale: ["Impact: HIGH"],
          severityMethodologyVersion: "1.0.0",
        },
        historicalStatus: "CURRENTLY_OBSERVED",
        state: "CANDIDATE",
        evidenceIds: ["EV-1"],
        reproduction: [],
        controlledPoc: [],
        businessImpact: "n/a",
        remediation: null,
        retestResult: null,
        regressionTestId: null,
        references: [],
        createdAt: new Date(NOW).toISOString(),
        updatedAt: new Date(NOW).toISOString(),
        fingerprint: "fp-1",
      },
    ],
    evidence: [
      {
        evidenceId: "EV-1",
        findingId: null,
        testId: "TEST-1",
        assessmentId,
        collectedAt: new Date(NOW).toISOString(),
        type: "CONFIGURATION",
        description: "CSP for callback",
        payload: {
          kind: "config-value",
          path: "vercel.json",
          pointer: "headers",
          value: "default-src 'none'",
        },
        sha256: "a".repeat(64),
        producedBy: "wm-securescan:vercel.json",
        targetEnvironment: "PRODUCTION",
        sourceLocation: "vercel.json#headers",
      },
    ],
    coverage: [],
    dependencies: [],
    regressionTests: [],
    remediations: [],
    retests: [],
    notTested: [{ module: "xss-content", reason: "no capability" }],
    toolVersion: "1.0.0",
    targetRevision: "abc123",
  } as unknown as AssessmentResult;
}

describe("recording an engine run", () => {
  test("a recorded run persists tests, evidence and candidates", async () => {
    const t0 = t();
    await grantRole(t0, ANALYST.subject, "SECURITY_ANALYST");
    const { assessmentId } = await createAssessment(t0, ANALYST);

    const result = engineResult(assessmentId, ANALYST.subject);
    const recorded = await t0.mutation(internal.securescan.assessments.recordRun, {
      ownerUserId: ANALYST.subject,
      result: JSON.stringify(result),
    });

    expect(recorded.counts).toEqual({
      pass: 1,
      fail: 1,
      inconclusive: 0,
      notTested: 0,
      skippedOutOfScope: 0,
    });
    expect(recorded.findings).toBe(1);

    const client = await as(t0, ANALYST);
    const detail = await client.query(internal.securescan.assessments.get, {
      assessmentId,
    });
    expect(detail.assessment.state).toBe("COMPLETED");
    expect(detail.assessment.latestRunId).toBe("RUN-1");
    expect(detail.testCounts).toMatchObject({ total: 2, pass: 1, fail: 1 });
    expect(detail.findings).toHaveLength(1);
  });

  test("a finding with no boundary round-trips as an explicit none", async () => {
    const t0 = t();
    await grantRole(t0, ANALYST.subject, "SECURITY_ANALYST");
    const { assessmentId } = await createAssessment(t0, ANALYST);
    await t0.mutation(internal.securescan.assessments.recordRun, {
      ownerUserId: ANALYST.subject,
      result: JSON.stringify(engineResult(assessmentId, ANALYST.subject)),
    });

    const stored = await t0.run(async (ctx) =>
      ctx.db
        .query("securescanFindings")
        .withIndex("by_findingId", (q) => q.eq("findingId", "FND-1"))
        .unique(),
    );
    expect(stored?.boundary).toBe("none");
  });

  test("a run for an assessment the caller does not own is refused", async () => {
    // Prevents one analyst from writing results into another's assessment,
    // which would let them manufacture a clean result set.
    const t0 = t();
    await grantRole(t0, ANALYST.subject, "SECURITY_ANALYST");
    await grantRole(t0, OTHER_ANALYST.subject, "SECURITY_ANALYST");
    const { assessmentId } = await createAssessment(t0, ANALYST);

    await expect(
      t0.mutation(internal.securescan.assessments.recordRun, {
        ownerUserId: OTHER_ANALYST.subject,
        result: JSON.stringify(engineResult(assessmentId, ANALYST.subject)),
      }),
    ).rejects.toThrow(/SECURESCAN_OWNER_MISMATCH/);
  });

  test("an unfinished run is stored as incomplete with a reason", async () => {
    const t0 = t();
    await grantRole(t0, ANALYST.subject, "SECURITY_ANALYST");
    const { assessmentId } = await createAssessment(t0, ANALYST);
    const result = engineResult(assessmentId, ANALYST.subject);
    (result.run as { finishedAt: string | null }).finishedAt = null;

    await t0.mutation(internal.securescan.assessments.recordRun, {
      ownerUserId: ANALYST.subject,
      result: JSON.stringify(result),
    });

    const client = await as(t0, ANALYST);
    const detail = await client.query(internal.securescan.assessments.get, {
      assessmentId,
    });
    // Partial counts must never read as a finished assessment.
    expect(detail.assessment.state).toBe("RUNNING");
    expect(detail.assessment.abortReason).toMatch(/did not finish/);
    expect(detail.runs[0]?.abortReason).toMatch(/partial/);
  });
});

describe("finding lifecycle", () => {
  async function seed() {
    const t0 = t();
    await grantRole(t0, ANALYST.subject, "SECURITY_ANALYST");
    await grantRole(t0, OTHER_ANALYST.subject, "SECURITY_ANALYST");
    await grantRole(t0, VIEWER.subject, "VIEWER");
    const { assessmentId } = await createAssessment(t0, ANALYST);
    await t0.mutation(internal.securescan.assessments.recordRun, {
      ownerUserId: ANALYST.subject,
      result: JSON.stringify(engineResult(assessmentId, ANALYST.subject)),
    });
    return { t0, assessmentId };
  }

  test("a viewer cannot transition a finding", async () => {
    const { t0 } = await seed();
    const client = await as(t0, VIEWER);
    const res = await client.mutation(internal.securescan.findings.transition, {
      findingId: "FND-1",
      to: "VALIDATING",
      reason: "looking into it",
    });
    // Returned rather than thrown so the denial survives the transaction.
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.code).toBe("ROLE_FORBIDDEN");
  });

  test("an analyst can move a candidate into validation with a recorded reason", async () => {
    const { t0 } = await seed();
    const client = await as(t0, ANALYST);
    const res = await client.mutation(internal.securescan.findings.transition, {
      findingId: "FND-1",
      to: "VALIDATING",
      reason: "reproducing against staging",
    });
    expect(res.ok).toBe(true);
    if (res.ok) expect(res.state).toBe("VALIDATING");

    const events = await t0.run(async (ctx) =>
      ctx.db
        .query("securescanFindingEvents")
        .withIndex("by_findingId", (q) => q.eq("findingId", "FND-1"))
        .collect(),
    );
    // CREATED plus the transition, both attributed.
    expect(events).toHaveLength(2);
    expect(events.map((e) => e.kind).sort()).toEqual(["CREATED", "VALIDATION_STARTED"]);
  });

  test("an illegal transition is refused even with permission", async () => {
    const { t0 } = await seed();
    const client = await as(t0, ANALYST);
    // CANDIDATE cannot jump straight to FIXED.
    const res = await client.mutation(internal.securescan.findings.transition, {
      findingId: "FND-1",
      to: "FIXED",
      reason: "trust me",
    });
    expect(res.ok).toBe(false);
    if (!res.ok) {
      expect(res.code).toBe("INVALID_TRANSITION");
      // The refusal must say why, so the UI does not have to invent a message.
      expect(res.reason).toContain("CANDIDATE");
      expect(res.reason).toContain("FIXED");
    }
  });

  test("a dismissal with no reason is refused", async () => {
    // The engine requires justification only for decisions that discard a
    // finding, not for routine forward progress. This is the case that matters:
    // a false positive with no stated cause silently removes work from the queue.
    const { t0 } = await seed();
    const client = await as(t0, ANALYST);
    const res = await client.mutation(internal.securescan.findings.transition, {
      findingId: "FND-1",
      to: "FALSE_POSITIVE",
      reason: "   ",
    });
    expect(res.ok).toBe(false);
    if (!res.ok) {
      expect(res.code).toBe("SECURESCAN_TRIAGE_REASON_INVALID");
      expect(res.reason).toMatch(/reason/i);
    }
  });

  test("a false-positive dismissal requires a stated cause", async () => {
    const { t0 } = await seed();
    const client = await as(t0, ANALYST);
    const res = await client.mutation(internal.securescan.findings.transition, {
      findingId: "FND-1",
      to: "FALSE_POSITIVE",
      reason: "the route intentionally returns no HTML and is not browser-navigable",
    });
    expect(res.ok).toBe(true);
  });

  test("an over-long reason is refused", async () => {
    const { t0 } = await seed();
    const client = await as(t0, ANALYST);
    const res = await client.mutation(internal.securescan.findings.transition, {
      findingId: "FND-1",
      to: "FALSE_POSITIVE",
      reason: "x".repeat(2500),
    });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.code).toBe("SECURESCAN_TRIAGE_REASON_INVALID");
  });

  test("another analyst cannot remediate a finding they do not own", async () => {
    const { t0 } = await seed();
    const client = await as(t0, OTHER_ANALYST);
    const res = await client.mutation(internal.securescan.findings.recordRemediation, {
      findingId: "FND-1",
      summary: "edited the config",
    });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.code).toBe("NOT_RESOURCE_OWNER");
  });

  describe("risk scoring is the analyst's judgement, recorded with its reasoning", () => {
  // A candidate arrives unscored on purpose: a static check cannot determine
  // impact, exposure, privileges or data class, and inventing them would produce
  // a confident-looking band with nothing behind it. These tests pin the rule
  // that the only source of those judgements is a person, and that their
  // reasoning is stored alongside the band.

  const INPUT = {
    exposure: "PUBLIC_INTERNET",
    privilegesRequired: "NONE",
    userInteraction: "REQUIRED",
    dataClass: "INTERNAL",
    boundaryCrossed: true,
    confidentiality: "LOW",
    integrity: "LOW",
    availability: "NONE",
    runtimeValidated: false,
    evidenceStrength: "CONFIGURATION",
    correlatedSources: 1,
  } as const;

  test("a score is stored with the engine's reasoning and the analyst's justification", async () => {
    const { t0 } = await seedWithUnscoredFinding();
    const client = await as(t0, ANALYST);
    const res = await client.mutation(internal.securescan.findings.scoreRisk, {
      findingId: "FND-UNSCORED",
      ...INPUT,
      justification: "Unauthenticated route returning markup; impact is limited to a phishing-flavoured page.",
    });

    expect(res.ok).toBe(true);
    if (!res.ok) return;
    // LOW, not MEDIUM: impact LOW gives a LOW base band, public exposure raises
    // it one step, and required user interaction lowers it again. The point of
    // asserting the exact band is that the methodology is versioned — if a rule
    // changes, this test should say so rather than the report quietly shifting.
    expect(res.severity).toBe("LOW");
    expect(res.severity).not.toBe("NONE");
    // The band must be accompanied by the steps that produced it, so a reader
    // can disagree with the inputs rather than with an opaque number.
    expect(res.severityRationale.join(" ")).toContain("Impact:");
    expect(res.severityRationale.join(" ")).toContain("User interaction:");
    expect(res.severityRationale.join(" ")).toContain("Analyst justification:");
    expect(res.severityMethodologyVersion).toBe("1.0.0");

    const stored = await t0.run(async (ctx) =>
      ctx.db
        .query("securescanFindings")
        .withIndex("by_findingId", (q) => q.eq("findingId", "FND-UNSCORED"))
        .unique(),
    );
    expect(stored?.severity).toBe("LOW");
    expect(stored?.risk).toContain("Analyst justification");
    expect(stored?.updatedAt).toBeGreaterThan(0);
  });

  test("a score with no justification is refused and audited", async () => {
    const { t0, assessmentId } = await seedWithUnscoredFinding();
    const client = await as(t0, ANALYST);
    const res = await client.mutation(internal.securescan.findings.scoreRisk, {
      findingId: "FND-UNSCORED",
      ...INPUT,
      justification: "high",
    });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.code).toBe("SECURESCAN_SCORE_JUSTIFICATION_REQUIRED");

    const stored = await t0.run(async (ctx) =>
      ctx.db
        .query("securescanFindings")
        .withIndex("by_findingId", (q) => q.eq("findingId", "FND-UNSCORED"))
        .unique(),
    );
    expect(stored?.severity).toBe("NONE");
    const entries = await auditEntries(t0, assessmentId);
    expect(
      entries.some((e) => e.action === "finding:score" && e.outcome === "DENIED"),
    ).toBe(true);
  });

  test("an unscored candidate cannot be validated", async () => {
    // This is the rule that stops a static FAIL being reported as a confirmed
    // weakness. VALIDATED means "a person confirmed this is real", and a person
    // confirming it has to say what it would cost if exploited.
    const { t0 } = await seedWithUnscoredFinding();
    const client = await as(t0, ANALYST);
    await client.mutation(internal.securescan.findings.transition, {
      findingId: "FND-UNSCORED",
      to: "VALIDATING",
      reason: "reading the deployed callback response headers",
    });
    const res = await client.mutation(internal.securescan.findings.transition, {
      findingId: "FND-UNSCORED",
      to: "VALIDATED",
      reason: "confirmed base-uri is absent on the deployed revision",
    });

    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.code).toBe("SECURESCAN_SEVERITY_NOT_SCORED");

    const stored = await t0.run(async (ctx) =>
      ctx.db
        .query("securescanFindings")
        .withIndex("by_findingId", (q) => q.eq("findingId", "FND-UNSCORED"))
        .unique(),
    );
    expect(stored?.state).toBe("VALIDATING");
  });

  test("scoring then validating succeeds, and the label is not VERIFIED", async () => {
    const { t0 } = await seedWithUnscoredFinding();
    const client = await as(t0, ANALYST);
    await client.mutation(internal.securescan.findings.scoreRisk, {
      findingId: "FND-UNSCORED",
      ...INPUT,
      justification: "Unauthenticated route returning markup; impact limited to injected content.",
    });
    await client.mutation(internal.securescan.findings.transition, {
      findingId: "FND-UNSCORED",
      to: "VALIDATING",
      reason: "reading the deployed callback response headers",
    });
    const res = await client.mutation(internal.securescan.findings.transition, {
      findingId: "FND-UNSCORED",
      to: "VALIDATED",
      reason: "confirmed base-uri is absent on the deployed revision",
    });
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.state).toBe("VALIDATED");
      // Validation is not verification. Showing a human-validated candidate with
      // the same word as a retest-passed fix would misrepresent both.
      expect(res.stateLabel).toBe("VALIDATED");
    }
  });

  test("a closed finding cannot be re-scored", async () => {
    // Otherwise a dismissed finding's severity could be rewritten after the
    // fact and the historical report would disagree with the record.
    const { t0 } = await seed();
    const client = await as(t0, ANALYST);
    await client.mutation(internal.securescan.findings.transition, {
      findingId: "FND-1",
      to: "FALSE_POSITIVE",
      reason: "the callback path is served by a route that always returns JSON, verified twice",
    });
    const res = await client.mutation(internal.securescan.findings.scoreRisk, {
      findingId: "FND-1",
      ...INPUT,
      justification: "attempting to rewrite the recorded severity after closure",
    });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.code).toBe("SECURESCAN_FINDING_CLOSED");

    const stored = await t0.run(async (ctx) =>
      ctx.db
        .query("securescanFindings")
        .withIndex("by_findingId", (q) => q.eq("findingId", "FND-1"))
        .unique(),
    );
    expect(stored?.severity).toBe("MEDIUM");
  });

  test("a viewer cannot score a finding", async () => {
    const { t0 } = await seedWithUnscoredFinding();
    const client = await as(t0, VIEWER);
    const res = await client.mutation(internal.securescan.findings.scoreRisk, {
      findingId: "FND-UNSCORED",
      ...INPUT,
      justification: "a viewer attempting to assign a severity to a finding",
    });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.code).toBe("ROLE_FORBIDDEN");
  });
});

test("a candidate that was never validated cannot be described as under remediation", async () => {
    // The engine's transition table sends a candidate through validation before
    // it can be remediated, so a fix is a conclusion the evidence supports.
    // `recordRemediation` used to patch any state straight to REMEDIATION, which
    // made the table advisory on that path: this test is what makes the claim
    // true rather than merely intended.
    const { t0 } = await seed();
    const client = await as(t0, ANALYST);
    const res = await client.mutation(internal.securescan.findings.recordRemediation, {
      findingId: "FND-1",
      summary: "claim the fix landed without validating anything",
    });

    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.code).toBe("INVALID_TRANSITION");

    const stored = await t0.run(async (ctx) =>
      ctx.db
        .query("securescanFindings")
        .withIndex("by_findingId", (q) => q.eq("findingId", "FND-1"))
        .unique(),
    );
    expect(stored?.state).toBe("CANDIDATE");
    expect(stored?.remediationSummary).toBeUndefined();

    const events = await t0.run(async (ctx) =>
      ctx.db
        .query("securescanFindingEvents")
        .withIndex("by_findingId", (q) => q.eq("findingId", "FND-1"))
        .collect(),
    );
    expect(events.some((event) => event.kind === "REMEDIATION_RECORDED")).toBe(false);
  });

  test("remediation does not mark the finding fixed", async () => {
    // This is the property that stops a fix being declared on the strength of
    // the author's own description of it.
    const { t0 } = await seed();
    const client = await as(t0, ANALYST);
    await advanceToValidated(t0, ANALYST);
    const res = await client.mutation(internal.securescan.findings.recordRemediation, {
      findingId: "FND-1",
      summary: "added base-uri to the callback policy",
    });
    expect(res.ok).toBe(true);
    const stored = await t0.run(async (ctx) =>
      ctx.db
        .query("securescanFindings")
        .withIndex("by_findingId", (q) => q.eq("findingId", "FND-1"))
        .unique(),
    );
    expect(stored?.state).toBe("REMEDIATION");
    expect(stored?.state).not.toBe("FIXED");
  });

  /**
   * Walks a finding to the point where remediation is legal.
   *
   * A candidate is not a validated problem, so the real path runs through
   * VALIDATING and VALIDATED first. The helper reproduces it rather than
   * jumping states, so a future change to the transition table surfaces here
   * instead of quietly making a shortcut legal.
   */
  async function advanceToValidated(
    t0: ReturnType<typeof convexTest>,
    identity: typeof ANALYST,
  ) {
    const client = await as(t0, identity);
    const validating = await client.mutation(internal.securescan.findings.transition, {
      findingId: "FND-1",
      to: "VALIDATING",
      reason: "reproducing the missing base-uri against the deployed config",
    });
    if (!validating.ok) throw new Error(`expected VALIDATING, got ${validating.code}`);
    const validated = await client.mutation(internal.securescan.findings.transition, {
      findingId: "FND-1",
      to: "VALIDATED",
      reason: "base-uri is absent from the callback sandbox policy",
    });
    if (!validated.ok) throw new Error(`expected VALIDATED, got ${validated.code}`);
  }

  /**
   * Walks a finding to the point where a retest verdict is legal.
   *
   * The engine's transition table does not allow REMEDIATION -> REGRESSION
   * directly; a fix must first be queued for retest. That step is part of the
   * lifecycle, not a formality, so the helper reproduces the real path rather
   than jumping states.
   */
  /**
   * The finding's recorded owner, read back from storage.
   *
   * Asserting the verdict is attributed to the engine is only meaningful if the
   * test can name the value it must *not* be, rather than assuming the owner is
   * whoever the fixture happens to use.
   */
  async function findingOwnerUserId(t0: ReturnType<typeof convexTest>) {
    const finding = await t0.run(async (ctx) =>
      ctx.db
        .query("securescanFindings")
        .withIndex("by_findingId", (q) => q.eq("findingId", "FND-1"))
        .unique(),
    );
    return finding?.ownerUserId;
  }

  async function advanceToRetest(
    t0: ReturnType<typeof convexTest>,
    identity: typeof ANALYST,
  ) {
    const client = await as(t0, identity);
    await advanceToValidated(t0, identity);
    const remediated = await client.mutation(internal.securescan.findings.recordRemediation, {
      findingId: "FND-1",
      summary: "added base-uri to the callback policy",
    });
    if (!remediated.ok) throw new Error(`expected REMEDIATION, got ${remediated.code}`);
    const queued = await client.mutation(internal.securescan.findings.transition, {
      findingId: "FND-1",
      to: "RETEST_REQUIRED",
      reason: "change deployed to staging, scheduling a retest",
    });
    expect(queued.ok).toBe(true);
    return client;
  }

  /**
   * Persists the stored test rows a retest verdict is derived from.
   *
   * `recordRetestResult` reads its outcome out of `securescanTests` rather than
   * accepting one, so the way to exercise it is to persist rows and let the
   * mutation decide. `status` defaults to PASS; the interesting cases are the
   * ones that are *not* a clean pass.
   */
  async function seedRetestTests(
    t0: ReturnType<typeof convexTest>,
    args: {
      assessmentId: string;
      runId: string;
      status?:
        | "PASS"
        | "FAIL"
        | "INCONCLUSIVE"
        | "NOT_TESTED"
        | "SKIPPED_OUT_OF_SCOPE";
    },
  ) {
    const status = args.status ?? "PASS";
    await t0.run(async (ctx) => {
      // The run row itself, so a verdict has a real completed execution behind
      // it rather than a set of orphaned test rows.
      const existingRun = await ctx.db
        .query("securescanRuns")
        .withIndex("by_runId", (q) => q.eq("runId", args.runId))
        .unique();
      if (!existingRun) {
        await ctx.db.insert("securescanRuns", {
          assessmentId: args.assessmentId,
          runId: args.runId,
          ownerUserId: ANALYST.subject,
          state: "COMPLETED",
          startedAt: NOW,
          finishedAt: NOW,
          modulesRun: ["security-headers"],
          counts: {
            pass: status === "PASS" ? 1 : 0,
            fail: status === "FAIL" ? 1 : 0,
            inconclusive: 0,
            notTested: 0,
            skippedOutOfScope: 0,
          },
          toolVersion: "test-engine",
        });
      }
      await ctx.db.insert("securescanTests", {
        assessmentId: args.assessmentId,
        runId: args.runId,
        testId: `TEST-${args.runId}`,
        module: "security-headers",
        category: "SECURITY_HEADERS",
        component: "Edge",
        control: "CSP",
        target: "vercel.json",
        expected: "CSP present",
        observed: status === "PASS" ? "CSP present" : "CSP missing",
        status,
        confidence: "HIGH",
        evidenceIds: [],
        notes: [],
      });
    });
  }

  test("a retest request must state what it observed", async () => {
    const { t0 } = await seed();
    const client = await advanceToRetest(t0, ANALYST);
    const res = await client.mutation(api.securescan.findings.requestRetest, {
      findingId: "FND-1",
      notes: "   ",
    });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.code).toBe("SECURESCAN_RETEST_NOTES_REQUIRED");
  });

  test("a blank retest request does not consume the queued transition", async () => {
    const { t0 } = await seed();
    const client = await advanceToRetest(t0, ANALYST);
    await client.mutation(api.securescan.findings.requestRetest, {
      findingId: "FND-1",
      notes: "   ",
    });
    const stored = await t0.run(async (ctx) =>
      ctx.db
        .query("securescanFindings")
        .withIndex("by_findingId", (q) => q.eq("findingId", "FND-1"))
        .unique(),
    );
    // The finding stays queued so a corrected request can still be made.
    expect(stored?.state).toBe("RETEST_REQUIRED");
  });

  test("requesting a retest queues the finding without judging it", async () => {
    // A request is a statement that a check is due. It must not resolve the
    // finding in either direction - only the engine's recorded run may do that.
    const { t0 } = await seed();
    const client = await advanceToRetest(t0, ANALYST);
    const res = await client.mutation(api.securescan.findings.requestRetest, {
      findingId: "FND-1",
      notes: "change deployed to staging; re-running the header checks",
    });
    expect(res.ok).toBe(true);
    if (res.ok) expect(res.state).toBe("RETEST_REQUIRED");

    const stored = await t0.run(async (ctx) =>
      ctx.db
        .query("securescanFindings")
        .withIndex("by_findingId", (q) => q.eq("findingId", "FND-1"))
        .unique(),
    );
    expect(stored?.state).toBe("RETEST_REQUIRED");
    // No verdict was recorded, so the resolution guard is still unsatisfied.
    expect(stored?.lastRetestState ?? null).toBeNull();

    const events = await t0.run(async (ctx) =>
      ctx.db
        .query("securescanFindingEvents")
        .withIndex("by_findingId", (q) => q.eq("findingId", "FND-1"))
        .collect(),
    );
    expect(events.some((e) => e.kind === "RETEST_STARTED")).toBe(true);
    expect(events.some((e) => e.kind === "RETEST_PASSED" || e.kind === "RETEST_FAILED")).toBe(
      false,
    );
  });

  test("a run that still fails records a regression rather than a fix", async () => {
    const { t0, assessmentId } = await seed();
    await advanceToRetest(t0, ANALYST);
    await seedRetestTests(t0, { assessmentId, runId: "RUN-2", status: "FAIL" });
    const res = await t0.mutation(internal.securescan.findings.recordRetestResult, {
      findingId: "FND-1",
      runId: "RUN-2",
      notes: "base-uri still absent on the deployed revision",
    });
    expect(res.ok).toBe(true);
    if (res.ok) expect(res.state).toBe("REGRESSION");

    const events = await t0.run(async (ctx) =>
      ctx.db
        .query("securescanFindingEvents")
        .withIndex("by_findingId", (q) => q.eq("findingId", "FND-1"))
        .collect(),
    );
    expect(events.some((e) => e.kind === "RETEST_FAILED")).toBe(true);
  });

  test("a queued retest cannot be declared verified without a retest having run", async () => {
    // The defect this pins: the transition table allows
    // RETEST_REQUIRED -> VERIFIED, but that edge means only "a retest is due".
    // `findings.transition` is reachable by any authenticated member, so without
    // a separate guard any client could mark a defect fixed without a single
    // retest having executed - asserting a security outcome nobody observed. The
    // UI never offers it, which is presentation, not enforcement.
    const { t0 } = await seed();
    const client = await advanceToRetest(t0, ANALYST);

    const res = await client.mutation(internal.securescan.findings.transition, {
      findingId: "FND-1",
      to: "VERIFIED",
      reason: "assuming the fix landed",
    });

    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.code).toBe("RETEST_REQUIRED_FOR_RESOLUTION");

    // And the refusal must not have moved the finding.
    const stored = await t0.run(async (ctx) =>
      ctx.db
        .query("securescanFindings")
        .withIndex("by_findingId", (q) => q.eq("findingId", "FND-1"))
        .unique(),
    );
    expect(stored?.state).toBe("RETEST_REQUIRED");

    // The refusal is auditable, like every other denial.
    const events = await t0.run(async (ctx) =>
      ctx.db
        .query("securescanFindingEvents")
        .withIndex("by_findingId", (q) => q.eq("findingId", "FND-1"))
        .collect(),
    );
    expect(events.some((e) => e.toState === "VERIFIED")).toBe(false);
  });

  test("a passing retest moves the finding to verified", async () => {
    // The verdict is read out of the run's stored rows, so this asserts the
    // whole path: a run that recorded a PASS for this finding's own control and
    // component, and nothing that contradicts it, resolves the finding.
    const { t0, assessmentId } = await seed();
    await advanceToRetest(t0, ANALYST);
    await seedRetestTests(t0, { assessmentId, runId: "RUN-2", status: "PASS" });

    const res = await t0.mutation(internal.securescan.findings.recordRetestResult, {
      findingId: "FND-1",
      runId: "RUN-2",
      notes: "base-uri declared on the deployed revision; test now passes",
    });
    expect(res.ok).toBe(true);
    if (res.ok) {
      expect(res.state).toBe("VERIFIED");
      expect(res.stateLabel).toBe("VERIFIED");
    }

    const stored = await t0.run(async (ctx) =>
      ctx.db
        .query("securescanFindings")
        .withIndex("by_findingId", (q) => q.eq("findingId", "FND-1"))
        .unique(),
    );
    expect(stored?.state).toBe("VERIFIED");
    expect(stored?.lastRetestState).toBe("PASSED");
  });

  // The defect this pins: deriving the verdict by asking "which matching tests
  // did NOT fail?" treats INCONCLUSIVE, NOT_TESTED and SKIPPED_OUT_OF_SCOPE as
  // evidence of a fix. None of those is an observation that the defect is gone,
  // so each must leave the finding queued rather than verifying it.
  test.each(["INCONCLUSIVE", "NOT_TESTED", "SKIPPED_OUT_OF_SCOPE"] as const)(
    "a retest that never passed (%s) does not verify the finding",
    async (status) => {
      const { t0, assessmentId } = await seed();
      await advanceToRetest(t0, ANALYST);
      await seedRetestTests(t0, { assessmentId, runId: "RUN-2", status });

      const res = await t0.mutation(internal.securescan.findings.recordRetestResult, {
        findingId: "FND-1",
        runId: "RUN-2",
        notes: "the check could not decide",
      });

      expect(res.ok).toBe(false);
      const stored = await t0.run(async (ctx) =>
        ctx.db
          .query("securescanFindings")
          .withIndex("by_findingId", (q) => q.eq("findingId", "FND-1"))
          .unique(),
      );
      // Still queued: an inconclusive run resolves nothing, in either direction.
      expect(stored?.state).toBe("RETEST_REQUIRED");
      expect(stored?.lastRetestState ?? null).toBeNull();
    },
  );

  test("a run from another assessment cannot resolve this finding", async () => {
    // The run has to belong to the finding's own assessment. A run from an
    // unrelated assessment is refused on the run itself, before its checks are
    // even considered.
    const { t0, assessmentId } = await seed();
    await advanceToRetest(t0, ANALYST);
    await seedRetestTests(t0, {
      assessmentId: `${assessmentId}-other`,
      runId: "RUN-OTHER",
      status: "PASS",
    });

    const res = await t0.mutation(internal.securescan.findings.recordRetestResult, {
      findingId: "FND-1",
      runId: "RUN-OTHER",
      notes: "unrelated assessment happened to pass",
    });

    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.code).toBe("SECURESCAN_RETEST_RUN_MISMATCH");

    const stored = await t0.run(async (ctx) =>
      ctx.db
        .query("securescanFindings")
        .withIndex("by_findingId", (q) => q.eq("findingId", "FND-1"))
        .unique(),
    );
    expect(stored?.state).toBe("RETEST_REQUIRED");
  });

  test("a run that was never recorded cannot resolve the finding", async () => {
    const { t0 } = await seed();
    await advanceToRetest(t0, ANALYST);

    // No run row and no checks: the premise fails before any test is examined.
    const res = await t0.mutation(internal.securescan.findings.recordRetestResult, {
      findingId: "FND-1",
      runId: "RUN-DOES-NOT-EXIST",
      notes: "naming a run that was never recorded",
    });

    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.code).toBe("SECURESCAN_RETEST_RUN_NOT_FOUND");

    const stored = await t0.run(async (ctx) =>
      ctx.db
        .query("securescanFindings")
        .withIndex("by_findingId", (q) => q.eq("findingId", "FND-1"))
        .unique(),
    );
    expect(stored?.state).toBe("RETEST_REQUIRED");
  });

  test("a run that never checked this control cannot resolve the finding", async () => {
    const { t0, assessmentId } = await seed();
    await advanceToRetest(t0, ANALYST);

    // A real, completed run of the right assessment whose only check is for a
    // different control. The run-level premise holds, so the refusal has to come
    // from the absence of a matching check.
    await t0.run(async (ctx) => {
      await ctx.db.insert("securescanRuns", {
        assessmentId,
        runId: "RUN-OTHER-CONTROL",
        ownerUserId: ANALYST.subject,
        state: "COMPLETED",
        startedAt: NOW,
        finishedAt: NOW,
        modulesRun: ["other-module"],
        counts: { pass: 1, fail: 0, inconclusive: 0, notTested: 0, skippedOutOfScope: 0 },
        toolVersion: "test-engine",
      });
      await ctx.db.insert("securescanTests", {
        assessmentId,
        runId: "RUN-OTHER-CONTROL",
        testId: "TEST-OTHER-CONTROL",
        module: "tls",
        category: "TRANSPORT",
        component: "Edge",
        control: "TLS_MINIMUM_VERSION",
        target: "edge",
        expected: "TLS 1.3",
        observed: "TLS 1.3",
        status: "PASS",
        confidence: "HIGH",
        evidenceIds: [],
        notes: [],
      });
    });

    const res = await t0.mutation(internal.securescan.findings.recordRetestResult, {
      findingId: "FND-1",
      runId: "RUN-OTHER-CONTROL",
      notes: "a passing run that never examined CSP",
    });

    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.code).toBe("SECURESCAN_RETEST_NO_MATCHING_TEST");

    const stored = await t0.run(async (ctx) =>
      ctx.db
        .query("securescanFindings")
        .withIndex("by_findingId", (q) => q.eq("findingId", "FND-1"))
        .unique(),
    );
    expect(stored?.state).toBe("RETEST_REQUIRED");
  });

  test("a retest result with no run is refused", async () => {
    const { t0 } = await seed();
    await advanceToRetest(t0, ANALYST);
    const res = await t0.mutation(internal.securescan.findings.recordRetestResult, {
      findingId: "FND-1",
      runId: "   ",
      notes: "no run named",
    });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.code).toBe("SECURESCAN_RETEST_RUN_REQUIRED");
  });

  test("a replayed run cannot overwrite a recorded verdict", async () => {
    // A later pass must not be able to paper over an earlier regression by
    // resubmitting the same run, so a run is judged once per finding.
    const { t0, assessmentId } = await seed();
    await advanceToRetest(t0, ANALYST);
    await seedRetestTests(t0, { assessmentId, runId: "RUN-2", status: "FAIL" });

    const first = await t0.mutation(internal.securescan.findings.recordRetestResult, {
      findingId: "FND-1",
      runId: "RUN-2",
      notes: "still absent",
    });
    expect(first.ok).toBe(true);
    if (first.ok) expect(first.state).toBe("REGRESSION");

    // Re-request a retest, then replay the same run claiming it passed.
    const client = await as(t0, ANALYST);
    await client.mutation(api.securescan.findings.requestRetest, {
      findingId: "FND-1",
      notes: "re-checking after a further deploy",
    });
    const replay = await t0.mutation(internal.securescan.findings.recordRetestResult, {
      findingId: "FND-1",
      runId: "RUN-2",
      notes: "claiming this time it passed",
    });

    expect(replay.ok).toBe(false);
    if (!replay.ok) expect(replay.code).toBe("SECURESCAN_RETEST_ALREADY_RECORDED");

    const stored = await t0.run(async (ctx) =>
      ctx.db
        .query("securescanFindings")
        .withIndex("by_findingId", (q) => q.eq("findingId", "FND-1"))
        .unique(),
    );
    // The re-request left the finding queued, and the replay changed nothing.
    expect(stored?.state).toBe("RETEST_REQUIRED");

    const events = await t0.run(async (ctx) =>
      ctx.db
        .query("securescanFindingEvents")
        .withIndex("by_findingId", (q) => q.eq("findingId", "FND-1"))
        .collect(),
    );
    // Exactly one verdict was ever recorded, and it was the regression. The
    // replay did not append a second one.
    expect(events.filter((e) => e.kind === "RETEST_FAILED")).toHaveLength(1);
    expect(events.filter((e) => e.kind === "RETEST_PASSED")).toHaveLength(0);
  });

  test("a run whose id extends an already-judged run is not treated as a replay", async () => {
    // The run id is stored as the event note's leading `run=<id>` token, so the
    // replay comparison has to be anchored to that token. A substring test would
    // read a note for `run=RUN-2` as having judged `run=RUN-20` and refuse a
    // legitimate, distinct run.
    const { t0, assessmentId } = await seed();
    await advanceToRetest(t0, ANALYST);
    await seedRetestTests(t0, { assessmentId, runId: "RUN-2", status: "FAIL" });
    await seedRetestTests(t0, { assessmentId, runId: "RUN-20", status: "PASS" });

    await t0.mutation(internal.securescan.findings.recordRetestResult, {
      findingId: "FND-1",
      runId: "RUN-2",
      notes: "first run still failing",
    });

    const client = await as(t0, ANALYST);
    await client.mutation(api.securescan.findings.requestRetest, {
      findingId: "FND-1",
      notes: "a second, separate run",
    });
    const res = await t0.mutation(internal.securescan.findings.recordRetestResult, {
      findingId: "FND-1",
      runId: "RUN-20",
      notes: "distinct run, genuinely passing",
    });

    // RUN-20 is not RUN-2, so it must be judged on its own rows.
    expect(res.ok).toBe(true);
    if (res.ok) expect(res.state).toBe("VERIFIED");
  });

  test("a retest verdict is attributed to the engine, not to a person", async () => {
    // The engine is not a user and holds no role. Recording the finding owner as
    // the actor would put a human in the chain for a judgement no human made.
    const { t0, assessmentId } = await seed();
    await advanceToRetest(t0, ANALYST);
    await seedRetestTests(t0, { assessmentId, runId: "RUN-2", status: "PASS" });

    await t0.mutation(internal.securescan.findings.recordRetestResult, {
      findingId: "FND-1",
      runId: "RUN-2",
      notes: "passing on the deployed revision",
    });

    const entries = await auditEntries(t0, assessmentId);
    const verdict = entries.find((e) => e.reasonCode === "RETEST_PASSED");
    expect(verdict?.actorUserId).toBe("engine");
    expect(verdict?.actorRole).toBe("SYSTEM");
    // Nobody with a role is credited with the verification.
    expect(verdict?.actorUserId).not.toBe(ANALYST.subject);

    // The finding timeline has to agree with the audit chain. It is read next to
    // it, so a timeline naming the owner would read as "this person verified
    // their own fix" even though the chain above correctly says the runner did.
    const events = await t0.run(async (ctx) =>
      ctx.db
        .query("securescanFindingEvents")
        .withIndex("by_findingId", (q) => q.eq("findingId", "FND-1"))
        .collect(),
    );
    const judgement = events.find(
      (e) => e.kind === "RETEST_PASSED" || e.kind === "RETEST_FAILED",
    );
    expect(judgement?.actorUserId).toBe("engine");
    expect(judgement?.actorUserId).not.toBe(await findingOwnerUserId(t0));
  });

  test("a run that has not finished cannot resolve the finding", async () => {
    // A run still in flight has not finished observing anything, and a run that
    // aborted is explicitly not a clean result set. Either way, deriving a
    // verdict from it would assert a determination the execution never made.
    const { t0, assessmentId } = await seed();
    await advanceToRetest(t0, ANALYST);
    await seedRetestTests(t0, { assessmentId, runId: "RUN-2", status: "PASS" });

    // Put the run back into the state `recordRun` stores for an unfinished
    // execution: still RUNNING, no `finishedAt`.
    await t0.run(async (ctx) => {
      const run = await ctx.db
        .query("securescanRuns")
        .withIndex("by_runId", (q) => q.eq("runId", "RUN-2"))
        .unique();
      if (run) {
        await ctx.db.patch(run._id, {
          finishedAt: undefined,
          state: "RUNNING",
          abortReason: undefined,
        });
      }
    });

    const res = await t0.mutation(internal.securescan.findings.recordRetestResult, {
      findingId: "FND-1",
      runId: "RUN-2",
      notes: "claiming a pass from a run that never finished",
    });

    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.code).toBe("SECURESCAN_RETEST_RUN_INCOMPLETE");

    const stored = await t0.run(async (ctx) =>
      ctx.db
        .query("securescanFindings")
        .withIndex("by_findingId", (q) => q.eq("findingId", "FND-1"))
        .unique(),
    );
    expect(stored?.state).toBe("RETEST_REQUIRED");
  });

  test("a run that stopped early cannot resolve the finding and says why", async () => {
    // A run that stopped early is stored with an abort reason precisely so it is
    // not reported as a clean result set. The reason is carried into the refusal
    // so the runner's next log line explains itself, rather than leaving an
    // operator to guess which of the two cases it was.
    const { t0, assessmentId } = await seed();
    await advanceToRetest(t0, ANALYST);
    await seedRetestTests(t0, { assessmentId, runId: "RUN-2", status: "PASS" });

    await t0.run(async (ctx) => {
      const run = await ctx.db
        .query("securescanRuns")
        .withIndex("by_runId", (q) => q.eq("runId", "RUN-2"))
        .unique();
      if (run) {
        await ctx.db.patch(run._id, {
          finishedAt: undefined,
          state: "CANCELLED",
          abortReason: "runner lost its credentials",
        });
      }
    });

    const res = await t0.mutation(internal.securescan.findings.recordRetestResult, {
      findingId: "FND-1",
      runId: "RUN-2",
      notes: "claiming a pass from a run that stopped early",
    });

    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.code).toBe("SECURESCAN_RETEST_RUN_INCOMPLETE");
    if (!res.ok) expect(res.reason).toContain("runner lost its credentials");

    // The refusal is on the audit chain, so the attempt is not invisible.
    const denied = await auditEntries(t0, assessmentId);
    const refusal = denied.find(
      (e) => e.reasonCode === "SECURESCAN_RETEST_RUN_INCOMPLETE",
    );
    expect(refusal?.outcome).toBe("DENIED");
    expect(refusal?.actorUserId).toBe("engine");
  });

  test("the browser cannot submit a retest verdict", async () => {
    // `requestRetest` takes no verdict at all and `recordRetestResult` is
    // internal, so no browser reference can state that a defect is fixed.
    // Asserting it on the type surface makes a regression a compile error rather
    // than a vulnerability found in review.
    const publicSurface = publicSecurescanFunctions();
    expect(publicSurface).not.toContain("securescan.findings.recordRetestResult");
    expect(publicSurface).not.toContain("securescan.findings.recordRetest");

    // The compile-time half of the same claim: a verdict is not part of the
    // request contract. Adding one back is a type error, not a review finding.
    const valid = { findingId: "FND-1", notes: "re-running the header checks" };
    const withVerdict = { ...valid, passed: true };
    // @ts-expect-error `passed` is not an accepted retest-request field
    const rejected: Parameters<typeof api.securescan.findings.requestRetest>[0]["args"] =
      withVerdict;
    expect(rejected.findingId).toBe("FND-1");
  });

  test("a role grant is not reachable from the public API", async () => {
    // `setRole` is an internalMutation, so a browser client has no reference to
    // it at all. This asserts that invariant on the public type surface, so
    // changing it to a public mutation is a compile error rather than a
    // privilege-escalation bug found in review.
    const publicSurface = publicSecurescanFunctions();
    expect(publicSurface).not.toContain("securescan.findings.setRole");
    expect(publicSurface).not.toContain("securescan.assessments.recordRun");
  });

  test("only an admin can list members", async () => {
    const { t0 } = await seed();
    await grantRole(t0, ADMIN.subject, "ADMIN");

    const analystClient = await as(t0, ANALYST);
    await expect(
      analystClient.query(internal.securescan.findings.listMembers, {}),
    ).rejects.toThrow(/ROLE_FORBIDDEN/);

    const adminClient = await as(t0, ADMIN);
    const members = await adminClient.query(internal.securescan.findings.listMembers, {});
    expect(members.map((m) => m.userId)).toContain(ANALYST.subject);
    expect(members.map((m) => m.userId)).toContain(VIEWER.subject);
    expect(members.find((m) => m.userId === ADMIN.subject)?.role).toBe("ADMIN");
  });
});

describe("audit trail", () => {
  async function seedWithActions() {
    const t0 = t();
    await grantRole(t0, ANALYST.subject, "SECURITY_ANALYST");
    await grantRole(t0, OTHER_ANALYST.subject, "SECURITY_ANALYST");
    await grantRole(t0, ADMIN.subject, "ADMIN");
    const { assessmentId } = await createAssessment(t0, ANALYST);
    await t0.mutation(internal.securescan.assessments.recordRun, {
      ownerUserId: ANALYST.subject,
      result: JSON.stringify(engineResult(assessmentId, ANALYST.subject)),
    });
    return { t0, assessmentId };
  }

  test("the chain verifies after real activity", async () => {
    const { t0, assessmentId } = await seedWithActions();
    const client = await as(t0, ADMIN);
    const report = await client.query(internal.securescan.audit.verify, { assessmentId });
    expect(report.intact).toBe(true);
    expect(report.problems).toEqual([]);
    expect(report.entryCount).toBeGreaterThan(0);
    expect(report.headHash).toBe(report.recordedHeadHash);
  });

  test("creation and run recording are both on the chain", async () => {
    const { t0, assessmentId } = await seedWithActions();
    const client = await as(t0, ADMIN);
    const entries = await client.query(internal.securescan.audit.list, { assessmentId });
    const actions = entries.map((e) => e.action);
    expect(actions).toContain("assessment:create");
    expect(actions).toContain("run:record");
    // The engine is recorded as a system principal, not as a fabricated user.
    expect(entries.find((e) => e.action === "run:record")?.actorRole).toBe("SYSTEM");
  });

  test("a denied remediation is recorded as DENIED", async () => {
    const { t0, assessmentId } = await seedWithActions();
    const client = await as(t0, OTHER_ANALYST);
    const res = await client.mutation(internal.securescan.findings.recordRemediation, {
      findingId: "FND-1",
      summary: "not mine",
    });
    expect(res.ok).toBe(false);

    // A refusal that leaves no trace is indistinguishable from a request that
    // never arrived, which is the gap this closes. The record only exists if the
    // denial was returned rather than thrown: a throw rolls the write back.
    const entries = await t0.run(async (ctx) =>
      ctx.db
        .query("securescanAuditLog")
        .withIndex("by_assessment_seq", (q) => q.eq("assessmentId", assessmentId))
        .collect(),
    );
    const denied = entries.filter((e) => e.outcome === "DENIED");
    expect(denied).toHaveLength(1);
    expect(denied[0]?.reasonCode).toBe("NOT_RESOURCE_OWNER");
    expect(denied[0]?.actorUserId).toBe(OTHER_ANALYST.subject);
  });

  test("a denied finding transition is recorded as DENIED", async () => {
    const { t0, assessmentId } = await seedWithActions();
    await grantRole(t0, VIEWER.subject, "VIEWER");
    const viewer = await as(t0, VIEWER);
    const res = await viewer.mutation(internal.securescan.findings.transition, {
      findingId: "FND-1",
      to: "VALIDATING",
      reason: "let me in",
    });
    expect(res.ok).toBe(false);

    const entries = await t0.run(async (ctx) =>
      ctx.db
        .query("securescanAuditLog")
        .withIndex("by_assessment_seq", (q) => q.eq("assessmentId", assessmentId))
        .collect(),
    );
    const denied = entries.filter((e) => e.outcome === "DENIED");
    expect(denied).toHaveLength(1);
    expect(denied[0]?.reasonCode).toBe("ROLE_FORBIDDEN");
    expect(denied[0]?.actorUserId).toBe(VIEWER.subject);
  });

  test("a denied transition does not change the finding's state", async () => {
    const { t0 } = await seedWithActions();
    await grantRole(t0, VIEWER.subject, "VIEWER");
    const viewer = await as(t0, VIEWER);
    await viewer.mutation(internal.securescan.findings.transition, {
      findingId: "FND-1",
      to: "VALIDATING",
      reason: "let me in",
    });
    const stored = await t0.run(async (ctx) =>
      ctx.db
        .query("securescanFindings")
        .withIndex("by_findingId", (q) => q.eq("findingId", "FND-1"))
        .unique(),
    );
    expect(stored?.state).toBe("CANDIDATE");
  });

  test("the chain still verifies after a denied attempt", async () => {
    const { t0, assessmentId } = await seedWithActions();
    await grantRole(t0, VIEWER.subject, "VIEWER");
    const viewer = await as(t0, VIEWER);
    await viewer.mutation(internal.securescan.findings.transition, {
      findingId: "FND-1",
      to: "VALIDATING",
      reason: "let me in",
    });
    const client = await as(t0, ADMIN);
    const report = await client.query(internal.securescan.audit.verify, { assessmentId });
    expect(report.intact).toBe(true);
  });

  test("an altered entry is detected by verification", async () => {
    const { t0, assessmentId } = await seedWithActions();
    // Rewrite history in place, the way an attacker with database access would.
    await t0.run(async (ctx) => {
      const rows = await ctx.db
        .query("securescanAuditLog")
        .withIndex("by_assessment_seq", (q) => q.eq("assessmentId", assessmentId))
        .collect();
      await ctx.db.patch(rows[0]!._id, { detail: "nothing happened here" });
    });

    const client = await as(t0, ADMIN);
    const report = await client.query(internal.securescan.audit.verify, { assessmentId });
    expect(report.intact).toBe(false);
    expect(report.problems.join(" ")).toMatch(/altered/);
  });

  test("truncating the tail is detected by the anchored head", async () => {
    const { t0, assessmentId } = await seedWithActions();
    const before = await t0.run(async (ctx) => ({
      rows: await ctx.db
        .query("securescanAuditLog")
        .withIndex("by_assessment_seq", (q) => q.eq("assessmentId", assessmentId))
        .collect(),
    }));
    const last = before.rows[before.rows.length - 1]!;
    await t0.run(async (ctx) => {
      await ctx.db.delete(last._id);
    });

    const client = await as(t0, ADMIN);
    const report = await client.query(internal.securescan.audit.verify, { assessmentId });
    // Deleting a suffix leaves a self-consistent prefix; only the anchored head
    // digest reveals it.
    expect(report.intact).toBe(false);
    expect(report.problems.join(" ")).toMatch(/does not match the digest recorded/);
  });

  test("only an admin can read the audit trail", async () => {
    const { t0, assessmentId } = await seedWithActions();
    const analyst = await as(t0, ANALYST);
    await expect(
      analyst.query(internal.securescan.audit.list, { assessmentId }),
    ).rejects.toThrow(/ROLE_FORBIDDEN/);
  });
});
