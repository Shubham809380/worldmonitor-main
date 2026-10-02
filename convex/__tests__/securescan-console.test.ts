import { convexTest } from "convex-test";
import { api, internal } from "../_generated/api";
import { describe, expect, test } from "vitest";
import schema from "../schema";
import type { AssessmentResult } from "../../server/securescan/types";

/**
 * Console and membership administration.
 *
 * The dashboard is the first thing an operator sees, so its numbers are the
 * numbers this file holds to account. Each assertion below exists because a
 * plausible-looking wrong value here would be invisible in the product: a bucket
 * that can never be non-zero, an unscored backlog folded into "no severity", or
 * an admin able to strand a deployment by demoting themselves.
 */

const modules = import.meta.glob("../**/*.ts");

const ANALYST = { subject: "user-analyst", tokenIdentifier: "clerk|user-analyst" };
const VIEWER = { subject: "user-viewer", tokenIdentifier: "clerk|user-viewer" };
const COLLEAGUE = { subject: "user-colleague", tokenIdentifier: "clerk|user-colleague" };
const ADMIN = { subject: "user-admin", tokenIdentifier: "clerk|user-admin" };
const NOBODY = { subject: "user-nobody", tokenIdentifier: "clerk|user-nobody" };

const NOW = Date.parse("2026-09-01T00:00:00.000Z");

function t() {
  return convexTest(schema, modules);
}

async function grantRole(
  t0: ReturnType<typeof convexTest>,
  userId: string,
  role: "ADMIN" | "SECURITY_ANALYST" | "VIEWER",
) {
  await t0.mutation(internal.securescan.findings.setRole, { userId, role });
}

const CREATE_ARGS = {
  name: "Console assessment",
  targetName: "worldmonitor",
  targetKind: "REPOSITORY" as const,
  repositoryUrl: "https://github.com/koala73/worldmonitor",
  allowlistedPaths: ["api/"],
  maxRuntimeRequests: 0,
};

async function createAssessment(
  t0: ReturnType<typeof convexTest>,
  identity: { subject: string; tokenIdentifier: string },
) {
  // Creation is an internal mutation: the product's entry point is the
  // assessment the console is looking at, not a public "run a scan" endpoint.
  const client = await t0.withIdentity(identity);
  return client.mutation(internal.securescan.assessments.create, CREATE_ARGS);
}

/**
 * A run whose findings deliberately span the distinctions the dashboard must
 * keep apart: a scored critical, and an unscored candidate nobody has judged.
 */
function consoleResult(assessmentId: string, ownerUserId: string): AssessmentResult {
  const at = new Date(NOW).toISOString();
  const risk = (technicalSeverity: "NONE" | "CRITICAL") => ({
    technicalSeverity,
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
    confidence: "HIGH" as const,
    severityRationale:
      technicalSeverity === "NONE" ? ["Not yet scored."] : ["Impact: HIGH", "Exposure: PUBLIC_INTERNET"],
    severityMethodologyVersion: "1.0.0",
  });

  return {
    assessment: {
      id: assessmentId,
      name: "Console assessment",
      state: "COMPLETED",
      scope: {
        targetId: "ss_target_console",
        targetKind: "REPOSITORY",
        allowedHosts: [],
        allowedPaths: ["api/"],
        maxRequests: 0,
        intensity: "PASSIVE",
        reason: "Baseline",
      },
      moduleNames: ["security-headers"],
      createdBy: ownerUserId,
      createdAt: at,
      startedAt: at,
      finishedAt: at,
      authorizationNote: "Baseline",
    },
    run: {
      id: "RUN-CONSOLE",
      assessmentId,
      startedAt: at,
      finishedAt: at,
      progress: [
        {
          module: "security-headers",
          status: "COMPLETE",
          testsRun: 1,
          startedAt: at,
          finishedAt: at,
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
        testId: "TEST-CONSOLE-1",
        assessmentId,
        runId: "RUN-CONSOLE",
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
        evidenceIds: ["EV-CONSOLE-1"],
        notes: [],
        requiresCapability: "NONE",
      },
      {
        testId: "TEST-CONSOLE-SKIPPED",
        assessmentId,
        runId: "RUN-CONSOLE",
        module: "cors",
        category: "CORS",
        component: "Edge",
        control: "CTRL-CORS-ORIGIN",
        target: "https://api.example.com",
        boundary: null,
        expected: "Origin reflected in Access-Control-Allow-Origin",
        observed: "",
        // A PASSIVE run cannot contact a live host, so this check is recorded as
        // never performed rather than as a pass or a fail.
        status: "NOT_TESTED",
        confidence: "LOW",
        evidenceIds: [],
        notes: ["Live probe not run: intensity is PASSIVE and no authorization was declared."],
        requiresCapability: "NETWORK_REQUEST",
      },
    ],
    controls: [],
    findings: [
      {
        id: "FND-SCORED",
        title: "CSP absent on the OAuth callback",
        category: "SECURITY_HEADERS",
        component: "Edge",
        node: "vercel-edge",
        boundary: null,
        control: "CSP",
        affectedEndpoints: ["/api/slack/oauth/callback"],
        description: "d",
        rootCause: "rc",
        rootCauseId: "RC-1",
        severity: "CRITICAL",
        confidence: "HIGH",
        risk: risk("CRITICAL"),
        historicalStatus: "CURRENTLY_OBSERVED",
        state: "CANDIDATE",
        evidenceIds: ["EV-CONSOLE-1"],
        reproduction: [],
        controlledPoc: [],
        businessImpact: "n/a",
        remediation: null,
        retestResult: null,
        regressionTestId: null,
        references: [],
        createdAt: at,
        updatedAt: at,
        fingerprint: "fp-scored",
      },
      {
        id: "FND-UNSCORED",
        title: "Header check could not be attributed to an endpoint",
        category: "SECURITY_HEADERS",
        component: "Edge",
        node: "vercel-edge",
        boundary: null,
        control: "CSP",
        affectedEndpoints: [],
        description: "d",
        rootCause: "rc",
        rootCauseId: "RC-2",
        severity: "NONE",
        confidence: "MEDIUM",
        risk: risk("NONE"),
        historicalStatus: "CURRENTLY_OBSERVED",
        state: "CANDIDATE",
        evidenceIds: ["EV-CONSOLE-1"],
        reproduction: [],
        controlledPoc: [],
        businessImpact: "n/a",
        remediation: null,
        retestResult: null,
        regressionTestId: null,
        references: [],
        createdAt: at,
        updatedAt: at,
        fingerprint: "fp-unscored",
      },
    ],
    evidence: [
      {
        evidenceId: "EV-CONSOLE-1",
        findingId: null,
        testId: "TEST-CONSOLE-1",
        assessmentId,
        collectedAt: at,
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
    notTested: [],
    toolVersion: "1.0.0",
    targetRevision: "abc123",
  } as unknown as AssessmentResult;
}

async function seedWithTwoFindings() {
  const t0 = t();
  await grantRole(t0, ANALYST.subject, "SECURITY_ANALYST");
  await grantRole(t0, VIEWER.subject, "VIEWER");
  const { assessmentId } = await createAssessment(t0, ANALYST);
  await t0.mutation(internal.securescan.assessments.recordRun, {
    ownerUserId: ANALYST.subject,
    result: JSON.stringify(consoleResult(assessmentId, ANALYST.subject)),
  });
  // Console functions are public, so every read and write in this file runs as a
  // named member rather than as an anonymous caller. `t0` stays available for the
  // tests that are specifically about a caller with no identity.
  const analyst = await t0.withIdentity(ANALYST);
  return { t0, analyst, assessmentId };
}

describe("security assessment dashboard", () => {
  test("counts stored rows rather than defaulting to zero", async () => {
    const { analyst } = await seedWithTwoFindings();
    const dash = await analyst.query(api.securescan.console.dashboard, {});

    expect(dash.totals.assessments).toBe(1);
    expect(dash.totals.runs).toBe(1);
    expect(dash.totals.tests).toBe(2);
    expect(dash.totals.evidence).toBe(1);
    expect(dash.totals.members).toBe(2);
    expect(dash.role).toBe("SECURITY_ANALYST");
  });

  test("keeps an unscored candidate visible instead of folding it into a severity bucket", async () => {
    const { analyst } = await seedWithTwoFindings();
    const dash = await analyst.query(api.securescan.console.dashboard, {});

    // One finding was scored CRITICAL, one is still a candidate nobody has
    // judged. Reporting only the severity mix would understate the queue.
    expect(dash.totals.findingsBySeverity.CRITICAL).toBe(1);
    expect(dash.totals.findingsBySeverity.NONE).toBe(1);
    expect(dash.totals.unscoredCandidates).toBe(1);
    expect(dash.totals.openFindings).toBe(2);
    expect(dash.totals.closedFindings).toBe(0);
  });

  test("separates the open backlog from findings that reached a decision", async () => {
    const { analyst } = await seedWithTwoFindings();
    const before = await analyst.query(api.securescan.console.dashboard, {});
    expect(before.totals.findingsByState.FALSE_POSITIVE).toBe(0);

    const dismissed = await analyst.mutation(api.securescan.findings.transition, {
      findingId: "FND-UNSCORED",
      to: "FALSE_POSITIVE",
      reason: "The header check could not be attributed to a real endpoint, so there is nothing to fix.",
    });
    expect(dismissed.ok).toBe(true);

    const after = await analyst.query(api.securescan.console.dashboard, {});
    expect(after.totals.findingsByState.FALSE_POSITIVE).toBe(1);
    expect(after.totals.openFindings).toBe(1);
    expect(after.totals.closedFindings).toBe(1);
  });

  test("every state bucket is one the engine can actually produce", async () => {
    const { analyst } = await seedWithTwoFindings();
    const dash = await analyst.query(api.securescan.console.dashboard, {});

    // A bucket for a state that does not exist is a permanently-zero column that
    // still looks like a measurement. This pins the bucket set to the engine.
    expect(Object.keys(dash.totals.assessmentsByState).sort()).toEqual([
      "CANCELLED",
      "COMPLETED",
      "DRAFT",
      "FAILED",
      "PAUSED",
      "READY",
      "RUNNING",
    ]);
    expect(Object.keys(dash.totals.findingsBySeverity).sort()).toEqual([
      "CRITICAL",
      "HIGH",
      "LOW",
      "MEDIUM",
      "NONE",
    ]);
  });

  test("an empty deployment reports zeros and no last run rather than failing", async () => {
    const t0 = t();
    await grantRole(t0, ANALYST.subject, "SECURITY_ANALYST");
    const analyst = await t0.withIdentity(ANALYST);
    const dash = await analyst.query(api.securescan.console.dashboard, {});

    expect(dash.totals.assessments).toBe(0);
    expect(dash.totals.openFindings).toBe(0);
    expect(dash.lastRun).toBeNull();
    expect(dash.recentAssessments).toEqual([]);
  });

  test("refuses an authenticated caller with no SecureScan membership", async () => {
    const t0 = t();
    const outsider = await t0.withIdentity(NOBODY);
    await expect(outsider.query(api.securescan.console.dashboard, {})).rejects.toThrow(
      /SECURESCAN_NO_MEMBERSHIP/,
    );
  });

  test("refuses an unauthenticated caller", async () => {
    const t0 = t();
    await expect(t0.query(api.securescan.console.dashboard, {})).rejects.toThrow(/AUTH_REQUIRED/);
  });
});

describe("viewer identity", () => {
  test("reports the caller's own grant without requiring one", async () => {
    const t0 = t();
    await grantRole(t0, ANALYST.subject, "SECURITY_ANALYST");
    const analyst = await t0.withIdentity(ANALYST);
    const viewer = await analyst.query(api.securescan.console.viewer, {});

    expect(viewer.signedIn).toBe(true);
    expect(viewer.userId).toBe(ANALYST.subject);
    expect(viewer.role).toBe("SECURITY_ANALYST");
  });

  test("distinguishes a signed-in caller with no grant from an anonymous one", async () => {
    const t0 = t();
    const outsider = await t0.withIdentity(NOBODY);
    const viewer = await outsider.query(api.securescan.console.viewer, {});

    // The whole point of this query. `dashboard` refuses this caller, and
    // without it the shell cannot tell this apart from having no session, so it
    // would report a signed-in user as "Not authenticated" -- or worse, report
    // a reachable refusal as a backend outage.
    expect(viewer.signedIn).toBe(true);
    expect(viewer.role).toBeNull();
  });

  test("reports no session for an anonymous caller without throwing", async () => {
    const t0 = t();
    const viewer = await t0.query(api.securescan.console.viewer, {});

    expect(viewer.signedIn).toBe(false);
    expect(viewer.userId).toBeNull();
    expect(viewer.role).toBeNull();
  });

  test("discloses only the caller's own identity", async () => {
    const t0 = t();
    await grantRole(t0, ANALYST.subject, "SECURITY_ANALYST");
    await grantRole(t0, COLLEAGUE.subject, "VIEWER");
    const analyst = await t0.withIdentity(ANALYST);
    const viewer = await analyst.query(api.securescan.console.viewer, {});

    // No member list, no other subject, no assessment data: answering "who am I"
    // must not become a directory read.
    expect(Object.keys(viewer).sort()).toEqual(["role", "signedIn", "userId"]);
    expect(JSON.stringify(viewer)).not.toContain(COLLEAGUE.subject);
  });

  test("a forged grant row for another user cannot be read as your own role", async () => {
    const t0 = t();
    await grantRole(t0, COLLEAGUE.subject, "ADMIN");
    const outsider = await t0.withIdentity(NOBODY);
    const viewer = await outsider.query(api.securescan.console.viewer, {});

    expect(viewer.role).toBeNull();
    expect(viewer.userId).toBe(NOBODY.subject);
  });
});

describe("findings across assessments", () => {
  test("lists findings from every assessment with their labels", async () => {
    const { analyst } = await seedWithTwoFindings();
    const list = await analyst.query(api.securescan.console.listFindings, {});

    expect(list.total).toBe(2);
    expect(list.findings.map((row) => row.findingId).sort()).toEqual(["FND-SCORED", "FND-UNSCORED"]);
    const scored = list.findings.find((row) => row.findingId === "FND-SCORED");
    // The engine's label for a candidate is POTENTIAL, not CANDIDATE: nobody has
    // confirmed anything yet, and the product should not imply otherwise.
    expect(scored?.stateLabel).toBe("POTENTIAL");
    expect(scored?.severityLabel).toBe("CRITICAL");
  });

  test("filters by state and severity without hiding the rest of the backlog", async () => {
    const { analyst } = await seedWithTwoFindings();
    const bySeverity = await analyst.query(api.securescan.console.listFindings, {
      severity: "CRITICAL",
    });
    expect(bySeverity.total).toBe(1);
    expect(bySeverity.findings[0]?.findingId).toBe("FND-SCORED");

    const byState = await analyst.query(api.securescan.console.listFindings, { state: "CANDIDATE" });
    expect(byState.total).toBe(2);
  });

  test("rejects a filter value outside the engine's union", async () => {
    const { analyst } = await seedWithTwoFindings();
    await expect(
      analyst.query(api.securescan.console.listFindings, { state: "QUEUED" as never }),
    ).rejects.toThrow();
  });

  test("a member with the viewer role reads the whole backlog but holds no owner scope", async () => {
    const { t0, analyst } = await seedWithTwoFindings();
    // Reads are workspace-wide by design, so a viewer sees the backlog. The
    // owner check applies to writes, which is why this test can assert both.
    const asViewer = await t0.withIdentity(VIEWER);
    const viewerList = await asViewer.query(api.securescan.console.listFindings, {});
    expect(viewerList.total).toBe(2);
    expect(viewerList.role).toBe("VIEWER");

    // ...and the same viewer cannot move a finding the analyst owns.
    const attempt = await asViewer.mutation(api.securescan.findings.transition, {
      findingId: "FND-SCORED",
      to: "VALIDATING",
      reason: "Trying to triage someone else's finding.",
    });
    expect(attempt.ok).toBe(false);

    const mine = await analyst.query(api.securescan.console.listFindings, {});
    expect(mine.role).toBe("SECURITY_ANALYST");
  });
});

describe("finding detail and evidence traceability", () => {
  test("shows only the evidence the finding actually cites", async () => {
    const { t0, analyst, assessmentId } = await seedWithTwoFindings();
    // A second record belonging to the same assessment but to no finding: a
    // detail view that mixed it in would make the cited support unassessable.
    await t0.run(async (ctx) => {
      await ctx.db.insert("securescanEvidence", {
        evidenceId: "EV-UNRELATED",
        assessmentId,
        collectedAt: NOW,
        type: "CONFIGURATION",
        description: "Evidence belonging to some other check.",
        payload: JSON.stringify({
          kind: "config-value",
          path: "vercel.json",
          pointer: "other",
          value: "x",
        }),
        sha256: "b".repeat(64),
        producedBy: "wm-securescan:vercel.json",
        targetEnvironment: "PRODUCTION",
      });
    });

    const detail = await analyst.query(api.securescan.console.findingDetail, {
      findingId: "FND-SCORED",
    });
    expect(detail.evidence).toHaveLength(1);
    expect(detail.evidence[0]?.evidenceId).toBe("EV-CONSOLE-1");
    expect(detail.tests).toHaveLength(1);
    expect(detail.tests[0]?.status).toBe("FAIL");
  });

  test("returns the full event history in order", async () => {
    const { analyst } = await seedWithTwoFindings();
    const started = await analyst.mutation(api.securescan.findings.transition, {
      findingId: "FND-SCORED",
      to: "VALIDATING",
      reason: "Reproduced against a staging deployment.",
    });
    expect(started.ok).toBe(true);

    const detail = await analyst.query(api.securescan.console.findingDetail, {
      findingId: "FND-SCORED",
    });
    const kinds = detail.events.map((event) => event.kind);
    expect(kinds).toContain("CREATED");
    expect(kinds).toContain("VALIDATION_STARTED");
    for (let i = 1; i < detail.events.length; i += 1) {
      expect(detail.events[i]!.at).toBeGreaterThanOrEqual(detail.events[i - 1]!.at);
    }
  });

  test("refuses an unknown finding", async () => {
    const { analyst } = await seedWithTwoFindings();
    await expect(
      analyst.query(api.securescan.console.findingDetail, { findingId: "FND-MISSING" }),
    ).rejects.toThrow(/SECURESCAN_FINDING_NOT_FOUND/);
  });

  test("evidence detail reports which findings cite it", async () => {
    const { analyst } = await seedWithTwoFindings();
    const detail = await analyst.query(api.securescan.console.evidenceDetail, {
      evidenceId: "EV-CONSOLE-1",
    });
    expect(detail.citedBy.map((row) => row.findingId).sort()).toEqual([
      "FND-SCORED",
      "FND-UNSCORED",
    ]);
    expect(detail.test?.status).toBe("FAIL");
  });

  test("a viewer with membership can read evidence", async () => {
    const { t0 } = await seedWithTwoFindings();
    const asViewer = await t0.withIdentity(VIEWER);
    const detail = await asViewer.query(api.securescan.console.evidenceDetail, {
      evidenceId: "EV-CONSOLE-1",
    });
    expect(detail.role).toBe("VIEWER");
  });
});

describe("membership administration", () => {
  async function seedWithAdmin() {
    const t0 = t();
    await grantRole(t0, ADMIN.subject, "ADMIN");
    const { assessmentId } = await createAssessment(t0, ADMIN);
    const admin = await t0.withIdentity(ADMIN);
    return { t0, admin, assessmentId };
  }

  test("an admin can grant a role to a colleague", async () => {
    const { t0, admin, assessmentId } = await seedWithAdmin();

    const result = await admin.mutation(api.securescan.members.setMemberRole, {
      userId: COLLEAGUE.subject,
      role: "SECURITY_ANALYST",
      assessmentId,
      reason: "Joining the assessment team for this repository.",
    });
    expect(result).toEqual({
      ok: true,
      userId: COLLEAGUE.subject,
      role: "SECURITY_ANALYST",
      action: "granted",
    });

    // The grant must actually open the door, not just record a row.
    const asColleague = await t0.withIdentity(COLLEAGUE);
    const dash = await asColleague.query(api.securescan.console.dashboard, {});
    expect(dash.role).toBe("SECURITY_ANALYST");
  });

  test("an admin cannot grant a role to themselves", async () => {
    const { admin, assessmentId } = await seedWithAdmin();

    const result = await admin.mutation(api.securescan.members.setMemberRole, {
      userId: ADMIN.subject,
      role: "ADMIN",
      assessmentId,
      reason: "Trying to self-grant.",
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.code).toBe("SECURESCAN_SELF_GRANT_FORBIDDEN");
  });

  test("a non-admin cannot grant roles", async () => {
    const t0 = t();
    await grantRole(t0, ANALYST.subject, "SECURITY_ANALYST");
    const { assessmentId } = await createAssessment(t0, ANALYST);
    const analyst = await t0.withIdentity(ANALYST);

    const result = await analyst.mutation(api.securescan.members.setMemberRole, {
      userId: COLLEAGUE.subject,
      role: "ADMIN",
      assessmentId,
      reason: "Escalation attempt.",
    });
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.code).toBe("ROLE_FORBIDDEN");
  });

  test("no sequence of role changes can leave a deployment with zero admins", async () => {
    // The two guards interact: self-targeting is refused first, so with a single
    // admin the self-grant rule is what stops the last one being removed. Rather
    // than assert which guard fires — that is an ordering detail — this asserts
    // the invariant that actually matters, across every role operation an admin
    // can perform against every other subject.
    const t0 = t();
    await grantRole(t0, ADMIN.subject, "ADMIN");
    const { assessmentId } = await createAssessment(t0, ADMIN);
    const admin = await t0.withIdentity(ADMIN);

    for (const role of ["SECURITY_ANALYST", "VIEWER"] as const) {
      await admin.mutation(api.securescan.members.setMemberRole, {
        userId: COLLEAGUE.subject,
        role,
        assessmentId,
        reason: "Onboarding the assessment team.",
      });
      await admin.mutation(api.securescan.members.setMemberRole, {
        userId: COLLEAGUE.subject,
        role: "ADMIN",
        assessmentId,
        reason: "Promoting to a second admin so the first can be reduced.",
      });
      await admin.mutation(api.securescan.members.setMemberRole, {
        userId: COLLEAGUE.subject,
        role: "VIEWER",
        assessmentId,
        reason: "Returning to read-only access.",
      });
    }

    // Self-grant, self-promotion and self-revocation are all refused.
    for (const attempt of [
      { role: "ADMIN" as const, revoke: true },
      { role: "ADMIN" as const, revoke: false },
      { role: "VIEWER" as const, revoke: false },
    ]) {
      const result = await admin.mutation(api.securescan.members.setMemberRole, {
        userId: ADMIN.subject,
        role: attempt.role,
        assessmentId,
        revoke: attempt.revoke,
        reason: "Attempting to act on my own membership.",
      });
      expect(result.ok, `self ${attempt.role}/${attempt.revoke} was allowed`).toBe(false);
    }

    const remaining = await t0.run(async (ctx) =>
      ctx.db.query("securescanMembers").withIndex("by_role", (q) => q.eq("role", "ADMIN")).collect(),
    );
    expect(remaining.length).toBeGreaterThan(0);
    const asAdmin = await t0.withIdentity(ADMIN);
    const dash = await asAdmin.query(api.securescan.console.dashboard, {});
    expect(dash.role).toBe("ADMIN");
  });

  test("an admin can be demoted once a second admin exists", async () => {
    const t0 = t();
    await grantRole(t0, ADMIN.subject, "ADMIN");
    await grantRole(t0, COLLEAGUE.subject, "ADMIN");
    const { assessmentId } = await createAssessment(t0, ADMIN);
    const asColleague = await t0.withIdentity(COLLEAGUE);

    const result = await asColleague.mutation(api.securescan.members.setMemberRole, {
      userId: ADMIN.subject,
      role: "VIEWER",
      assessmentId,
      reason: "Role reduced during offboarding.",
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.action).toBe("changed");
  });

  test("a revoked member is refused at the door", async () => {
    const t0 = t();
    await grantRole(t0, ADMIN.subject, "ADMIN");
    await grantRole(t0, COLLEAGUE.subject, "SECURITY_ANALYST");
    const { assessmentId } = await createAssessment(t0, ADMIN);
    const admin = await t0.withIdentity(ADMIN);

    const result = await admin.mutation(api.securescan.members.setMemberRole, {
      userId: COLLEAGUE.subject,
      role: "VIEWER",
      assessmentId,
      revoke: true,
      reason: "Offboarding.",
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.action).toBe("revoked");

    const asColleague = await t0.withIdentity(COLLEAGUE);
    await expect(asColleague.query(api.securescan.console.dashboard, {})).rejects.toThrow(
      /SECURESCAN_NO_MEMBERSHIP/,
    );
  });

  test("a role change is written to the audit chain", async () => {
    const { t0, admin, assessmentId } = await seedWithAdmin();
    await admin.mutation(api.securescan.members.setMemberRole, {
      userId: COLLEAGUE.subject,
      role: "VIEWER",
      assessmentId,
      reason: "Read-only access for the review.",
    });

    const entries = await t0.run(async (ctx) =>
      ctx.db
        .query("securescanAuditLog")
        .withIndex("by_assessment_seq", (q) => q.eq("assessmentId", assessmentId))
        .collect(),
    );
    const grant = entries.find((entry) => entry.reasonCode === "MEMBERSHIP_GRANTED");
    expect(grant?.action).toBe("member:setRole");
    expect(grant?.actorUserId).toBe(ADMIN.subject);
  });

  test("a refused role change is audited too", async () => {
    const { t0, admin, assessmentId } = await seedWithAdmin();
    await admin.mutation(api.securescan.members.setMemberRole, {
      userId: ADMIN.subject,
      role: "ADMIN",
      assessmentId,
      reason: "Self-grant attempt.",
    });

    const entries = await t0.run(async (ctx) =>
      ctx.db
        .query("securescanAuditLog")
        .withIndex("by_assessment_seq", (q) => q.eq("assessmentId", assessmentId))
        .collect(),
    );
    const denied = entries.find((entry) => entry.reasonCode === "SECURESCAN_SELF_GRANT_FORBIDDEN");
    expect(denied?.outcome).toBe("DENIED");
  });

  test("only an admin can list members", async () => {
    const t0 = t();
    await grantRole(t0, ADMIN.subject, "ADMIN");
    await grantRole(t0, VIEWER.subject, "VIEWER");
    const asAdmin = await t0.withIdentity(ADMIN);
    const members = await asAdmin.query(api.securescan.members.listMembers, {});
    expect(members.map((row) => row.userId).sort()).toEqual([ADMIN.subject, VIEWER.subject]);

    const asViewer = await t0.withIdentity(VIEWER);
    await expect(asViewer.query(api.securescan.members.listMembers, {})).rejects.toThrow();
  });
});

describe("assessment report", () => {
  test("reports the recorded run, not a re-analysis", async () => {
    const { analyst, assessmentId } = await seedWithTwoFindings();
    const report = await analyst.query(api.securescan.console.report, { assessmentId });

    expect(report.hasRun).toBe(true);
    expect(report.run?.runId).toBe("RUN-CONSOLE");
    expect(report.run?.targetRevision).toBe("abc123");
    expect(report.run?.toolVersion).toBe("1.0.0");
    expect(report.assessment.state).toBe("COMPLETED");
  });

  test("has no posture score to misread as a verdict", async () => {
    const { analyst, assessmentId } = await seedWithTwoFindings();
    const report = await analyst.query(api.securescan.console.report, { assessmentId });

    // A single graded number would need a published weighting between critical
    // and informational. That is a policy decision, not a scan result, so the
    // report renders the mix and the list and offers no grade.
    expect(Object.keys(report)).not.toContain("postureScore");
    expect(Object.keys(report)).not.toContain("score");
    expect(Object.keys(report)).not.toContain("grade");
    expect(Object.keys(report)).not.toContain("rating");
  });

  test("keeps unscored candidates out of the severity mix and in their own section", async () => {
    const { analyst, assessmentId } = await seedWithTwoFindings();
    const report = await analyst.query(api.securescan.console.report, { assessmentId });

    // FND-UNSCORED is severity NONE because nobody has judged it. Counting it as
    // an informational finding would report an unjudged item as a triaged one.
    expect(report.severityMix.NONE).toBe(0);
    expect(report.severityMix.CRITICAL).toBe(1);
    expect(report.unscoredCandidates.map((row) => row.findingId)).toEqual(["FND-UNSCORED"]);
    expect(report.basis.findingsScored).toBe(1);
    expect(report.basis.findingsUnscored).toBe(1);
  });

  test("states plainly that a report with no run has no basis", async () => {
    const t0 = t();
    await grantRole(t0, ANALYST.subject, "SECURITY_ANALYST");
    const { assessmentId } = await createAssessment(t0, ANALYST);
    const analyst = await t0.withIdentity(ANALYST);

    const report = await analyst.query(api.securescan.console.report, { assessmentId });

    // "Nothing found" and "nothing looked" are different sentences. An empty
    // report must not read like a clean result.
    expect(report.hasRun).toBe(false);
    expect(report.run).toBeNull();
    expect(report.coverage.recorded).toBeNull();
    expect(report.basis.testsObserved).toBe(0);
    expect(report.basis.evidenceRecords).toBe(0);
  });

  test("counts coverage from stored tests and lists what was never tested", async () => {
    const { analyst, assessmentId } = await seedWithTwoFindings();
    const report = await analyst.query(api.securescan.console.report, { assessmentId });

    // The run recorded one FAIL, and one check it never performed. Counting both
    // as "tests run" would make a passive scan look like a full one.
    expect(report.coverage.observedTests).toBe(1);
    expect(report.coverage.notTestedTests).toBe(1);
    expect(report.coverage.recorded?.fail).toBe(1);
    expect(report.coverage.recorded?.notTested).toBe(1);
    expect(report.coverage.evidenceCount).toBe(1);

    // The gap is named, with the reason the tool did not close it.
    expect(report.coverage.notTested.map((row) => row.testId)).toEqual(["TEST-CONSOLE-SKIPPED"]);
    expect(report.coverage.notTested[0]?.reason).toMatch(/PASSIVE/i);
    expect(report.basis.testsObserved).toBe(1);
    expect(report.basis.testsNotTested).toBe(1);
  });

  test("keeps outstanding work separate from findings that reached a decision", async () => {
    const { analyst, assessmentId } = await seedWithTwoFindings();
    const before = await analyst.query(api.securescan.console.report, { assessmentId });
    expect(before.outstanding).toHaveLength(2);

    await analyst.mutation(api.securescan.findings.transition, {
      findingId: "FND-UNSCORED",
      to: "FALSE_POSITIVE",
      reason: "The header check could not be attributed to a real endpoint, so there is nothing to fix.",
    });
    const after = await analyst.query(api.securescan.console.report, { assessmentId });

    expect(after.outstanding.map((row) => row.findingId)).toEqual(["FND-SCORED"]);
    expect(after.findings).toHaveLength(2);
    expect(after.stateMix.FALSE_POSITIVE).toBe(1);
  });

  test("verifies the audit chain instead of asserting integrity", async () => {
    const { analyst, assessmentId } = await seedWithTwoFindings();
    const report = await analyst.query(api.securescan.console.report, { assessmentId });
    expect(report.integrity.intact).toBe(true);
    expect(report.integrity.problems).toEqual([]);
    expect(report.integrity.entryCount).toBeGreaterThan(0);
    expect(report.integrity.headHash).toMatch(/^[0-9a-f]{64}$/);
  });

  test("an altered chain is reported as altered rather than rendering normally", async () => {
    const { t0, analyst, assessmentId } = await seedWithTwoFindings();

    // Simulate a tampered entry: the row survives, its content no longer matches
    // its digest. A report that did not check would render as a clean result.
    const entry = await t0.run(async (ctx) =>
      ctx.db
        .query("securescanAuditLog")
        .withIndex("by_assessment_seq", (q) => q.eq("assessmentId", assessmentId))
        .first(),
    );
    expect(entry).not.toBeNull();
    await t0.run(async (ctx) => {
      await ctx.db.patch(entry!._id, { detail: "quietly rewritten" });
    });

    const report = await analyst.query(api.securescan.console.report, { assessmentId });
    expect(report.integrity.intact).toBe(false);
    expect(report.integrity.problems.join(" ")).toMatch(/altered|count mismatch|does not match/i);
  });

  test("describes the newest run only, so a report cannot mix two scans", async () => {
    const { t0, assessmentId } = await seedWithTwoFindings();

    const rerun = consoleResult(assessmentId, ANALYST.subject);
    rerun.run.id = "RUN-SECOND";
    rerun.run.startedAt = new Date(NOW + 60_000).toISOString();
    rerun.toolVersion = "10.0.0";
    await t0.mutation(internal.securescan.assessments.recordRun, {
      ownerUserId: ANALYST.subject,
      result: JSON.stringify(rerun),
    });

    const analyst = await t0.withIdentity(ANALYST);
    const report = await analyst.query(api.securescan.console.report, { assessmentId });

    expect(report.run?.runId).toBe("RUN-SECOND");
    expect(report.run?.toolVersion).toBe("10.0.0");
    expect(report.run?.runCount).toBe(2);
  });

  test("requires membership and refuses a caller with none", async () => {
    const { t0, assessmentId } = await seedWithTwoFindings();

    await expect(t0.query(api.securescan.console.report, { assessmentId })).rejects.toThrow();
    const nobody = await t0.withIdentity(NOBODY);
    await expect(nobody.query(api.securescan.console.report, { assessmentId })).rejects.toThrow();
  });

  test("a member with the viewer role may read the report", async () => {
    const { t0, assessmentId } = await seedWithTwoFindings();

    // Reading a report is a read, and a VIEWER holds workspace-wide read even
    // though the assessment belongs to somebody else.
    const asViewer = await t0.withIdentity(VIEWER);
    const report = await asViewer.query(api.securescan.console.report, { assessmentId });
    expect(report.role).toBe("VIEWER");
    expect(report.assessment.ownerUserId).toBe(ANALYST.subject);
  });

  test("refuses an assessment that does not exist", async () => {
    const { analyst } = await seedWithTwoFindings();
    await expect(
      analyst.query(api.securescan.console.report, { assessmentId: "ss_assessment_missing" }),
    ).rejects.toThrow();
  });
});
