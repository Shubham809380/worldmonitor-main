import { convexTest } from "convex-test";
import { describe, expect, test } from "vitest";
import schema from "../schema";
import { internal } from "../_generated/api";
import {
  handleRetestSubmission,
  handleRunSubmission,
  type RunnerContext,
  secretMatches,
} from "../securescan/runner";
import type { AssessmentResult } from "../../server/securescan/types";

/**
 * Runner bridge.
 *
 * The bridge is the only way a real out-of-process scan reaches the console, and
 * it is also the only place a secret authorises a write. The tests here are
 * about the shape of that authorisation: an unconfigured deployment writes
 * nothing, a wrong key writes nothing, and a correct key still cannot write to an
 * assessment it does not own.
 */

const modules = import.meta.glob("../**/*.ts");

const ANALYST = { subject: "user-analyst", tokenIdentifier: "clerk|user-analyst" };
const OTHER = { subject: "user-other", tokenIdentifier: "clerk|user-other" };
const NOW = Date.parse("2026-09-01T00:00:00.000Z");
const KEY = "runner-key-for-tests";

function t() {
  return convexTest(schema, modules);
}

const CREATE_ARGS = {
  name: "Bridge assessment",
  targetName: "worldmonitor",
  targetKind: "REPOSITORY" as const,
  repositoryUrl: "https://github.com/koala73/worldmonitor",
  allowlistedPaths: ["api/"],
  maxRuntimeRequests: 0,
};

async function seed() {
  const t0 = t();
  await t0.mutation(internal.securescan.findings.setRole, {
    userId: ANALYST.subject,
    role: "SECURITY_ANALYST",
  });
  const client = await t0.withIdentity(ANALYST);
  const { assessmentId } = await client.mutation(
    internal.securescan.assessments.create,
    CREATE_ARGS,
  );
  return { t0, client, assessmentId };
}

function result(assessmentId: string, ownerUserId: string): string {
  const at = new Date(NOW).toISOString();
  return JSON.stringify({
    assessment: {
      id: assessmentId,
      name: "Bridge assessment",
      state: "COMPLETED",
      scope: {
        targetId: "ss_target_x",
        targetKind: "REPOSITORY",
        allowedHosts: [],
        allowedPaths: ["api/"],
        maxRequests: 0,
        intensity: "PASSIVE",
        reason: "Bridge",
      },
      moduleNames: ["security-headers"],
      createdBy: ownerUserId,
      createdAt: at,
      startedAt: at,
      finishedAt: at,
      authorizationNote: "Bridge",
    },
    run: {
      id: "RUN-BRIDGE",
      assessmentId,
      startedAt: at,
      finishedAt: at,
      progress: [],
      requestsIssued: 0,
      errorCount: 0,
      warningCount: 0,
      durationMs: 0,
    },
    architecture: { nodes: [], edges: [], boundaries: [] },
    surface: [],
    tests: [],
    controls: [],
    coverage: [],
    dependencies: [],
    regressionTests: [],
    remediations: [],
    retests: [],
    findings: [],
    evidence: [],
    notTested: [],
    toolVersion: "1.0.0",
    targetRevision: "abc123",
  } as unknown as AssessmentResult);
}

/**
 * A run payload that also carries a candidate finding, so the retest bridge can
 * be exercised end to end rather than only at its authorization layer.
 */
function resultWithFinding(assessmentId: string, ownerUserId: string): string {
  const base = JSON.parse(result(assessmentId, ownerUserId)) as {
    tests: unknown[];
    findings: unknown[];
  };
  base.tests = [
    {
      testId: "TEST-CSP",
      assessmentId,
      runId: "RUN-BRIDGE",
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
      evidenceIds: [],
      notes: [],
      requiresCapability: "NONE",
    },
  ];
  base.findings = [
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
      evidenceIds: [],
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
  ];
  return JSON.stringify(base);
}

/**
 * Drives FND-1 to RETEST_REQUIRED through the real transitions.
 *
 * The retest bridge is only meaningful against a finding that is actually
 * awaiting a retest, and reaching that state the legal way is the point: a
 * fixture that jumped the state machine would test the bridge against a state
 * the product can never be in.
 */
async function seedAwaitingRetest() {
  const { t0, client, assessmentId } = await seed();
  const ctx = runnerContext(
    t0,
    { ownerUserId: ANALYST.subject, result: resultWithFinding(assessmentId, ANALYST.subject) },
    KEY,
  );
  const recorded = await handleRunSubmission(ctx, { SECURESCAN_RUNNER_KEY: KEY });
  expect(recorded.status).toBe(200);

  await client.mutation(internal.securescan.findings.transition, {
    findingId: "FND-1",
    to: "VALIDATING",
    reason: "reproducing against staging",
  });
  await client.mutation(internal.securescan.findings.transition, {
    findingId: "FND-1",
    to: "VALIDATED",
    reason: "base-uri is absent from the callback sandbox policy",
  });
  const remediated = await client.mutation(internal.securescan.findings.recordRemediation, {
    findingId: "FND-1",
    summary: "added base-uri to the callback policy",
  });
  expect(remediated.ok).toBe(true);
  // The engine's transition table has no REMEDIATION -> REGRESSION edge, so a fix
  // has to be queued for retest first. That step is part of the lifecycle.
  const queued = await client.mutation(internal.securescan.findings.transition, {
    findingId: "FND-1",
    to: "RETEST_REQUIRED",
    reason: "deployed, scheduling a retest",
  });
  expect(queued.ok).toBe(true);
  return { t0, client, assessmentId };
}

function runnerContext(
  t0: ReturnType<typeof convexTest>,
  body: unknown,
  key: string | null,
): RunnerContext {
  const headers = new Headers({ "content-type": "application/json" });
  if (key !== null) headers.set("x-wm-securescan-runner-key", key);
  return {
    request: new Request("https://bridge.test/submitRun", {
      method: "POST",
      headers,
      body: JSON.stringify(body),
    }),
    runMutation: t0.runMutation.bind(t0) as unknown as RunnerContext["runMutation"],
  };
}

async function runCount(t0: ReturnType<typeof convexTest>, assessmentId: string): Promise<number> {
  const rows = await t0.run(async (ctx) =>
    ctx.db
      .query("securescanRuns")
      .withIndex("by_assessment_startedAt", (q) => q.eq("assessmentId", assessmentId))
      .collect(),
  );
  return rows.length;
}

describe("runner key comparison", () => {
  test("an unconfigured secret never matches, including the empty string", async () => {
    // This is the fail-closed property: if the deployment has no key, presenting
    // nothing must not be treated as presenting the right thing.
    expect(await secretMatches("", "")).toBe(false);
    expect(await secretMatches("anything", "")).toBe(false);
  });

  test("a correct key matches and a near miss does not", async () => {
    expect(await secretMatches(KEY, KEY)).toBe(true);
    expect(await secretMatches(`${KEY}x`, KEY)).toBe(false);
    expect(await secretMatches(KEY.slice(0, -1), KEY)).toBe(false);
    expect(await secretMatches("", KEY)).toBe(false);
  });

  test("length differences do not throw", async () => {
    // A fixed-length comparison means an attacker cannot learn the secret's
    // length by sending a differently sized value and watching for an error.
    await expect(secretMatches("a", "a".repeat(4096))).resolves.toBe(false);
  });
});

describe("run submission bridge", () => {
  test("refuses every request when no runner key is configured", async () => {
    const { t0, assessmentId } = await seed();
    const ctx = runnerContext(
      t0,
      { ownerUserId: ANALYST.subject, result: result(assessmentId, ANALYST.subject) },
      null,
    );

    const response = await handleRunSubmission(ctx, { SECURESCAN_RUNNER_KEY: undefined });
    expect(response.status).toBe(503);
    expect(((await response.json()) as { error: string }).error).toBe(
      "SECURESCAN_RUNNER_KEY_NOT_CONFIGURED",
    );
    // Nothing was written: the assessment is still waiting for its first run.
    expect(await runCount(t0, assessmentId)).toBe(0);
  });

  test("refuses a request that presents the wrong key", async () => {
    const { t0, assessmentId } = await seed();
    const ctx = runnerContext(
      t0,
      { ownerUserId: ANALYST.subject, result: result(assessmentId, ANALYST.subject) },
      "wrong-key",
    );

    const response = await handleRunSubmission(ctx, { SECURESCAN_RUNNER_KEY: KEY });
    expect(response.status).toBe(401);
    expect(await runCount(t0, assessmentId)).toBe(0);
  });

  test("accepts a correctly keyed run and records it against the assessment", async () => {
    const { t0, assessmentId } = await seed();
    const ctx = runnerContext(
      t0,
      { ownerUserId: ANALYST.subject, result: result(assessmentId, ANALYST.subject) },
      KEY,
    );

    const response = await handleRunSubmission(ctx, { SECURESCAN_RUNNER_KEY: KEY });
    expect(response.status).toBe(200);
    const body = (await response.json()) as { runId: string; resultDigest: string };
    expect(body.runId).toBe("RUN-BRIDGE");
    // A digest of the payload is returned so a runner can prove what it sent.
    expect(body.resultDigest).toMatch(/^[0-9a-f]{64}$/);

    const client = await t0.withIdentity(ANALYST);
    const detail = await client.query(internal.securescan.assessments.get, { assessmentId });
    expect(detail.assessment.state).toBe("COMPLETED");
    expect(detail.assessment.latestRunId).toBe("RUN-BRIDGE");
  });

  test("the recorded run is attributable to the engine, not to a fabricated user", async () => {
    const { t0, assessmentId } = await seed();
    const ctx = runnerContext(
      t0,
      { ownerUserId: ANALYST.subject, result: result(assessmentId, ANALYST.subject) },
      KEY,
    );
    await handleRunSubmission(ctx, { SECURESCAN_RUNNER_KEY: KEY });

    const entries = await t0.run(async (ctx2) =>
      ctx2.db
        .query("securescanAuditLog")
        .withIndex("by_assessment_seq", (q) => q.eq("assessmentId", assessmentId))
        .collect(),
    );
    const recorded = entries.find((entry) => entry.reasonCode === "RUN_RECORDED");
    // The engine is not a user and holds no role. Recording "ADMIN" would put a
    // fabricated principal in the accountability trail.
    expect(recorded?.actorRole).toBe("SYSTEM");
    expect(recorded?.actorUserId).toMatch(/^engine:/);
  });

  test("a correct key still cannot record against an assessment the runner does not own", async () => {
    // The key authorises the runner, not the owner. Holding it must not be a
    // licence to write into somebody else's assessment.
    const { t0, assessmentId } = await seed();
    const ctx = runnerContext(
      t0,
      { ownerUserId: OTHER.subject, result: result(assessmentId, ANALYST.subject) },
      KEY,
    );

    const response = await handleRunSubmission(ctx, { SECURESCAN_RUNNER_KEY: KEY });
    expect(response.status).toBe(409);
    expect(((await response.json()) as { error: string }).error).toBe("SECURESCAN_OWNER_MISMATCH");
    expect(await runCount(t0, assessmentId)).toBe(0);
  });

  test("a run for an assessment that does not exist is a 404, not a write", async () => {
    const { t0 } = await seed();
    const ctx = runnerContext(
      t0,
      { ownerUserId: ANALYST.subject, result: result("ss_assessment_missing", ANALYST.subject) },
      KEY,
    );

    const response = await handleRunSubmission(ctx, { SECURESCAN_RUNNER_KEY: KEY });
    expect(response.status).toBe(404);
  });

  test("a payload missing its owner or result is rejected before any write", async () => {
    const { t0 } = await seed();
    for (const body of [{ result: "{}" }, { ownerUserId: ANALYST.subject }, {}]) {
      const ctx = runnerContext(t0, body, KEY);
      const response = await handleRunSubmission(ctx, { SECURESCAN_RUNNER_KEY: KEY });
      expect(response.status).toBe(400);
    }
    const rows = await t0.run(async (ctx2) => ctx2.db.query("securescanRuns").collect());
    expect(rows).toHaveLength(0);
  });

  test("a malformed body is a 400 rather than a crash", async () => {
    const { t0 } = await seed();
    const ctx: RunnerContext = {
      request: new Request("https://bridge.test/submitRun", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-wm-securescan-runner-key": KEY,
        },
        body: "{not json",
      }),
      runMutation: t0.runMutation.bind(t0) as unknown as RunnerContext["runMutation"],
    };
    const response = await handleRunSubmission(ctx, { SECURESCAN_RUNNER_KEY: KEY });
    expect(response.status).toBe(400);
  });
});

/**
 * The retest bridge.
 *
 * `recordRetestResult` is internal, so this route is the only way a retest
 * verdict can ever be recorded -- which makes it the place a compromised runner
 * key would aim at. The tests are about what the bridge is *able* to do: point at
 * a run, and nothing else.
 */
describe("retest submission bridge", () => {
  function retestCtx(
    t0: ReturnType<typeof convexTest>,
    body: unknown,
    key: string | null,
  ): RunnerContext {
    const headers = new Headers({ "content-type": "application/json" });
    if (key !== null) headers.set("x-wm-securescan-runner-key", key);
    return {
      request: new Request("https://bridge.test/retest", {
        method: "POST",
        headers,
        body: JSON.stringify(body),
      }),
      runMutation: t0.runMutation.bind(t0) as unknown as RunnerContext["runMutation"],
    };
  }

  async function findingState(t0: ReturnType<typeof convexTest>) {
    const row = await t0.run(async (ctx) =>
      ctx.db
        .query("securescanFindings")
        .withIndex("by_findingId", (q) => q.eq("findingId", "FND-1"))
        .unique(),
    );
    return row?.state;
  }

  test("refuses every retest when no runner key is configured", async () => {
    const { t0 } = await seedAwaitingRetest();
    const ctx = retestCtx(t0, { findingId: "FND-1", runId: "RUN-BRIDGE" }, null);

    const response = await handleRetestSubmission(ctx, { SECURESCAN_RUNNER_KEY: undefined });
    expect(response.status).toBe(503);
    expect(((await response.json()) as { error: string }).error).toBe(
      "SECURESCAN_RUNNER_KEY_NOT_CONFIGURED",
    );
    // Nothing was judged: the finding is still waiting for a real retest.
    expect(await findingState(t0)).toBe("RETEST_REQUIRED");
  });

  test("refuses a retest that presents the wrong key", async () => {
    const { t0 } = await seedAwaitingRetest();
    const ctx = retestCtx(
      t0,
      { findingId: "FND-1", runId: "RUN-BRIDGE" },
      `${KEY}-almost`,
    );

    const response = await handleRetestSubmission(ctx, { SECURESCAN_RUNNER_KEY: KEY });
    expect(response.status).toBe(401);
    expect(await findingState(t0)).toBe("RETEST_REQUIRED");
  });

  test("a payload missing a finding or a run is rejected before any write", async () => {
    const { t0 } = await seedAwaitingRetest();
    for (const body of [{ runId: "RUN-BRIDGE" }, { findingId: "FND-1" }, { findingId: "  " }]) {
      const ctx = retestCtx(t0, body, KEY);
      const response = await handleRetestSubmission(ctx, { SECURESCAN_RUNNER_KEY: KEY });
      expect(response.status).toBe(400);
    }
    expect(await findingState(t0)).toBe("RETEST_REQUIRED");
  });

  test("a malformed retest body is a 400 rather than a crash", async () => {
    const { t0 } = await seedAwaitingRetest();
    const ctx: RunnerContext = {
      request: new Request("https://bridge.test/retest", {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-wm-securescan-runner-key": KEY,
        },
        body: "{not json",
      }),
      runMutation: t0.runMutation.bind(t0) as unknown as RunnerContext["runMutation"],
    };
    const response = await handleRetestSubmission(ctx, { SECURESCAN_RUNNER_KEY: KEY });
    expect(response.status).toBe(400);
  });

  test("a runner cannot submit a verdict, only point at a run", async () => {
    // The strongest claim this bridge makes: holding the key is not a licence to
    // declare a defect fixed. The submitted `passed`/`state` fields are not part
    // of the request contract, so they are dropped and the state is derived from
    // the run's own stored tests.
    const { t0 } = await seedAwaitingRetest();

    // The run recorded FAIL, so the derived verdict has to be REGRESSION even
    // though the payload insists the fix is verified.
    const ctx = retestCtx(
      t0,
      { findingId: "FND-1", runId: "RUN-BRIDGE", passed: true, state: "VERIFIED" },
      KEY,
    );

    const response = await handleRetestSubmission(ctx, { SECURESCAN_RUNNER_KEY: KEY });
    expect(response.status).toBe(200);
    const body = (await response.json()) as { state: string };
    // A run whose check failed says the defect persists. The payload's claim is
    // not consulted.
    expect(body.state).toBe("REGRESSION");
    expect(await findingState(t0)).toBe("REGRESSION");
  });

  test("a run the server refuses is a 409 carrying the reason, not a 500", async () => {
    const { t0 } = await seedAwaitingRetest();
    // RUN-BRIDGE is the only recorded run, so naming an absent one is a
    // deliberate refusal by the state machine rather than a crash.
    const ctx = retestCtx(
      t0,
      { findingId: "FND-1", runId: "RUN-NEVER-EXISTED", notes: "pointing at nothing" },
      KEY,
    );

    const response = await handleRetestSubmission(ctx, { SECURESCAN_RUNNER_KEY: KEY });
    expect(response.status).toBe(409);
    const body = (await response.json()) as { error: string; reason: string };
    expect(body.error).toBe("SECURESCAN_RETEST_RUN_NOT_FOUND");
    expect(body.reason).toContain("RUN-NEVER-EXISTED");
    expect(await findingState(t0)).toBe("RETEST_REQUIRED");
  });

  test("a finding that does not exist is a 404", async () => {
    const { t0 } = await seedAwaitingRetest();
    const ctx = retestCtx(
      t0,
      { findingId: "FND-NOT-THERE", runId: "RUN-BRIDGE" },
      KEY,
    );

    const response = await handleRetestSubmission(ctx, { SECURESCAN_RUNNER_KEY: KEY });
    expect(response.status).toBe(404);
    expect(((await response.json()) as { error: string }).error).toBe(
      "SECURESCAN_FINDING_NOT_FOUND",
    );
  });

  test("a retest through the route is attributed to the engine end to end", async () => {
    // The bridge adds no actor of its own, so this asserts the attribution
    // survives the whole path rather than only the mutation's own unit test.
    const { t0, assessmentId } = await seedAwaitingRetest();
    const ctx = retestCtx(
      t0,
      { findingId: "FND-1", runId: "RUN-BRIDGE", notes: "re-ran the header checks" },
      KEY,
    );

    const response = await handleRetestSubmission(ctx, { SECURESCAN_RUNNER_KEY: KEY });
    expect(response.status).toBe(200);

    const entries = await t0.run(async (ctx2) =>
      ctx2.db
        .query("securescanAuditLog")
        .withIndex("by_assessment_seq", (q) => q.eq("assessmentId", assessmentId))
        .collect(),
    );
    const verdict = entries.find((entry) => entry.reasonCode === "RETEST_FAILED");
    expect(verdict?.actorRole).toBe("SYSTEM");
    expect(verdict?.actorUserId).toBe("engine");
    // The finding's owner is never credited with judging their own remediation.
    expect(verdict?.actorUserId).not.toBe(ANALYST.subject);
  });

  test("replaying the same run through the route is refused", async () => {
    const { t0 } = await seedAwaitingRetest();
    const body = { findingId: "FND-1", runId: "RUN-BRIDGE", notes: "first submission" };

    const first = await handleRetestSubmission(retestCtx(t0, body, KEY), {
      SECURESCAN_RUNNER_KEY: KEY,
    });
    expect(first.status).toBe(200);

    // Same run, second submission. The finding is already REGRESSION, so this is
    // refused whichever guard catches it -- the point is that it is refused.
    const second = await handleRetestSubmission(retestCtx(t0, body, KEY), {
      SECURESCAN_RUNNER_KEY: KEY,
    });
    expect(second.status).toBe(409);
    const parsed = (await second.json()) as { error: string };
    expect([
      "SECURESCAN_RETEST_ALREADY_RECORDED",
      "INVALID_TRANSITION",
    ]).toContain(parsed.error);
  });
});
