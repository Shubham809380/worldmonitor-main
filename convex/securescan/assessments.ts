import { ConvexError, v } from "convex/values";
import type { Doc } from "../_generated/dataModel";
import { internalMutation, query, type MutationCtx } from "../_generated/server";
import { requireUserId } from "../lib/auth";
import { authorize, type Actor } from "../../server/securescan/identity";
import {
  appendAudit,
  attestedSource,
  requireMemberRole,
  sha256Hex,
} from "./_shared";
import { createAssessment } from "./_lifecycle";
import type { AssessmentResult } from "../../server/securescan/types";

async function loadAssessment(
  ctx: Parameters<typeof requireMemberRole>[0],
  assessmentId: string,
): Promise<Doc<"securescanAssessments">> {
  const row = await ctx.db
    .query("securescanAssessments")
    .withIndex("by_assessmentId", (q) => q.eq("assessmentId", assessmentId))
    .unique();
  if (!row) throw new ConvexError("SECURESCAN_ASSESSMENT_NOT_FOUND");
  return row;
}

type RunWriter = MutationCtx;

/**
 * Writes one completed engine run into the assessment it belongs to.
 *
 * Both the internal mutation and the runner bridge call this, rather than each
 * having their own copy. Two copies of the persistence rules would be free to
 * disagree about dedup, state preservation or audit wording, and the difference
 * would only surface as a finding that reappears or an analyst's score silently
 * reset — the kind of defect nobody can diagnose from the database alone.
 */
async function persistRun(
  ctx: RunWriter,
  args: { ownerUserId: string; result: string },
): Promise<{
  runId: string;
  counts: Record<string, number>;
  findings: number;
  resultDigest: string;
}> {
  const result = JSON.parse(args.result) as AssessmentResult;
  const assessmentId = result.assessment.id;
  const assessment = await loadAssessment(ctx, assessmentId);

  if (assessment.ownerUserId !== args.ownerUserId) {
    throw new ConvexError("SECURESCAN_OWNER_MISMATCH");
  }

  const now = Date.now();
  const runId = result.run.id;

  const counts = {
    pass: result.tests.filter((t) => t.status === "PASS").length,
    fail: result.tests.filter((t) => t.status === "FAIL").length,
    inconclusive: result.tests.filter((t) => t.status === "INCONCLUSIVE").length,
    notTested: result.tests.filter((t) => t.status === "NOT_TESTED").length,
    skippedOutOfScope: result.tests.filter((t) => t.status === "SKIPPED_OUT_OF_SCOPE").length,
  };

  await ctx.db.insert("securescanRuns", {
    assessmentId,
    runId,
    ownerUserId: args.ownerUserId,
    state: result.run.finishedAt === null ? "RUNNING" : "COMPLETED",
    startedAt: Date.parse(result.run.startedAt),
    ...(result.run.finishedAt ? { finishedAt: Date.parse(result.run.finishedAt) } : {}),
    modulesRun: result.run.progress
      .filter((p) => p.status === "COMPLETE")
      .map((p) => p.module),
    counts,
    // An aborted or unfinished run must say so; silently reporting the partial
    // counts as a completed assessment is the failure mode this guards.
    ...(result.run.finishedAt === null
      ? { abortReason: "Run did not finish; counts below are partial." }
      : {}),
    ...(result.targetRevision ? { targetRevision: result.targetRevision } : {}),
    toolVersion: result.toolVersion,
  });
    for (const test of result.tests) {
      await ctx.db.insert("securescanTests", {
        assessmentId,
        runId,
        testId: test.testId,
        module: test.module,
        category: test.category,
        component: test.component,
        control: test.control,
        target: test.target,
        ...(test.boundary ? { boundary: test.boundary } : {}),
        expected: test.expected,
        observed: test.observed,
        status: test.status,
        confidence: test.confidence,
        evidenceIds: [...test.evidenceIds],
        notes: [...test.notes],
      });
    }

    for (const item of result.evidence) {
      await ctx.db.insert("securescanEvidence", {
        assessmentId,
        evidenceId: item.evidenceId,
        ...(item.testId ? { testId: item.testId } : {}),
        type: item.type,
        description: item.description,
        payload: JSON.stringify(item.payload),
        sha256: item.sha256,
        producedBy: item.producedBy,
        targetEnvironment: item.targetEnvironment,
        ...(item.sourceLocation ? { sourceLocation: item.sourceLocation } : {}),
        collectedAt: Date.parse(item.collectedAt),
      });
    }

    const startedAt = Date.parse(result.assessment.createdAt);
    for (const finding of result.findings) {
      // A re-run of the same assessment re-observes the same weakness and
      // produces the same `findingId`, because finding ids are derived from the
      // fingerprint. Inserting a second row would break every `by_findingId`
      // lookup, which uses `.unique()`. So a re-observation updates the existing
      // candidate rather than duplicating it.
      const existing = await ctx.db
        .query("securescanFindings")
        .withIndex("by_findingId", (q) => q.eq("findingId", finding.id))
        .unique();

      const field = {
        title: finding.title,
        category: finding.category,
        component: finding.component,
        node: finding.node,
        // The engine allows a finding with no boundary (a weakness entirely
        // inside one component). The column is NOT NULL, so that case is
        // recorded explicitly rather than as an empty string that would read
        // as a real boundary id.
        boundary: finding.boundary ?? "none",
        control: finding.control,
        confidence: finding.confidence,
        description: finding.description,
        rootCause: finding.rootCause,
        rootCauseId: finding.rootCauseId,
        businessImpact: finding.businessImpact,
        risk: JSON.stringify(finding.risk),
        affectedEndpoints: [...finding.affectedEndpoints],
        evidenceIds: [...finding.evidenceIds],
        fingerprint: finding.fingerprint,
        historicalStatus: finding.historicalStatus,
        runId,
        updatedAt: now,
      };

      if (existing) {
        // A candidate that an analyst has not yet worked is refreshed wholesale.
        // One that has been carried past CANDIDATE keeps its state and any
        // scored severity: a fresh observation must not silently discard an
        // analyst's judgement, and a re-run is not a licence to reset a finding
        // that is already under remediation.
        const untouched = existing.state === "CANDIDATE";
        await ctx.db.patch(existing._id, {
          ...field,
          ...(untouched
            ? { severity: finding.severity, risk: JSON.stringify(finding.risk) }
            : { severity: existing.severity, risk: existing.risk }),
        });
        await ctx.db.insert("securescanFindingEvents", {
          assessmentId,
          findingId: finding.id,
          kind: "RE_OBSERVED",
          fromState: existing.state,
          toState: existing.state,
          actorUserId: "engine",
          note: `Re-observed by run ${runId}.`,
          at: now,
        });
        continue;
      }

      await ctx.db.insert("securescanFindings", {
        assessmentId,
        findingId: finding.id,
        ownerUserId: args.ownerUserId,
        ...field,
        createdAt: startedAt,
        updatedAt: startedAt,
        severity: finding.severity,
        state: finding.state,
      });
      // Every finding starts life as a recorded CREATED event, so the lifecycle
      // history is never reconstructed after the fact.
      await ctx.db.insert("securescanFindingEvents", {
        assessmentId,
        findingId: finding.id,
        kind: "CREATED",
        toState: finding.state,
        actorUserId: "engine",
        note: `Detected by module run ${runId}.`,
        at: startedAt,
      });
    }

    await ctx.db.patch(assessment._id, {
      state: result.run.finishedAt === null ? "RUNNING" : "COMPLETED",
      latestRunId: runId,
      // A finished run clears a previous abort reason; an unfinished one sets it.
      ...(result.run.finishedAt === null
        ? { abortReason: "Run did not finish; latest counts are partial." }
        : { abortReason: undefined }),
      updatedAt: now,
    });

    const source = attestedSource();
    await appendAudit(
      ctx,
      {
        assessmentId,
        // The engine is not a user and holds no role. Recording "ADMIN" here
        // would put a fabricated principal in the accountability trail.
        actorUserId: `engine:${result.toolVersion}`,
        actorRole: "SYSTEM",
        action: "run:record",
        resourceType: "run",
        resourceId: runId,
        outcome: "ALLOWED",
        reasonCode: "RUN_RECORDED",
        detail: `Run ${runId} recorded: ${counts.pass} pass, ${counts.fail} fail, ${counts.inconclusive} inconclusive, ${counts.notTested} not tested, ${counts.skippedOutOfScope} skipped; ${result.findings.length} candidate finding(s).`,
        sourceUserAgent: source.userAgent,
        sourceIp: source.ip,
      },
      now,
    );

    return {
      runId,
      counts,
      findings: result.findings.length,
      resultDigest: await sha256Hex(args.result),
    };
}

/**
 * Maps the engine's internal lifecycle onto the vocabulary the product shows.
 *
 * The stored value stays engine-native so there is one canonical transition
 * table; this is a presentation concern and nothing else may read it.
 */
export const FINDING_STATE_LABELS: Readonly<Record<string, string>> = {
  CANDIDATE: "POTENTIAL",
  VALIDATING: "POTENTIAL",
  // Deliberately not "VERIFIED". Validation means an analyst confirmed the
  // weakness is real; verification means a retest confirmed a fix works. Giving
  // both the same label would let a static candidate that a human read once
  // appear in a report with the same word as a fix that was tested and passed.
  VALIDATED: "VALIDATED",
  REMEDIATION: "IN_PROGRESS",
  RETEST_REQUIRED: "RETEST_PENDING",
  RETESTING: "RETEST_PENDING",
  VERIFIED: "VERIFIED",
  FALSE_POSITIVE: "FALSE_POSITIVE",
  ACCEPTED_RISK: "ACCEPTED_RISK",
  INCONCLUSIVE: "INCONCLUSIVE",
  REGRESSION: "REGRESSION",
  INFORMATIONAL: "INFORMATIONAL",
  FIXED: "FIXED",
};

/** The engine's `NONE` is the product's `INFORMATIONAL`; it is not a severity. */
export const SEVERITY_LABELS: Readonly<Record<string, string>> = {
  NONE: "INFORMATIONAL",
  LOW: "LOW",
  MEDIUM: "MEDIUM",
  HIGH: "HIGH",
  CRITICAL: "CRITICAL",
};

/**
 * Registers a target and opens its first assessment.
 *
 * Internal, and that is a security decision rather than a temporary shortcut: an
 * unguarded public "start a scan" mutation would let any signed-in member point
 * the engine at a host the owner never authorized. The product reaches this
 * through `console.startAssessment`, which validates the owner's authorization
 * note and the supplied target before calling the same shared implementation.
 *
 * The body lives in `_lifecycle.ts` so both callers share one lifecycle. This
 * internal path keeps the exact validation it has always had; the browser-facing
 * wrapper adds its own on top rather than widening this one.
 */
export const create = internalMutation({
  args: {
    name: v.string(),
    targetName: v.string(),
    targetKind: v.union(
      v.literal("REPOSITORY"),
      v.literal("DEPLOYED_APPLICATION"),
      v.literal("API"),
    ),
    repositoryUrl: v.optional(v.string()),
    baseUrl: v.optional(v.string()),
    allowlistedPaths: v.array(v.string()),
    maxRuntimeRequests: v.number(),
    authorizationNote: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    const userId = await requireUserId(ctx);
    const role = await requireMemberRole(ctx, userId);
    const actor: Actor = { userId, role };
    const decision = authorize(actor, "assessment:create", {
      id: "new",
      kind: "assessment",
    });
    if (!decision.allowed) throw new ConvexError(decision.code);

    return createAssessment(ctx, userId, role, args);
  },
});

/**
 * Owner-scoped list of assessments.
 *
 * Deliberately narrower than `get`: a colleague with membership can open an
 * assessment they were handed, but the list is what an analyst uses to find their
 * own work, and returning every colleague's assessment there would be noise at
 * best and a disclosure of in-flight investigations at worst.
 */
export const list = query({
  args: {},
  handler: async (ctx) => {
    const userId = await requireUserId(ctx);
    const role = await requireMemberRole(ctx, userId);
    const decision = authorize({ userId, role }, "assessment:read", {
      id: "list",
      kind: "assessment",
    });
    if (!decision.allowed) throw new ConvexError(decision.code);

    const rows = await ctx.db
      .query("securescanAssessments")
      .withIndex("by_owner_updatedAt", (q) => q.eq("ownerUserId", userId))
      .collect();

    return {
      role,
      assessments: rows
        .sort((a, b) => b.updatedAt - a.updatedAt)
        .map((row) => ({
          assessmentId: row.assessmentId,
          name: row.name,
          state: row.state,
          targetId: row.targetId,
          ownerUserId: row.ownerUserId,
          latestRunId: row.latestRunId ?? null,
          abortReason: row.abortReason ?? null,
          createdAt: row.createdAt,
          updatedAt: row.updatedAt,
        })),
    };
  },
});

/**
 * One assessment in full: the target it runs against, every run, its findings
 * and its test counts.
 *
 * The counts here are counted from stored rows rather than read back from the
 * run's own summary, so a summary that was written by an older engine version
 * cannot disagree with the tests that are actually in the database.
 */
export const get = query({
  args: { assessmentId: v.string() },
  handler: async (ctx, args) => {
    const userId = await requireUserId(ctx);
    const role = await requireMemberRole(ctx, userId);
    const actor: Actor = { userId, role };
    const decision = authorize(actor, "assessment:read", {
      id: args.assessmentId,
      kind: "assessment",
    });
    if (!decision.allowed) throw new ConvexError(decision.code);

    const assessment = await loadAssessment(ctx, args.assessmentId);
    const target = await ctx.db
      .query("securescanTargets")
      .withIndex("by_targetId", (q) => q.eq("targetId", assessment.targetId))
      .unique();
    const runs = await ctx.db
      .query("securescanRuns")
      .withIndex("by_assessment_startedAt", (q) =>
        q.eq("assessmentId", args.assessmentId),
      )
      .collect();
    const findings = await ctx.db
      .query("securescanFindings")
      .withIndex("by_assessmentId", (q) =>
        q.eq("assessmentId", args.assessmentId),
      )
      .collect();
    const tests = await ctx.db
      .query("securescanTests")
      .withIndex("by_assessment_status", (q) =>
        q.eq("assessmentId", args.assessmentId),
      )
      .collect();

    const byState = new Map<string, number>();
    for (const finding of findings) {
      byState.set(finding.state, (byState.get(finding.state) ?? 0) + 1);
    }

    return {
      role,
      assessment: {
        assessmentId: assessment.assessmentId,
        name: assessment.name,
        state: assessment.state,
        targetId: assessment.targetId,
        ownerUserId: assessment.ownerUserId,
        latestRunId: assessment.latestRunId ?? null,
        abortReason: assessment.abortReason ?? null,
        auditHeadHash: assessment.auditHeadHash,
        auditEntryCount: assessment.auditEntryCount,
        createdAt: assessment.createdAt,
        updatedAt: assessment.updatedAt,
      },
      target: target
        ? {
            targetId: target.targetId,
            name: target.name,
            kind: target.kind,
            state: target.state,
            repositoryUrl: target.repositoryUrl ?? null,
            baseUrl: target.baseUrl ?? null,
            allowlistedPaths: [...target.allowlistedPaths],
            maxRuntimeRequests: target.maxRuntimeRequests,
            createdAt: target.createdAt,
            updatedAt: target.updatedAt,
          }
        : null,
      runs: runs.map((row) => ({
        runId: row.runId,
        state: row.state,
        startedAt: row.startedAt,
        finishedAt: row.finishedAt ?? null,
        modulesRun: [...row.modulesRun],
        counts: row.counts,
        abortReason: row.abortReason ?? null,
        targetRevision: row.targetRevision ?? null,
        toolVersion: row.toolVersion,
      })),
      findings: findings.map((row) => ({
        findingId: row.findingId,
        title: row.title,
        state: row.state,
        stateLabel: FINDING_STATE_LABELS[row.state] ?? row.state,
        severity: row.severity,
        severityLabel: SEVERITY_LABELS[row.severity] ?? row.severity,
        confidence: row.confidence,
        category: row.category,
        component: row.component,
        control: row.control,
        affectedEndpoints: [...row.affectedEndpoints],
        evidenceCount: row.evidenceIds.length,
        updatedAt: row.updatedAt,
      })),
      testCounts: {
        total: tests.length,
        pass: tests.filter((t) => t.status === "PASS").length,
        fail: tests.filter((t) => t.status === "FAIL").length,
        inconclusive: tests.filter((t) => t.status === "INCONCLUSIVE").length,
        notTested: tests.filter(
          (t) => t.status === "NOT_TESTED" || t.status === "SKIPPED_OUT_OF_SCOPE",
        ).length,
      },
      findingCountsByState: Object.fromEntries(byState),
    };
  },
});

/**
 * Persists one completed engine run. Internal only.
 *
 * The caller is the trusted runner that already executed the engine against a
 * scope-checked target; letting a browser client post results would make every
 * finding forgeable. The runner reaches the same code through the HTTP bridge in
 * `runner.ts`, which is why both delegate to `persistRun` rather than
 * reimplementing it.
 */
export const recordRun = internalMutation({
  args: {
    ownerUserId: v.string(),
    result: v.string(),
  },
  handler: async (ctx, args) => persistRun(ctx, args),
});
