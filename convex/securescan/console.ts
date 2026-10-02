/**
 * WM SecureScan — console read model.
 *
 * The console needs aggregates that span assessments (the dashboard), a finding
 * list that is not scoped to one assessment (the findings page), and a report
 * view that is a faithful rendering of what was recorded rather than a
 * re-analysis. All three live here so the shape of "what the operator sees" is
 * defined in one place and the mutations stay focused on lifecycle.
 *
 * Two rules run through every query in this file:
 *
 *  1. **No number here is computed from a default.** Counts come from stored
 *     rows. An assessment with no run reports zero tests because it has none,
 *     not because a default said zero, and the response says which.
 *  2. **Nothing is derived that the run did not observe.** The severity mix is
 *     counted from stored severities, and unscored candidates appear in their
 *     own bucket rather than being folded into "no severity", so a console can
 *     never make a backlog of unvalidated candidates look like a clean board.
 */

import { ConvexError, v } from "convex/values";
import { mutation, query } from "../_generated/server";
import { resolveUserId, requireUserId } from "../lib/auth";
import { authorize, type Actor, type Role } from "../../server/securescan/identity";
import { FINDING_STATE_LABELS, SEVERITY_LABELS } from "./assessments";
import { ASSESSMENT_STATES, FINDING_STATES, SEVERITIES } from "./validators";
import { requireMemberRole, resolveRole, verifyAuditChain } from "./_shared";
import { createAssessment, normaliseAllowlist, validateCreateRequest } from "./_lifecycle";

/** Cap on rows any single console list will return, so a large deployment cannot stall a page. */
const MAX_ROWS = 500;

function countBy<T extends string>(keys: readonly T[], values: readonly T[]): Record<T, number> {
  const counts = {} as Record<T, number>;
  for (const key of keys) counts[key] = 0;
  for (const value of values) counts[value] = (counts[value] ?? 0) + 1;
  return counts;
}

async function actorFor(ctx: Parameters<typeof requireMemberRole>[0]): Promise<Actor> {
  const userId = await requireUserId(ctx);
  const role = await requireMemberRole(ctx, userId);
  return { userId, role };
}

/**
 * The caller's own identity, with no membership requirement.
 *
 * This exists because "not authenticated" and "authenticated but not a member"
 * are different facts and a console has to be able to tell them apart. Every
 * data query refuses a non-member, so before this query there was no authorized
 * way for the shell to learn *who* it was refusing — a signed-in caller with no
 * SecureScan grant was indistinguishable from an anonymous one, and the shell
 * had to guess. Guessing wrong is how a refusal screen ends up claiming to be
 * a backend outage.
 *
 * It reports only the caller's own id and their own grant, so it discloses
 * nothing about other members and no assessment data. `signedIn` is the
 * authoritative answer to "is there a session"; `role` is null both for an
 * anonymous caller and for one with no grant, which is why `signedIn` is a
 * separate field rather than being inferred from `role`.
 */
export const viewer = query({
  args: {},
  handler: async (ctx) => {
    const userId = await resolveUserId(ctx);
    if (!userId) {
      return { signedIn: false as const, userId: null, role: null };
    }
    const role = await resolveRole(ctx, userId);
    return { signedIn: true as const, userId, role };
  },
});

/**
 * Dashboard aggregate.
 *
 * Everything here is a count over stored rows. There is no scoring formula and
 * no "posture score": a number that looks like a grade but is not derived from a
 * published methodology is exactly the kind of thing this product must not
 * publish, so the dashboard reports what exists and lets the operator read it.
 */
export const dashboard = query({
  args: {},
  handler: async (ctx) => {
    const actor = await actorFor(ctx);
    const read = authorize(actor, "assessment:read", { id: "dashboard", kind: "assessment" });
    if (!read.allowed) throw new ConvexError(read.code);

    const [assessments, findings, runs, evidence, tests, members] = await Promise.all([
      ctx.db.query("securescanAssessments").collect(),
      ctx.db.query("securescanFindings").take(MAX_ROWS),
      ctx.db.query("securescanRuns").take(MAX_ROWS),
      ctx.db.query("securescanEvidence").take(MAX_ROWS),
      ctx.db.query("securescanTests").take(MAX_ROWS),
      ctx.db.query("securescanMembers").collect(),
    ]);

    const openStates = new Set([
      "CANDIDATE",
      "VALIDATING",
      "VALIDATED",
      "REMEDIATION",
      "RETEST_REQUIRED",
      "REGRESSION",
    ]);
    const open = findings.filter((row) => openStates.has(row.state as (typeof FINDING_STATES)[number]));
    const closed = findings.filter((row) => !openStates.has(row.state as (typeof FINDING_STATES)[number]));

    const lastRun = runs
      .filter((row) => typeof row.finishedAt === "number")
      .sort((a, b) => (b.finishedAt ?? 0) - (a.finishedAt ?? 0))[0];

    return {
      role: actor.role as Role,
      userId: actor.userId,
      totals: {
        assessments: assessments.length,
        assessmentsByState: countBy(ASSESSMENT_STATES, assessments.map((row) => row.state)),
        /** Findings still moving. This is the working backlog. */
        openFindings: open.length,
        /** Findings that reached a terminal decision, in any direction. */
        closedFindings: closed.length,
        findingsByState: countBy(FINDING_STATES, findings.map((row) => row.state)),
        findingsBySeverity: countBy(SEVERITIES, findings.map((row) => row.severity)),
        /**
         * Candidates that carry no severity yet, broken out. Folding these into
         * a severity bucket would let an unvalidated backlog look identical to
         * an absence of medium-severity problems.
         */
        unscoredCandidates: findings.filter(
          (row) => row.severity === "NONE" && row.state === "CANDIDATE",
        ).length,
        runs: runs.length,
        evidence: evidence.length,
        tests: tests.length,
        /** Members with a role. A non-zero count is what makes the console usable at all. */
        members: members.length,
      },
      lastRun: lastRun
        ? {
            runId: lastRun.runId,
            assessmentId: lastRun.assessmentId,
            state: lastRun.state,
            finishedAt: lastRun.finishedAt ?? null,
            counts: lastRun.counts,
            toolVersion: lastRun.toolVersion,
          }
        : null,
      recentAssessments: assessments
        .sort((a, b) => b.updatedAt - a.updatedAt)
        .slice(0, 8)
        .map((row) => ({
          assessmentId: row.assessmentId,
          name: row.name,
          state: row.state,
          ownerUserId: row.ownerUserId,
          latestRunId: row.latestRunId ?? null,
          abortReason: row.abortReason ?? null,
          updatedAt: row.updatedAt,
          createdAt: row.createdAt,
        })),
      recentFindings: findings
        .sort((a, b) => b.updatedAt - a.updatedAt)
        .slice(0, 8)
        .map((row) => ({
          findingId: row.findingId,
          assessmentId: row.assessmentId,
          title: row.title,
          state: row.state,
          stateLabel: FINDING_STATE_LABELS[row.state] ?? row.state,
          severity: row.severity,
          severityLabel: SEVERITY_LABELS[row.severity] ?? row.severity,
          confidence: row.confidence,
          updatedAt: row.updatedAt,
        })),
    };
  },
});

/** Findings across every assessment, for the findings page. */
export const listFindings = query({
  args: {
    state: v.optional(v.union(...FINDING_STATES.map((s) => v.literal(s)))),
    severity: v.optional(v.union(...SEVERITIES.map((s) => v.literal(s)))),
    assessmentId: v.optional(v.string()),
    limit: v.optional(v.number()),
  },
  handler: async (ctx, args) => {
    const actor = await actorFor(ctx);
    const read = authorize(actor, "finding:read", { id: "findings", kind: "assessment" });
    if (!read.allowed) throw new ConvexError(read.code);

    const limit = Math.min(MAX_ROWS, Math.max(1, Math.trunc(args.limit ?? 200)));
    let rows = await ctx.db.query("securescanFindings").take(MAX_ROWS);
    if (args.assessmentId) rows = rows.filter((row) => row.assessmentId === args.assessmentId);
    if (args.state) rows = rows.filter((row) => row.state === args.state);
    if (args.severity) rows = rows.filter((row) => row.severity === args.severity);

    return {
      role: actor.role as Role,
      total: rows.length,
      findings: rows
        .sort((a, b) => b.updatedAt - a.updatedAt)
        .slice(0, limit)
        .map((row) => ({
          findingId: row.findingId,
          assessmentId: row.assessmentId,
          title: row.title,
          state: row.state,
          stateLabel: FINDING_STATE_LABELS[row.state] ?? row.state,
          severity: row.severity,
          severityLabel: SEVERITY_LABELS[row.severity] ?? row.severity,
          confidence: row.confidence,
          component: row.component,
          node: row.node,
          boundary: row.boundary,
          control: row.control,
          category: row.category,
          evidenceCount: row.evidenceIds.length,
          affectedEndpoints: [...row.affectedEndpoints],
          fingerprint: row.fingerprint,
          updatedAt: row.updatedAt,
        })),
    };
  },
});

/**
 * One finding in full: identity, the evidence it cites, the tests that produced
 * it, and its whole event history.
 *
 * The evidence is looked up by the ids the finding actually references rather
 * than "all evidence for the assessment", because a finding that can be shown
 * next to unrelated evidence is a finding whose support cannot be assessed.
 */
export const findingDetail = query({
  args: { findingId: v.string() },
  handler: async (ctx, args) => {
    const actor = await actorFor(ctx);
    const finding = await ctx.db
      .query("securescanFindings")
      .withIndex("by_findingId", (q) => q.eq("findingId", args.findingId))
      .unique();
    if (!finding) throw new ConvexError("SECURESCAN_FINDING_NOT_FOUND");

    const read = authorize(actor, "finding:read", {
      id: finding.findingId,
      kind: "finding",
      ownerId: finding.ownerUserId,
    });
    if (!read.allowed) throw new ConvexError(read.code);

    const wanted = new Set(finding.evidenceIds);
    const [allEvidence, allTests, events] = await Promise.all([
      ctx.db
        .query("securescanEvidence")
        .withIndex("by_assessmentId", (q) => q.eq("assessmentId", finding.assessmentId))
        .collect(),
      ctx.db
        .query("securescanTests")
        .withIndex("by_assessment_status", (q) => q.eq("assessmentId", finding.assessmentId))
        .collect(),
      ctx.db
        .query("securescanFindingEvents")
        .withIndex("by_findingId", (q) => q.eq("findingId", finding.findingId))
        .collect(),
    ]);

    const evidence = allEvidence.filter((row) => wanted.has(row.evidenceId));
    // The linkage runs through the evidence: a test supports this finding only if
    // it is the test that collected the evidence this finding cites.
    const testIds = new Set(
      evidence.map((row) => row.testId).filter((id): id is string => typeof id === "string" && id !== ""),
    );

    return {
      role: actor.role as Role,
      finding: {
        findingId: finding.findingId,
        assessmentId: finding.assessmentId,
        runId: finding.runId,
        title: finding.title,
        category: finding.category,
        component: finding.component,
        node: finding.node,
        boundary: finding.boundary,
        control: finding.control,
        severity: finding.severity,
        severityLabel: SEVERITY_LABELS[finding.severity] ?? finding.severity,
        confidence: finding.confidence,
        state: finding.state,
        stateLabel: FINDING_STATE_LABELS[finding.state] ?? finding.state,
        description: finding.description,
        rootCause: finding.rootCause,
        rootCauseId: finding.rootCauseId,
        businessImpact: finding.businessImpact,
        risk: JSON.parse(finding.risk) as unknown,
        affectedEndpoints: [...finding.affectedEndpoints],
        fingerprint: finding.fingerprint,
        historicalStatus: finding.historicalStatus,
        remediationSummary: finding.remediationSummary ?? null,
        remediatedAt: finding.remediatedAt ?? null,
        lastRetestState: finding.lastRetestState ?? null,
        lastRetestedAt: finding.lastRetestedAt ?? null,
        regressionTestId: finding.regressionTestId ?? null,
        createdAt: finding.createdAt,
        updatedAt: finding.updatedAt,
      },
      evidence: evidence.map((row) => ({
        evidenceId: row.evidenceId,
        testId: row.testId ?? null,
        type: row.type,
        description: row.description,
        payload: row.payload,
        sha256: row.sha256,
        producedBy: row.producedBy,
        sourceLocation: row.sourceLocation ?? null,
        targetEnvironment: row.targetEnvironment,
        collectedAt: row.collectedAt,
      })),
      tests: allTests
        .filter((row) => testIds.has(row.testId))
        .map((row) => ({
          testId: row.testId,
          module: row.module,
          category: row.category,
          component: row.component,
          control: row.control,
          target: row.target,
          expected: row.expected,
          observed: row.observed,
          status: row.status,
          confidence: row.confidence,
          notes: [...row.notes],
        })),
      events: events
        .sort((a, b) => a.at - b.at)
        .map((row) => ({
          kind: row.kind,
          fromState: row.fromState ?? null,
          toState: row.toState ?? null,
          actorUserId: row.actorUserId,
          note: row.note,
          at: row.at,
        })),
    };
  },
});

/**
 * Assessment report.
 *
 * This is a rendering of one recorded assessment, not a second analysis. Every
 * number is read from a stored row, and the report is explicit about what it
 * does not know:
 *
 *  - There is no posture score. A single number graded from A to F would need a
 *    published weighting between critical and informational, and that weighting
 *    is a policy decision no scan can make. A reader who wants severity order
 *    gets the severity mix; a reader who wants a verdict gets the finding list.
 *  - A report for an assessment with no run says so in a field rather than
 *    reporting zero findings, because "nothing found" and "nothing looked" are
 *    very different sentences.
 *  - Unscored candidates are reported in their own section, never folded into
 *    the severity mix. A backlog of things nobody has scored must not read as a
 *    clean board, and it must not read as a set of low-severity findings either.
 *  - Chain integrity is computed, not asserted. If the audit chain does not
 *    verify, the report says so instead of quietly rendering as normal.
 */
export const report = query({
  args: { assessmentId: v.string() },
  handler: async (ctx, args) => {
    const actor = await actorFor(ctx);
    const read = authorize(actor, "assessment:read", { id: args.assessmentId, kind: "assessment" });
    if (!read.allowed) throw new ConvexError(read.code);

    const assessment = await ctx.db
      .query("securescanAssessments")
      .withIndex("by_assessmentId", (q) => q.eq("assessmentId", args.assessmentId))
      .unique();
    if (!assessment) throw new ConvexError("SECURESCAN_ASSESSMENT_NOT_FOUND");

    const [runs, tests, findings, evidence, audit] = await Promise.all([
      ctx.db
        .query("securescanRuns")
        .withIndex("by_assessment_startedAt", (q) => q.eq("assessmentId", args.assessmentId))
        .collect(),
      ctx.db
        .query("securescanTests")
        .withIndex("by_assessment_status", (q) => q.eq("assessmentId", args.assessmentId))
        .collect(),
      ctx.db
        .query("securescanFindings")
        .withIndex("by_assessmentId", (q) => q.eq("assessmentId", args.assessmentId))
        .collect(),
      ctx.db
        .query("securescanEvidence")
        .withIndex("by_assessmentId", (q) => q.eq("assessmentId", args.assessmentId))
        .collect(),
      ctx.db
        .query("securescanAuditLog")
        .withIndex("by_assessment_seq", (q) => q.eq("assessmentId", args.assessmentId))
        .collect(),
    ]);

    // The newest run is the one the report describes. Earlier runs stay in the
    // chain and in the finding history, but a report that mixed runs would be
    // describing a scan that never happened.
    const latestRun = runs.length === 0
      ? null
      : runs.reduce((best, row) => (row.startedAt > best.startedAt ? row : best));

    const chain = await verifyAuditChain(audit, {
      auditEntryCount: assessment.auditEntryCount,
      auditHeadHash: assessment.auditHeadHash,
    });

    // A finding whose severity is NONE has not been scored by an analyst. It is
    // reported as a candidate for triage, never as an informational finding.
    const unscored = findings.filter((row) => row.severity === "NONE");
    const scored = findings.filter((row) => row.severity !== "NONE");

    const notTested = tests.filter((row) => row.status === "NOT_TESTED" || row.status === "SKIPPED_OUT_OF_SCOPE");
    const observed = tests.filter((row) => row.status !== "NOT_TESTED" && row.status !== "SKIPPED_OUT_OF_SCOPE");

    const outstanding = findings.filter((row) =>
      !["VERIFIED", "FALSE_POSITIVE", "ACCEPTED_RISK", "FIXED"].includes(row.state),
    );

    return {
      role: actor.role as Role,
      assessment: {
        assessmentId: assessment.assessmentId,
        name: assessment.name,
        state: assessment.state,
        ownerUserId: assessment.ownerUserId,
        targetId: assessment.targetId,
        createdAt: assessment.createdAt,
        updatedAt: assessment.updatedAt,
        abortReason: assessment.abortReason ?? null,
      },
      /** Explicit, so "no run" cannot be rendered as "no findings". */
      hasRun: latestRun !== null,
      run: latestRun
        ? {
            runId: latestRun.runId,
            state: latestRun.state,
            startedAt: latestRun.startedAt,
            finishedAt: latestRun.finishedAt ?? null,
            /** Only what actually ran, so an aborted run is not reported as complete. */
            modulesRun: [...latestRun.modulesRun],
            targetRevision: latestRun.targetRevision ?? null,
            toolVersion: latestRun.toolVersion,
            abortReason: latestRun.abortReason ?? null,
            runCount: runs.length,
          }
        : null,
      coverage: {
        recorded: latestRun?.counts ?? null,
        /** Counted from the stored tests, not copied from the run's own tally. */
        observedTests: observed.length,
        notTestedTests: notTested.length,
        evidenceCount: evidence.length,
        notTested: notTested.map((row) => ({
          testId: row.testId,
          module: row.module,
          control: row.control,
          target: row.target,
          expected: row.expected,
          reason: row.notes[0] ?? "No reason recorded.",
        })),
      },
      severityMix: countBy(SEVERITIES, scored.map((row) => row.severity)),
      stateMix: countBy(FINDING_STATES, findings.map((row) => row.state)),
      /** Awaiting an analyst. Never counted as a severity. */
      unscoredCandidates: unscored.map((row) => ({
        findingId: row.findingId,
        title: row.title,
        state: row.state,
        stateLabel: FINDING_STATE_LABELS[row.state] ?? row.state,
        confidence: row.confidence,
        control: row.control,
        evidenceIds: [...row.evidenceIds],
      })),
      outstanding: outstanding.map((row) => ({
        findingId: row.findingId,
        title: row.title,
        severity: row.severity,
        severityLabel: SEVERITY_LABELS[row.severity] ?? row.severity,
        state: row.state,
        stateLabel: FINDING_STATE_LABELS[row.state] ?? row.state,
        confidence: row.confidence,
        control: row.control,
        component: row.component,
        evidenceIds: [...row.evidenceIds],
        remediatedAt: row.remediatedAt ?? null,
        lastRetestState: row.lastRetestState ?? null,
        lastRetestedAt: row.lastRetestedAt ?? null,
        regressionTestId: row.regressionTestId ?? null,
      })),
      findings: findings.map((row) => ({
        findingId: row.findingId,
        title: row.title,
        severity: row.severity,
        severityLabel: SEVERITY_LABELS[row.severity] ?? row.severity,
        state: row.state,
        stateLabel: FINDING_STATE_LABELS[row.state] ?? row.state,
        confidence: row.confidence,
        category: row.category,
        component: row.component,
        boundary: row.boundary,
        control: row.control,
        description: row.description,
        rootCause: row.rootCause,
        businessImpact: row.businessImpact,
        evidenceIds: [...row.evidenceIds],
        affectedEndpoints: [...row.affectedEndpoints],
        remediationSummary: row.remediationSummary ?? null,
        remediatedAt: row.remediatedAt ?? null,
        lastRetestState: row.lastRetestState ?? null,
        lastRetestedAt: row.lastRetestedAt ?? null,
      })),
      /** Computed, not asserted: a report that says nothing about a broken chain reads as a clean bill of health. */
      integrity: {
        intact: chain.intact,
        problems: chain.problems,
        entryCount: chain.entryCount,
        headHash: chain.headHash,
      },
      /** A reader can tell a report with no basis from one with a full basis. */
      basis: {
        evidenceRecords: evidence.length,
        testsObserved: observed.length,
        testsNotTested: notTested.length,
        findingsScored: scored.length,
        findingsUnscored: unscored.length,
      },
    };
  },
});

/**
 * Starts a new assessment from the console.
 *
 * `assessments.create` is internal on purpose: it is the server talking to
 * itself, and it carries no input hardening because an internal caller is not
 * a browser. The product still needs a way for a signed-in analyst to open an
 * assessment, so this is the guarded public door rather than a widened internal
 * one. It does the same authorization the internal path does, and then adds the
 * checks a client can otherwise skip:
 *
 *  - `assessment:create`, which a VIEWER does not hold. The client never sends a
 *    role and the server never reads one from the request.
 *  - A substantive authorization note. The opening audit entry records it, so a
 *    one-word note produces a chain that attests nothing.
 *  - A locatable, http(s) target with no embedded credentials.
 *  - A traversal-free, repo-relative allowlist.
 *  - A bounded request budget.
 *
 * Validation problems are returned rather than thrown so the form can attach
 * each to a field. A refusal is returned as `{ ok: false }` rather than raised
 * because a raise would roll back the audit entry recording the refusal.
 */
export const startAssessment = mutation({
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
    /**
     * Required here, unlike on the internal path, because this value is typed
     * into the console by a person and becomes part of the permanent record of
     * who authorized what.
     */
    authorizationNote: v.string(),
  },
  handler: async (ctx, args) => {
    const userId = await requireUserId(ctx);
    const role = await requireMemberRole(ctx, userId);
    const actor: Actor = { userId, role };

    const decision = authorize(actor, "assessment:create", { id: "new", kind: "assessment" });
    if (!decision.allowed) {
      return {
        ok: false as const,
        code: decision.code,
        reason: decision.reason,
        problems: [] as { field: string; message: string }[],
      };
    }

    const problems = validateCreateRequest(args);
    if (problems.length > 0) {
      return {
        ok: false as const,
        code: "SECURESCAN_INVALID_ASSESSMENT_REQUEST",
        reason: "The assessment request was rejected before anything was created.",
        problems,
      };
    }

    const created = await createAssessment(ctx, userId, role, {
      ...args,
      allowlistedPaths: normaliseAllowlist(args.allowlistedPaths),
    });
    return { ok: true as const, ...created };
  },
});

/** One evidence record on its own, for the evidence viewer. */
export const evidenceDetail = query({
  args: { evidenceId: v.string() },
  handler: async (ctx, args) => {
    const actor = await actorFor(ctx);
    const row = await ctx.db
      .query("securescanEvidence")
      .withIndex("by_evidenceId", (q) => q.eq("evidenceId", args.evidenceId))
      .unique();
    if (!row) throw new ConvexError("SECURESCAN_EVIDENCE_NOT_FOUND");

    const read = authorize(actor, "evidence:read", {
      id: row.evidenceId,
      kind: "evidence",
    });
    if (!read.allowed) throw new ConvexError(read.code);

    const [test, findings] = await Promise.all([
      row.testId
        ? ctx.db
            .query("securescanTests")
            .withIndex("by_testId", (q) => q.eq("testId", row.testId as string))
            .unique()
        : Promise.resolve(null),
      ctx.db
        .query("securescanFindings")
        .withIndex("by_assessmentId", (q) => q.eq("assessmentId", row.assessmentId))
        .collect(),
    ]);

    return {
      role: actor.role as Role,
      evidence: {
        evidenceId: row.evidenceId,
        assessmentId: row.assessmentId,
        testId: row.testId ?? null,
        type: row.type,
        description: row.description,
        payload: row.payload,
        sha256: row.sha256,
        producedBy: row.producedBy,
        sourceLocation: row.sourceLocation ?? null,
        targetEnvironment: row.targetEnvironment,
        collectedAt: row.collectedAt,
      },
      test: test
        ? {
            testId: test.testId,
            module: test.module,
            target: test.target,
            expected: test.expected,
            observed: test.observed,
            status: test.status,
            confidence: test.confidence,
          }
        : null,
      /** Which findings cite this record. Traceability in both directions. */
      citedBy: findings
        .filter((finding) => finding.evidenceIds.includes(row.evidenceId))
        .map((finding) => ({
          findingId: finding.findingId,
          title: finding.title,
          state: finding.state,
          stateLabel: FINDING_STATE_LABELS[finding.state] ?? finding.state,
          severity: finding.severity,
        })),
    };
  },
});
