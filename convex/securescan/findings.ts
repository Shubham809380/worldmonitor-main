import { ConvexError, v } from "convex/values";
import type { Doc } from "../_generated/dataModel";
import { internalMutation, mutation, query } from "../_generated/server";
import type { MutationCtx, QueryCtx } from "../_generated/server";
import { requireUserId } from "../lib/auth";
import {
  authorize,
  authorizeFindingTransition,
  validateTriageInput,
  type Actor,
} from "../../server/securescan/identity";
import { assertsResolution, canTransitionFinding } from "../../server/securescan/findings";
import { assessRisk, SEVERITY_METHODOLOGY } from "../../server/securescan/risk";
import type { FindingState, Severity } from "../../server/securescan/types";
import { appendAudit, attestedSource, requireMemberRole } from "./_shared";
import {
  FINDING_STATE_LABELS,
  SEVERITY_LABELS,
} from "./assessments";

const FINDING_STATES = [
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
] as const satisfies readonly FindingState[];

async function loadFinding(
  ctx: QueryCtx | MutationCtx,
  findingId: string,
): Promise<Doc<"securescanFindings">> {
  const row = await ctx.db
    .query("securescanFindings")
    .withIndex("by_findingId", (q) => q.eq("findingId", findingId))
    .unique();
  if (!row) throw new ConvexError("SECURESCAN_FINDING_NOT_FOUND");
  return row;
}

export const listByAssessment = query({
  args: { assessmentId: v.string() },
  handler: async (ctx, args) => {
    const userId = await requireUserId(ctx);
    const role = await requireMemberRole(ctx, userId);
    const actor: Actor = { userId, role };
    const read = authorize(actor, "finding:read", {
      id: args.assessmentId,
      kind: "assessment",
    });
    if (!read.allowed) throw new ConvexError(read.code);

    const findings = await ctx.db
      .query("securescanFindings")
      .withIndex("by_assessmentId", (q) => q.eq("assessmentId", args.assessmentId))
      .collect();

    return findings
      .sort((a, b) => b.updatedAt - a.updatedAt)
      .map((finding) => ({
        findingId: finding.findingId,
        title: finding.title,
        state: finding.state,
        stateLabel: FINDING_STATE_LABELS[finding.state] ?? finding.state,
        severity: finding.severity,
        severityLabel: SEVERITY_LABELS[finding.severity] ?? finding.severity,
        confidence: finding.confidence,
        component: finding.component,
        control: finding.control,
        evidenceIds: finding.evidenceIds,
        risk: JSON.parse(finding.risk) as unknown,
        remediationSummary: finding.remediationSummary ?? null,
        remediatedAt: finding.remediatedAt ?? null,
        lastRetestState: finding.lastRetestState ?? null,
        lastRetestedAt: finding.lastRetestedAt ?? null,
        updatedAt: finding.updatedAt,
      }));
  },
});

/**
 * Outcome of a lifecycle write.
 *
 * Authorization and input failures are returned rather than thrown, because a
 * Convex mutation is transactional: throwing rolls back every write in the
 * handler, which would discard the denial entry this API exists to record. A
 * refusal that leaves no trace is indistinguishable from a request that never
 * arrived, so the refusal is made durable and the caller is told to treat it as
 * a failure. Unexpected faults still throw, since those should surface as errors.
 */
export type LifecycleResult =
  | { readonly ok: true; readonly findingId: string; readonly state: FindingState; readonly stateLabel: string }
  | {
      readonly ok: false;
      readonly code:
        | "AUTH_REQUIRED"
        | "ROLE_FORBIDDEN"
        | "NOT_RESOURCE_OWNER"
        | "INVALID_TRANSITION"
        | "SECURESCAN_TRIAGE_REASON_INVALID"
        | "SECURESCAN_REMEDIATION_SUMMARY_REQUIRED"
        | "SECURESCAN_RETEST_NOTES_REQUIRED"
        | "SECURESCAN_SCORE_JUSTIFICATION_REQUIRED"
        | "SECURESCAN_FINDING_CLOSED"
        | "RETEST_REQUIRED_FOR_RESOLUTION"
        | "SECURESCAN_SEVERITY_NOT_SCORED";
      /** Engine-supplied explanation. Present so the UI can say why, not guess. */
      readonly reason: string;
    };

/** Outcome of a risk scoring write. */
export type ScoreResult =
  | {
      readonly ok: true;
      readonly findingId: string;
      readonly severity: Severity;
      readonly severityLabel: string;
      readonly confidence: "LOW" | "MEDIUM" | "HIGH";
      readonly severityRationale: readonly string[];
      readonly severityMethodologyVersion: string;
    }
  | { readonly ok: false; readonly code: LifecycleFailureCode; readonly reason: string };

type LifecycleFailureCode = Extract<LifecycleResult, { ok: false }>["code"];

/**
 * Records a lifecycle transition.
 *
 * Both the transition table and the permission check come from the engine, so
 * the API cannot invent a path the engine forbids. A denied attempt is written
 * to the audit chain and committed, then reported to the caller.
 */
export const transition = mutation({
  args: {
    findingId: v.string(),
    to: v.union(...FINDING_STATES.map((state) => v.literal(state))),
    reason: v.string(),
  },
  handler: async (ctx, args): Promise<LifecycleResult> => {
    const userId = await requireUserId(ctx);
    const role = await requireMemberRole(ctx, userId);
    const actor: Actor = { userId, role };
    const finding = await loadFinding(ctx, args.findingId);
    const to = args.to as FindingState;
    const source = attestedSource();

    const decision = authorizeFindingTransition(
      actor,
      { id: finding.findingId, state: finding.state as FindingState, ownerId: finding.ownerUserId },
      to,
    );
    if (!decision.allowed) {
      await appendAudit(ctx, {
        assessmentId: finding.assessmentId,
        actorUserId: userId,
        actorRole: role,
        action: "finding:triage",
        resourceType: "finding",
        resourceId: finding.findingId,
        outcome: "DENIED",
        reasonCode: decision.code,
        detail: `${decision.reason} Requested transition ${finding.state} -> ${to}.`,
        sourceUserAgent: source.userAgent,
        sourceIp: source.ip,
      });
      return { ok: false, code: decision.code, reason: decision.reason };
    }

    if (!canTransitionFinding(finding.state as FindingState, to)) {
      const reason = `${finding.state} cannot become ${to}. The engine's transition table does not allow it.`;
      await appendAudit(ctx, {
        assessmentId: finding.assessmentId,
        actorUserId: userId,
        actorRole: role,
        action: "finding:triage",
        resourceType: "finding",
        resourceId: finding.findingId,
        outcome: "DENIED",
        reasonCode: "INVALID_TRANSITION",
        detail: reason,
        sourceUserAgent: source.userAgent,
        sourceIp: source.ip,
      });
      return { ok: false, code: "INVALID_TRANSITION", reason };
    }

    if (assertsResolution(to as FindingState) && finding.lastRetestState !== "PASSED") {
      // The transition table allows `RETEST_REQUIRED -> VERIFIED`, but that edge
      // records only that a retest is *due*. Reaching a resolution state through
      // this generic mutation would let any authenticated client declare a defect
      // fixed without a single retest having run. The UI never offers this, which
      // is presentation, not enforcement — so refuse it here and make the refusal
      // auditable like every other denial.
      const reason =
        `${finding.state} cannot become ${to} without a passing retest. ` +
        `This finding's last recorded retest is ${finding.lastRetestState ?? "none"}; ` +
        "use the runner bridge so the verdict comes from a real execution.";
      await appendAudit(ctx, {
        assessmentId: finding.assessmentId,
        actorUserId: userId,
        actorRole: role,
        action: "finding:triage",
        resourceType: "finding",
        resourceId: finding.findingId,
        outcome: "DENIED",
        reasonCode: "SECURESCAN_RESOLUTION_REQUIRES_RETEST",
        detail: reason,
        sourceUserAgent: source.userAgent,
        sourceIp: source.ip,
      });
      return { ok: false, code: "RETEST_REQUIRED_FOR_RESOLUTION", reason };
    }

    const triageErrors = validateTriageInput({ reason: args.reason, to });
    if (triageErrors.length > 0) {
      const reason = triageErrors.map((e) => e.message).join(" ");
      await appendAudit(ctx, {
        assessmentId: finding.assessmentId,
        actorUserId: userId,
        actorRole: role,
        action: "finding:triage",
        resourceType: "finding",
        resourceId: finding.findingId,
        outcome: "DENIED",
        reasonCode: "SECURESCAN_TRIAGE_REASON_INVALID",
        detail: reason,
        sourceUserAgent: source.userAgent,
        sourceIp: source.ip,
      });
      return { ok: false, code: "SECURESCAN_TRIAGE_REASON_INVALID", reason };
    }

    // Promoting to VALIDATED is the step that turns a candidate into a
    // confirmed weakness, so it is the step that must not leave severity
    // unscored. A validated finding with `NONE` and a "not yet scored" rationale
    // is a contradiction: it asserts the weakness is real while declining to say
    // what it would cost if exploited. The analyst has to record the risk
    // judgements first via `scoreRisk`.
    if (to === "VALIDATED" && finding.severity === "NONE") {
      const reason =
        "This finding has not been scored. Record the risk judgements with scoreRisk before validating it, " +
        "so the confirmed weakness carries a severity and the reasoning behind it.";
      await appendAudit(ctx, {
        assessmentId: finding.assessmentId,
        actorUserId: userId,
        actorRole: role,
        action: "finding:triage",
        resourceType: "finding",
        resourceId: finding.findingId,
        outcome: "DENIED",
        reasonCode: "SECURESCAN_SEVERITY_NOT_SCORED",
        detail: reason,
        sourceUserAgent: source.userAgent,
        sourceIp: source.ip,
      });
      return { ok: false, code: "SECURESCAN_SEVERITY_NOT_SCORED", reason };
    }

    const now = Date.now();
    await ctx.db.patch(finding._id, { state: to, updatedAt: now });
    await ctx.db.insert("securescanFindingEvents", {
      assessmentId: finding.assessmentId,
      findingId: finding.findingId,
      kind: eventKindFor(to),
      fromState: finding.state,
      toState: to,
      actorUserId: userId,
      note: args.reason.trim(),
      at: now,
    });

    await appendAudit(ctx, {
      assessmentId: finding.assessmentId,
      actorUserId: userId,
      actorRole: role,
      action: "finding:triage",
      resourceType: "finding",
      resourceId: finding.findingId,
      outcome: "ALLOWED",
      reasonCode: `TRANSITION_${to}`,
      detail: `${finding.state} -> ${to}: ${args.reason.trim()}`,
      sourceUserAgent: source.userAgent,
      sourceIp: source.ip,
    }, now);

    return {
      ok: true,
      findingId: finding.findingId,
      state: to,
      stateLabel: FINDING_STATE_LABELS[to] ?? to,
    };
  },
});

/**
 * Records an analyst's risk judgement for a finding.
 *
 * This exists because the engine deliberately refuses to invent severity. A
 * candidate arrives with `NONE` and a "not yet scored" rationale, because a
 * static check cannot determine impact, exposure, privileges or data class. The
 * only honest source for those judgements is a person who has read the evidence.
 * They supply them here, `assessRisk` turns them into a band *and* the reasoning
 * that produced it, and both are stored — so a reader can disagree with the
 * band by arguing with the inputs rather than by guessing.
 *
 * The stored `risk` therefore always contains a `severityRationale` naming the
 * methodology version, and the UI can render "not scored" only when this
 * mutation has never run for the finding.
 */
export const scoreRisk = mutation({
  args: {
    findingId: v.string(),
    exposure: v.union(
      v.literal("PUBLIC_INTERNET"),
      v.literal("UNAUTHENTICATED_REMOTE"),
      v.literal("AUTHENTICATED_REMOTE"),
      v.literal("SAME_ORIGIN"),
      v.literal("INTERNAL_ONLY"),
      v.literal("BUILD_TIME"),
    ),
    privilegesRequired: v.union(
      v.literal("NONE"),
      v.literal("USER"),
      v.literal("PRIVILEGED"),
    ),
    userInteraction: v.union(v.literal("NONE"), v.literal("REQUIRED")),
    dataClass: v.union(
      v.literal("PUBLIC"),
      v.literal("INTERNAL"),
      v.literal("CONFIDENTIAL"),
      v.literal("REGULATED"),
    ),
    boundaryCrossed: v.boolean(),
    confidentiality: v.union(v.literal("NONE"), v.literal("LOW"), v.literal("HIGH")),
    integrity: v.union(v.literal("NONE"), v.literal("LOW"), v.literal("HIGH")),
    availability: v.union(v.literal("NONE"), v.literal("LOW"), v.literal("HIGH")),
    /**
     * True only when a runtime test actually demonstrated the behaviour. The UI
     * must not offer this for a static candidate, and setting it is an assertion
     * the analyst makes in full view of the evidence.
     */
    runtimeValidated: v.boolean(),
    evidenceStrength: v.union(
      v.literal("INFERENCE"),
      v.literal("SOURCE"),
      v.literal("CONFIGURATION"),
      v.literal("RUNTIME"),
    ),
    correlatedSources: v.number(),
    justification: v.string(),
  },
  handler: async (ctx, args): Promise<ScoreResult> => {
    const userId = await requireUserId(ctx);
    const role = await requireMemberRole(ctx, userId);
    const actor: Actor = { userId, role };
    const finding = await loadFinding(ctx, args.findingId);
    const source = attestedSource();

    const decision = authorize(actor, "finding:verify", {
      id: finding.findingId,
      kind: "finding",
      ownerId: finding.ownerUserId,
    });
    if (!decision.allowed) {
      await appendAudit(ctx, {
        assessmentId: finding.assessmentId,
        actorUserId: userId,
        actorRole: role,
        action: "finding:score",
        resourceType: "finding",
        resourceId: finding.findingId,
        outcome: "DENIED",
        reasonCode: decision.code,
        detail: decision.reason,
        sourceUserAgent: source.userAgent,
        sourceIp: source.ip,
      });
      return { ok: false, code: decision.code, reason: decision.reason };
    }

    // A score with no stated justification is an opinion. The methodology is
    // only auditable if the inputs came with a reason.
    if (args.justification.trim().length < 20) {
      const reason =
        "A severity judgement needs a justification of at least 20 characters explaining why these inputs produce this band.";
      await appendAudit(ctx, {
        assessmentId: finding.assessmentId,
        actorUserId: userId,
        actorRole: role,
        action: "finding:score",
        resourceType: "finding",
        resourceId: finding.findingId,
        outcome: "DENIED",
        reasonCode: "SECURESCAN_SCORE_JUSTIFICATION_REQUIRED",
        detail: reason,
        sourceUserAgent: source.userAgent,
        sourceIp: source.ip,
      });
      return { ok: false, code: "SECURESCAN_SCORE_JUSTIFICATION_REQUIRED", reason };
    }

    // A finding that is closed cannot be re-scored: doing so would let a
    // dismissed or fixed finding have its severity rewritten after the fact,
    // which would make the historical report disagree with the record.
    const closedStates: readonly FindingState[] = [
      "FALSE_POSITIVE",
      "ACCEPTED_RISK",
      "INFORMATIONAL",
      "FIXED",
    ];
    if (closedStates.includes(finding.state as FindingState)) {
      const reason = `A ${finding.state} finding is closed and cannot be re-scored. Its recorded severity is part of the historical record.`;
      await appendAudit(ctx, {
        assessmentId: finding.assessmentId,
        actorUserId: userId,
        actorRole: role,
        action: "finding:score",
        resourceType: "finding",
        resourceId: finding.findingId,
        outcome: "DENIED",
        reasonCode: "SECURESCAN_FINDING_CLOSED",
        detail: reason,
        sourceUserAgent: source.userAgent,
        sourceIp: source.ip,
      });
      return { ok: false, code: "SECURESCAN_FINDING_CLOSED", reason };
    }

    const scored = assessRisk({
      exposure: args.exposure,
      privilegesRequired: args.privilegesRequired,
      userInteraction: args.userInteraction,
      dataClass: args.dataClass,
      boundaryCrossed: args.boundaryCrossed,
      confidentiality: args.confidentiality,
      integrity: args.integrity,
      availability: args.availability,
      runtimeValidated: args.runtimeValidated,
      evidenceStrength: args.evidenceStrength,
      correlatedSources: Math.max(1, Math.trunc(args.correlatedSources)),
    });

    const now = Date.now();
    const justification = args.justification.trim();
    const risk = {
      ...scored,
      // The analyst's own words are kept alongside the engine's derivation, so
      // the report can show both what was concluded and on what grounds.
      severityRationale: [
        ...scored.severityRationale,
        `Analyst justification: ${justification}`,
      ],
    };

    await ctx.db.patch(finding._id, {
      severity: scored.technicalSeverity,
      confidence: scored.confidence,
      businessImpact: scored.businessImpact,
      risk: JSON.stringify(risk),
      updatedAt: now,
    });

    await ctx.db.insert("securescanFindingEvents", {
      assessmentId: finding.assessmentId,
      findingId: finding.findingId,
      kind: "SCORED",
      fromState: finding.state,
      toState: finding.state,
      actorUserId: userId,
      note: `Severity ${scored.technicalSeverity} (${SEVERITY_METHODOLOGY.version}). ${justification}`,
      at: now,
    });

    await appendAudit(ctx, {
      assessmentId: finding.assessmentId,
      actorUserId: userId,
      actorRole: role,
      action: "finding:score",
      resourceType: "finding",
      resourceId: finding.findingId,
      outcome: "ALLOWED",
      reasonCode: "RISK_SCORED",
      detail:
        `Severity ${scored.technicalSeverity}, confidence ${scored.confidence}, ` +
        `methodology ${scored.severityMethodologyVersion}. ${justification}`,
      sourceUserAgent: source.userAgent,
      sourceIp: source.ip,
    }, now);

    return {
      ok: true,
      findingId: finding.findingId,
      severity: scored.technicalSeverity,
      severityLabel: SEVERITY_LABELS[scored.technicalSeverity] ?? scored.technicalSeverity,
      confidence: scored.confidence,
      severityRationale: risk.severityRationale,
      severityMethodologyVersion: scored.severityMethodologyVersion,
    };
  },
});

function eventKindFor(to: FindingState) {
  switch (to) {
    case "VALIDATED":
      return "VALIDATED" as const;
    case "REMEDIATION":
      return "REMEDIATION_STARTED" as const;
    case "RETEST_REQUIRED":
      return "RETEST_STARTED" as const;
    case "VERIFIED":
      return "RETEST_PASSED" as const;
    case "REGRESSION":
      return "RETEST_FAILED" as const;
    case "ACCEPTED_RISK":
      return "ACCEPTED_RISK" as const;
    case "FALSE_POSITIVE":
      return "FALSE_POSITIVE" as const;
    case "INFORMATIONAL":
      return "INFORMATIONAL" as const;
    default:
      return "VALIDATION_STARTED" as const;
  }
}

/**
 * Records a remediation. This does not move the finding to FIXED: only a retest
 * that passes can do that, which is what stops a fix being declared on the
 * strength of someone's own description of it.
 */
export const recordRemediation = mutation({
  args: {
    findingId: v.string(),
    summary: v.string(),
  },
  handler: async (ctx, args) => {
    const userId = await requireUserId(ctx);
    const role = await requireMemberRole(ctx, userId);
    const actor: Actor = { userId, role };
    const finding = await loadFinding(ctx, args.findingId);

    const source = attestedSource();

    const decision = authorize(actor, "remediation:write", {
      id: finding.findingId,
      kind: "finding",
      ownerId: finding.ownerUserId,
    });
    if (!decision.allowed) {
      // Returned, not thrown: a throw would roll this denial record back with
      // everything else in the transaction.
      await appendAudit(ctx, {
        assessmentId: finding.assessmentId,
        actorUserId: userId,
        actorRole: role,
        action: "remediation:write",
        resourceType: "finding",
        resourceId: finding.findingId,
        outcome: "DENIED",
        reasonCode: decision.code,
        detail: decision.reason,
        sourceUserAgent: source.userAgent,
        sourceIp: source.ip,
      });
      return { ok: false as const, code: decision.code, reason: decision.reason };
    }
    if (args.summary.trim() === "") {
      const reason = "A remediation with no description cannot be reviewed later.";
      await appendAudit(ctx, {
        assessmentId: finding.assessmentId,
        actorUserId: userId,
        actorRole: role,
        action: "remediation:write",
        resourceType: "finding",
        resourceId: finding.findingId,
        outcome: "DENIED",
        reasonCode: "SECURESCAN_REMEDIATION_SUMMARY_REQUIRED",
        detail: reason,
        sourceUserAgent: source.userAgent,
        sourceIp: source.ip,
      });
      return {
        ok: false as const,
        code: "SECURESCAN_REMEDIATION_SUMMARY_REQUIRED" as const,
        reason,
      };
    }
    // Checked before the patch, not after. Without this, this mutation was a
    // side door around the transition table: it patched any state straight to
    // REMEDIATION, so a CANDIDATE that was never validated could be described
    // as under remediation and pushed to retest from there. Fixing a finding is
    // meant to be a conclusion the evidence supports, reached through
    // VALIDATING -> VALIDATED, not a shortcut past them.
    if (!canTransitionFinding(finding.state as FindingState, "REMEDIATION")) {
      const reason = `${finding.state} cannot become REMEDIATION. The engine's transition table does not allow it.`;
      await appendAudit(ctx, {
        assessmentId: finding.assessmentId,
        actorUserId: userId,
        actorRole: role,
        action: "remediation:write",
        resourceType: "finding",
        resourceId: finding.findingId,
        outcome: "DENIED",
        reasonCode: "INVALID_TRANSITION",
        detail: reason,
        sourceUserAgent: source.userAgent,
        sourceIp: source.ip,
      });
      return { ok: false as const, code: "INVALID_TRANSITION" as const, reason };
    }

    const now = Date.now();
    await ctx.db.patch(finding._id, {
      state: "REMEDIATION",
      remediationSummary: args.summary.trim(),
      remediatedAt: now,
      updatedAt: now,
    });
    await ctx.db.insert("securescanFindingEvents", {
      assessmentId: finding.assessmentId,
      findingId: finding.findingId,
      kind: "REMEDIATION_RECORDED",
      fromState: finding.state,
      toState: "REMEDIATION",
      actorUserId: userId,
      note: args.summary.trim(),
      at: now,
    });

    await appendAudit(ctx, {
      assessmentId: finding.assessmentId,
      actorUserId: userId,
      actorRole: role,
      action: "remediation:write",
      resourceType: "finding",
      resourceId: finding.findingId,
      outcome: "ALLOWED",
      reasonCode: "REMEDIATION_RECORDED",
      detail: args.summary.trim(),
      sourceUserAgent: source.userAgent,
      sourceIp: source.ip,
    }, now);

    return {
      ok: true as const,
      findingId: finding.findingId,
      state: "REMEDIATION" as FindingState,
      stateLabel: FINDING_STATE_LABELS.REMEDIATION ?? "IN_PROGRESS",
    };
  },
});

/**
 * Queues a retest. Public, and deliberately unable to state a verdict.
 *
 * This replaces the mutation that used to accept a browser-supplied
 * `passed: boolean`. That version let any authenticated member type "passed" into
 * a form and have the server move a finding to VERIFIED, with no run, no
 * evidence, and no observation behind it. The transition table's
 * `RETEST_REQUIRED -> VERIFIED` edge only ever meant "a retest is due"; the
 * generic `transition` mutation refuses to walk it (`RETEST_REQUIRED_FOR_RESOLUTION`),
 * but that guard protected only the other door. This one was the door the console
 * actually used.
 *
 * A retest is now two steps: an authorized analyst *requests* one here, and the
 * assessment engine *reports* one through `recordRetestResult`, which is internal
 * and derives the verdict from persisted test rows. The browser cannot skip the
 * second step, and neither can the runner - it names a run, not an outcome.
 */
export const requestRetest = mutation({
  args: {
    findingId: v.string(),
    notes: v.string(),
  },
  handler: async (ctx, args): Promise<LifecycleResult> => {
    const userId = await requireUserId(ctx);
    const role = await requireMemberRole(ctx, userId);
    const actor: Actor = { userId, role };
    const finding = await loadFinding(ctx, args.findingId);
    const source = attestedSource();

    const decision = authorize(actor, "retest:execute", {
      id: finding.findingId,
      kind: "finding",
      ownerId: finding.ownerUserId,
    });
    if (!decision.allowed) {
      await appendAudit(ctx, {
        assessmentId: finding.assessmentId,
        actorUserId: userId,
        actorRole: role,
        action: "retest:execute",
        resourceType: "finding",
        resourceId: finding.findingId,
        outcome: "DENIED",
        reasonCode: decision.code,
        detail: decision.reason,
        sourceUserAgent: source.userAgent,
        sourceIp: source.ip,
      });
      return { ok: false, code: decision.code, reason: decision.reason };
    }

    const deny = async (code: LifecycleFailureCode, reason: string) => {
      await appendAudit(ctx, {
        assessmentId: finding.assessmentId,
        actorUserId: userId,
        actorRole: role,
        action: "retest:execute",
        resourceType: "finding",
        resourceId: finding.findingId,
        outcome: "DENIED",
        reasonCode: code,
        detail: reason,
        sourceUserAgent: source.userAgent,
        sourceIp: source.ip,
      });
      return { ok: false as const, code, reason };
    };

    if (args.notes.trim() === "") {
      return await deny(
        "SECURESCAN_RETEST_NOTES_REQUIRED",
        "A retest request with no observation to check cannot be reviewed later.",
      );
    }
    if (!canTransitionFinding(finding.state as FindingState, "RETEST_REQUIRED")) {
      return await deny(
        "INVALID_TRANSITION",
        `${finding.state} cannot become RETEST_REQUIRED. The engine's transition table does not allow it.`,
      );
    }

    const now = Date.now();
    await ctx.db.patch(finding._id, { state: "RETEST_REQUIRED", updatedAt: now });
    await ctx.db.insert("securescanFindingEvents", {
      assessmentId: finding.assessmentId,
      findingId: finding.findingId,
      kind: "RETEST_STARTED",
      fromState: finding.state,
      toState: "RETEST_REQUIRED",
      actorUserId: userId,
      note: args.notes.trim(),
      at: now,
    });
    await appendAudit(ctx, {
      assessmentId: finding.assessmentId,
      actorUserId: userId,
      actorRole: role,
      action: "retest:execute",
      resourceType: "finding",
      resourceId: finding.findingId,
      outcome: "ALLOWED",
      reasonCode: "RETEST_REQUESTED",
      // States what this entry does *not* do, because the next entry in the
      // chain is the one that carries the outcome.
      detail:
        `Retest requested: ${args.notes.trim().slice(0, 400)} ` +
        "The finding stays in RETEST_REQUIRED until the assessment engine reports a result for a run.",
      sourceUserAgent: source.userAgent,
      sourceIp: source.ip,
    }, now);

    return {
      ok: true as const,
      findingId: finding.findingId,
      state: "RETEST_REQUIRED" as FindingState,
      stateLabel: FINDING_STATE_LABELS.RETEST_REQUIRED ?? "RETEST_REQUIRED",
    };
  },
});

/**
 * The verdict, derived from what a run actually recorded.
 *
 * Internal, reached only through the runner bridge and its shared secret. The
 * caller supplies a `runId` and nothing else: the outcome is read out of the
 * `securescanTests` rows that run persisted, matched to the finding's control
 * and component. A run with no matching check produces no verdict, so pointing
 * at an unrelated run cannot mark anything fixed - and the runner cannot assert a
 * pass, only a run in which the server looks for the answer itself.
 *
 * Refuses to re-judge a run it has already consumed, so a replayed submission
 * cannot overwrite a recorded regression with a later pass.
 */
export const recordRetestResult = internalMutation({
  args: {
    findingId: v.string(),
    runId: v.string(),
    notes: v.string(),
  },
  handler: async (ctx, args) => {
    const finding = await loadFinding(ctx, args.findingId);
    const runId = args.runId.trim();

    const fail = async (code: string, reason: string) => {
      await appendAudit(ctx, {
        assessmentId: finding.assessmentId,
        // The engine is not a user and holds no role. Attributing this to the
        // owner would put a human in the chain for a verdict the owner never
        // made, so it is recorded as the runner that made it - matching how
        // `assessments.recordRun` attributes its own writes.
        actorUserId: "engine",
        actorRole: "SYSTEM",
        action: "retest:execute",
        resourceType: "finding",
        resourceId: finding.findingId,
        outcome: "DENIED",
        reasonCode: code,
        detail: reason,
        sourceUserAgent: "runner",
        sourceIp: "unavailable",
      });
      return { ok: false as const, code, reason };
    };

    if (runId === "") {
      return await fail(
        "SECURESCAN_RETEST_RUN_REQUIRED",
        "A retest result must name the run that produced it.",
      );
    }

    // Replay protection: a run is judged once per finding.
    //
    // The run id is stored as the note's leading `run=<id>` token, so the
    // comparison has to be anchored to that token. A plain substring test would
    // treat run `abc` as already judged by a note reading `run=abcdef`, which
    // would silently refuse a legitimate retest.
    const events = await ctx.db
      .query("securescanFindingEvents")
      .withIndex("by_findingId", (q) => q.eq("findingId", finding.findingId))
      .collect();
    const alreadyJudged = events.some(
      (event) =>
        (event.kind === "RETEST_PASSED" || event.kind === "RETEST_FAILED") &&
        (event.note === `run=${runId}` || event.note.startsWith(`run=${runId} `)),
    );
    if (alreadyJudged) {
      return await fail(
        "SECURESCAN_RETEST_ALREADY_RECORDED",
        `Run ${runId} has already been judged for this finding.`,
      );
    }

    if (!canTransitionFinding(finding.state as FindingState, "VERIFIED")) {
      return await fail(
        "INVALID_TRANSITION",
        `${finding.state} cannot be resolved by a retest. The engine's transition table does not allow it.`,
      );
    }

    // The run has to exist, belong to this assessment, and have finished.
    //
    // The per-test check below already filters on `assessmentId`, so a run from
    // a different assessment cannot supply rows. This is the coarser guard that
    // states the premise outright: a verdict is only ever derived from a run
    // this assessment actually executed and that completed. A run still in
    // flight has not finished observing anything, and a run that aborted is
    // explicitly not a clean result set -- treating either as evidence would
    // assert a determination the execution never made.
    const run = await ctx.db
      .query("securescanRuns")
      .withIndex("by_runId", (q) => q.eq("runId", runId))
      .unique();
    if (!run) {
      return await fail(
        "SECURESCAN_RETEST_RUN_NOT_FOUND",
        `No run ${runId} is recorded in this deployment.`,
      );
    }
    if (run.assessmentId !== finding.assessmentId) {
      return await fail(
        "SECURESCAN_RETEST_RUN_MISMATCH",
        `Run ${runId} belongs to assessment ${run.assessmentId}, not to ` +
          `assessment ${finding.assessmentId}, so it cannot judge this finding.`,
      );
    }
    if (typeof run.finishedAt !== "number") {
      return await fail(
        "SECURESCAN_RETEST_RUN_INCOMPLETE",
        run.abortReason
          ? `Run ${runId} ended abnormally (${run.abortReason}), so it is not a result set.`
          : `Run ${runId} has not finished. A verdict cannot be derived from a run still in progress.`,
      );
    }

    // The verdict comes from the stored rows, not from the submission.
    const tests = await ctx.db
      .query("securescanTests")
      .withIndex("by_runId", (q) => q.eq("runId", runId))
      .collect();
    // Scoped to the finding's own assessment *and* the finding's control and
    // component. Matching on control/component alone would accept a run from an
    // unrelated assessment, letting one deployment's passing check resolve
    // another assessment's finding.
    const matching = tests.filter(
      (test) =>
        test.assessmentId === finding.assessmentId &&
        test.control === finding.control &&
        test.component === finding.component,
    );
    if (matching.length === 0) {
      return await fail(
        "SECURESCAN_RETEST_NO_MATCHING_TEST",
        `Run ${runId} recorded no check of ${finding.control} on ${finding.component} ` +
          `in assessment ${finding.assessmentId}, so it cannot support a verdict for this finding.`,
      );
    }
    // A verdict has to rest on an observation. The status enum also admits
    // INCONCLUSIVE, NOT_TESTED and SKIPPED_OUT_OF_SCOPE, and none of those says
    // anything about whether the defect is gone or still present.
    //
    // So the rule is not "not a FAIL means a PASS". A run that actually
    // recorded a FAIL is evidence the defect persists, and a run whose checks
    // all passed is evidence it is gone. A run that did neither observed
    // nothing: calling that a regression would assert a determination nobody
    // made, in the pessimistic direction - the same defect as asserting a pass,
    // just less obviously wrong. It leaves the finding queued for a run that
    // actually checks.
    const failed = matching.filter((test) => test.status === "FAIL");
    const passed = matching.every((test) => test.status === "PASS");
    if (failed.length === 0 && !passed) {
      const undecided = matching.filter((test) => test.status !== "PASS");
      return await fail(
        "SECURESCAN_RETEST_INCONCLUSIVE",
        `Run ${runId} recorded ${undecided.length} check(s) of ${finding.control} on ` +
          `${finding.component} that did not decide (${undecided
            .map((test) => test.status)
            .join(", ")}), so it neither confirms nor contradicts the fix. ` +
          "The finding stays queued until a run observes an actual result.",
      );
    }
const to: FindingState = passed ? "VERIFIED" : "REGRESSION";
    const now = Date.now();
    // The run id travels in the event note so replay protection has something
    // durable to compare against, and so an auditor can see which execution
    // produced the verdict without needing a second table.
    const note = `run=${runId} ${args.notes.trim() || "(no runner note)"}`.trim();

    await ctx.db.patch(finding._id, {
      state: to,
      lastRetestState: passed ? "PASSED" : "FAILED",
      lastRetestedAt: now,
      regressionTestId: matching[0]!.testId,
      updatedAt: now,
    });
    await ctx.db.insert("securescanFindingEvents", {
      assessmentId: finding.assessmentId,
      findingId: finding.findingId,
      kind: passed ? "RETEST_PASSED" : "RETEST_FAILED",
      fromState: finding.state,
      toState: to,
      // The engine, not the owner. This timeline is read next to the audit
      // chain, and the chain attributes the verdict to the runner; a timeline
      // naming the owner would read as "this person verified their own fix".
      actorUserId: "engine",
      note,
      at: now,
    });
    await appendAudit(ctx, {
      assessmentId: finding.assessmentId,
      actorUserId: "engine",
      // The engine is not a user and holds no role, so it is recorded as the
      // runner. This chain must never imply a person verified the fix.
      actorRole: "SYSTEM",
      action: "retest:execute",
      resourceType: "finding",
      resourceId: finding.findingId,
      outcome: "ALLOWED",
      reasonCode: passed ? "RETEST_PASSED" : "RETEST_FAILED",
      detail:
        `Run ${runId} re-checked ${matching.length} control(s) on ${finding.component}: ` +
          `${failed.length} failing. ${args.notes.trim()}`.trim(),
      sourceUserAgent: "runner",
      sourceIp: "unavailable",
    }, now);

    return {
      ok: true as const,
      findingId: finding.findingId,
      state: to,
      stateLabel: FINDING_STATE_LABELS[to] ?? to,
      checksConsidered: matching.length,
      checksFailing: failed.length,
    };
  },
});

/**
 * Grants a SecureScan role. Internal only.
 *
 * There is deliberately no public function that can call this: a role grant is
 * the one operation that must not be reachable from the product's own API, or
 * privilege escalation becomes a self-service feature.
 */
export const setRole = internalMutation({
  args: {
    userId: v.string(),
    role: v.union(
      v.literal("ADMIN"),
      v.literal("SECURITY_ANALYST"),
      v.literal("VIEWER"),
    ),
    grantedByUserId: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    const now = Date.now();
    const existing = await ctx.db
      .query("securescanMembers")
      .withIndex("by_userId", (q) => q.eq("userId", args.userId))
      .unique();
    if (existing) {
      await ctx.db.patch(existing._id, { role: args.role, grantedAt: now });
      return { userId: args.userId, role: args.role, updated: true };
    }
    await ctx.db.insert("securescanMembers", {
      userId: args.userId,
      role: args.role,
      ...(args.grantedByUserId ? { grantedByUserId: args.grantedByUserId } : {}),
      grantedAt: now,
    });
    return { userId: args.userId, role: args.role, updated: false };
  },
});

export const listMembers = query({
  args: {},
  handler: async (ctx) => {
    const userId = await requireUserId(ctx);
    const role = await requireMemberRole(ctx, userId);
    const decision = authorize({ userId, role }, "admin:users");
    if (!decision.allowed) throw new ConvexError(decision.code);

    const members = await ctx.db.query("securescanMembers").collect();
    return members.map((member) => ({
      userId: member.userId,
      role: member.role,
      grantedByUserId: member.grantedByUserId ?? null,
      grantedAt: member.grantedAt,
    }));
  },
});
