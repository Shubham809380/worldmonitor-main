import { ConvexError, v } from "convex/values";
import { query } from "../_generated/server";
import { requireUserId } from "../lib/auth";
import { authorize, type Actor } from "../../server/securescan/identity";
import { requireMemberRole, verifyAuditChain } from "./_shared";

/**
 * Recomputes the hash chain for an assessment and compares it against the head
 * digest stored on the assessment row.
 *
 * Comparing against the stored head rather than only walking the entries is
 * what makes truncation detectable: an attacker who removes the tail of the
 * chain leaves a self-consistent prefix, which only fails because the head no
 * longer matches.
 */
export const verify = query({
  args: { assessmentId: v.string() },
  handler: async (ctx, args) => {
    const userId = await requireUserId(ctx);
    const role = await requireMemberRole(ctx, userId);
    const actor: Actor = { userId, role };
    const decision = authorize(actor, "admin:audit", {
      id: args.assessmentId,
      kind: "assessment",
    });
    if (!decision.allowed) throw new ConvexError(decision.code);

    const assessment = await ctx.db
      .query("securescanAssessments")
      .withIndex("by_assessmentId", (q) => q.eq("assessmentId", args.assessmentId))
      .unique();
    if (!assessment) throw new ConvexError("SECURESCAN_ASSESSMENT_NOT_FOUND");

    const entries = await ctx.db
      .query("securescanAuditLog")
      .withIndex("by_assessment_seq", (q) => q.eq("assessmentId", args.assessmentId))
      .collect();

    const verification = await verifyAuditChain(entries, {
      auditEntryCount: assessment.auditEntryCount,
      auditHeadHash: assessment.auditHeadHash,
    });

    return { assessmentId: args.assessmentId, ...verification };
  },
});

/**
 * Reads the audit trail. Admin-only, because it exposes every principal's
 * actions on the workspace.
 */
export const list = query({
  args: { assessmentId: v.string(), limit: v.optional(v.number()) },
  handler: async (ctx, args) => {
    const userId = await requireUserId(ctx);
    const role = await requireMemberRole(ctx, userId);
    const actor: Actor = { userId, role };
    const decision = authorize(actor, "admin:audit", {
      id: args.assessmentId,
      kind: "assessment",
    });
    if (!decision.allowed) throw new ConvexError(decision.code);

    const limit = Math.min(Math.max(args.limit ?? 100, 1), 500);
    const entries = await ctx.db
      .query("securescanAuditLog")
      .withIndex("by_assessment_seq", (q) => q.eq("assessmentId", args.assessmentId))
      .take(limit);

    return entries.map((entry) => ({
      seq: entry.seq,
      actorUserId: entry.actorUserId,
      actorRole: entry.actorRole,
      action: entry.action,
      resourceType: entry.resourceType,
      resourceId: entry.resourceId,
      outcome: entry.outcome,
      reasonCode: entry.reasonCode,
      detail: entry.detail,
      sourceUserAgent: entry.sourceUserAgent,
      sourceIp: entry.sourceIp,
      at: entry.at,
      hash: entry.hash,
    }));
  },
});
