/**
 * WM SecureScan — membership administration.
 *
 * There are two separate questions here and conflating them is how privilege
 * escalation becomes a product feature:
 *
 *  - **"May I grant a role to somebody else?"** An admin may. This is the
 *    product's only way to onboard a colleague, and without it every real user
 *    is refused at the door by `requireMemberRole`.
 *  - **"May I grant a role to myself?"** Nobody may. That is not a missing
 *    feature; it is the thing the whole role model exists to prevent.
 *
 * `setRole` in `findings.ts` stays `internalMutation` for bootstrap and trusted
 * runners. This module is the *admin* path: it authorizes with `admin:users`,
 * refuses self-assignment, and refuses to remove the last admin, because a
 * deployment whose final admin has been demoted is permanently unmanageable and
 * would need a direct database edit to recover.
 *
 * Every grant, change and revocation is written to the audit chain of the
 * assessment the calling admin is looking at when they make it, so a role change
 * has the same traceability as a scan.
 */

import { ConvexError, v } from "convex/values";
import { mutation, query } from "../_generated/server";
import { requireUserId } from "../lib/auth";
import { authorize, type Actor, type Role } from "../../server/securescan/identity";
import { ROLES } from "./validators";
import { appendAudit, attestedSource, requireMemberRole } from "./_shared";

function roleValidator() {
  return v.union(...ROLES.map((role) => v.literal(role)));
}


type GrantResult =
  | {
      readonly ok: true;
      readonly userId: string;
      readonly role: Role;
      readonly action: "granted" | "changed" | "revoked";
    }
  | {
      readonly ok: false;
      readonly code:
        | "ROLE_FORBIDDEN"
        | "SECURESCAN_SELF_GRANT_FORBIDDEN"
        | "SECURESCAN_LAST_ADMIN"
        | "SECURESCAN_MEMBER_NOT_FOUND"
        | "SECURESCAN_INVALID_SUBJECT";
      readonly reason: string;
    };

export const listMembers = query({
  args: {},
  handler: async (ctx) => {
    const userId = await requireUserId(ctx);
    const role = await requireMemberRole(ctx, userId);
    const decision = authorize({ userId, role }, "admin:users");
    if (!decision.allowed) throw new ConvexError(decision.code);

    const members = await ctx.db.query("securescanMembers").collect();
    return members
      .map((member) => ({
        userId: member.userId,
        role: member.role as Role,
        grantedByUserId: member.grantedByUserId ?? null,
        grantedAt: member.grantedAt,
      }))
      .sort((a, b) => a.userId.localeCompare(b.userId));
  },
});

/**
 * Grants, changes or revokes a role.
 *
 * `assessmentId` is required and is where the change is audited. It is not
 * decoration: a role change with no recorded context is indistinguishable from a
 * role change that never happened, and an admin reviewing the console needs to
 * see it attached to the work that prompted it.
 */
export const setMemberRole = mutation({
  args: {
    userId: v.string(),
    role: roleValidator(),
    assessmentId: v.string(),
    /**
     * Revokes access entirely rather than demoting. Distinct from setting
     * VIEWER because after revocation the subject is refused at the door with
     * SECURESCAN_NO_MEMBERSHIP, which is a different and more accurate signal
     * than "still a member, can read".
     */
    revoke: v.optional(v.boolean()),
    reason: v.string(),
  },
  handler: async (ctx, args): Promise<GrantResult> => {
    const userId = await requireUserId(ctx);
    const role = await requireMemberRole(ctx, userId);
    const actor: Actor = { userId, role };
    const source = attestedSource();

    const target = args.userId.trim();
    if (target === "") {
      return { ok: false, code: "SECURESCAN_INVALID_SUBJECT", reason: "A user id is required." };
    }

    const decision = authorize(actor, "admin:users");
    if (!decision.allowed) {
      return { ok: false, code: "ROLE_FORBIDDEN", reason: decision.reason };
    }

    // Self-assignment is refused in every form, including "grant myself
    // ADMIN" and "grant myself VIEWER then promote". An admin who needs a
    // different role changes it with another admin.
    if (target === userId) {
      const reason =
        "You cannot change your own SecureScan role. Self-assignment is refused so a role can never be granted without a second admin's agreement.";
      await appendAudit(ctx, {
        assessmentId: args.assessmentId,
        actorUserId: userId,
        actorRole: role,
        action: "member:setRole",
        resourceType: "member",
        resourceId: target,
        outcome: "DENIED",
        reasonCode: "SECURESCAN_SELF_GRANT_FORBIDDEN",
        detail: reason,
        sourceUserAgent: source.userAgent,
        sourceIp: source.ip,
      });
      return { ok: false, code: "SECURESCAN_SELF_GRANT_FORBIDDEN", reason };
    }

    const existing = await ctx.db
      .query("securescanMembers")
      .withIndex("by_userId", (q) => q.eq("userId", target))
      .unique();

    // Removing the final admin would leave the deployment with no way to manage
    // membership at all, recoverable only by editing the database directly.
    if (args.revoke === true) {
      if (!existing) {
        const reason = `${target} has no SecureScan membership to revoke.`;
        await appendAudit(ctx, {
          assessmentId: args.assessmentId,
          actorUserId: userId,
          actorRole: role,
          action: "member:setRole",
          resourceType: "member",
          resourceId: target,
          outcome: "DENIED",
          reasonCode: "SECURESCAN_MEMBER_NOT_FOUND",
          detail: reason,
          sourceUserAgent: source.userAgent,
          sourceIp: source.ip,
        });
        return { ok: false, code: "SECURESCAN_MEMBER_NOT_FOUND", reason };
      }
      if (existing.role === "ADMIN") {
        const admins = await ctx.db
          .query("securescanMembers")
          .withIndex("by_role", (q) => q.eq("role", "ADMIN"))
          .collect();
        if (admins.length <= 1) {
          const reason =
            "This is the only remaining SecureScan admin. Revoking it would leave no way to manage membership, " +
            "recoverable only by editing the database directly. Grant another admin first.";
          await appendAudit(ctx, {
            assessmentId: args.assessmentId,
            actorUserId: userId,
            actorRole: role,
            action: "member:setRole",
            resourceType: "member",
            resourceId: target,
            outcome: "DENIED",
            reasonCode: "SECURESCAN_LAST_ADMIN",
            detail: reason,
            sourceUserAgent: source.userAgent,
            sourceIp: source.ip,
          });
          return { ok: false, code: "SECURESCAN_LAST_ADMIN", reason };
        }
      }
      const now = Date.now();
      await ctx.db.delete(existing._id);
      await appendAudit(ctx, {
        assessmentId: args.assessmentId,
        actorUserId: userId,
        actorRole: role,
        action: "member:setRole",
        resourceType: "member",
        resourceId: target,
        outcome: "ALLOWED",
        reasonCode: "MEMBERSHIP_REVOKED",
        detail: `Revoked SecureScan access for ${target} (was ${existing.role}). ${args.reason.trim()}`,
        sourceUserAgent: source.userAgent,
        sourceIp: source.ip,
      }, now);
      // The stored role is narrowed the same way `listMembers` narrows it: the
      // row's type widens to `string` because the generated table types lag the
      // schema, and `securescanRoleValidator` is what actually guarantees the
      // value is one of `ROLES` at rest.
      return { ok: true, userId: target, role: existing.role as Role, action: "revoked" };
    }

    const now = Date.now();
    if (existing) {
      await ctx.db.patch(existing._id, { role: args.role, grantedAt: now });
      await appendAudit(ctx, {
        assessmentId: args.assessmentId,
        actorUserId: userId,
        actorRole: role,
        action: "member:setRole",
        resourceType: "member",
        resourceId: target,
        outcome: "ALLOWED",
        reasonCode: "MEMBERSHIP_CHANGED",
        detail: `Changed ${target} from ${existing.role} to ${args.role}. ${args.reason.trim()}`,
        sourceUserAgent: source.userAgent,
        sourceIp: source.ip,
      }, now);
      return { ok: true, userId: target, role: args.role, action: "changed" };
    }

    await ctx.db.insert("securescanMembers", {
      userId: target,
      role: args.role,
      grantedByUserId: userId,
      grantedAt: now,
    });
    await appendAudit(ctx, {
      assessmentId: args.assessmentId,
      actorUserId: userId,
      actorRole: role,
      action: "member:setRole",
      resourceType: "member",
      resourceId: target,
      outcome: "ALLOWED",
      reasonCode: "MEMBERSHIP_GRANTED",
      detail: `Granted ${target} the role ${args.role}. ${args.reason.trim()}`,
      sourceUserAgent: source.userAgent,
      sourceIp: source.ip,
    }, now);
    return { ok: true, userId: target, role: args.role, action: "granted" };
  },
});
