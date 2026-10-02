/**
 * WorldGuard Google-account store (api/auth/google/*).
 *
 * The Google OAuth callback persists the verified profile here via a protected
 * Convex relay route (/relay/worldguard-user). The primary key is Google's
 * stable `sub`, NOT a Clerk subject — see the schema comment on
 * `worldguardUsers` for why this lives apart from `users`.
 *
 * Internal-only: no public query exposes these rows, and the relay route is
 * the only caller. Identity comes from the body, but only the edge callback
 * can reach the relay (authorized by CONVEX_TENANT_RELAY_SECRET), and every
 * field is length-bounded + shape-validated before it is stored.
 */
import { internalMutation } from "./_generated/server";
import { v } from "convex/values";

const MAX_SUB_LEN = 256;
const MAX_EMAIL_LEN = 320;
const MAX_NAME_LEN = 256;
const MAX_PICTURE_LEN = 2048;

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export const upsert = internalMutation({
  args: {
    googleSub: v.string(),
    email: v.optional(v.string()),
    name: v.optional(v.string()),
    picture: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    const sub = args.googleSub.trim();
    if (!sub || sub.length > MAX_SUB_LEN) {
      return { ok: false as const, reason: "invalid-sub" };
    }

    const email = (args.email ?? "").trim();
    if (email.length > 0) {
      if (email.length > MAX_EMAIL_LEN || !EMAIL_RE.test(email)) {
        return { ok: false as const, reason: "invalid-email" };
      }
    }
    const normalizedEmail = email.length > 0 ? email.toLowerCase() : undefined;

    const name = (args.name ?? "").trim().slice(0, MAX_NAME_LEN) || undefined;
    const picture = (args.picture ?? "").trim().slice(0, MAX_PICTURE_LEN) || undefined;

    const now = Date.now();
    const existing = await ctx.db
      .query("worldguardUsers")
      .withIndex("by_googleSub", (q) => q.eq("googleSub", sub))
      .unique();

    if (existing) {
      const changed =
        (email.length > 0 && existing.email !== email) ||
        (normalizedEmail && existing.normalizedEmail !== normalizedEmail) ||
        (name && existing.name !== name) ||
        (picture !== undefined && existing.picture !== picture);
      if (!changed) {
        return { ok: true as const, isNew: false };
      }
      await ctx.db.patch(existing._id, {
        email: email.length > 0 ? email : undefined,
        normalizedEmail,
        name,
        picture,
        lastSeenAt: now,
      });
      return { ok: true as const, isNew: false };
    }

    await ctx.db.insert("worldguardUsers", {
      googleSub: sub,
      email: email.length > 0 ? email : undefined,
      normalizedEmail,
      name,
      picture,
      firstSeenAt: now,
      lastSeenAt: now,
    });
    return { ok: true as const, isNew: true };
  },
});